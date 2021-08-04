using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Identity.Client;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using asp_net_core_user_input;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Identity.Web;
using Microsoft.Identity.Client;
using System.Net.Http.Headers;
using Microsoft.Extensions.Options;

namespace Verifiable_credentials_DotNet
{
    public class VerifierController : Controller
    {
        const string PRESENTATIONPAYLOAD = "presentation_request_config.json";

        protected readonly AppSettingsModel AppSettings;
        protected IMemoryCache _cache;
        public VerifierController(IOptions<AppSettingsModel> appSettings,IMemoryCache memoryCache)
        {
            this.AppSettings = appSettings.Value;
            _cache = memoryCache;
        }


        [HttpGet("/api/verifier/presentation-request")]
        public async Task<ActionResult> presentationRequest()
        {
            try
            {
                //
                //TODO Setup the proper access token cache for client credentials
                //
                // You can run this sample using ClientSecret or Certificate. The code will differ only when instantiating the IConfidentialClientApplication
                bool isUsingClientSecret = AppSettings.AppUsesClientSecret(AppSettings);
                
                // Since we are using application permissions this will be a confidential client application
                IConfidentialClientApplication app;
                if (isUsingClientSecret)
                {
                    app = ConfidentialClientApplicationBuilder.Create(AppSettings.ClientId)
                        .WithClientSecret(AppSettings.ClientSecret)
                        .WithAuthority(new Uri(AppSettings.Authority))
                        .Build();
                }
                else
                {
                    X509Certificate2 certificate = AppSettings.ReadCertificate(AppSettings.CertificateName);
                    app = ConfidentialClientApplicationBuilder.Create(AppSettings.ClientId)
                        .WithCertificate(certificate)
                        .WithAuthority(new Uri(AppSettings.Authority))
                        .Build();
                }

                // With client credentials flows the scopes is ALWAYS of the shape "resource/.default", as the 
                // application permissions need to be set statically (in the portal or by PowerShell), and then granted by
                // a tenant administrator. 
                string[] scopes = new string[] { AppSettings.VCServiceScope };

                AuthenticationResult result = null;
                try
                {
                    result = await app.AcquireTokenForClient(scopes)
                        .ExecuteAsync();
                }
                catch (MsalServiceException ex) when (ex.Message.Contains("AADSTS70011"))
                {
                    // Invalid scope. The scope has to be of the form "https://resourceurl/.default"
                    // Mitigation: change the scope to be as expected
                    return BadRequest(new { error = "500", error_description = "Scope provided is not suppoerted" });
                }
                catch (MsalServiceException ex)
                {
                    // general error getting an access token
                    return BadRequest(new { error = "500", error_description = "Something went wrong getting an access token for the client API:" + ex.Message });
                }

                string jsonString = null;

                string payloadpath = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location), PRESENTATIONPAYLOAD);
                if (!System.IO.File.Exists(payloadpath)) { return BadRequest(new { error = "400", error_description = PRESENTATIONPAYLOAD + " not found" }); }
                jsonString = System.IO.File.ReadAllText(payloadpath);
                if (string.IsNullOrEmpty(jsonString)) { return BadRequest(new { error = "400", error_description = PRESENTATIONPAYLOAD + " not found" }); }

                string state = Guid.NewGuid().ToString();

                //modify payload with new state
                JObject config = JObject.Parse(jsonString);
                if (config["callback"]["state"] != null)
                {
                    config["callback"]["state"] = state;
                }

                jsonString = JsonConvert.SerializeObject(config);


                //CALL REST API WITH PAYLOAD
                HttpStatusCode statusCode = HttpStatusCode.OK;
                string response = null;
                try
                {
                    HttpClient client = new HttpClient();
                    var defaultRequestHeaders = client.DefaultRequestHeaders;
                    defaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);

                    HttpResponseMessage res = client.PostAsync(AppSettings.ApiEndpoint, new StringContent(jsonString, Encoding.UTF8, "application/json")).Result;
                    response = res.Content.ReadAsStringAsync().Result;
                    client.Dispose();
                    statusCode = res.StatusCode;

                    JObject requestConfig = JObject.Parse(response);
                    requestConfig.Add(new JProperty("id", state));
                    jsonString = JsonConvert.SerializeObject(requestConfig);

                    var cacheData = new
                    {
                        status = "notscanned",
                        message = "Request ready, please scan with Authenticator",
                        expiry = requestConfig["expiry"].ToString()
                    };
                    _cache.Set(state, JsonConvert.SerializeObject(cacheData));

                    return new ContentResult { ContentType = "application/json", Content = jsonString };
                }
                catch (Exception ex)
                {
                    return BadRequest(new { error = "400", error_description = "Something went wrong calling the API: " + ex.Message });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = "400", error_description = ex.Message });
            }
        }


        [HttpPost("/api/verifier/presentationCallback")]
        public async Task<ActionResult> presentationCallback()
        {
            try
            {
                string content = new System.IO.StreamReader(this.Request.Body).ReadToEndAsync().Result;
                Debug.WriteLine("callback!: " + content);
                JObject presentationResponse = JObject.Parse(content);
                var state = presentationResponse["state"].ToString();

                if (presentationResponse["code"].ToString() == "request_retrieved")
                {
                    var cacheData = new
                    {
                        status = "request_retrieved",
                        message = "QR Code is scanned. Waiting for validation...",
                    };
                    _cache.Set(state, JsonConvert.SerializeObject(cacheData));
                }

                if (presentationResponse["code"].ToString() == "presentation_verified")
                {
                    var cacheData = new
                    {
                        status = "presentation_verified",
                        message = "Presentation received",
                        payload = presentationResponse["issuers"].ToString(),
                        subject = presentationResponse["subject"].ToString()
                    };
                    _cache.Set(state, JsonConvert.SerializeObject(cacheData));

                }

                return new OkResult();
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = "400", error_description = ex.Message });
            }
        }

        //
        //this function is called from the UI polling for a response from the AAD VC Service.
        //when a callback is recieved at the presentationCallback service the session will be updated
        //this method will respond with the status so the UI can reflect if the QR code was scanned and with the result of the presentation
        //
        [HttpGet("/api/verifier/presentation-response")]
        public async Task<ActionResult> presentationResponse()
        {
            
            try
            {
                string state = this.Request.Query["id"];
                if (string.IsNullOrEmpty(state))
                {
                    return BadRequest(new { error = "400", error_description = "Missing argument 'id'" });
                }
                JObject value = null;
                if (_cache.TryGetValue(state, out string buf))
                {
                    value = JObject.Parse(buf);

                    Debug.WriteLine("check if there was a response yet: " + value);
                    return new ContentResult { ContentType = "application/json", Content = JsonConvert.SerializeObject(value) }; 
                }

                //JObject cacheData = null;
                //if (GetCachedJsonObject(state, out cacheData))
                //{
                //    _log.LogTrace("Have VC validation result");
                //    //RemoveCacheValue( state ); // if you're not using B2C integration, uncomment this line
                //    return ReturnJson(TransformCacheDataToBrowserResponse(cacheData));
                //}
                //else
                //{
                //    string requestId = this.Request.Query["requestId"];
                //    if (!string.IsNullOrEmpty(requestId) && GetCachedJsonObject(requestId, out cacheData))
                //    {
                //        _log.LogTrace("Have 1st callback");
                //        RemoveCacheValue(requestId);
                //        return ReturnJson(TransformCacheDataToBrowserResponse(cacheData));
                //    }
                //}
                return new OkResult();
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = "400", error_description = ex.Message });
            }


        }
    }
}
