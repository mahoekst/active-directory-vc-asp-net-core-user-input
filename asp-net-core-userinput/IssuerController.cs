using Microsoft.AspNetCore.Mvc;
using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Hosting;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Net;
using System.Net.Http;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using System.Diagnostics;
using asp_net_core_user_input;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Identity.Web;
using Microsoft.Identity.Client;
using System.Net.Http.Headers;

namespace Verifiable_credentials_DotNet
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class IssuerController : ControllerBase
    {
        const string ISSUANCEPAYLOAD = "issuance_request_config.json";

        protected readonly AppSettingsModel AppSettings;
        protected IMemoryCache _cache;

        public IssuerController(IOptions<AppSettingsModel> appSettings, IMemoryCache memoryCache)
        {
            this.AppSettings = appSettings.Value;
            _cache = memoryCache;
        }

        [HttpGet("/api/issuer/issuance-request")]
        public async Task<ActionResult> issuanceRequest()
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

                //
                // modify the payload from the template with the correct values like pincode and state
                //
                string jsonString = null;
                string newpin = null;

                string payloadpath = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location), ISSUANCEPAYLOAD);
                if (!System.IO.File.Exists(payloadpath)) { return BadRequest(new { error = "400", error_description = ISSUANCEPAYLOAD + " not found" }); }
                jsonString = System.IO.File.ReadAllText(payloadpath);
                if (string.IsNullOrEmpty(jsonString)) { return BadRequest(new { error = "400", error_description = ISSUANCEPAYLOAD + " not found" }); }

                string state = Guid.NewGuid().ToString();

                //check if pin is required, if found make sure we set a new random pin
                JObject payload = JObject.Parse(jsonString);
                if (payload["issuance"]["pin"] != null)
                {
                    var length = (int)payload["issuance"]["pin"]["length"];
                    var pinMaxValue = (int)Math.Pow(10, length) - 1;
                    var randomNumber = RandomNumberGenerator.GetInt32(1, pinMaxValue);
                    newpin = string.Format("{0:D" + length.ToString() + "}", randomNumber);
                    payload["issuance"]["pin"]["value"] = newpin;
                }

                if (payload["callback"]["state"] != null)
                {
                    payload["callback"]["state"] = state;
                }

                jsonString = JsonConvert.SerializeObject(payload);

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

                    if (statusCode == HttpStatusCode.Created)
                    {

                        JObject requestConfig = JObject.Parse(response);
                        if (newpin != null) { requestConfig["pin"] = newpin; }
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
                    else
                    {
                        return BadRequest(new { error = "400", error_description = "Something went wrong calling the API: " + response });
                    }

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


        [HttpPost("/api/issuer/issuanceCallback")]
        public async Task<ActionResult> issuanceCallback()
        {
            try
            {
                string content = new System.IO.StreamReader(this.Request.Body).ReadToEndAsync().Result;
                Debug.WriteLine("callback!: " + content);
                JObject issuanceResponse = JObject.Parse(content);
                var state = issuanceResponse["state"].ToString();

                if (issuanceResponse["code"].ToString() == "request_retrieved")
                {
                    var cacheData = new
                    {
                        status = "request_retrieved",
                        message = "QR Code is scanned. Waiting for issuance...",
                    };
                    _cache.Set(state, JsonConvert.SerializeObject(cacheData));
                }

                //
                //THIS IS NOT IMPLEMENTED IN OUR SERVICE YET, ONLY MOCKUP FOR ONCE WE DO SUPPORT THE CALLBACK AFTER ISSUANCE
                //
                if (issuanceResponse["code"].ToString() == "issuance_succesful")
                {
                    var cacheData = new
                    {
                        status = "issuance_succesful",
                        message = "Credential succesful issued",
                    };
                    _cache.Set(state, JsonConvert.SerializeObject(cacheData));
                }
                if (issuanceResponse["code"].ToString() == "issuance_failed")
                {
                    var cacheData = new
                    {
                        status = "issuance_failed",
                        message = "Credential issuance failed",
                        payload = issuanceResponse["details"].ToString()
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

        [HttpGet("/api/issuer/issuance-response")]
        public async Task<ActionResult> issuanceResponse()
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

                return new OkResult();
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = "400", error_description = ex.Message });
            }
        }
    }
}
