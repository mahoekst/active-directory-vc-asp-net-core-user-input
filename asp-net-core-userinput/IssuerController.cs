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
        const string APIENDPOINT = "https://beta.did.msidentity.com/v1.0/cc7743d2-9026-44df-ba0e-33f87ebba062/verifiablecredentials/request";

        protected IMemoryCache _cache;

        public IssuerController(IMemoryCache memoryCache)
        {
            _cache = memoryCache;
        }

        [HttpGet("/api/issuer/issuance-request")]
        public async Task<ActionResult> issuanceRequest()
        {
            try
            {
 
                //
                //TODO put the MSAL and auth config piece centrally and setup the proper access token cache
                //
                AuthenticationConfig config = AuthenticationConfig.ReadFromJsonFile("appsettings.json");
                // You can run this sample using ClientSecret or Certificate. The code will differ only when instantiating the IConfidentialClientApplication
                bool isUsingClientSecret = AppUsesClientSecret(config);

                // Since we are using application permissions this will be a confidential client application
                IConfidentialClientApplication app;
                if (isUsingClientSecret)
                {
                    app = ConfidentialClientApplicationBuilder.Create(config.ClientId)
                        .WithClientSecret(config.ClientSecret)
                        .WithAuthority(new Uri(config.Authority))
                        .Build();
                }

                else
                {
                    X509Certificate2 certificate = ReadCertificate(config.CertificateName);
                    app = ConfidentialClientApplicationBuilder.Create(config.ClientId)
                        .WithCertificate(certificate)
                        .WithAuthority(new Uri(config.Authority))
                        .Build();
                }

                // With client credentials flows the scopes is ALWAYS of the shape "resource/.default", as the 
                // application permissions need to be set statically (in the portal or by PowerShell), and then granted by
                // a tenant administrator. 
                string[] scopes = new string[] { config.VCServiceScope };

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

                    HttpResponseMessage res = client.PostAsync(APIENDPOINT, new StringContent(jsonString, Encoding.UTF8, "application/json")).Result;
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
                if (issuanceResponse["code"].ToString() == "credential_issued")
                {
                    var cacheData = new
                    {
                        status = "credential_issued",
                        message = "Credential succesful issued",
                        payload = issuanceResponse["issuers"].ToString(),
                        subject = issuanceResponse["subject"].ToString()
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



        /// <summary>
        /// Checks if the sample is configured for using ClientSecret or Certificate. This method is just for the sake of this sample.
        /// You won't need this verification in your production application since you will be authenticating in AAD using one mechanism only.
        /// </summary>
        /// <param name="config">Configuration from appsettings.json</param>
        /// <returns></returns>
        private static bool AppUsesClientSecret(AuthenticationConfig config)
        {
            string clientSecretPlaceholderValue = "[Enter here a client secret for your application]";
            string certificatePlaceholderValue = "[Or instead of client secret: Enter here the name of a certificate (from the user cert store) as registered with your application]";

            if (!String.IsNullOrWhiteSpace(config.ClientSecret) && config.ClientSecret != clientSecretPlaceholderValue)
            {
                return true;
            }

            else if (!String.IsNullOrWhiteSpace(config.CertificateName) && config.CertificateName != certificatePlaceholderValue)
            {
                return false;
            }

            else
                throw new Exception("You must choose between using client secret or certificate. Please update appsettings.json file.");
        }

        private static X509Certificate2 ReadCertificate(string certificateName)
        {
            if (string.IsNullOrWhiteSpace(certificateName))
            {
                throw new ArgumentException("certificateName should not be empty. Please set the CertificateName setting in the appsettings.json", "certificateName");
            }
            CertificateDescription certificateDescription = CertificateDescription.FromStoreWithDistinguishedName(certificateName);
            DefaultCertificateLoader defaultCertificateLoader = new DefaultCertificateLoader();
            defaultCertificateLoader.LoadIfNeeded(certificateDescription);
            return certificateDescription.Certificate;
        }
    }

}
