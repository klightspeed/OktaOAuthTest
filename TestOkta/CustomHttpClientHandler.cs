using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Okta.Sdk.Client;
using System.Buffers.Text;
using System.Net;
using System.Text;

namespace TestOkta
{
    internal class CustomHttpClientHandler(Configuration config) : HttpClientHandler
    {
        private readonly Configuration Configuration = config;
        public string? LastRequestMethod { get; private set; }
        public string? LastRequestURI { get; private set; }
        public string? LastRequestAuthScheme { get; private set; }
        public string? LastRequestAuthTokenHeader { get; private set; }
        public string? LastRequestAuthTokenPayload { get; private set; }
        public string? LastRequestDPoPTokenHeader { get; private set; }
        public string? LastRequestDPoPTokenPayload { get; private set; }
        public HttpStatusCode? LastResponseStatus { get; private set; }
        public string? LastContentType { get; private set; }

        private void PrintAuth(HttpRequestMessage request)
        {
            LastRequestAuthScheme = request.Headers.Authorization?.Scheme;

            if (request.Headers.Authorization is { } authHeader
                && authHeader.Scheme == "DPoP"
                && authHeader.Parameter is string auth
                && auth.Split('.') is [string authTokenHdrB64, string authTokenPayloadB64, string]
                && request.Headers.GetValues("DPoP")?.ToList() is [string dpopHeader]
                && dpopHeader.Split('.') is [string dpopTokenHdrB64, string dpopTokenPayloadB64, string])
            {
                var authTokenHdr = JObject.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(authTokenHdrB64)));
                var authTokenPayload = JObject.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(authTokenPayloadB64)));
                var dpopTokenHdr = JObject.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(dpopTokenHdrB64)));
                var dpopTokenPayload = JObject.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(dpopTokenPayloadB64)));
                if (authTokenHdr["kid"] != null) authTokenHdr["kid"] = "«REDACTED»";
                if (authTokenPayload["jti"] != null) authTokenPayload["jti"] = "«REDACTED»";
                if (authTokenPayload["sub"] != null) authTokenPayload["sub"] = "«REDACTED»";
                if (authTokenPayload["cid"] != null) authTokenPayload["cid"] = "«REDACTED»";
                if (authTokenPayload["iss"] != null) authTokenPayload["iss"] = authTokenPayload.Value<string>("iss")?.Replace(Configuration.OktaDomain, "https://«REDACTED».okta.com");
                if (authTokenPayload["aud"] != null) authTokenPayload["aud"] = authTokenPayload.Value<string>("aud")?.Replace(Configuration.OktaDomain, "https://«REDACTED».okta.com");
                if (authTokenPayload["cnf"]?["jkt"] != null) authTokenPayload["cnf"]?["jkt"] = "«REDACTED»";
                if (dpopTokenHdr["jwk"]?["n"] != null) dpopTokenHdr["jwk"]?["n"] = "«REDACTED»";
                if (dpopTokenPayload["ath"] != null) dpopTokenPayload["ath"] = "«REDACTED»";
                if (dpopTokenPayload["htu"] != null) dpopTokenPayload["htu"] = dpopTokenPayload.Value<string>("htu")?.Replace(Configuration.OktaDomain, "https://«REDACTED».okta.com");
                LastRequestAuthTokenHeader = authTokenHdr.ToString(Formatting.Indented);
                LastRequestAuthTokenPayload = authTokenPayload.ToString(Formatting.Indented);
                LastRequestDPoPTokenHeader = dpopTokenHdr.ToString(Formatting.Indented);
                LastRequestDPoPTokenPayload = dpopTokenPayload.ToString(Formatting.Indented);
                Console.WriteLine($"Authorization: {LastRequestAuthScheme}");
                Console.WriteLine($"Authorization.Header: {LastRequestAuthTokenHeader}");
                Console.WriteLine($"Authorization.Payload: {LastRequestAuthTokenPayload}");
                Console.WriteLine($"DPoP.Header: {LastRequestDPoPTokenHeader}");
                Console.WriteLine($"DPoP.Payload: {LastRequestDPoPTokenPayload}");
            }
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequestMethod = request.Method.Method;
            LastRequestURI = request.RequestUri?.ToString().Replace(Configuration.OktaDomain, "https://«REDACTED».okta.com");
            Console.WriteLine($"Sending {LastRequestMethod} {LastRequestURI}");

            PrintAuth(request);

            var resp = await base.SendAsync(request, cancellationToken);

            LastResponseStatus = resp.StatusCode;
            LastContentType = resp.Content.Headers.ContentType?.MediaType;

            Console.WriteLine($"Got {(int)resp.StatusCode} {resp.ReasonPhrase} with Content-Type: {resp.Content.Headers.ContentType?.MediaType} and Content-Length: {resp.Content.Headers.ContentLength}");

            return resp;
        }
    }
}
