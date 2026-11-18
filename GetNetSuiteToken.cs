using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Identity;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace NetSuiteAuth;

public class GetNetSuiteToken
{
    private readonly IHttpClientFactory _http;
    private readonly ILogger<GetNetSuiteToken> _log;

    public GetNetSuiteToken(IHttpClientFactory http, ILogger<GetNetSuiteToken> log)
    {
        _http = http;
        _log = log;
    }

    [Function("GetNetSuiteToken")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "get", "post")] HttpRequest req)
    {
        try
        {
            // App settings
            var accountId = Env("NETSUITE_ACCOUNT_ID");   // e.g. TSTDRV123456_SB1
            var clientId  = Env("NETSUITE_CLIENT_ID");
            var certId    = Env("NETSUITE_CERT_ID");      // used as "kid"
            var vaultName = Env("KEYVAULT_NAME");
            var keyName   = Env("KEYVAULT_KEY_NAME");
            var scope     = Environment.GetEnvironmentVariable("NETSUITE_SCOPE") ?? "rest_webservices";

            // Optional input: mode = "token" (default) or "assertion"
            var mode = req.Query["mode"].ToString();
            if (string.IsNullOrEmpty(mode) && req.Method == "POST" && req.ContentLength > 0)
            {
                using var doc = await JsonDocument.ParseAsync(req.Body);
                if (doc.RootElement.TryGetProperty("mode", out var m))
                    mode = m.GetString() ?? "";
            }
            if (string.IsNullOrEmpty(mode)) mode = "token";

            // NetSuite URL format: lowercase, underscores become hyphens
            var host = accountId.ToLowerInvariant().Replace('_', '-');
            var tokenEndpoint = $"https://{host}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token";

            // Build JWT
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var header = JsonSerializer.Serialize(new { alg = "PS256", typ = "JWT", kid = certId });
            var claims = JsonSerializer.Serialize(new
            {
                iss = clientId,
                scope = new[] { scope },
                aud = tokenEndpoint,
                iat = now,
                exp = now + 3300   // NetSuite max is 1 hour
            });

            var signingInput = $"{B64Url(Encoding.UTF8.GetBytes(header))}.{B64Url(Encoding.UTF8.GetBytes(claims))}";

            // Sign in Key Vault using the managed identity; the private key never leaves the vault
            var keyUri = new Uri($"https://{vaultName}.vault.azure.net/keys/{keyName}");
            var crypto = new CryptographyClient(keyUri, new DefaultAzureCredential());
            var signResult = await crypto.SignDataAsync(
                SignatureAlgorithm.PS256, Encoding.UTF8.GetBytes(signingInput));

            var jwt = $"{signingInput}.{B64Url(signResult.Signature)}";

            if (mode == "assertion")
                return new OkObjectResult(new { client_assertion = jwt });

            // Exchange the JWT for a NetSuite access token
            var client = _http.CreateClient();
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ["client_assertion"] = jwt
            });

            var resp = await client.PostAsync(tokenEndpoint, form);
            var content = await resp.Content.ReadAsStringAsync();

            return new ContentResult
            {
                Content = content,
                ContentType = "application/json",
                StatusCode = (int)resp.StatusCode
            };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to get NetSuite token");
            return new ObjectResult(ex.Message) { StatusCode = 500 };
        }
    }

    private static string Env(string name) =>
        Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException($"Missing app setting: {name}");

    private static string B64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
