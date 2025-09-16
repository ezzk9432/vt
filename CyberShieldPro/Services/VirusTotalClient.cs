
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace Antivruis.Services
{
    public class VirusTotalClient : IDisposable
    {
        private readonly HttpClient _http;
        private string _apiKey;
        private readonly string _baseUrl;

        public VirusTotalClient()
        {
            _http = new HttpClient();
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var appsettingsPath = Path.Combine(baseDir, "appsettings.json");
            string? fileApiKey = null;
            try
            {
                if (File.Exists(appsettingsPath))
                {
                    var json = System.Text.Json.JsonDocument.Parse(File.ReadAllText(appsettingsPath));
                    if (json.RootElement.TryGetProperty("VirusTotal", out var vt) && vt.TryGetProperty("ApiKey", out var keyEl))
                        fileApiKey = keyEl.GetString();
                    if (json.RootElement.TryGetProperty("VirusTotal", out vt) && vt.TryGetProperty("BaseUrl", out var urlEl))
                        _baseUrl = urlEl.GetString() ?? "https://www.virustotal.com/api/v3/";
                    else
                        _baseUrl = "https://www.virustotal.com/api/v3/";
                }
                else
                {
                    _baseUrl = "https://www.virustotal.com/api/v3/";
                }
            }
            catch
            {
                _baseUrl = "https://www.virustotal.com/api/v3/";
            }

            _apiKey = Environment.GetEnvironmentVariable("VT_API_KEY") ?? fileApiKey ?? "";
            if (string.IsNullOrWhiteSpace(_apiKey))
                throw new InvalidOperationException("VirusTotal API key not configured. Set env VT_API_KEY or appsettings.json VirusTotal:ApiKey.");
        }

        public void OverrideApiKey(string? apiKey)
        {
            if (!string.IsNullOrWhiteSpace(apiKey))
                _apiKey = apiKey!;
            else
                _apiKey = Environment.GetEnvironmentVariable("VT_API_KEY") 
                          ?? _apiKey; // keep prior or env
        }

        private void ApplyHeaders(HttpRequestMessage req)
        {
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            req.Headers.Add("x-apikey", _apiKey);
        }

        private async Task<JObject> SendAsync(HttpRequestMessage req)
        {
            ApplyHeaders(req);
            using var resp = await _http.SendAsync(req);
            var content = await resp.Content.ReadAsStringAsync();
            if ((int)resp.StatusCode == 429)
                throw new Exception("Rate limit hit (429). The Public API is ~4 req/min and ~500/day.");
            if (!resp.IsSuccessStatusCode)
                throw new Exception($"HTTP {(int)resp.StatusCode} - {resp.ReasonPhrase}\n{content}");
            return JObject.Parse(string.IsNullOrWhiteSpace(content) ? "{}" : content);
        }

        // Upload small (<32MB) or regular file
        public async Task<JObject> UploadFileAsync(string path)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, _baseUrl + "files");
            var mp = new MultipartFormDataContent();
            var fs = File.OpenRead(path);
            mp.Add(new StreamContent(fs), "file", Path.GetFileName(path));
            req.Content = mp;
            return await SendAsync(req);
        }

        // Large files: first get upload_url, then POST to that absolute url
        public async Task<string> GetLargeFileUploadUrlAsync()
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, _baseUrl + "files/upload_url");
            var json = await SendAsync(req);
            return json["data"]?.ToString() ?? throw new Exception("No upload URL received.");
        }

        public async Task<JObject> UploadLargeFileAsync(string uploadUrl, string path)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, uploadUrl);
            var mp = new MultipartFormDataContent();
            var fs = File.OpenRead(path);
            mp.Add(new StreamContent(fs), "file", Path.GetFileName(path));
            req.Content = mp;
            return await SendAsync(req);
        }

        // Poll analysis by id
        public async Task<JObject> GetAnalysisAsync(string analysisId)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, _baseUrl + "analyses/" + analysisId);
            return await SendAsync(req);
        }

        // File report by hash
        public async Task<JObject> GetFileReportByHashAsync(string hash)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, _baseUrl + "files/" + hash);
            return await SendAsync(req);
        }

        // Submit URL for scanning
        public async Task<JObject> SubmitUrlForScanAsync(string url)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, _baseUrl + "urls");
            req.Content = new StringContent("url=" + Uri.EscapeDataString(url), Encoding.UTF8, "application/x-www-form-urlencoded");
            return await SendAsync(req);
        }

        // Get URL report: use base64 URL-safe (no padding) ID
        public async Task<JObject> GetUrlReportAsync(string url)
        {
            string urlId = ToUrlIdBase64(url);
            using var req = new HttpRequestMessage(HttpMethod.Get, _baseUrl + "urls/" + urlId);
            return await SendAsync(req);
        }

        public static string ToUrlIdBase64(string url)
        {
            var bytes = Encoding.UTF8.GetBytes(url);
            var b64 = Convert.ToBase64String(bytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
            return b64;
        }

        // Domain report
        public async Task<JObject> GetDomainReportAsync(string domain)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, _baseUrl + "domains/" + domain);
            return await SendAsync(req);
        }

        // IP report
        public async Task<JObject> GetIpReportAsync(string ip)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, _baseUrl + "ip_addresses/" + ip);
            return await SendAsync(req);
        }

        public void Dispose()
        {
            _http.Dispose();
        }
    }

    static class StringExt
    {
        public static string rstrip(this string s, string trim) => s.EndsWith(trim) ? s.Substring(0, s.Length - trim.Length) : s;
    }
}
