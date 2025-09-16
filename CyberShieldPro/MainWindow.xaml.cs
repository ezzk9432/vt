
using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Collections.Generic;
using System.Linq;

namespace Antivruis
{
    public partial class MainWindow : Window
    {
        private Services.VirusTotalClient _vt;
        private JObject? _lastJson;
        private string? _lastContextLink; // VT GUI link
        private string? _lastKind;        // "file","url","domain","ip"
        private List<Models.EngineResultItem> _engines = new();

        public MainWindow()
        {
            InitializeComponent();
            _vt = new Services.VirusTotalClient();
            AppendActivity("App started.");
            LastScanText.Text = "Last action: ready";
        }

        private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
        { if (e.LeftButton == MouseButtonState.Pressed) DragMove(); }
        private void Close_Click(object s, RoutedEventArgs e) => Close();
        private void Minimize_Click(object s, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void Maximize_Click(object s, RoutedEventArgs e) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

        private void AppendActivity(string text) =>
            ActivityList.Items.Insert(0, new TextBlock { Text = $"• {DateTime.Now:HH:mm} - {text}", Foreground = (System.Windows.Media.Brush)this.FindResource("TextSecondary"), FontSize = 12 });

        private void SetProgress(double pct, string? detail = null)
        {
            MainProgress.Value = pct;
            ProgressPercentText.Text = $"{(int)pct}%";
            if (!string.IsNullOrWhiteSpace(detail)) ProgressDetail.Text = detail;
        }

        private void DumpJsonToOutput(JObject json)
        {
            _lastJson = json;
            OutputBox.Text = json.ToString(Newtonsoft.Json.Formatting.Indented);
            TrySummarize(json);
            PopulateFromJson(json);
        }

        private void TrySummarize(JObject json)
        {
            string summary = "—";
            try
            {
                var attrs = json["data"]?["attributes"];
                JObject? stats = (attrs?["stats"] as JObject) ?? (attrs?["last_analysis_stats"] as JObject);
                if (stats != null)
                {
                    int m = stats.Value<int?>("malicious") ?? 0;
                    int s = stats.Value<int?>("suspicious") ?? 0;
                    int u = stats.Value<int?>("undetected") ?? 0;
                    int h = stats.Value<int?>("harmless") ?? 0;
                    summary = $"Detections — malicious: {m}, suspicious: {s}, harmless: {h}, undetected: {u}.";
                }
            } catch {}
            SummaryText.Text = summary;
        }

        private void PopulateFromJson(JObject json)
        {
            var stats = (json.SelectToken("data.attributes.stats") as JObject)
                     ?? (json.SelectToken("data.attributes.last_analysis_stats") as JObject);

            int malicious = stats?.Value<int?>("malicious") ?? 0;
            int suspicious = stats?.Value<int?>("suspicious") ?? 0;
            int harmless = stats?.Value<int?>("harmless") ?? 0;
            int undetected = stats?.Value<int?>("undetected") ?? 0;

            BadgeHarmless.Text   = $"Harmless: {harmless}";
            BadgeHarmless.Foreground = (System.Windows.Media.Brush)this.FindResource("TextPrimary");
            BadgeUndetected.Text = $"Undetected: {undetected}";
            BadgeUndetected.Foreground = (System.Windows.Media.Brush)this.FindResource("TextPrimary");
            BadgeSuspicious.Text = $"Suspicious: {suspicious}";
            BadgeSuspicious.Foreground = (System.Windows.Media.Brush)this.FindResource("WarningColor");
            BadgeMalicious.Text  = $"Malicious: {malicious}";
            BadgeMalicious.Foreground = (System.Windows.Media.Brush)this.FindResource("DangerColor");

            string verdictText;
            var dot = (System.Windows.Shapes.Ellipse)VerdictDot;
            if (malicious > 0) { verdictText = "Malicious — do NOT trust this."; dot.Fill = (System.Windows.Media.Brush)this.FindResource("DangerColor"); }
            else if (suspicious > 0) { verdictText = "Caution — suspicious indicators present."; dot.Fill = (System.Windows.Media.Brush)this.FindResource("WarningColor"); }
            else { verdictText = "No engines flagged this object."; dot.Fill = (System.Windows.Media.Brush)this.FindResource("SuccessColor"); }
            VerdictText.Text = verdictText;

            var url = json.SelectToken("meta.url_info.url")?.ToString();
            var fid = json.SelectToken("data.id")?.ToString();
            var epoch = (json.SelectToken("data.attributes.date")?.Value<long?>()) ?? 0;
            var when = epoch > 0 ? DateTimeOffset.FromUnixTimeSeconds(epoch).LocalDateTime.ToString("g") : "—";
            ObjectLine.Text = url ?? fid ?? "—";
            WhenLine.Text = when;

            _engines.Clear();
            var results = json.SelectToken("data.attributes.results") as JObject;
            if (results != null)
            {
                foreach (var p in results.Properties())
                {
                    var o = p.Value as JObject;
                    if (o == null) continue;
                    _engines.Add(new Models.EngineResultItem
                    {
                        Engine = o.Value<string>("engine_name") ?? p.Name,
                        Category = o.Value<string>("category") ?? "",
                        Result = o.Value<string>("result") ?? "",
                        Method = o.Value<string>("method") ?? ""
                    });
                }
            }
            ApplyFilters();
            if (CategoryFilter != null) CategoryFilter.SelectionChanged += (s,e) => ApplyFilters();
        }

        private void ApplyFilters()
        {
            if (_engines == null || EnginesGrid == null) return;
            var q = SearchBox?.Text?.Trim().ToLowerInvariant() ?? "";
            var cat = (CategoryFilter?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All";

            IEnumerable<Models.EngineResultItem> filtered = _engines;
            if (!string.IsNullOrEmpty(q))
                filtered = filtered.Where(x => (x.Engine ?? "").ToLower().Contains(q) || (x.Result ?? "").ToLower().Contains(q));
            if (cat != "All")
                filtered = filtered.Where(x => string.Equals(x.Category, cat.ToLower(), StringComparison.OrdinalIgnoreCase));

            EnginesGrid.ItemsSource = filtered.ToList();
        }
        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilters();

        private async Task PollAnalysisAsync(string analysisId)
        {
            SetProgress(40, "Polling analysis…");
            for (int i = 0; i < 30; i++)
            {
                await Task.Delay(2000);
                var result = await _vt.GetAnalysisAsync(analysisId);
                var status = result["data"]?["attributes"]?["status"]?.ToString();
                if (status == "completed")
                {
                    SetProgress(100, "Analysis completed.");
                    _lastKind = "analysis"; _lastContextLink = null;
                    DumpJsonToOutput(result);
                    return;
                }
                SetProgress(Math.Min(95, MainProgress.Value + 2), $"Status: {status ?? "queued"}…");
            }
            ProgressDetail.Text = "Timed out waiting for analysis.";
        }

        private static (string sha256, string md5) ComputeHashes(string path)
        {
            using var fs = File.OpenRead(path);
            using var sha = SHA256.Create();
            using var md5 = MD5.Create();
            fs.Position = 0; var s = sha.ComputeHash(fs);
            fs.Position = 0; var m = md5.ComputeHash(fs);
            string Hex(byte[] b) => string.Concat(b.Select(x => x.ToString("x2")));
            return (Hex(s), Hex(m));
        }

        private async void UploadFile_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog();
            if (dlg.ShowDialog() != true) return;
            OutputBox.Clear(); SetProgress(10, "Preparing upload…");
            AppendActivity($"Uploading file: {System.IO.Path.GetFileName(dlg.FileName)}");

            try
            {
                var (sha256, md5) = ComputeHashes(dlg.FileName);
                _lastContextLink = $"https://www.virustotal.com/gui/file/{sha256}";
                _lastKind = "file";

                var fi = new FileInfo(dlg.FileName);
                JObject response;
                if (fi.Length > 32 * 1024 * 1024)
                {
                    SetProgress(20, "Requesting large-file upload URL…");
                    var uploadUrl = await _vt.GetLargeFileUploadUrlAsync();
                    SetProgress(30, "Uploading large file…");
                    response = await _vt.UploadLargeFileAsync(uploadUrl, dlg.FileName);
                }
                else
                {
                    SetProgress(30, "Uploading file…");
                    response = await _vt.UploadFileAsync(dlg.FileName);
                }

                DumpJsonToOutput(response);
                var analysisId = response["data"]?["id"]?.ToString();
                LastScanText.Text = $"Last action: uploaded at {DateTime.Now:t}";
                if (!string.IsNullOrEmpty(analysisId)) await PollAnalysisAsync(analysisId);
                AppendActivity($"File upload submitted. SHA256: {sha256[..8]}… MD5: {md5[..8]}…");
            }
            catch (Exception ex) { OutputBox.Text = ex.ToString(); ProgressDetail.Text = "Error during upload."; }
        }

        private async void FileReportByHash_Click(object sender, RoutedEventArgs e)
        {
            var hash = InputText.Text?.Trim();
            if (string.IsNullOrWhiteSpace(hash)) { MessageBox.Show("Enter MD5/SHA1/SHA256 hash."); return; }
            OutputBox.Clear(); SetProgress(20, "Fetching file report…");
            try
            {
                var json = await _vt.GetFileReportByHashAsync(hash);
                DumpJsonToOutput(json);
                _lastContextLink = $"https://www.virustotal.com/gui/file/{hash}"; _lastKind = "file";
                LastScanText.Text = $"Last action: hash lookup {DateTime.Now:t}";
                SetProgress(100, "Done."); AppendActivity($"File report fetched.");
            }
            catch (Exception ex) { OutputBox.Text = ex.ToString(); }
        }

        private async void ScanUrl_Click(object sender, RoutedEventArgs e)
        {
            var url = InputText.Text?.Trim();
            if (string.IsNullOrWhiteSpace(url)) { MessageBox.Show("Enter a URL."); return; }
            OutputBox.Clear(); SetProgress(20, "Submitting URL…");
            try
            {
                var resp = await _vt.SubmitUrlForScanAsync(url);
                DumpJsonToOutput(resp);
                _lastContextLink = $"https://www.virustotal.com/gui/url/{Services.VirusTotalClient.ToUrlIdBase64(url)}";
                _lastKind = "url";
                LastScanText.Text = $"Last action: URL submitted {DateTime.Now:t}";
                var analysisId = resp["data"]?["id"]?.ToString();
                if (!string.IsNullOrEmpty(analysisId)) await PollAnalysisAsync(analysisId);
                AppendActivity("URL submitted for analysis.");
            }
            catch (Exception ex) { OutputBox.Text = ex.ToString(); }
        }

        private async void UrlReport_Click(object sender, RoutedEventArgs e)
        {
            var url = InputText.Text?.Trim();
            if (string.IsNullOrWhiteSpace(url)) { MessageBox.Show("Enter a URL."); return; }
            OutputBox.Clear(); SetProgress(20, "Fetching URL report…");
            try
            {
                var json = await _vt.GetUrlReportAsync(url);
                DumpJsonToOutput(json);
                _lastContextLink = $"https://www.virustotal.com/gui/url/{Services.VirusTotalClient.ToUrlIdBase64(url)}";
                _lastKind = "url";
                LastScanText.Text = $"Last action: URL report {DateTime.Now:t}";
                SetProgress(100, "Done."); AppendActivity("URL report fetched.");
            }
            catch (Exception ex) { OutputBox.Text = ex.ToString(); }
        }

        private async void DomainReport_Click(object sender, RoutedEventArgs e)
        {
            var domain = InputText.Text?.Trim();
            if (string.IsNullOrWhiteSpace(domain)) { MessageBox.Show("Enter a domain."); return; }
            OutputBox.Clear(); SetProgress(20, "Fetching domain info…");
            try
            {
                var json = await _vt.GetDomainReportAsync(domain);
                DumpJsonToOutput(json);
                _lastContextLink = $"https://www.virustotal.com/gui/domain/{domain}";
                _lastKind = "domain";
                LastScanText.Text = $"Last action: domain report {DateTime.Now:t}";
                SetProgress(100, "Done."); AppendActivity("Domain report fetched.");
            }
            catch (Exception ex) { OutputBox.Text = ex.ToString(); }
        }

        private async void IpReport_Click(object sender, RoutedEventArgs e)
        {
            var ip = InputText.Text?.Trim();
            if (string.IsNullOrWhiteSpace(ip)) { MessageBox.Show("Enter an IP address."); return; }
            OutputBox.Clear(); SetProgress(20, "Fetching IP info…");
            try
            {
                var json = await _vt.GetIpReportAsync(ip);
                DumpJsonToOutput(json);
                _lastContextLink = $"https://www.virustotal.com/gui/ip-address/{ip}";
                _lastKind = "ip";
                LastScanText.Text = $"Last action: IP report {DateTime.Now:t}";
                SetProgress(100, "Done."); AppendActivity("IP report fetched.");
            }
            catch (Exception ex) { OutputBox.Text = ex.ToString(); }
        }

        private void ApplyApiKey_Click(object sender, RoutedEventArgs e)
        {
            var key = ApiKeyBox.Password?.Trim();
            _vt.OverrideApiKey(string.IsNullOrWhiteSpace(key) ? null : key);
            AppendActivity(string.IsNullOrWhiteSpace(key) ? "Using default API key (env/config)." : "Using API key from UI.");
        }
        private void CopyOutput_Click(object s, RoutedEventArgs e) { try { Clipboard.SetText(OutputBox.Text); } catch {} }
        private void ClearOutput_Click(object s, RoutedEventArgs e) { OutputBox.Clear(); SummaryText.Text = "—"; }
        private void SaveJson_Click(object s, RoutedEventArgs e)
        {
            if (_lastJson is null) { MessageBox.Show("No data to save yet."); return; }
            var dlg = new SaveFileDialog { Filter = "JSON (*.json)|*.json", FileName = $"vt_{_lastKind ?? "result"}_{DateTime.Now:yyyyMMdd_HHmmss}.json" };
            if (dlg.ShowDialog() == true) { File.WriteAllText(dlg.FileName, _lastJson.ToString(Newtonsoft.Json.Formatting.Indented), Encoding.UTF8); AppendActivity($"Saved JSON: {System.IO.Path.GetFileName(dlg.FileName)}"); }
        }
        private void SaveCsv_Click(object s, RoutedEventArgs e)
        {
            if (_lastJson is null) { MessageBox.Show("No data to save yet."); return; }
            var dlg = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = $"vt_{_lastKind ?? "result"}_{DateTime.Now:yyyyMMdd_HHmmss}.csv" };
            if (dlg.ShowDialog() == true)
            {
                var sb = new StringBuilder(); sb.AppendLine("metric,value");
                var stats = _lastJson.SelectToken("data.attributes.last_analysis_stats") as JObject
                         ?? _lastJson.SelectToken("data.attributes.stats") as JObject;
                if (stats != null) foreach (var p in stats.Properties()) sb.AppendLine($"{p.Name},{p.Value}");
                else sb.AppendLine("info,No standard stats found");
                File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
                AppendActivity($"Saved CSV: {System.IO.Path.GetFileName(dlg.FileName)}");
            }
        }
        private void OpenInVT_Click(object s, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_lastContextLink)) { MessageBox.Show("No context link yet. Perform an action first."); return; }
            try { Process.Start(new ProcessStartInfo { FileName = _lastContextLink, UseShellExecute = true }); } catch {}
        }
    }
}
