
# CyberShield Pro (WPF) — VirusTotal v3 client

A modern WPF desktop UI that talks to VirusTotal v3 Public API to:
- Upload files for scanning (supports >32MB via `files/upload_url`).
- Get a file report by MD5/SHA1/SHA256.
- Scan URLs (submit + poll analysis).
- Get a URL report (using base64 URL ID).
- Get a Domain report.
- Get an IP address report.

## Build

- Requires .NET 6 SDK and Windows.
- Open `CyberShieldPro.sln` in Visual Studio 2022+ or run:
  ```powershell
  dotnet restore
  dotnet build
  dotnet run --project .\CyberShieldPro\CyberShieldPro.csproj
  ```

## Configure API key

The app looks for your VT key in this order:
1. UI field (Settings panel) — click **Use** to apply.
2. Environment variable `VT_API_KEY`.
3. `appsettings.json` (`VirusTotal:ApiKey` key).

> **Note:** Public API is limited to ~4 requests/min and ~500/day; large files >32MB require the `files/upload_url` flow. See VT docs for details.

## Credits / Docs

- VT v3 overview, file, URL, domain & IP endpoints are documented by VirusTotal.
