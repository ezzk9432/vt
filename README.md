# CyberShield Pro | VirusTotal Desktop Client

A C# WPF desktop client for the VirusTotal v3 API. This is an API client, not a standalone antivirus engine or an independent malware-detection model.

## Included workflows

- Submit files and URLs for analysis.
- Look up file reports by hash.
- Retrieve URL, domain and IP-address reports.

## Build and run

Use Windows with the .NET 6 SDK and WPF tooling. Open `CyberShieldPro.sln` in Visual Studio, restore dependencies, then build and run the project. Detailed notes are in [`CyberShieldPro/README.md`](CyberShieldPro/README.md).

This documentation update did not build or run the Windows application.

## API credentials

Use your own VirusTotal API key. The application supports its settings field, the `VT_API_KEY` environment variable, and the `VirusTotal:ApiKey` configuration field. Keep the committed configuration value empty. Never commit keys, local credentials or populated build-output configuration.

If a key has ever been committed, revoke or rotate it at the provider. Editing the latest file does not remove previous values from Git history.

## Data handling

File and URL submissions are sent to VirusTotal. Do not submit confidential files, credentials, patient information or other sensitive material without permission and a review of the provider's data-sharing terms. Use benign test material when evaluating the client.

## Repository map

- `CyberShieldPro/MainWindow.xaml`: WPF interface.
- `CyberShieldPro/MainWindow.xaml.cs`: interface behavior.
- `CyberShieldPro/Services/VirusTotalClient.cs`: API client.
- `CyberShieldPro/Models/`: report display models.

Provider quotas and API behavior can change. Check the current VirusTotal documentation before using the client.
