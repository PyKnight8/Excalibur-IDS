# Windows installation

Excalibur uses WinSW to run the sensor, dashboard, and service-control helper as native Windows services. MSI packaging is not part of this installation method.

Excalibur ships with the WinSW executable and its license under `third_party/winsw`. The installer uses this bundled binary and does not download WinSW, allowing service installation without internet access. If `third_party/winsw/SHA256.txt` is present, the installer verifies the bundled executable before making system changes.

## Prerequisites

- Windows 10/11 or Windows Server with 64-bit Python available in `PATH`.
- Npcap installed with the options required for Scapy packet capture. If capture fails, reinstall the current Npcap release and enable WinPcap API-compatible mode when required by the local Scapy/Npcap setup.
- An Administrator PowerShell session.
- A complete Excalibur distribution containing `third_party\winsw\WinSW-x64.exe` and `third_party\winsw\LICENSE.txt`.

## Install

From the Excalibur source directory, open PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\windows\install.ps1
```

The installer preserves existing configuration, rules, and plugins under ProgramData. It creates a virtual environment, installs `requirements.txt`, copies the bundled WinSW binary for each service wrapper, registers the services, and starts them. It does not download WinSW from GitHub or any other remote source.

The installer also enables the Excalibur tray app for the current user
automatically. It adds a Startup launcher and starts the tray immediately after
installation so the tray becomes the default desktop control surface.

## Services

| Display name | Service name | Purpose |
| --- | --- | --- |
| Excalibur Sensor | `ExcaliburSensor` | Packet capture and detection |
| Excalibur Dashboard | `ExcaliburDashboard` | Local dashboard on `127.0.0.1:5000` |
| Excalibur Helper | `ExcaliburHelper` | Windows service-control helper |

## Tray app

The tray app is installed automatically on Windows and runs in the logged-in
user's desktop session. It uses the Excalibur helper service to open the
dashboard and control the sensor.

To disable tray auto-start later, remove:

```text
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\ExcaliburTray.cmd
```

## Default paths

- Application and virtual environment: `C:\Program Files\Excalibur`
- Runtime data and configuration: `C:\ProgramData\Excalibur`
- Database: `C:\ProgramData\Excalibur\excalibur.sqlite`
- Logs: `C:\ProgramData\Excalibur\logs`
- Rule packs: `C:\ProgramData\Excalibur\rules`
- Plugins: `C:\ProgramData\Excalibur\plugins`

## Uninstall

Run from an Administrator PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\windows\uninstall.ps1
```

The uninstaller asks whether to create a backup, remove application files, and remove ProgramData. Runtime data is not deleted without explicit confirmation.

## Troubleshooting

Inspect service state:

```powershell
Get-Service ExcaliburSensor, ExcaliburDashboard, ExcaliburHelper
```

Restart individual services:

```powershell
Restart-Service ExcaliburSensor
Restart-Service ExcaliburDashboard
Restart-Service ExcaliburHelper
```

Inspect service configuration:

```powershell
sc.exe qc ExcaliburSensor
sc.exe queryex ExcaliburSensor
```

WinSW stdout/stderr and wrapper logs are written under `C:\ProgramData\Excalibur\logs`. If the sensor starts but does not capture packets, verify that Npcap is installed and running:

```powershell
Get-Service npcap
```

The dashboard is available only on the local machine at `http://127.0.0.1:5000`.
