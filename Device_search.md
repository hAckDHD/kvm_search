# Laptop Farm Hunting Playbook (SentinelOne)

> **Note:** Single indicators are informational. KVM hardware + input simulator + external-IP clustering = high confidence. Validate with HR/Legal before any employee action.
> **Note:** USB queries use custom field names; remap to your Device Control schema.

---

## 1. KVM and Capture Hardware

**SentinelOne Event Search: Known KVM vendors**
```
EventType = "USB Device Connected" AND AgentOS = "windows"
AND (
  USBVendorID = "0557"      // ATEN
  OR USBVendorID = "0624"   // Avocent
  OR USBVendorID = "1d6b"   // Linux gadget family (PiKVM/TinyPilot/JetKVM-type)
  OR USBVendorID = "3346"   // Sipeed NanoKVM
  OR USBVendorID = "534d"   // MacroSilicon HDMI capture
)
```

**SentinelOne Event Search: Specific NanoKVM / PiKVM IDs**
```
EventType = "USB Device Connected" AND AgentOS = "windows"
AND (
  (USBVendorID = "3346" AND USBProductID = "1009")    // Sipeed NanoKVM
  OR (USBVendorID = "1d6b" AND USBProductID = "0104") // PiKVM composite gadget
)
```

---

## 2. Remote Access Tools

**SentinelOne Event Search: Process creation**
```
event.type = "Process Creation" AND endpoint.os = "windows"
AND tgt.process.name In Contains Anycase (
  "anydesk", "teamviewer", "rustdesk", "splashtop", "screenconnect",
  "connectwise", "parsecd", "tailscale", "zerotier", "ngrok",
  "meshagent", "dwagent", "getscreen", "ultraviewer", "supremo",
  "remotepc", "logmein", "nomachine", "tightvnc", "ultravnc", "chromeremotedesktop"
)
```

**SentinelOne Event Search: DNS to relay infrastructure**
```
event.type = "DNS Resolved" AND endpoint.os = "windows"
AND event.dns.request In Contains Anycase (
  "anydesk.com", "teamviewer.com", "rustdesk.com", "splashtop.com",
  "relay.screenconnect.com", "ngrok.io", "ngrok-free.app", "tailscale.com",
  "zerotier.com", "dwservice.net", "getscreen.me", "meshcentral",
  "parsec.app", "remotedesktop.google.com"
)
```

---

## 3. Remote Interactive Logons

**SentinelOne Event Search: Remote logons**
```
event.type = "Login" AND endpoint.os = "windows"
AND event.login.type In ("REMOTE_INTERACTIVE", "NETWORK_INTERACTIVE")
```
Windows equivalent: Event ID 4624 Logon Type 10, plus 4778/4779 (reconnect/disconnect). Frequent odd-hour reconnects are a strong signal.

---

## 4. Mouse Jigglers and Input Simulation

**SentinelOne Event Search: Jiggler process or cmdline**
```
event.type = "Process Creation" AND endpoint.os = "windows"
AND (
  tgt.process.name In Contains Anycase ("autohotkey", "mousejiggler", "movemouse", "caffeine", "jiggler", "keepawake", "nomouse")
  OR tgt.process.cmdline Contains Anycase "SetThreadExecutionState"
  OR tgt.process.cmdline Contains Anycase "mouse_event"
  OR tgt.process.cmdline Contains Anycase "SendKeys"
  OR tgt.process.cmdline Contains Anycase "System.Windows.Forms.Cursor"
)
```

**SentinelOne Event Search: Original jiggler query**
```
event.type = "Process Creation" AND endpoint.os = "windows"
AND (tgt.process.name Contains Anycase "jiggler" OR tgt.process.name Contains Anycase "caffeine" OR tgt.process.cmdline Contains Anycase "SendInput")
```

---

## 5. Lid-Closed and Never-Sleep Power Config

**SentinelOne Event Search: powercfg changes**
```
event.type = "Process Creation" AND endpoint.os = "windows"
AND tgt.process.name = "powercfg.exe"
AND tgt.process.cmdline Contains Anycase ("LIDACTION", "standby-timeout", "hibernate-timeout", "monitor-timeout")
```

**SentinelOne Event Search: Lid action registry change**
```
event.type = "Registry Value Modified" AND endpoint.os = "windows"
AND registry.keyPath Contains "4f971e89-eebd-4455-a8de-9e59040e7347"
```

---

## 6. Virtual Displays and Virtual Cameras

**SentinelOne Event Search: Virtual cam / face swap / virtual display**
```
event.type = "Process Creation" AND endpoint.os = "windows"
AND tgt.process.name In Contains Anycase (
  "obs64", "obs32", "manycam", "xsplit", "vcam", "DeepFaceLive",
  "Deep-Live-Cam", "facefusion", "spacedesk", "usbmmidd", "IddSampleDriver"
)
```

---

## 7. VPN and Proxy Tools

**SentinelOne Event Search: VPN processes**
```
event.type = "Process Creation" AND endpoint.os = "windows"
AND tgt.process.name In Contains Anycase ("astrill", "expressvpn", "nordvpn", "proton", "mullvad", "windscribe", "psiphon", "shadowsocks", "v2ray", "clash")
```

**SentinelOne Event Search: Astrill DNS**
```
event.type = "DNS Resolved" AND endpoint.os = "windows"
AND event.dns.request Contains Anycase "astrill"
```

---

## 8. Locale, Time Zone, and Language Recon

**SentinelOne Event Search: Locale/timezone commands**
```
event.type = "Process Creation" AND endpoint.os = "windows"
AND (
  tgt.process.cmdline Contains Anycase "tzutil"
  OR tgt.process.cmdline Contains Anycase "Get-WinUserLanguageList"
  OR tgt.process.cmdline Contains Anycase "Set-TimeZone"
  OR tgt.process.cmdline Contains Anycase "Get-WinSystemLocale"
)
```

---

## 9. Persistence of Remote Tooling

**SentinelOne Event Search: Scheduled tasks**
```
event.type = "Scheduled Task Registered" AND endpoint.os = "windows"
AND task.name In Contains Anycase ("anydesk", "teamviewer", "rustdesk", "screenconnect")
```

**SentinelOne Event Search: Service creation via sc.exe**
```
event.type = "Process Creation" AND endpoint.os = "windows"
AND tgt.process.name = "sc.exe" AND tgt.process.cmdline Contains Anycase "create"
AND tgt.process.cmdline In Contains Anycase ("anydesk", "teamviewer", "rustdesk", "screenconnect", "meshagent")
```

**SentinelOne Event Search: Run key persistence**
```
event.type = "Registry Value Modified" AND endpoint.os = "windows"
AND registry.keyPath Contains Anycase "\\CurrentVersion\\Run"
AND registry.value Contains Anycase ("anydesk", "teamviewer", "rustdesk", "screenconnect")
```

---

## 10. Analytics (Not Single Events)

| Signal | How to hunt |
|---|---|
| Many endpoints behind one external IP | Export inventory, group by `externalIp`, flag IPs with 3+ corporate devices that aren't an office |
| Residential ISP / VPS ASNs | Enrich external IPs against ASN data |
| Concurrent logins | Same user active on two endpoints or geos at once |
| Impossible travel | IdP sign-in geo vs endpoint external IP geo |
| Device-IP mismatch | Laptop assigned at address A, user authenticates from B |
| 24/7 activity, no idle | Constant input at all hours with lid closed |
| Same SSID or gateway MAC | Multiple "remote" employees on identical network fingerprints |

---

## 11. Local Triage Commands (PowerShell)

**KVM / capture device check**
```powershell
Get-PnpDevice | Where-Object { $_.InstanceId -match 'VID_0557|VID_0624|VID_1D6B|VID_3346|VID_534D' } |
  Select FriendlyName, InstanceId, Status
```

**USB history from registry (survives unplug)**
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' | Select Name
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' | Select Name
```

**Monitor names (quick)**
```powershell
Get-PnpDevice -Class Monitor | Select-Object FriendlyName, InstanceId, Status
```

**Monitor names (decoded EDID: catches "PiKVM V3", NanoKVM strings)**
```powershell
Get-WmiObject WmiMonitorID -Namespace root\wmi | ForEach-Object {
    $mfg    = ($_.ManufacturerName -ne 0 | ForEach-Object {[char]$_}) -join ""
    $name   = ($_.UserFriendlyName -ne 0 | ForEach-Object {[char]$_}) -join ""
    $serial = ($_.SerialNumberID -ne 0 | ForEach-Object {[char]$_}) -join ""
    [PSCustomObject]@{
        InstanceName = $_.InstanceName
        Manufacturer = $mfg
        FriendlyName = $name
        Serial       = $serial
    }
}
```

**Video adapters (virtual or headless indicators)**
```powershell
Get-CimInstance Win32_VideoController | Select Name, AdapterCompatibility, VideoProcessor, Status
Get-CimInstance Win32_DesktopMonitor | Select Name, PNPDeviceID, MonitorManufacturer
```

**Remote tool services and installs**
```powershell
Get-Service | Where-Object { $_.Name -match 'anydesk|teamviewer|rustdesk|screenconnect|splashtop|mesh|tailscale|zerotier' }
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
  Where-Object DisplayName -match 'AnyDesk|TeamViewer|RustDesk|ScreenConnect|Splashtop|Parsec|Tailscale|ZeroTier' |
  Select DisplayName, InstallDate, Publisher
```

**Active and recent remote sessions**
```powershell
qwinsta
query user
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 500 |
  Where-Object { $_.Properties[8].Value -in 10,3 } |
  Select TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='SrcIP';e={$_.Properties[18].Value}}
```

**Outbound connections by process**
```powershell
Get-NetTCPConnection -State Established |
  ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{Proc=$p.Name; Remote="$($_.RemoteAddress):$($_.RemotePort)"} } |
  Sort Proc | Format-Table -AutoSize
```

**Locale, time zone, keyboard layout**
```powershell
Get-TimeZone
Get-WinUserLanguageList
Get-WinSystemLocale
Get-Culture
```

**Lid action setting**
```powershell
powercfg /query SCHEME_CURRENT SUB_BUTTONS LIDACTION
```

**RDP client history**
```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Terminal Server Client\Default'
```

---

## 12. Non-Endpoint Corroboration

- **HR/Recruiting:** reused phone numbers, resume overlap, candidates who avoid or fumble live video
- **Shipping:** laptops sent to addresses shared by multiple employees, or to freight forwarders
- **IdP:** sign-in geo vs claimed location, MFA device changes, new device registrations
- **Payroll:** shared bank accounts or payment-platform overlap
- **Interviews:** face-swap tells (edge artifacts on head turns, audio/lip lag)

---

# STAR Method: Laptop Farm Detection

**Situation**
Our organization was exposed to laptop farm and DPRK-linked IT worker schemes, where company laptops are hosted at a US address and operated remotely. Existing detections focused on malware and had no coverage for KVM hardware, input simulators, or remote-access tooling used for this purpose.

**Task**
Build detection coverage in SentinelOne to identify potential laptop farm activity across [number] endpoints while keeping false positives low enough for the SOC to act on.

**Action**
- Mapped TTPs from public FBI/CISA/DOJ reporting: KVM-over-IP hardware, jigglers, remote tools, VPN/proxy use, lid-closed operation.
- Wrote Event Search hunts for USB vendor/product IDs, jiggler and remote-tool processes, DNS to relay infrastructure, and power-policy changes.
- Added EDID/monitor and video adapter checks via PowerShell to catch headless or virtual-display setups.
- Built correlation logic (shared external IP, capture device + input simulator) instead of single-signal alerts.
- Tuned against legitimate IT use with allowlists and documented everything in a runbook.
- Set up an HR/Legal escalation path so findings were validated before employee action.

**Result**
- [Number] hunts deployed; [X]% noise reduction after tuning.
- [Number] endpoints investigated, resulting in [confirmed findings / policy violations / validated clean].
- Reusable runbook now run [weekly/monthly] by the SOC; investigation time cut from [X] to [Y].

**30-second spoken version**
> "We had no visibility into laptop farm activity, so I built SentinelOne hunts around the known TTPs: KVM hardware by USB vendor ID, jigglers and remote tools by process and DNS, and external-IP clustering. I tuned them against legitimate IT use, wrote a runbook, and set up an HR/Legal escalation path. The result was [metric], and the SOC now runs the hunts on a recurring schedule."
