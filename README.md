# IISGuard

```
=============================
        IISGuard V1.0
=============================
```

**IISGuard** is a self-contained .NET application that monitors IIS logs in real time and automatically blocks abusive IP addresses.  
It is designed for administrators who want to protect their IIS servers against brute force attempts, bots, and excessive POST/ERROR traffic.

---

## ✨ Features

- **Real-time log monitoring**  
  Tails IIS W3C log files and inspects each request as it arrives.

- **Auto-blocking rules**  
  - Honeypot URLs → instant block  
  - Excessive POSTs per minute → block  
  - Excessive HTTP errors per minute → block  

- **Firewall & IIS integration**  
  - Creates Windows Firewall rules (`INetFwPolicy2`) for blocked IPs  
  - Optionally adds `<ipSecurity>` deny rules to IIS sites (using `Microsoft.Web.Administration`)  

- **Console UI (Win-ACME style)**  
  When run interactively, IISGuard shows a text-based menu:
  ```
  =============================
          IISGuard V1.0
  =============================
  Monitors IIS logs in real time and auto-blocks abusive IPs (POST rate, errors, honeypots).
  Use the options below to manage whitelist, blocked IPs, and firewall rules.

    W  -  Whitelist an IP
    R  -  Remove IP from whitelist
    L  -  List whitelist
    B  -  View blocked list
    K  -  Block an IP (manual)
    U  -  Unblock an IP
    F  -  List firewall rules (by prefix)
    D  -  Dedupe firewall rules (by prefix)
    Q  -  Quit console (IisGuard keeps running)
  ```

- **Daily log files**  
  Logs are written to `./logs/iisguard-YYYY-MM-DD.log` with auto-cleanup after 5 days.

- **Detailed block reasons**  
  Block messages include status code counts, sample failing paths, and user agents.  
  Example:
  ```
  Blocking 192.0.2.44 (High error rate (16/min): statuses 404x12, 500x4; UA "curl/8.4.0"; sample 500 /SendMail | 404 /wp-login.php | 404 /xmlrpc.php)
  ```

- **Task Scheduler integration**  
  On first run, IISGuard can install itself as a scheduled task to auto-start:
  - **On Boot** (as SYSTEM)  
  - **On Logon** (as the current user)

---

## 🚀 Getting Started

### Requirements
- Windows Server with IIS installed
- .NET 8 runtime (or publish as self-contained)
- Administrator privileges (required to add firewall/IIS rules)

### Build
```bash
dotnet publish -c Release -r win-x64 --self-contained true \\
  /p:PublishSingleFile=true \\
  /p:IncludeNativeLibrariesForSelfExtract=true \\
  -o ./publish
```

### Run
Interactive mode (shows menu):
```powershell
.\\publish\\IisGuard.exe
```

Headless mode (service/task):
```powershell
.\\publish\\IisGuard.exe --service
```

Command-line options:
- `--install-boot`   → register scheduled task (auto-start on boot, SYSTEM)  
- `--install-logon`  → register scheduled task (auto-start on logon, current user)  
- `--uninstall`      → remove scheduled task  
- `--service`        → run in Windows Service mode (no UI)  
- `--no-ui`          → run without showing the console menu  

---

## ⚙️ Configuration

All runtime settings are stored in `appsettings.json`:

```json
{
  "LogWatcher": {
    "Paths": [ "C:/inetpub/logs/LogFiles/W3SVC*/u_ex*.log" ],
    "PollIntervalMs": 1000
  },
  "Rules": {
    "PostPerMinute": 20,
    "ErrorsPerMinute": 15,
    "BanMinutes": 0,
    "HoneypotPaths": [ "/hidden-honey", "/secret-admin" ],
    "Whitelist": [ "127.0.0.1", "::1" ],
    "IgnoreUserAgents": [ "Googlebot", "Bingbot" ]
  },
  "Blocking": {
    "EnableFirewall": true,
    "FirewallRulePrefix": "AutoBlock",
    "EnableIIS": true,
    "IisSites": [] // leave empty to auto-detect
  },
  "State": {
    "BlockedStore": "blocked.json"
  }
}
```

---

## 🛡️ How It Works

1. IISGuard tails IIS W3C log files (`u_ex*.log`).
2. Each request is inspected:
   - If path matches honeypot → block immediately.
   - If POST rate > threshold → block.
   - If error responses > threshold → block.
3. When blocked:
   - Firewall inbound rule is created.
   - IIS `<ipSecurity>` deny entry is added.
   - Entry is saved to `blocked.json` and displayed in UI.

---

## 📂 Project Structure

- `Program.cs` → entry point, DI setup, console UI
- `IisGuardWorker` → background service, log tailer, blocking rules
- `LogTail` → file tail implementation
- `DailyFileLoggerProvider` → custom file logger with rotation
- `IisGuardConsole` → interactive console UI

---

## ⚠️ Notes

- IIS config commits (`applicationHost.config`) may conflict if other tools (SolidCP, IIS Manager) save at the same time. IISGuard retries safely.  
- To avoid global config conflicts, you can delegate `ipSecurity` to per-site `web.config`.  
- Always run IISGuard elevated so it can modify firewall and IIS settings.

---

## 📜 License

MIT License – see [LICENSE](LICENSE) for details.
