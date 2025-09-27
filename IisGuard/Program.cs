using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Web.Administration;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Linq;

var builder = Host.CreateApplicationBuilder(args);

// --- Logging: file + optional console ---
var logsDir = Path.Combine(AppContext.BaseDirectory, "logs");
Directory.CreateDirectory(logsDir);

// Decide UI vs headless first
var runAsService = args.Any(a => string.Equals(a, "--service", StringComparison.OrdinalIgnoreCase));
var showMenu = Environment.UserInteractive && !runAsService &&
               !args.Any(a => string.Equals(a, "--no-ui", StringComparison.OrdinalIgnoreCase));

builder.Logging.ClearProviders();

// Always log to file
builder.Logging.AddProvider(new DailyFileLoggerProvider(
    logsDir: logsDir,
    filePrefix: "iisguard",
    retentionDays: 5,
    minLevel: LogLevel.Information // change to Debug for more detail
));

// Console logging only when headless (so the menu “owns” the console when shown)
if (!showMenu)
{
    builder.Logging.AddSimpleConsole(o =>
    {
        o.SingleLine = true;
        o.TimestampFormat = "HH:mm:ss ";
    });
}

// Run properly as a Windows Service only when explicitly requested
if (runAsService)
{
    builder.Services.AddWindowsService(o => o.ServiceName = "IisGuard");
}

// Load config from app folder (important for services)
builder.Configuration
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

// Register the worker (singleton so the console UI can call it)
builder.Services.AddSingleton<IisGuardWorker>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<IisGuardWorker>());

// One-time prompt only when launched interactively (not by SCM)
if (Environment.UserInteractive)
{
    const string TaskName = "IisGuard";
    var exe = Process.GetCurrentProcess().MainModule!.FileName!;
    var workDir = AppContext.BaseDirectory.TrimEnd('\\');

    if (args.Contains("--install-boot", StringComparer.OrdinalIgnoreCase))
    {
        var ok = CreateStartupTaskOnBoot(TaskName, exe, workDir);
        Console.WriteLine(ok ? "Scheduled task (ONSTART) created." : "Failed to create ONSTART task (run as admin).");
    }
    else if (args.Contains("--install-logon", StringComparer.OrdinalIgnoreCase))
    {
        var ok = CreateStartupTaskOnLogon(TaskName, exe, workDir);
        Console.WriteLine(ok ? "Scheduled task (ONLOGON) created." : "Failed to create ONLOGON task.");
    }
    else if (args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase))
    {
        DeleteTask(TaskName);
        Console.WriteLine("Scheduled task removed (if it existed).");
    }
    else if (!IsTaskInstalled(TaskName))
    {
        Console.WriteLine("IisGuard can run automatically on this machine.");
        Console.Write("Install auto-start? [Y]=On boot (SYSTEM), [L]=On logon (current user), [N]=No: ");
        var key = Console.ReadKey(true).Key;

        if (key == ConsoleKey.Y)
        {
            var ok = CreateStartupTaskOnBoot(TaskName, exe, workDir);
            Console.WriteLine(ok
                ? "\n✓ Auto-start on boot installed (SYSTEM)."
                : "\n✗ Failed to install ONSTART task (run console as Administrator).");
        }
        else if (key == ConsoleKey.L)
        {
            var ok = CreateStartupTaskOnLogon(TaskName, exe, workDir);
            Console.WriteLine(ok
                ? "\n✓ Auto-start on logon installed (current user)."
                : "\n✗ Failed to install ONLOGON task.");
        }
        else
        {
            Console.WriteLine("\n(Continuing without auto-start.)");
        }
    }
}

var host = builder.Build();

// Start background services
await host.StartAsync();

// Show menu only when interactive (not service/scheduled task)
if (showMenu)
{
    var worker = host.Services.GetRequiredService<IisGuardWorker>();
    IisGuardConsole.Run(worker, "V1.0"); // menu owns the console
}

// Headless wait (service/scheduled task) or after closing the menu (if you left it running)
await host.WaitForShutdownAsync();


// ----------------- helper funcs (task scheduler) -----------------
static bool IsAdmin()
{
    using var id = WindowsIdentity.GetCurrent();
    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
}

static bool IsTaskInstalled(string taskName)
{
    try
    {
        var psi = new ProcessStartInfo("schtasks", $"/Query /TN \"{taskName}\"")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi)!;
        p.WaitForExit();
        return p.ExitCode == 0;
    }
    catch { return false; }
}

static int RunProc(string file, string args)
{
    var psi = new ProcessStartInfo(file, args)
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };
    using var p = Process.Start(psi)!;
    p.WaitForExit();
    return p.ExitCode;
}

static bool CreateStartupTaskOnBoot(string taskName, string exePath, string workingDir)
{
    if (!IsAdmin()) return false; // ONSTART under SYSTEM needs admin
    var args =
        $"/Create /TN \"{taskName}\" " +
        "/SC ONSTART " +
        "/RU SYSTEM " +
        "/RL HIGHEST /F " +
        $"/TR \"\\\"{exePath}\\\"\" " +
        $"/WD \"{workingDir}\"";
    return (RunProc("schtasks", args) == 0);
}

static bool CreateStartupTaskOnLogon(string taskName, string exePath, string workingDir)
{
    var user = $"{Environment.UserDomainName}\\{Environment.UserName}".Trim('\\');
    var args =
        $"/Create /TN \"{taskName}\" " +
        "/SC ONLOGON " +
        $"/RU \"{user}\" " +
        "/RL HIGHEST /F " +
        $"/TR \"\\\"{exePath}\\\"\" " +
        $"/WD \"{workingDir}\"";
    return (RunProc("schtasks", args) == 0);
}

static void DeleteTask(string taskName)
{
    RunProc("schtasks", $"/Delete /TN \"{taskName}\" /F");
}


// ============================== worker ==============================
sealed class IisGuardWorker : BackgroundService
{
    private readonly ILogger<IisGuardWorker> _log;
    private readonly IConfiguration _cfg;

    // Settings
    private readonly string[] _pathPatterns;
    private readonly int _pollMs;
    private readonly int _postPerMin;
    private readonly int _errorsPerMin;
    private readonly int _banMinutes;
    private readonly HashSet<string> _honeypots;
    private readonly HashSet<string> _whitelist;
    private readonly List<string> _ignoreUAs;
    private readonly bool _enableFw;
    private readonly bool _enableIis;
    private readonly string _fwPrefix;
    private string[] _iisSites;
    private readonly string _blockedStore;

    // State
    private readonly ConcurrentDictionary<string, SlidingWindow> _postCounter = new();
    private readonly ConcurrentDictionary<string, SlidingWindow> _errCounter = new();
    private readonly ConcurrentDictionary<string, BlockRecord> _blocked = new();

    // NEW: keep last N events per IP for detailed reasons
    private readonly ConcurrentDictionary<string, Queue<(DateTimeOffset Ts, string Path, string Status, string Ua)>> _recentEvents
        = new();
    private const int RecentEventLimit = 20;

    private readonly object _stateLock = new();

    // Tailing handles
    private readonly List<LogTail> _tails = new();
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly HashSet<string> _allFiles = new(StringComparer.OrdinalIgnoreCase);

    // W3C parsing
    private string[] _fieldOrder = Array.Empty<string>();
    private static readonly Regex W3cSplit = new(@" (?=(?:[^""]*""[^""]*"")*[^""]*$)", RegexOptions.Compiled);


    // Serialize IIS config writes across threads in this process
    private static readonly object _iisConfigLock = new();

    // Backoff settings
    private const int IisCommitMaxRetries = 5;     // attempts
    private const int IisCommitBaseDelayMs = 120;  // base backoff

    public IisGuardWorker(ILogger<IisGuardWorker> log, IConfiguration cfg)
    {
        _log = log;
        _cfg = cfg;

        _pathPatterns = cfg.GetSection("LogWatcher:Paths").Get<string[]>() ?? Array.Empty<string>();
        _pollMs = cfg.GetValue("LogWatcher:PollIntervalMs", 1000);

        _postPerMin = cfg.GetValue("Rules:PostPerMinute", 20);
        _errorsPerMin = cfg.GetValue("Rules:ErrorsPerMinute", 15);
        _banMinutes = cfg.GetValue("Rules:BanMinutes", 0);

        _honeypots = new HashSet<string>((cfg.GetSection("Rules:HoneypotPaths").Get<string[]>() ?? Array.Empty<string>()).Select(s => s.ToLowerInvariant()));
        _whitelist = new HashSet<string>(cfg.GetSection("Rules:Whitelist").Get<string[]>() ?? Array.Empty<string>());
        _ignoreUAs = (cfg.GetSection("Rules:IgnoreUserAgents").Get<string[]>() ?? Array.Empty<string>()).ToList();

        _enableFw = cfg.GetValue("Blocking:EnableFirewall", true);
        _enableIis = cfg.GetValue("Blocking:EnableIIS", true);
        _fwPrefix = cfg.GetValue("Blocking:FirewallRulePrefix", "AutoBlock");
        _iisSites = cfg.GetSection("Blocking:IisSites").Get<string[]>() ?? Array.Empty<string>();

        _blockedStore = cfg.GetValue("State:BlockedStore", "blocked.json");

        // Load block state
        LoadState();

        // Auto-load IIS sites if not specified
        if (_enableIis && _iisSites.Length == 0)
        {
            _iisSites = GetAllIisSites();
            _log.LogInformation("Auto-loaded IIS sites: {sites}", string.Join(", ", _iisSites));
        }

        // remove duplicate blocks in firewall
        var removed = WindowsFirewall.DeduplicateByNamePrefix(_fwPrefix);
        if (removed > 0) _log.LogInformation("Firewall dedupe removed {removed} duplicate rules.", removed);
    }

    // So menu can show default prefix
    public string FirewallRulePrefix => _fwPrefix;

    // Blocked list for UI
    public (string Ip, string Reason, DateTimeOffset BlockedAt, DateTimeOffset? ExpiresAt, bool IsExpired)[] GetBlocked()
        => _blocked.Values
           .OrderBy(b => b.Ip)
           .Select(b => (b.Ip, b.Reason, b.BlockedAt, b.ExpiresAt, b.IsExpired))
           .ToArray();

    // Whitelist view & edit
    public string[] GetWhitelist() => _whitelist.OrderBy(x => x).ToArray();
    public void AddWhitelist(string ip) => _whitelist.Add(ip);
    public void RemoveWhitelist(string ip) => _whitelist.Remove(ip);

    // Manual block / unblock
    public void BlockNow(string ip, string reason = "manual") => TriggerBlock(ip, reason);

    public void UnblockNow(string ip)
    {
        var ruleName = $"{_fwPrefix}-{ip}";
        WindowsFirewall.RemoveRule(ruleName);

        if (_enableIis && _iisSites.Length > 0)
        {
            lock (_iisConfigLock)
            {
                for (int attempt = 1; attempt <= IisCommitMaxRetries; attempt++)
                {
                    try
                    {
                        using var sm = new ServerManager();
                        var cfg = sm.GetApplicationHostConfiguration();
                        foreach (var site in _iisSites)
                        {
                            var sec = cfg.GetSection("system.webServer/security/ipSecurity", site);
                            var coll = sec.GetCollection();
                            var removes = coll.Where(el =>
                            {
                                if (!string.Equals(el.ElementTagName, "add", StringComparison.OrdinalIgnoreCase)) return false;
                                var addr = (string?)el.GetAttributeValue("ipAddress");
                                var allowed = el.GetAttributeValue("allowed");
                                return !string.IsNullOrEmpty(addr)
                                       && addr.Equals(ip, StringComparison.OrdinalIgnoreCase)
                                       && allowed is bool b && b == false;
                            }).ToList();

                            foreach (var el in removes) coll.Remove(el);
                        }
                        sm.CommitChanges();
                        break; // success
                    }
                    catch (System.IO.FileLoadException)
                    {
                        if (attempt == IisCommitMaxRetries)
                            _log.LogError("IIS commit conflict after {attempts} attempts while unblocking {ip}", attempt, ip);
                        else
                            _log.LogWarning("IIS commit conflict (attempt {attempt}/{max}) while unblocking {ip}; retrying…",
                                            attempt, IisCommitMaxRetries, ip);

                        SleepBackoff(attempt);
                        continue;
                    }
                    catch (Exception ex)
                    {
                        _log.LogError(ex, "Unblock: failed to remove IIS ipSecurity entries for {ip}", ip);
                        break;
                    }
                }
            }
        }

        _blocked.TryRemove(ip, out _);
        SaveState();
    }


    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _ = Task.Run(() => RunMainLoop(stoppingToken), stoppingToken);
        return Task.CompletedTask;
    }

    private List<FileSystemWatcher> StartFolderWatchers(IEnumerable<string> patterns, Action<string> onNewFile)
    {
        var watchers = new List<FileSystemWatcher>();

        foreach (var pattern in patterns)
        {
            var (baseDir, _, filePattern) = SplitPattern(pattern);
            if (string.IsNullOrWhiteSpace(baseDir) || !Directory.Exists(baseDir))
                continue;

            var w = new FileSystemWatcher(baseDir)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite,
                Filter = "*.*"
            };

            FileSystemEventHandler handleCreateOrChange = (_, e) =>
            {
                try
                {
                    if (WildcardIsMatch(Path.GetFileName(e.FullPath), filePattern))
                    {
                        onNewFile(e.FullPath);
                    }
                }
                catch { }
            };

            RenamedEventHandler handleRenamed = (_, e) =>
            {
                try
                {
                    if (WildcardIsMatch(Path.GetFileName(e.FullPath), filePattern))
                    {
                        onNewFile(e.FullPath);
                    }
                }
                catch { }
            };

            w.Created += handleCreateOrChange;
            w.Changed += handleCreateOrChange;
            w.Renamed += handleRenamed;

            w.EnableRaisingEvents = true;
            watchers.Add(w);
        }

        return watchers;
    }

    private async Task RunMainLoop(CancellationToken ct)
    {
        try
        {
            if (_pathPatterns.Length == 0)
            {
                _log.LogError("No paths configured under LogWatcher:Paths. Example: C:/inetpub/logs/LogFiles/W3SVC*/u_ex*.log");
                return;
            }

            _log.LogInformation("IisGuard running. Poll={ms}ms, POST/min={post}, ERR/min={err}, BanMinutes={ban}",
                _pollMs, _postPerMin, _errorsPerMin, _banMinutes);

            // Tail existing files
            foreach (var pattern in _pathPatterns)
            {
                foreach (var f in ExpandPathPattern(pattern))
                {
                    if (_allFiles.Add(f))
                    {
                        _tails.Add(new LogTail(f, OnLogLine, _pollMs, _log));
                        _log.LogInformation("Tailing {file}", f);
                    }
                }
            }

            // Watch for new rolling logs
            _watchers.AddRange(StartFolderWatchers(_pathPatterns, (newFile) =>
            {
                try
                {
                    if (_allFiles.Add(newFile))
                    {
                        _tails.Add(new LogTail(newFile, OnLogLine, _pollMs, _log));
                        _log.LogInformation("New log detected & tailed: {f}", newFile);
                    }
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "Failed to start tail on {f}", newFile);
                }
            }));

            while (!ct.IsCancellationRequested)
                await Task.Delay(1000, ct);
        }
        catch (TaskCanceledException) { }
        catch (Exception ex)
        {
            TryWriteCrash(ex);
            _log.LogError(ex, "Fatal error in main loop");
        }
        finally
        {
            Cleanup();
        }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _log.LogInformation("Stopping IisGuard...");
        Cleanup();
        return base.StopAsync(cancellationToken);
    }

    private void Cleanup()
    {
        foreach (var t in _tails) t.Dispose();
        _tails.Clear();

        foreach (var w in _watchers) w.Dispose();
        _watchers.Clear();

        SaveState();
    }

    private void OnLogLine(string file, string line)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(line)) return;

            if (line.StartsWith("#Fields:", StringComparison.OrdinalIgnoreCase))
            {
                var f = line.Substring(8).Trim();
                _fieldOrder = f.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                _log.LogInformation("Fields from {file}: {f}", Path.GetFileName(file), string.Join(", ", _fieldOrder));
                return;
            }
            if (line.StartsWith("#")) return; // skip comments
            if (_fieldOrder.Length == 0) return; // wait until we know the field order

            var parts = W3cSplit.Split(line);
            if (parts.Length < _fieldOrder.Length) return;

            var rec = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < _fieldOrder.Length; i++)
                rec[_fieldOrder[i]] = parts[i];

            var ip = Get(rec, "c-ip");
            var ua = Get(rec, "cs(User-Agent)");
            var meth = Get(rec, "cs-method");
            var path = (Get(rec, "cs-uri-stem") ?? "").ToLowerInvariant();
            var sc = Get(rec, "sc-status");

            if (string.IsNullOrWhiteSpace(ip)) return;
            if (_whitelist.Contains(ip)) return;
            if (!string.IsNullOrWhiteSpace(ua) && _ignoreUAs.Any(ua.Contains)) return;

            var now = DateTimeOffset.UtcNow;

            // Record recent events for better reasons (up to 20 per IP)
            var q = _recentEvents.GetOrAdd(ip, _ => new Queue<(DateTimeOffset, string, string, string)>());
            lock (q)
            {
                q.Enqueue((now, path, sc ?? "-", ua ?? "-"));
                while (q.Count > RecentEventLimit)
                    q.Dequeue();
            }

            // Honeypot: instant block
            if (_honeypots.Contains(path))
            {
                TriggerBlock(ip, $"honeypot: {path}");
                return;
            }

            // Excessive POSTs
            if (string.Equals(meth, "POST", StringComparison.OrdinalIgnoreCase))
            {
                var sw = _postCounter.GetOrAdd(ip, _ => new SlidingWindow(TimeSpan.FromMinutes(1)));
                sw.Add(now);
                if (sw.Count >= _postPerMin)
                {
                    var details = BuildPostSummary(ip);
                    TriggerBlock(ip, $"High POST rate ({sw.Count}/min): {details}");
                }
            }

            // Many errors (>=400)
            if (int.TryParse(sc, out var code) && code >= 400)
            {
                var esw = _errCounter.GetOrAdd(ip, _ => new SlidingWindow(TimeSpan.FromMinutes(1)));
                esw.Add(now);
                if (esw.Count >= _errorsPerMin)
                {
                    var details = BuildErrorSummary(ip);
                    TriggerBlock(ip, $"High error rate ({esw.Count}/min): {details}");
                }
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to process line from {file}", file);
        }
    }

    private static string? Get(Dictionary<string, string> rec, string key)
        => rec.TryGetValue(key, out var v) ? (v == "-" ? null : v) : null;

    private string BuildErrorSummary(string ip)
    {
        if (!_recentEvents.TryGetValue(ip, out var q)) return "(no details)";
        lock (q)
        {
            if (q.Count == 0) return "(no details)";

            // Group by status
            var statusCounts = q.GroupBy(e => e.Status)
                                .OrderByDescending(g => g.Count())
                                .Select(g => $"{g.Key}x{g.Count()}")
                                .ToArray();

            // Most common UA among recent events
            var topUa = q.GroupBy(e => e.Ua)
                         .OrderByDescending(g => g.Count())
                         .Select(g => g.Key)
                         .FirstOrDefault() ?? "-";

            // Last 3 failing paths (most recent first)
            var samples = q.Reverse()
                           .Take(3)
                           .Select(e => $"{e.Status} {e.Path}")
                           .ToArray();

            return $"statuses {string.Join(", ", statusCounts)}; UA \"{topUa}\"; sample {string.Join(" | ", samples)}";
        }
    }

    private string BuildPostSummary(string ip)
    {
        if (!_recentEvents.TryGetValue(ip, out var q)) return "(no details)";
        lock (q)
        {
            var lastPosts = q.Reverse()
                             .Where(e => e.Path != null)
                             .Take(5)
                             .Select(e => e.Path)
                             .ToArray();

            var topUa = q.GroupBy(e => e.Ua)
                         .OrderByDescending(g => g.Count())
                         .Select(g => g.Key)
                         .FirstOrDefault() ?? "-";

            return $"UA \"{topUa}\"; recent paths: {string.Join(", ", lastPosts)}";
        }
    }

    private void TriggerBlock(string ip, string reason)
    {
        if (_blocked.TryGetValue(ip, out var existing) && !existing.IsExpired) return;

        _log.LogWarning("Blocking {ip} ({reason})", ip, reason);
        var expiry = _banMinutes > 0 ? DateTimeOffset.UtcNow.AddMinutes(_banMinutes) : (DateTimeOffset?)null;

        if (_enableFw) TryFirewallBlock(ip, _fwPrefix, expiry);

        if (_enableIis && _iisSites.Length > 0)
        {
            foreach (var site in _iisSites)
                TryIisBlock(ip, site);
        }

        _blocked[ip] = new BlockRecord { Ip = ip, Reason = reason, BlockedAt = DateTimeOffset.UtcNow, ExpiresAt = expiry };
        SaveState();
    }

    private void TryFirewallBlock(string ip, string prefix, DateTimeOffset? expiry)
    {
        try
        {
            var ruleName = $"{prefix}-{ip}";
            if (!WindowsFirewall.RuleExists(ruleName))
            {
                WindowsFirewall.AddBlockInboundRule(ruleName, ip);
            }

            if (expiry.HasValue)
            {
                var when = expiry.Value.LocalDateTime.ToString("yyyy-MM-ddTHH:mm:ss");
                // Use built-in NetSecurity cmdlets instead of calling our class
                var ps = $"-NoProfile -NonInteractive -Command " +
                         $"\"Try {{ Get-NetFirewallRule -DisplayName '{ruleName}' -ErrorAction Stop | Remove-NetFirewallRule }} Catch {{ }}\"";
                var sched = "-NoProfile -ExecutionPolicy Bypass -Command " +
                            $"\"Register-ScheduledTask -TaskName 'Unblock-{ruleName}' " +
                            $"-Trigger (New-ScheduledTaskTrigger -Once -At '{when}') " +
                            $"-Action (New-ScheduledTaskAction -Execute 'powershell' -Argument \\\"{ps}\\\") " +
                            "-RunLevel Highest -Force\"";
                Run("powershell", sched);
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Firewall block failed for {ip}", ip);
        }
    }

    private void TryIisBlock(string ip, string site)
    {
        // Only one IIS write at a time in this process
        lock (_iisConfigLock)
        {
            for (int attempt = 1; attempt <= IisCommitMaxRetries; attempt++)
            {
                try
                {
                    using var sm = new ServerManager();
                    var siteObj = sm.Sites.FirstOrDefault(s => s.Name.Equals(site, StringComparison.OrdinalIgnoreCase));
                    if (siteObj == null) return;
                    var app = siteObj.Applications["/"];
                    var vdir = app.VirtualDirectories["/"];
                    var webConfig = sm.GetWebConfiguration(site, app.Path);
                    var section = webConfig.GetSection("system.webServer/security/ipSecurity"); // writes to web.config
                    var collection = section.GetCollection();

                    // skip if exists
                    var exists = collection.Any(el =>
                    {
                        if (!string.Equals(el.ElementTagName, "add", StringComparison.OrdinalIgnoreCase)) return false;
                        var addr = (string?)el.GetAttributeValue("ipAddress");
                        var allowed = el.GetAttributeValue("allowed");
                        return !string.IsNullOrEmpty(addr)
                               && addr.Equals(ip, StringComparison.OrdinalIgnoreCase)
                               && allowed is bool b && b == false;
                    });
                    if (exists) return;

                    var add = collection.CreateElement("add");
                    add.SetAttributeValue("ipAddress", ip);
                    add.SetAttributeValue("allowed", false);
                    collection.Add(add);

                    sm.CommitChanges(); // may throw if file changed on disk
                    return;             // success
                }
                catch (System.IO.FileLoadException fle)
                {
                    // appHost.config changed between read and commit — retry with backoff
                    if (attempt == IisCommitMaxRetries)
                        _log.LogError(fle, "IIS commit conflict after {attempts} attempts for {ip} on {site}", attempt, ip, site);
                    else
                        _log.LogWarning("IIS commit conflict (attempt {attempt}/{max}) for {ip} on {site}; retrying…",
                                        attempt, IisCommitMaxRetries, ip, site);

                    SleepBackoff(attempt);
                    continue;
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "IIS ipSecurity block failed for {ip} on {site}", ip, site);
                    return;
                }
            }
        }
    }

    private static void SleepBackoff(int attempt)
    {
        // exponential-ish backoff with small jitter
        var delay = IisCommitBaseDelayMs * attempt * attempt;
        var jitter = Random.Shared.Next(25, 75);
        Thread.Sleep(delay + jitter);
    }



    // ---- helpers ----

    // Windows Firewall helper using COM (INetFwPolicy2)
    public static class WindowsFirewall
    {
        private static object GetPolicy2()
        {
            var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
                ?? throw new InvalidOperationException("Windows Firewall API not available (HNetCfg.FwPolicy2).");
            return Activator.CreateInstance(t)!;
        }

        public static bool RuleExists(string displayName)
        {
            try
            {
                dynamic policy2 = GetPolicy2();
                foreach (dynamic r in policy2.Rules)
                {
                    if (string.Equals((string)r.Name, displayName, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch { }
            return false;
        }

        public static void AddBlockInboundRule(string displayName, string remoteIp)
        {
            dynamic policy2 = GetPolicy2();
            var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule")
                ?? throw new InvalidOperationException("Windows Firewall Rule API not available (HNetCfg.FWRule).");

            dynamic rule = Activator.CreateInstance(ruleType)!;
            rule.Name = displayName;
            rule.Description = "IisGuard auto-block";
            rule.Direction = 1;          // NET_FW_RULE_DIR_IN
            rule.Action = 0;             // NET_FW_ACTION_BLOCK
            rule.Enabled = true;
            rule.InterfaceTypes = "All";
            rule.RemoteAddresses = remoteIp;
            rule.Profiles = 0x7FFFFFFF;  // All profiles
            rule.Protocol = 256;         // ANY

            policy2.Rules.Add(rule);
        }

        public static void RemoveRule(string displayName)
        {
            try
            {
                dynamic policy2 = GetPolicy2();
                policy2.Rules.Remove(displayName);
            }
            catch { }
        }

        public static IEnumerable<(string Name, string RemoteAddresses, string Direction, string Action)> ListRules(string? namePrefix = null)
        {
            dynamic policy2 = GetPolicy2();
            foreach (dynamic r in policy2.Rules)
            {
                string name = r.Name;
                if (!string.IsNullOrEmpty(namePrefix) && !name.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase))
                    continue;

                string dir = (int)r.Direction == 1 ? "In" : "Out";
                string act = (int)r.Action == 0 ? "Block" : "Allow";
                string addrs = r.RemoteAddresses ?? "";
                yield return (name, addrs, dir, act);
            }
        }

        public static int DeduplicateByNamePrefix(string namePrefix)
        {
            var groups = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var (Name, RemoteAddresses, _, _) in ListRules(namePrefix))
            {
                var key = $"{Name}|{RemoteAddresses}";
                if (!groups.TryGetValue(key, out var list))
                    groups[key] = list = new List<string>();
                list.Add(Name);
            }

            int removed = 0;
            foreach (var kv in groups)
            {
                var dupes = kv.Value.Skip(1); // keep-first
                foreach (var d in dupes)
                {
                    RemoveRule(d);
                    removed++;
                }
            }
            return removed;
        }
    }

    private static void Run(string file, string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = Environment.ExpandEnvironmentVariables(file),
            Arguments = args,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi)!;
        p.WaitForExit();
    }

    private void LoadState()
    {
        try
        {
            if (!File.Exists(_blockedStore)) return;
            var json = File.ReadAllText(_blockedStore);
            var list = JsonSerializer.Deserialize<List<BlockRecord>>(json) ?? new();
            foreach (var br in list)
            {
                if (!br.IsExpired)
                    _blocked[br.Ip] = br;
            }
            _log.LogInformation("Loaded {n} existing blocked IP(s).", _blocked.Count);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to load blocked state");
        }
    }

    private void SaveState()
    {
        try
        {
            lock (_stateLock)
            {
                var list = _blocked.Values.OrderBy(b => b.Ip).ToList();
                File.WriteAllText(_blockedStore, JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true }));
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to save blocked state");
        }
    }

    private static string[] GetAllIisSites()
    {
        try
        {
            using var sm = new ServerManager();
            return sm.Sites.Select(s => s.Name)
                           .Distinct(StringComparer.OrdinalIgnoreCase)
                           .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    // -------- Pattern Expansion (supports * and ? in directory/file segments) --------
    private static IEnumerable<string> ExpandPathPattern(string pattern)
    {
        var (baseDir, dirSegments, filePattern) = SplitPattern(pattern);
        if (string.IsNullOrWhiteSpace(baseDir) || !Directory.Exists(baseDir))
            yield break;

        foreach (var dir in ExpandDirectories(baseDir, dirSegments, 0))
        {
            string[] files;
            try { files = Directory.GetFiles(dir, filePattern, SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (var f in files)
                yield return f;
        }
    }

    private static (string baseDir, string[] dirSegments, string filePattern) SplitPattern(string pattern)
    {
        pattern = pattern.Replace('\\', Path.DirectorySeparatorChar)
                         .Replace('/', Path.DirectorySeparatorChar);

        var filePattern = Path.GetFileName(pattern);
        var dirPart = Path.GetDirectoryName(pattern) ?? "";
        var segments = dirPart.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);

        var baseSegments = new List<string>();
        var wildcardSegments = new List<string>();
        bool inWildcard = false;
        foreach (var s in segments)
        {
            if (!inWildcard && !HasWildcard(s)) baseSegments.Add(s);
            else { inWildcard = true; wildcardSegments.Add(s); }
        }

        string baseDir;
        if (Path.IsPathRooted(pattern))
        {
            baseDir = Path.Combine(Path.GetPathRoot(pattern) ?? "", Path.Combine(baseSegments.ToArray()));
        }
        else
        {
            baseDir = Path.Combine(Directory.GetCurrentDirectory(), Path.Combine(baseSegments.ToArray()));
        }
        if (string.IsNullOrEmpty(baseDir)) baseDir = Directory.GetCurrentDirectory();

        return (baseDir, wildcardSegments.ToArray(), filePattern);
    }

    private static IEnumerable<string> ExpandDirectories(string currentBase, string[] segments, int idx)
    {
        if (idx >= segments.Length) { yield return currentBase; yield break; }

        var seg = segments[idx];
        if (!HasWildcard(seg))
        {
            var next = Path.Combine(currentBase, seg);
            if (Directory.Exists(next))
                foreach (var d in ExpandDirectories(next, segments, idx + 1)) yield return d;
            yield break;
        }

        string[] children;
        try { children = Directory.GetDirectories(currentBase); }
        catch { yield break; }

        foreach (var child in children)
        {
            var name = Path.GetFileName(child);
            if (WildcardIsMatch(name, seg))
                foreach (var d in ExpandDirectories(child, segments, idx + 1)) yield return d;
        }
    }

    private static bool HasWildcard(string s) => s.Contains('*') || s.Contains('?');

    private static bool WildcardIsMatch(string text, string pattern)
    {
        var sb = new System.Text.StringBuilder("^");
        foreach (var ch in pattern)
        {
            switch (ch)
            {
                case '*': sb.Append(".*"); break;
                case '?': sb.Append('.'); break;
                case '.': sb.Append(@"\."); break;
                case '\\': sb.Append(@"\\"); break;
                default: sb.Append(Regex.Escape(ch.ToString())); break;
            }
        }
        sb.Append("$");
        return Regex.IsMatch(text, sb.ToString(), RegexOptions.IgnoreCase);
    }

    // -------- Sliding Window & Block record --------
    private sealed class SlidingWindow
    {
        private readonly TimeSpan _window;
        private readonly Queue<DateTimeOffset> _q = new();
        public int Count => _q.Count;
        public SlidingWindow(TimeSpan window) => _window = window;
        public void Add(DateTimeOffset t)
        {
            _q.Enqueue(t);
            while (_q.Count > 0 && (t - _q.Peek()) > _window) _q.Dequeue();
        }
    }

    private sealed class BlockRecord
    {
        public string Ip { get; set; } = "";
        public string Reason { get; set; } = "";
        public DateTimeOffset BlockedAt { get; set; }
        public DateTimeOffset? ExpiresAt { get; set; }
        public bool IsExpired => ExpiresAt.HasValue && ExpiresAt.Value < DateTimeOffset.UtcNow;
    }

    private void TryWriteCrash(Exception ex)
    {
        try
        {
            var crash = Path.Combine(AppContext.BaseDirectory, "IisGuard.crash.log");
            File.AppendAllText(crash, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {ex}\r\n");
        }
        catch { }
    }
}

// ============================== console menu ==============================
static class IisGuardConsole
{
    public static void Run(IisGuardWorker worker, string versionText)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        while (true)
        {
            Console.Clear();
            Banner(versionText);
            ShortDescription();

            Console.WriteLine("  W  -  Whitelist an IP");
            Console.WriteLine("  R  -  Remove IP from whitelist");
            Console.WriteLine("  L  -  List whitelist");
            Console.WriteLine("  B  -  View blocked list");
            Console.WriteLine("  K  -  Block an IP (manual)");
            Console.WriteLine("  U  -  Unblock an IP");
            Console.WriteLine("  F  -  List firewall rules (by prefix)");
            Console.WriteLine("  D  -  Dedupe firewall rules (by prefix)");
            Console.WriteLine("  Q  -  Quit console (IisGuard keeps running)\n");
            Console.Write("Select option: ");

            var key = Console.ReadKey(true).Key;
            Console.WriteLine();

            try
            {
                switch (key)
                {
                    case ConsoleKey.W:
                        Console.Write("IP to whitelist: ");
                        var wip = ReadTrim();
                        if (!string.IsNullOrWhiteSpace(wip)) { worker.AddWhitelist(wip); Info("Added to whitelist."); }
                        break;

                    case ConsoleKey.R:
                        Console.Write("IP to remove from whitelist: ");
                        var rip = ReadTrim();
                        if (!string.IsNullOrWhiteSpace(rip)) { worker.RemoveWhitelist(rip); Info("Removed from whitelist."); }
                        break;

                    case ConsoleKey.L:
                        var wl = worker.GetWhitelist();
                        if (wl.Length == 0) Info("(whitelist empty)");
                        else foreach (var x in wl) Console.WriteLine($"  {x}");
                        break;

                    case ConsoleKey.B:
                        var bl = worker.GetBlocked();
                        if (bl.Length == 0) Info("(no blocked IPs)");
                        else
                        {
                            Console.WriteLine("  IP                 Reason                          BlockedAt              Expires");
                            Console.WriteLine("  -----------------  ------------------------------  ---------------------  ---------------------");
                            foreach (var b in bl)
                                Console.WriteLine($"  {b.Ip,-17}  {Trunc(b.Reason, 28),-28}  {b.BlockedAt:g,-21}  {(b.ExpiresAt?.ToString("g") ?? "-"),-21}");
                        }
                        break;

                    case ConsoleKey.K:
                        Console.Write("IP to BLOCK: ");
                        var bip = ReadTrim();
                        if (string.IsNullOrWhiteSpace(bip)) break;
                        Console.Write("Reason (optional): ");
                        var br = ReadTrim();
                        worker.BlockNow(bip, string.IsNullOrEmpty(br) ? "manual" : br);
                        Info("Blocked.");
                        break;

                    case ConsoleKey.U:
                        Console.Write("IP to UNBLOCK: ");
                        var uip = ReadTrim();
                        if (!string.IsNullOrWhiteSpace(uip)) { worker.UnblockNow(uip); Info("Unblocked."); }
                        break;

                    case ConsoleKey.F:
                        Console.Write($"Prefix (ENTER = {worker.FirewallRulePrefix}): ");
                        var pf = ReadTrim();
                        var prefix = string.IsNullOrWhiteSpace(pf) ? worker.FirewallRulePrefix : pf;
                        var rules = IisGuardWorker.WindowsFirewall.ListRules(prefix).ToArray();
                        if (rules.Length == 0) Info("(no rules with that prefix)");
                        else
                        {
                            Console.WriteLine("  Name                                     Dir  Act   RemoteAddresses");
                            Console.WriteLine("  ---------------------------------------- ---- ----- ----------------");
                            foreach (var r in rules)
                                Console.WriteLine($"  {Trunc(r.Name, 40),-40} {r.Direction,3}  {r.Action,5} {r.RemoteAddresses}");
                        }
                        break;

                    case ConsoleKey.D:
                        Console.Write($"Prefix (ENTER = {worker.FirewallRulePrefix}): ");
                        var pd = ReadTrim();
                        var dprefix = string.IsNullOrWhiteSpace(pd) ? worker.FirewallRulePrefix : pd;
                        var removed = IisGuardWorker.WindowsFirewall.DeduplicateByNamePrefix(dprefix);
                        Info($"Removed {removed} duplicate firewall rule(s).");
                        break;

                    case ConsoleKey.Q:
                        Info("Closing console (IisGuard continues in background).");
                        Thread.Sleep(600);
                        return;

                    default:
                        break;
                }
            }
            catch (Exception ex)
            {
                Error(ex.Message);
            }

            Console.WriteLine();
            Console.Write("Press any key to return to menu…");
            Console.ReadKey(true);
        }

        // --- local helpers ---
        static void Banner(string v)
        {
            Console.WriteLine("=============================");
            var title = $"IISGuard {v}";
            var width = 29;
            var pad = Math.Max(0, (width - title.Length) / 2);
            Console.WriteLine($"{new string(' ', pad)}{title}");
            Console.WriteLine("=============================");
        }

        static void ShortDescription()
        {
            Console.WriteLine("Monitors IIS logs in real time and auto-blocks abusive IPs (POST rate, errors, honeypots).");
            Console.WriteLine("Use the options below to manage whitelist, blocked IPs, and firewall rules.\n");
        }

        static string ReadTrim() => (Console.ReadLine() ?? "").Trim();
        static string Trunc(string s, int n) => s.Length <= n ? s : s[..n];
        static void Info(string s) => Console.WriteLine($"  [✓] {s}");
        static void Error(string s) => Console.WriteLine($"  [x] {s}");
    }
}

// ============================== log tail ==============================
sealed class LogTail : IDisposable
{
    private readonly string _file;
    private readonly Action<string, string> _onLine;
    private readonly ILogger _log;
    private readonly CancellationTokenSource _cts = new();
    private readonly int _pollMs;
    private long _pos;
    private FileStream? _fs;
    private StreamReader? _sr;

    public LogTail(string file, Action<string, string> onLine, int pollMs, ILogger log)
    {
        _file = file;
        _onLine = onLine;
        _pollMs = pollMs;
        _log = log;
        Task.Run(ReadLoop);
    }

    private async Task ReadLoop()
    {
        try
        {
            _fs = new FileStream(_file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            _sr = new StreamReader(_fs);

            _pos = _fs.Length;
            if (_pos > 8192) _pos -= 8192; // back up to catch last #Fields
            _fs.Seek(_pos, SeekOrigin.Begin);

            while (!_cts.IsCancellationRequested)
            {
                while (!_sr.EndOfStream)
                {
                    var line = await _sr.ReadLineAsync() ?? "";
                    _pos += (line.Length + Environment.NewLine.Length);
                    _onLine(_file, line);
                }

                await Task.Delay(_pollMs, _cts.Token);
                _fs.Seek(_pos, SeekOrigin.Begin);
            }
        }
        catch (TaskCanceledException) { }
        catch (Exception ex)
        {
            _log.LogError(ex, "Tail loop failed for {f}", _file);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _sr?.Dispose();
        _fs?.Dispose();
    }
}

// ---------- Daily rolling file logger ----------
sealed class DailyFileLoggerProvider : ILoggerProvider
{
    private readonly string _dir;
    private readonly string _prefix;
    private readonly int _retentionDays;
    private readonly LogLevel _minLevel;
    private readonly object _gate = new();
    private StreamWriter? _writer;
    private DateOnly _currentDate;
    private bool _disposed;

    public DailyFileLoggerProvider(string logsDir, string filePrefix = "app",
                                   int retentionDays = 5, LogLevel minLevel = LogLevel.Information)
    {
        _dir = logsDir;
        _prefix = filePrefix;
        _retentionDays = Math.Max(1, retentionDays);
        _minLevel = minLevel;

        Directory.CreateDirectory(_dir);
        RollIfNeeded(force: true);
        CleanupOldFiles();
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName, _minLevel);

    internal void Write(string category, LogLevel level, EventId eventId, string message, Exception? ex)
    {
        if (_disposed) return;

        lock (_gate)
        {
            RollIfNeeded();
            var ts = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            _writer!.Write(ts);
            _writer!.Write(" ");
            _writer!.Write(level.ToString().PadRight(11)); // align
            _writer!.Write(" ");
            _writer!.Write('[');
            _writer!.Write(category);
            _writer!.Write(']');
            if (eventId.Id != 0)
            {
                _writer!.Write(" (");
                _writer!.Write(eventId.Id);
                _writer!.Write(')');
            }
            _writer!.Write(" - ");
            _writer!.WriteLine(message);

            if (ex != null)
            {
                _writer!.WriteLine(ex.ToString());
            }
            _writer!.Flush();
        }
    }

    private void RollIfNeeded(bool force = false)
    {
        var today = DateOnly.FromDateTime(DateTime.Now);
        if (!force && today == _currentDate && _writer != null) return;

        _writer?.Dispose();
        _currentDate = today;

        var path = Path.Combine(_dir, $"{_prefix}-{today:yyyy-MM-dd}.log");
        _writer = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true,
            NewLine = Environment.NewLine
        };

        // On each roll, tidy old files
        CleanupOldFiles();
    }

    private void CleanupOldFiles()
    {
        try
        {
            var cutoff = DateTime.Now.Date.AddDays(-_retentionDays);
            foreach (var file in Directory.EnumerateFiles(_dir, $"{_prefix}-*.log"))
            {
                // Expect: prefix-YYYY-MM-DD.log
                var name = Path.GetFileNameWithoutExtension(file);
                var parts = name.Split('-');
                if (parts.Length >= 4 &&
                    DateTime.TryParse($"{parts[^3]}-{parts[^2]}-{parts[^1]}", out var dt) &&
                    dt.Date < cutoff)
                {
                    File.Delete(file);
                }
            }
        }
        catch
        {
            // ignore cleanup errors
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        lock (_gate)
        {
            _writer?.Dispose();
            _writer = null;
        }
    }

    private sealed class FileLogger : ILogger
    {
        private readonly DailyFileLoggerProvider _owner;
        private readonly string _category;
        private readonly LogLevel _minLevel;

        public FileLogger(DailyFileLoggerProvider owner, string category, LogLevel minLevel)
        {
            _owner = owner;
            _category = category;
            _minLevel = minLevel;
        }

        public IDisposable BeginScope<TState>(TState state) => NullScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= _minLevel;

        public void Log<TState>(LogLevel logLevel, EventId eventId,
                                TState state, Exception? exception,
                                Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            var message = formatter(state, exception);
            _owner.Write(_category, logLevel, eventId, message, exception);
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}
