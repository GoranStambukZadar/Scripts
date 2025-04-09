// Program.cs
using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net;
using System.Windows.Forms;
using System.Drawing;
using System.Reflection;

class Program
{
    private static NotifyIcon? trayIcon;
    private static bool realTimeProtectionEnabled = true;
    private static readonly string logFile = @"C:\antivirus_log.txt";

    [STAThread]
    static void Main(string[] args)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        // Set up the tray icon and context menu
        ContextMenuStrip contextMenu = new ContextMenuStrip();
        contextMenu.Items.Add("Toggle Real-Time Protection", null, (s, e) => ToggleRealtimeProtection());
        contextMenu.Items.Add("View Log", null, (s, e) => Process.Start("notepad.exe", logFile));
        contextMenu.Items.Add("View Quarantine Folder", null, (s, e) => Process.Start("explorer.exe", AntivirusEngine.quarantineFolder));
        contextMenu.Items.Add("Exit", null, (s, e) => Application.Exit());

        Icon trayIconImage = SystemIcons.Application; // Default fallback icon
        try
        {
            var resourceName = "Antivirus.Autorun.ico"; // Matches your RootNamespace
            var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
            if (stream != null)
            {
                trayIconImage = new Icon(stream);
                WriteLog("[INFO] Custom tray icon loaded successfully.");
            }
            else
            {
                WriteLog($"[WARNING] Embedded icon '{resourceName}' not found. Using default icon.");
            }
        }
        catch (Exception ex)
        {
            WriteLog($"[ERROR] Failed to load tray icon: {ex.Message}");
        }

        trayIcon = new NotifyIcon()
        {
            Icon = trayIconImage,
            Text = "GorstakAV Antivirus",
            Visible = true,
            ContextMenuStrip = contextMenu
        };

        // Start the antivirus engine
        WriteLog("[INFO] Starting GorstakAV Antivirus Engine...");
        AntivirusEngine.Start();
        trayIcon.ShowBalloonTip(3000, "GorstakAV", "Antivirus engine started.", ToolTipIcon.Info);

        // Run the application
        Application.Run();
    }

    private static void ToggleRealtimeProtection()
    {
        realTimeProtectionEnabled = !realTimeProtectionEnabled;
        string status = realTimeProtectionEnabled ? "enabled" : "disabled";
        trayIcon!.Text = $"GorstakAV Antivirus ({status})";
        trayIcon.ShowBalloonTip(1000, "GorstakAV", $"Real-time protection {status}.", ToolTipIcon.Info);
        AntivirusEngine.SetRealTimeProtection(realTimeProtectionEnabled);
        WriteLog($"[INFO] Real-time protection {status}.");
    }

    public static void WriteLog(string message) // Changed to public static
    {
        try
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            File.AppendAllText(logFile, $"{timestamp} {message}\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to write to log: {ex.Message}");
        }
    }
}

public class AntivirusEngine
{
    public static readonly string baseFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GorstakAV");
    public static readonly string quarantineFolder = Path.Combine(baseFolder, "Quarantine");
    private static readonly string localDatabase = Path.Combine(baseFolder, "local_database.dat");
    private static Dictionary<string, (bool Valid, bool FromVT)> scannedFiles = new();
    private static DateTime lastEventTime = DateTime.MinValue;
    private static readonly int minIntervalMs = 500;
    private static readonly byte[] dbKey = SHA256.HashData(Encoding.UTF8.GetBytes("some-super-secret-key"));
    private static List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
    private static bool realTimeProtectionEnabled = true;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, MoveFileFlags dwFlags);

    [Flags]
    private enum MoveFileFlags
    {
        MOVEFILE_REPLACE_EXISTING = 0x00000001,
        MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
    }

    public static void Start()
    {
        Directory.CreateDirectory(baseFolder);
        Directory.CreateDirectory(quarantineFolder);
        LoadDatabase();
        SetupFileWatchers();
    }

    public static void SetRealTimeProtection(bool enabled)
    {
        realTimeProtectionEnabled = enabled;
        foreach (var watcher in watchers)
        {
            watcher.EnableRaisingEvents = enabled;
        }
    }

    private static void SetupFileWatchers()
    {
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (!drive.IsReady) continue;
            try
            {
                FileSystemWatcher watcher = new(drive.RootDirectory.FullName)
                {
                    Filter = "*.*",
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true
                };

                watcher.Created += OnFileEvent;
                watcher.Changed += OnFileEvent;
                watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                Program.WriteLog($"[ERROR] Failed to set up watcher for {drive.Name}: {ex.Message}");
            }
        }
    }

    private static void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        if (!realTimeProtectionEnabled) return;
        if ((DateTime.Now - lastEventTime).TotalMilliseconds < minIntervalMs) return;
        lastEventTime = DateTime.Now;

        if (!File.Exists(e.FullPath)) return;

        string ext = Path.GetExtension(e.FullPath).ToLower();
        if (ext == ".dll")
        {
            ScanDll(e.FullPath);
        }
        else
        {
            _ = ScanWithVirusTotal(e.FullPath);
        }
    }

    private static void ScanDll(string path)
    {
        var hashInfo = CalculateFileHash(path);
        if (hashInfo == null)
        {
            Program.WriteLog($"[WARNING] Failed to calculate hash for {path}");
            return;
        }

        Program.WriteLog($"[INFO] Scanning DLL: {path}, Hash: {hashInfo.Value.Hash}");

        if (scannedFiles.TryGetValue(hashInfo.Value.Hash, out var cached) && !cached.Valid)
        {
            KillProcessesUsingFile(path);
            QuarantineFile(path);
            return;
        }

        if (!hashInfo.Value.Valid)
        {
            scannedFiles[hashInfo.Value.Hash] = (false, false);
            KillProcessesUsingFile(path);
            QuarantineFile(path);
            SaveDatabase();
            Program.WriteLog($"[ALERT] Invalid DLL detected and quarantined: {path}");
        }
        else
        {
            scannedFiles[hashInfo.Value.Hash] = (true, false);
            SaveDatabase();
            Program.WriteLog($"[INFO] DLL verified as valid: {path}");
        }
    }

    private static (string Hash, bool Valid)? CalculateFileHash(string filePath)
    {
        try
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            string hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLower();
            bool valid = false;
            try
            {
                var cert = X509CertificateLoader.LoadCertificateFromFile(filePath);
                if (cert != null)
                {
                    var chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    valid = chain.Build(new X509Certificate2(cert));
                }
            }
            catch { }
            return (hash, valid);
        }
        catch (Exception ex)
        {
            Program.WriteLog($"[ERROR] Error calculating hash for {filePath}: {ex.Message}");
            return null;
        }
    }

    private static async Task ScanWithVirusTotal(string filePath)
    {
        var hashInfo = CalculateFileHash(filePath);
        if (hashInfo == null) return;
        if (scannedFiles.ContainsKey(hashInfo.Value.Hash)) return;

        Program.WriteLog($"[INFO] Scanning with VirusTotal: {filePath}, Hash: {hashInfo.Value.Hash}");
        bool flagged = await VirusTotalAPI.CheckFileAsync(hashInfo.Value.Hash, filePath);
        scannedFiles[hashInfo.Value.Hash] = (!flagged, true);
        SaveDatabase();

        if (flagged)
        {
            QuarantineFile(filePath);
            Program.WriteLog($"[ALERT] File flagged by VirusTotal and quarantined: {filePath}");
        }
        else
        {
            Program.WriteLog($"[INFO] File cleared by VirusTotal: {filePath}");
        }
    }

    private static void KillProcessesUsingFile(string filePath)
    {
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                foreach (ProcessModule module in proc.Modules)
                {
                    if (string.Equals(module.FileName, filePath, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            proc.Kill();
                            Program.WriteLog($"[INFO] Killed process using {filePath}: {proc.ProcessName}");
                        }
                        catch (Exception ex)
                        {
                            Program.WriteLog($"[ERROR] Failed to kill process using {filePath}: {ex.Message}");
                        }
                        break;
                    }
                }
            }
            catch { }
        }
    }

    private static void QuarantineFile(string filePath)
    {
        try
        {
            string dest = Path.Combine(quarantineFolder, Path.GetFileName(filePath));
            File.Move(filePath, dest);
            Program.WriteLog($"[INFO] File moved to quarantine: {filePath} -> {dest}");
        }
        catch
        {
            TakeFileOwnership(filePath);
            if (!MoveFileEx(filePath, null, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT))
            {
                Program.WriteLog($"[ERROR] Failed to quarantine {filePath}, scheduled for deletion on reboot.");
            }
            else
            {
                Program.WriteLog($"[INFO] File {filePath} scheduled for deletion on reboot.");
            }
        }
    }

    private static void TakeFileOwnership(string filePath)
    {
        try
        {
            Process.Start(new ProcessStartInfo("takeown", $"/f \"{filePath}\"") { CreateNoWindow = true, UseShellExecute = false });
            Process.Start(new ProcessStartInfo("icacls", $"\"{filePath}\" /grant Administrators:F") { CreateNoWindow = true, UseShellExecute = false });
            Program.WriteLog($"[INFO] Took ownership of {filePath}");
        }
        catch (Exception ex)
        {
            Program.WriteLog($"[ERROR] Failed to take ownership of {filePath}: {ex.Message}");
        }
    }

    private static void LoadDatabase()
    {
        try
        {
            if (!File.Exists(localDatabase)) return;
            var lines = File.ReadAllBytes(localDatabase);
            string decrypted = Encoding.UTF8.GetString(ProtectedData.Unprotect(lines, dbKey, DataProtectionScope.CurrentUser));
            foreach (var line in decrypted.Split('\n'))
            {
                var parts = line.Split(',');
                if (parts.Length == 3)
                    scannedFiles[parts[0]] = (bool.Parse(parts[1]), bool.Parse(parts[2]));
            }
            Program.WriteLog("[INFO] Local database loaded successfully.");
        }
        catch (Exception ex)
        {
            Program.WriteLog($"[ERROR] Failed to load local database: {ex.Message}");
        }
    }

    private static void SaveDatabase()
    {
        try
        {
            var sb = new StringBuilder();
            foreach (var kvp in scannedFiles)
                sb.AppendLine($"{kvp.Key},{kvp.Value.Valid},{kvp.Value.FromVT}");
            byte[] encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes(sb.ToString()), dbKey, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(localDatabase, encrypted);
            Program.WriteLog("[INFO] Local database saved successfully.");
        }
        catch (Exception ex)
        {
            Program.WriteLog($"[ERROR] Failed to save local database: {ex.Message}");
        }
    }
}

public static class VirusTotalAPI
{
    private const string ApiKey = "b2b90f8df9d89f4bba576642326738bec2f83fa5c2d5314838993d5cd8b3a175"; // Replace this

    public static async Task<bool> CheckFileAsync(string hash, string filePath)
    {
        try
        {
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("x-apikey", ApiKey);

            var resp = await client.GetAsync($"https://www.virustotal.com/api/v3/files/{hash}");
            if (resp.IsSuccessStatusCode)
            {
                var json = await resp.Content.ReadAsStringAsync();
                if (json.Contains("malicious") || json.Contains("suspicious")) return true;
                return false;
            }
            else if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                using var fs = File.OpenRead(filePath);
                var form = new MultipartFormDataContent();
                form.Add(new StreamContent(fs), "file", Path.GetFileName(filePath));
                var uploadResp = await client.PostAsync("https://www.virustotal.com/api/v3/files", form);
                return false; // uploaded, assume clean until we have data
            }
        }
        catch (Exception ex)
        {
            Program.WriteLog($"[ERROR] VirusTotal scan failed for {filePath}: {ex.Message}");
        }
        return false;
    }
}