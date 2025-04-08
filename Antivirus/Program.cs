using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Reflection;
using System.Management;
using System.Drawing;

class Program
{
    static string logFile = "C:\\antivirus_log.txt";
    static string quarantineFolder = "C:\\Quarantine";
    static string localDatabase = "C:\\local_database.txt";
    static Dictionary<string, bool> scannedFiles = new();
    static DateTime lastEventTime = DateTime.MinValue;
    static int minIntervalMs = 500;

    [STAThread]
    static void Main()
    {
        EnsureScheduledTask();

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        ContextMenuStrip contextMenu = new ContextMenuStrip();
        contextMenu.Items.Add("Toggle Real-Time Protection", null, (s, e) => ToggleRealtimeProtection());
        contextMenu.Items.Add("View Log", null, (s, e) => Process.Start("notepad.exe", logFile));
        contextMenu.Items.Add("Open Quarantine Folder", null, (s, e) => Process.Start("explorer.exe", quarantineFolder));
        contextMenu.Items.Add("Exit", null, (s, e) => Application.Exit());

        Icon trayIconImage = SystemIcons.Application; // fallback

        try
        {
            var resourceName = "Antivirus.Autorun.ico"; // Match your namespace and filename
            var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
            if (stream != null)
            {
                trayIconImage = new Icon(stream);
            }
            else
            {
                WriteLog($"[ERROR] Embedded icon '{resourceName}' not found. Tray icon will fallback.");
            }
        }
        catch (Exception ex)
        {
            WriteLog($"[ERROR] Failed to load tray icon: {ex.Message}");
        }

        NotifyIcon trayIcon = new NotifyIcon()
        {
            Icon = trayIconImage,
            Text = "Simple Antivirus by Gorstak",
            Visible = true,
            ContextMenuStrip = contextMenu
        };

        Directory.CreateDirectory(quarantineFolder);
        WriteLog("Antivirus started.");

        FileSystemWatcher watcher = new FileSystemWatcher("C:\\")
        {
            Filter = "*.dll",
            IncludeSubdirectories = true,
            EnableRaisingEvents = true
        };

        watcher.Changed += OnChanged;
        watcher.Created += OnChanged;

        Application.Run();
    }

    static bool realtimeProtectionEnabled = true;

    static void ToggleRealtimeProtection()
    {
        realtimeProtectionEnabled = !realtimeProtectionEnabled;
        WriteLog($"Real-Time Protection {(realtimeProtectionEnabled ? "Enabled" : "Disabled")}");
    }

    static void OnChanged(object sender, FileSystemEventArgs e)
    {
        if (!realtimeProtectionEnabled) return;
        if ((DateTime.Now - lastEventTime).TotalMilliseconds < minIntervalMs) return;
        lastEventTime = DateTime.Now;

        WriteLog($"DLL Change Detected: {e.FullPath}");
        if (!File.Exists(e.FullPath)) return;

        var hashInfo = CalculateFileHash(e.FullPath);
        if (hashInfo == null) return;

        if (scannedFiles.ContainsKey(hashInfo.Value.Hash))
        {
            if (!scannedFiles[hashInfo.Value.Hash])
            {
                KillProcessesUsingFile(e.FullPath);
                QuarantineFile(e.FullPath);
            }
            return;
        }

        scannedFiles[hashInfo.Value.Hash] = hashInfo.Value.Valid;
        File.AppendAllText(localDatabase, $"{hashInfo.Value.Hash},{hashInfo.Value.Valid}\n");
        if (!hashInfo.Value.Valid)
        {
            KillProcessesUsingFile(e.FullPath);
            QuarantineFile(e.FullPath);
        }
    }

    static (string Hash, bool Valid)? CalculateFileHash(string filePath)
    {
        try
        {
            var signer = X509Certificate.CreateFromSignedFile(filePath);
            bool valid = signer != null;

            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            string hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLower();

            WriteLog($"Signature for {filePath}: {(valid ? "Valid" : "Invalid")}");
            return (hash, valid);
        }
        catch (Exception ex)
        {
            WriteLog($"Hashing error: {filePath} - {ex.Message}");
            return null;
        }
    }

    static void KillProcessesUsingFile(string filePath)
    {
        try
        {
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    foreach (ProcessModule module in process.Modules)
                    {
                        if (string.Equals(module.FileName, filePath, StringComparison.OrdinalIgnoreCase))
                        {
                            WriteLog($"Killing process {process.ProcessName} (PID {process.Id}) using {filePath}");
                            try
                            {
                                Process parent = GetParentProcess(process);
                                if (parent != null)
                                {
                                    WriteLog($"Also killing parent process {parent.ProcessName} (PID {parent.Id})");
                                    try
                                    {
                                        parent.Kill();
                                    }
                                    catch (Exception ex)
                                    {
                                        WriteLog($"Failed to kill parent process: {ex.Message}");
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                WriteLog($"Error getting parent process: {ex.Message}");
                            }

                            process.Kill();
                            break;
                        }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            WriteLog($"Failed to kill process using {filePath}: {ex.Message}");
        }
    }

    static Process GetParentProcess(Process process)
    {
        try
        {
            int parentPid = 0;
            using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Process WHERE ProcessId = " + process.Id))
            {
                foreach (var obj in searcher.Get())
                {
                    parentPid = Convert.ToInt32(obj["ParentProcessId"]);
                    break;
                }
            }
            return Process.GetProcessById(parentPid);
        }
        catch
        {
            return null;
        }
    }

    static void QuarantineFile(string filePath)
    {
        try
        {
            string dest = Path.Combine(quarantineFolder, Path.GetFileName(filePath));
            File.Move(filePath, dest);
            WriteLog($"Quarantined {filePath}");
        }
        catch (Exception ex)
        {
            WriteLog($"Failed to quarantine {filePath}: {ex.Message}");
        }
    }

    static void WriteLog(string message)
    {
        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        string entry = $"[{timestamp}] {message}";
        Console.WriteLine(entry);
        File.AppendAllText(logFile, entry + Environment.NewLine);
    }

    static void EnsureScheduledTask()
    {
        string taskName = "GorstakAV";
        string exePath = Process.GetCurrentProcess().MainModule.FileName;

        var checkTask = new ProcessStartInfo
        {
            FileName = "schtasks",
            Arguments = $"/Query /TN \"{taskName}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (var process = Process.Start(checkTask))
        {
            process.WaitForExit();
            if (process.ExitCode == 0)
            {
                return; // Task exists
            }
        }

        var createTask = new ProcessStartInfo
        {
            FileName = "schtasks",
            Arguments = $"/Create /TN \"{taskName}\" /TR \"\"{exePath}\"\" /SC ONSTART /RU SYSTEM /RL HIGHEST /F",
            Verb = "runas",
            UseShellExecute = true
        };

        Process.Start(createTask);
    }
}