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
using System.Runtime.InteropServices;
using System.Linq;

class Program
{
    static readonly string baseFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GorstakAV");
    static readonly string logFile = Path.Combine(baseFolder, "antivirus_log.txt");
    static readonly string quarantineFolder = Path.Combine(baseFolder, "Quarantine");
    static readonly string localDatabase = Path.Combine(baseFolder, "local_database.txt");
    static Dictionary<string, bool> scannedFiles = new();
    static DateTime lastEventTime = DateTime.MinValue;
    static int minIntervalMs = 500;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, MoveFileFlags dwFlags);

    [Flags]
    enum MoveFileFlags
    {
        MOVEFILE_REPLACE_EXISTING = 0x00000001,
        MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
    }

    [STAThread]
    static void Main()
    {
        EnsureScheduledTask();

        Directory.CreateDirectory(baseFolder);
        Directory.CreateDirectory(quarantineFolder);

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        ContextMenuStrip contextMenu = new ContextMenuStrip();
        contextMenu.Items.Add("Toggle Real-Time Protection", null, (s, e) => ToggleRealtimeProtection());
        contextMenu.Items.Add("View Log", null, (s, e) => Process.Start("notepad.exe", logFile));
        contextMenu.Items.Add("Open Quarantine Folder", null, (s, e) => Process.Start("explorer.exe", quarantineFolder));
        contextMenu.Items.Add("Exit", null, (s, e) => Application.Exit());

        string? iconName = Array.Find(
            Assembly.GetExecutingAssembly().GetManifestResourceNames(),
            name => name.EndsWith("Autorun.ico")
        );

        if (iconName == null)
        {
            MessageBox.Show("Tray icon resource not found.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        using Stream? iconStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(iconName);
        if (iconStream == null)
        {
            MessageBox.Show($"Failed to load tray icon resource '{iconName}'. Available resources: \n" + string.Join("\n", Assembly.GetExecutingAssembly().GetManifestResourceNames()), "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        NotifyIcon trayIcon = new NotifyIcon()
        {
            Icon = new Icon(iconStream),
            Text = "Simple Antivirus by Gorstak",
            Visible = true,
            ContextMenuStrip = contextMenu
        };

        WriteLog("Antivirus started.");

        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.IsReady && (drive.DriveType == DriveType.Fixed || drive.DriveType == DriveType.Removable || drive.DriveType == DriveType.Network))
            {
                try
                {
                    FileSystemWatcher watcher = new FileSystemWatcher(drive.RootDirectory.FullName)
                    {
                        Filter = "*.dll",
                        IncludeSubdirectories = true,
                        EnableRaisingEvents = true
                    };

                    watcher.Changed += OnChanged;
                    watcher.Created += OnChanged;

                    WriteLog($"Watching drive: {drive.Name}");
                }
                catch (Exception ex)
                {
                    WriteLog($"Failed to watch drive {drive.Name}: {ex.Message}");
                }
            }
        }

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
        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                bool valid = false;
                try
                {
                    var cert = X509Certificate.CreateFromSignedFile(filePath);
                    if (cert != null)
                    {
                        var cert2 = new X509Certificate2(cert);
                        var chain = new X509Chain();
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        valid = chain.Build(cert2);

                        if (!valid)
                        {
                            WriteLog($"Certificate chain validation failed for {filePath}: {string.Join(", ", chain.ChainStatus.Select(s => s.Status))}");
                        }
                    }
                    else
                    {
                        WriteLog($"No valid certificate found for {filePath}");
                    }
                }
                catch (CryptographicException cryptoEx)
                {
                    WriteLog($"Cryptographic error validating signature for {filePath}: {cryptoEx.Message}");
                    valid = false;
                }

                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                string hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLower();

                WriteLog($"Signature for {filePath}: {(valid ? "Valid" : "Invalid")} (AGGRESSIVE MODE)");
                return (hash, valid);
            }
            catch (IOException ioEx)
            {
                WriteLog($"[Attempt {attempt + 1}] IO Error reading {filePath}: {ioEx.Message}");
                Thread.Sleep(500);
            }
            catch (Exception ex)
            {
                WriteLog($"[Attempt {attempt + 1}] Error hashing {filePath}: {ex.Message}");
                Thread.Sleep(500);
            }
        }

        WriteLog($"Failed to hash or validate signature for {filePath} after multiple attempts.");
        return null;
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
                                    parent.Kill();
                                    parent.WaitForExit(2000);
                                }
                            }
                            catch (Exception ex)
                            {
                                WriteLog($"Error getting parent process: {ex.Message}");
                            }

                            process.Kill();
                            process.WaitForExit(2000);
                            break;
                        }
                    }
                }
                catch { }
            }

            if (File.Exists(filePath))
            {
                TakeFileOwnership(filePath);
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
            using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Process WHERE ProcessId = " + process.Id))
            {
                foreach (var obj in searcher.Get())
                {
                    int parentPid = Convert.ToInt32(obj["ParentProcessId"]);
                    return Process.GetProcessById(parentPid);
                }
            }
        }
        catch { }
        return null;
    }

    static void TakeFileOwnership(string filePath)
    {
        try
        {
            Process.Start(new ProcessStartInfo("cmd.exe", $"/c takeown /f \"{filePath}\" && icacls \"{filePath}\" /grant Administrators:F")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            }).WaitForExit();
        }
        catch (Exception ex)
        {
            WriteLog($"Failed to take ownership of {filePath}: {ex.Message}");
        }
    }

    static void QuarantineFile(string filePath)
    {
        try
        {
            string dest = Path.Combine(quarantineFolder, Path.GetFileName(filePath));
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    File.Move(filePath, dest);
                    WriteLog($"Quarantined {filePath} to {dest}");
                    return;
                }
                catch (IOException ex)
                {
                    WriteLog($"[Attempt {attempt + 1}] Failed to move {filePath} to quarantine: {ex.Message}");
                    Thread.Sleep(1000);
                    if (attempt == 2)
                    {
                        TakeFileOwnership(filePath);
                        try
                        {
                            File.Move(filePath, dest);
                            WriteLog($"Quarantined {filePath} to {dest} after taking ownership");
                            return;
                        }
                        catch
                        {
                            if (ScheduleFileDeletionOnReboot(filePath))
                            {
                                WriteLog($"Scheduled {filePath} for deletion on reboot");
                            }
                            else
                            {
                                WriteLog($"Failed to schedule {filePath} for deletion on reboot");
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            WriteLog($"Failed to quarantine {filePath} after retries: {ex.Message}");
            if (ScheduleFileDeletionOnReboot(filePath))
            {
                WriteLog($"Scheduled {filePath} for deletion on reboot as final fallback");
            }
            else
            {
                WriteLog($"Failed to schedule {filePath} for deletion on reboot as final fallback");
            }
        }
    }

    static bool ScheduleFileDeletionOnReboot(string filePath)
    {
        try
        {
            bool success = MoveFileEx(filePath, null, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT);
            if (!success)
            {
                int error = Marshal.GetLastWin32Error();
                WriteLog($"MoveFileEx failed for {filePath} with error code {error}");
            }
            return success;
        }
        catch (Exception ex)
        {
            WriteLog($"Exception while scheduling {filePath} for reboot deletion: {ex.Message}");
            return false;
        }
    }

    static void WriteLog(string message)
    {
        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        string entry = $"[{timestamp}] {message}";
        Console.WriteLine(entry);
        try
        {
            File.AppendAllText(logFile, entry + Environment.NewLine);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to write to log: {ex.Message}");
        }
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
                return;
        }

        var createTask = new ProcessStartInfo
        {
            FileName = "schtasks",
            Arguments = $"/Create /TN \"{taskName}\" /TR \"\"{exePath}\"\" /SC ONSTART /RU SYSTEM /RL HIGHEST /F",
            UseShellExecute = false,
            CreateNoWindow = true
        };

        Process.Start(createTask)?.WaitForExit();
    }
}
