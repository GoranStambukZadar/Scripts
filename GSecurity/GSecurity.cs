using System;
using System.IO;
using System.Security.Cryptography; // Already present for SHA256
using System.Security.Cryptography.X509Certificates; // Added for X509Certificate
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using System.Threading;
using System.Net.NetworkInformation;

namespace GSecurity
{
    public class SecurityService
    {
        private List<FileSystemWatcher> _fileWatchers = new();
        private Dictionary<string, string>? _scannedFiles;
        private const string VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE";
        private const string DB_PATH = @"C:\ProgramData\SilentSecurity\scanned.db";
        private const string LOG_PATH = @"C:\ProgramData\SilentSecurity\service.log";
        private volatile bool _running = true;
        private bool _useNetwork;

        public SecurityService()
        {
            _useNetwork = CheckNetwork();
            Log("Application constructed");
        }

        private void Log(string message)
        {
            try
            {
                string? dir = Path.GetDirectoryName(LOG_PATH);
                if (dir != null) Directory.CreateDirectory(dir);
                File.AppendAllText(LOG_PATH, $"{DateTime.Now}: {message}\n");
            }
            catch { }
        }

        public void Start()
        {
            Log("Start called");
            try
            {
                _scannedFiles = LoadScannedFiles();

                Thread monitorThread = new Thread(() =>
                {
                    while (_running)
                    {
                        UpdateMonitoring();
                        Thread.Sleep(300000); // Check every 5 minutes
                    }
                });
                monitorThread.Start();

                Thread scanThread = new Thread(() =>
                {
                    while (_running)
                    {
                        ScanSystem();
                        Thread.Sleep(60000); // Scan every minute
                    }
                });
                scanThread.Start();

                Log("Monitoring and scanning threads started");
            }
            catch (Exception ex)
            {
                Log($"Startup failed: {ex.Message}");
            }

            Thread.Sleep(Timeout.Infinite);
        }

        private void UpdateMonitoring()
        {
            try
            {
                _useNetwork = CheckNetwork();
                Log($"Network status updated: {_useNetwork}");

                foreach (var watcher in _fileWatchers) watcher.Dispose();
                _fileWatchers.Clear();
                var drives = GetAvailableDrives();
                foreach (var drive in drives)
                {
                    var watcher = new FileSystemWatcher(drive, "*.dll")
                    {
                        EnableRaisingEvents = true,
                        IncludeSubdirectories = true
                    };
                    watcher.Created += CheckDLL;
                    _fileWatchers.Add(watcher);
                    Log($"Monitoring drive: {drive}");
                }
                if (drives.Count == 0)
                {
                    Log("No drives available to monitor");
                }
            }
            catch (Exception ex)
            {
                Log($"Error updating monitoring: {ex.Message}");
            }
        }

        private List<string> GetAvailableDrives()
        {
            var drives = new List<string>();
            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                    {
                        drives.Add(drive.Name);
                        Log($"Drive available: {drive.Name}");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Error getting drives: {ex.Message}");
            }
            return drives;
        }

        private bool CheckNetwork()
        {
            try
            {
                using (var ping = new Ping())
                {
                    var reply = ping.Send("8.8.8.8", 2000);
                    return reply?.Status == IPStatus.Success;
                }
            }
            catch (Exception ex)
            {
                Log($"Network check failed: {ex.Message}");
                return false;
            }
        }

        public void Stop()
        {
            _running = false;
            foreach (var watcher in _fileWatchers) watcher.Dispose();
            _fileWatchers.Clear();
            Log("Application stopped");
        }

        private void CheckDLL(object sender, FileSystemEventArgs e)
        {
            try
            {
                Log($"Checking DLL: {e.FullPath}");
                if (!IsFileSigned(e.FullPath))
                {
                    File.Delete(e.FullPath);
                    Log($"Deleted unsigned DLL: {e.FullPath}");
                }
            }
            catch (Exception ex)
            {
                Log($"Error in CheckDLL: {ex.Message}");
            }
        }

        private bool IsFileSigned(string filePath)
        {
            try
            {
                var fileInfo = new X509Certificate(filePath); // Now recognized with using directive
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void ScanSystem()
        {
            Log("ScanSystem started");
            try
            {
                var drives = GetAvailableDrives();
                foreach (var drive in drives)
                {
                    foreach (string file in Directory.EnumerateFiles(drive, "*.*", SearchOption.AllDirectories))
                    {
                        try
                        {
                            string hash = GetFileHash(file);
                            if (_scannedFiles?.ContainsKey(hash) != true)
                            {
                                Log($"Scanning new file: {file}");
                                ScanWithVirusTotal(file, hash);
                            }
                        }
                        catch (Exception ex)
                        {
                            Log($"Error scanning {file}: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Error enumerating drives: {ex.Message}");
            }
        }

        private string GetFileHash(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                {
                    using (var stream = File.OpenRead(filePath))
                    {
                        byte[] hash = sha256.ComputeHash(stream);
                        return BitConverter.ToString(hash).Replace("-", "").ToLower();
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Error hashing {filePath}: {ex.Message}");
                throw;
            }
        }

        private async void ScanWithVirusTotal(string filePath, string hash)
        {
            if (!_useNetwork)
            {
                Log($"Network unavailable, skipping VT scan for {filePath}");
                if (!IsFileSigned(filePath))
                {
                    File.Delete(filePath);
                    Log($"Deleted {filePath} due to no network and unsigned");
                }
                return;
            }

            try
            {
                Log($"VirusTotal scan started for {filePath}");
                using (var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) })
                {
                    client.DefaultRequestHeaders.Add("x-apikey", VT_API_KEY);
                    var response = await client.GetAsync($"https://www.virustotal.com/api/v3/files/{hash}");
                    if (response.IsSuccessStatusCode)
                    {
                        var result = JsonSerializer.Deserialize<VTResponse>(await response.Content.ReadAsStringAsync(), VTJsonContext.Default.VTResponse);
                        if (result != null)
                        {
                            HandleVTResult(filePath, hash, result);
                            Log($"VT scan completed for {filePath}");
                        }
                    }
                    else
                    {
                        var form = new MultipartFormDataContent();
                        form.Add(new ByteArrayContent(File.ReadAllBytes(filePath)), "file", Path.GetFileName(filePath));
                        response = await client.PostAsync("https://www.virustotal.com/api/v3/files", form);
                        var analysis = JsonSerializer.Deserialize<VTResponse>(await response.Content.ReadAsStringAsync(), VTJsonContext.Default.VTResponse);
                        if (analysis != null)
                        {
                            HandleVTResult(filePath, hash, analysis);
                            Log($"VT upload and scan completed for {filePath}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"VT scan failed for {filePath}: {ex.Message}");
                if (!IsFileSigned(filePath))
                {
                    File.Delete(filePath);
                    Log($"Deleted {filePath} due to VT failure and unsigned");
                }
            }
        }

        private void HandleVTResult(string filePath, string hash, VTResponse result)
        {
            try
            {
                if (result.data?.attributes?.last_analysis_stats?.malicious > 0)
                {
                    File.Delete(filePath);
                    if (_scannedFiles != null) _scannedFiles[hash] = "malicious";
                    Log($"Deleted malicious file: {filePath}");
                }
                else
                {
                    if (_scannedFiles != null) _scannedFiles[hash] = "clean";
                    Log($"File marked clean: {filePath}");
                }
                SaveScannedFiles();
            }
            catch (Exception ex)
            {
                Log($"Error handling VT result for {filePath}: {ex.Message}");
            }
        }

        private Dictionary<string, string>? LoadScannedFiles()
        {
            try
            {
                if (File.Exists(DB_PATH))
                {
                    string json = File.ReadAllText(DB_PATH);
                    return JsonSerializer.Deserialize<Dictionary<string, string>>(json, VTJsonContext.Default.DictionaryStringString);
                }
            }
            catch (Exception ex)
            {
                Log($"Error loading scanned files: {ex.Message}");
            }
            return new Dictionary<string, string>();
        }

        private void SaveScannedFiles()
        {
            try
            {
                if (_scannedFiles == null) return;
                string? dir = Path.GetDirectoryName(DB_PATH);
                if (dir != null) Directory.CreateDirectory(dir);
                string json = JsonSerializer.Serialize(_scannedFiles, VTJsonContext.Default.DictionaryStringString);
                File.WriteAllText(DB_PATH, json);
            }
            catch (Exception ex)
            {
                Log($"Error saving scanned files: {ex.Message}");
            }
        }
    }

    [JsonSourceGenerationOptions(WriteIndented = true)]
    [JsonSerializable(typeof(VTResponse))]
    [JsonSerializable(typeof(Dictionary<string, string>))]
    public partial class VTJsonContext : JsonSerializerContext { }

    public class VTResponse
    {
        public VTData? data { get; set; }
    }

    public class VTData
    {
        public VTAttributes? attributes { get; set; }
    }

    public class VTAttributes
    {
        public VTStats? last_analysis_stats { get; set; }
    }

    public class VTStats
    {
        public int malicious { get; set; }
    }

    static class Program
    {
        static void Main(string[] args)
        {
            var service = new SecurityService();
            AppDomain.CurrentDomain.ProcessExit += (s, e) => service.Stop();
            Console.CancelKeyPress += (s, e) => service.Stop();
            service.Start();
        }
    }
}