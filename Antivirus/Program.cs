using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Net.Http;
using System.Text.Json;
using System.Security.Principal;
using System.Security.AccessControl;
using Microsoft.Data.Sqlite;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace SimpleAntivirus
{
    [ComVisible(true)]
    public class Antivirus
    {
        private const string VirusTotalApiKey = "2725fb8657925117fedbebd856b450fd0d0d53678eae2d318e19d7946f7086c9"; // Replace with your actual VirusTotal API key
        private readonly string _dbPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SimpleAntivirus", "scans.db");
        private readonly string _quarantinePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SimpleAntivirus", "Quarantine");
        private readonly HashSet<string> _whitelistedDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HttpClient _httpClient = new HttpClient();
        private readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();

        public Antivirus()
        {
            VerifyAdminPrivileges();
            InitializeDirectories();
            InitializeDatabase();
            InitializeWhitelist();
            InitializeFileSystemWatchers();
        }

        private void VerifyAdminPrivileges()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                throw new UnauthorizedAccessException("SimpleAntivirus requires administrative privileges to run.");
        }

        private void InitializeDirectories()
        {
            string? dbDir = Path.GetDirectoryName(_dbPath);
            if (!string.IsNullOrEmpty(dbDir))
                Directory.CreateDirectory(dbDir);
            Directory.CreateDirectory(_quarantinePath);
        }

        private void InitializeDatabase()
        {
            using var connection = new SqliteConnection($"Data Source={_dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = @"
                CREATE TABLE IF NOT EXISTS ScannedFiles (
                    FileHash TEXT PRIMARY KEY,
                    ScanResult TEXT,
                    ScanDate TEXT
                )";
            command.ExecuteNonQuery();
        }

        private void InitializeWhitelist()
        {
            var systemDlls = new[]
            {
                "kernel32.dll", "user32.dll", "ntdll.dll", "advapi32.dll",
                "chrome.dll", "firefox.dll", "edgehtml.dll",
                "steam_api.dll", "d3d11.dll", "dxgi.dll",
                "nvapi64.dll", "amdxn64.dll"
            };
            foreach (var dll in systemDlls)
                _whitelistedDlls.Add(dll);

            var selfDll = Path.GetFileName(Assembly.GetExecutingAssembly().Location);
            _whitelistedDlls.Add(selfDll);
        }

        private void InitializeFileSystemWatchers()
        {
            foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady))
            {
                var watcher = new FileSystemWatcher
                {
                    Path = drive.RootDirectory.FullName,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite,
                    Filter = "*.*",
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true
                };
                watcher.Created += async (s, e) => await OnFileCreated(e.FullPath);
                watcher.Changed += async (s, e) => await OnFileCreated(e.FullPath);
                _watchers.Add(watcher);
            }
        }

        private async Task OnFileCreated(string filePath)
        {
            try
            {
                if (!File.Exists(filePath) || !IsFileAccessible(filePath)) return;

                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) && !IsWhitelisted(fileInfo.Name))
                {
                    if (!IsSigned(filePath))
                    {
                        await QuarantineFile(filePath, "Unsigned DLL");
                        return;
                    }
                }

                var fileHash = await ComputeFileHash(filePath);
                if (await IsFileScanned(fileHash))
                {
                    var scanResult = await GetScanResult(fileHash);
                    if (scanResult == "Malicious")
                        await QuarantineFile(filePath, "Previously flagged as malicious");
                    return;
                }

                var vtResult = await ScanWithVirusTotal(filePath, fileHash);
                await StoreScanResult(fileHash, vtResult);

                if (vtResult == "Malicious")
                    await QuarantineFile(filePath, "Flagged as malicious by VirusTotal");
            }
            catch (Exception ex)
            {
                LogError($"Error processing file {filePath}: {ex.Message}");
            }
        }

        private bool IsFileAccessible(string filePath)
        {
            try
            {
                using (File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    return true;
            }
            catch
            {
                return false;
            }
        }

        private bool IsWhitelisted(string fileName)
        {
            return _whitelistedDlls.Contains(fileName);
        }

        private bool IsSigned(string filePath)
        {
            try
            {
                var bytes = File.ReadAllBytes(filePath);
                var cert = X509Certificate.CreateFromSignedFile(filePath);
                return cert != null;
            }
            catch
            {
                return false;
            }
        }

        private async Task<string> ComputeFileHash(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = await Task.Run(() => sha256.ComputeHash(stream));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        private async Task<bool> IsFileScanned(string fileHash)
        {
            using var connection = new SqliteConnection($"Data Source={_dbPath}");
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM ScannedFiles WHERE FileHash = $hash";
            command.Parameters.AddWithValue("$hash", fileHash);
            var count = (long?)await command.ExecuteScalarAsync();
            return count > 0;
        }

        private async Task<string?> GetScanResult(string fileHash)
        {
            using var connection = new SqliteConnection($"Data Source={_dbPath}");
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT ScanResult FROM ScannedFiles WHERE FileHash = $hash";
            command.Parameters.AddWithValue("$hash", fileHash);
            var result = await command.ExecuteScalarAsync();
            return result?.ToString();
        }

        private async Task StoreScanResult(string fileHash, string result)
        {
            using var connection = new SqliteConnection($"Data Source={_dbPath}");
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT OR REPLACE INTO ScannedFiles (FileHash, ScanResult, ScanDate)
                VALUES ($hash, $result, $date)";
            command.Parameters.AddWithValue("$hash", fileHash);
            command.Parameters.AddWithValue("$result", result);
            command.Parameters.AddWithValue("$date", DateTime.UtcNow.ToString("o"));
            await command.ExecuteNonQueryAsync();
        }

        private async Task<string> ScanWithVirusTotal(string filePath, string fileHash)
        {
            try
            {
                var url = $"https://www.virustotal.com/api/v3/files/{fileHash}";
                _httpClient.DefaultRequestHeaders.Add("x-apikey", VirusTotalApiKey);
                var response = await _httpClient.GetAsync(url);
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    using var vtResult = JsonDocument.Parse(json);
                    var root = vtResult.RootElement;
                    if (root.TryGetProperty("data", out var data) &&
                        data.TryGetProperty("attributes", out var attributes) &&
                        attributes.TryGetProperty("last_analysis_stats", out var stats) &&
                        stats.TryGetProperty("malicious", out var malicious))
                    {
                        return malicious.GetInt32() > 0 ? "Malicious" : "Clean";
                    }
                }

                using var form = new MultipartFormDataContent();
                byte[] fileBytes;
                using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 4096, useAsync: true))
                {
                    fileBytes = new byte[stream.Length];
                    await stream.ReadAsync(fileBytes, 0, fileBytes.Length);
                }
                var fileContent = new ByteArrayContent(fileBytes);
                form.Add(fileContent, "file", Path.GetFileName(filePath));
                response = await _httpClient.PostAsync("https://www.virustotal.com/api/v3/files", form);
                if (!response.IsSuccessStatusCode)
                {
                    LogError($"VirusTotal upload failed for {filePath}: {response.StatusCode}");
                    return "Unknown";
                }

                var uploadJson = await response.Content.ReadAsStringAsync();
                using var uploadResult = JsonDocument.Parse(uploadJson);
                var analysisId = uploadResult.RootElement.GetProperty("data").GetProperty("id").GetString();

                for (int i = 0; i < 10; i++)
                {
                    await Task.Delay(30000);
                    response = await _httpClient.GetAsync($"https://www.virustotal.com/api/v3/analyses/{analysisId}");
                    if (response.IsSuccessStatusCode)
                    {
                        var analysisJson = await response.Content.ReadAsStringAsync();
                        using var analysisResult = JsonDocument.Parse(analysisJson);
                        var root = analysisResult.RootElement;
                        if (root.TryGetProperty("data", out var data) &&
                            data.TryGetProperty("attributes", out var attributes) &&
                            attributes.TryGetProperty("status", out var status) &&
                            status.GetString() == "completed" &&
                            attributes.TryGetProperty("stats", out var stats) &&
                            stats.TryGetProperty("malicious", out var malicious))
                        {
                            return malicious.GetInt32() > 0 ? "Malicious" : "Clean";
                        }
                    }
                }

                return "Unknown";
            }
            catch (Exception ex)
            {
                LogError($"VirusTotal scan failed for {filePath}: {ex.Message}");
                return "Unknown";
            }
            finally
            {
                _httpClient.DefaultRequestHeaders.Remove("x-apikey");
            }
        }

        private async Task QuarantineFile(string filePath, string reason)
        {
            try
            {
                await KillProcessesUsingFile(filePath);
                await TakeOwnership(filePath);
                await RemoveInheritedPermissions(filePath);

                var quarantineFile = Path.Combine(_quarantinePath, $"{Path.GetFileName(filePath)}_{DateTime.UtcNow:yyyyMMddHHmmss}.zip");
                using (var zip = new ZipArchive(File.Create(quarantineFile), ZipArchiveMode.Create))
                {
                    var entry = zip.CreateEntry(Path.GetFileName(filePath));
                    using var entryStream = entry.Open();
                    using var fileStream = File.OpenRead(filePath);
                    await fileStream.CopyToAsync(entryStream);
                }

                File.Delete(filePath);
                LogQuarantine(filePath, quarantineFile, reason);
            }
            catch (Exception ex)
            {
                LogError($"Failed to quarantine {filePath}: {ex.Message}");
            }
        }

        private async Task KillProcessesUsingFile(string filePath)
        {
            var processes = Process.GetProcesses();
            foreach (var process in processes)
            {
                try
                {
                    if (process.MainModule?.FileName.Equals(filePath, StringComparison.OrdinalIgnoreCase) == true)
                    {
                        process.Kill();
                        await Task.Run(() => process.WaitForExit(5000));
                    }
                }
                catch { }
            }

            if (filePath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                await Task.Run(() => FreeLibrary(filePath));

            foreach (var process in Process.GetProcessesByName("explorer"))
            {
                try
                {
                    process.Kill();
                    await Task.Run(() => process.WaitForExit(5000));
                }
                catch { }
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        private static void FreeLibrary(string filePath)
        {
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    foreach (ProcessModule module in process.Modules)
                    {
                        if (module.FileName.Equals(filePath, StringComparison.OrdinalIgnoreCase))
                            FreeLibrary(module.BaseAddress);
                    }
                }
                catch { }
            }
        }

        private async Task TakeOwnership(string filePath)
        {
            await Task.Run(() =>
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "takeown",
                    Arguments = $"/F \"{filePath}\" /A",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var proc = Process.Start(psi);
                proc?.WaitForExit();
            });
        }

        private async Task RemoveInheritedPermissions(string filePath)
        {
            await Task.Run(() =>
            {
                var fileInfo = new FileInfo(filePath);
                var security = fileInfo.GetAccessControl();
                security.SetAccessRuleProtection(true, false);
                fileInfo.SetAccessControl(security);

                var identity = new NTAccount("Administrators");
                var rule = new FileSystemAccessRule(identity, FileSystemRights.FullControl, AccessControlType.Allow);
                security.AddAccessRule(rule);
                fileInfo.SetAccessControl(security);
            });
        }

        private void LogError(string message)
        {
            File.AppendAllText(Path.Combine(_quarantinePath, "error.log"), $"{DateTime.UtcNow:o}: {message}\n");
        }

        private void LogQuarantine(string filePath, string quarantineFile, string reason)
        {
            File.AppendAllText(Path.Combine(_quarantinePath, "quarantine.log"), $"{DateTime.UtcNow:o}: Quarantined {filePath} to {quarantineFile}. Reason: {reason}\n");
        }

        public void StartMonitoring()
        {
            foreach (var watcher in _watchers)
                watcher.EnableRaisingEvents = true;
        }

        public void StopMonitoring()
        {
            foreach (var watcher in _watchers)
                watcher.EnableRaisingEvents = false;
        }

        public void Dispose()
        {
            _httpClient.Dispose();
            foreach (var watcher in _watchers)
                watcher.Dispose();
        }
    }
}