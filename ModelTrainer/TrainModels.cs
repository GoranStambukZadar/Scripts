using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Microsoft.ML;
using Serilog;
using Antivirus;

namespace ModelTrainer
{
    class Program
    {
        static void Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Information()
                .WriteTo.Console()
                .WriteTo.File("logs/model_training.log", rollingInterval: RollingInterval.Day)
                .CreateLogger();

            try
                {
                    var mlContext = new MLContext(seed: 42);
                    string baseDir = AppDomain.CurrentDomain.BaseDirectory;

                    // Train PE Model
                    string peDatasetPath = Path.Combine(baseDir, "Data", "MalwareDataSet.csv.zip");
                    string peModelPath = Path.Combine(baseDir, "pe_model.zip");

                    if (!File.Exists(peDatasetPath))
                    {
                        Log.Error("PE dataset file missing at {Path}", peDatasetPath);
                        return;
                    }

                    string decompressedPEDataset = DecompressDataset(peDatasetPath);
                    Log.Information("Training PE model with neural network...");
                    MalwareModel.TrainPEModel(mlContext, decompressedPEDataset, peModelPath);
                    File.Delete(decompressedPEDataset);

                    // Train URL Model
                    string urlDatasetPath = Path.Combine(baseDir, "Data", "URLDataSet.csv.zip");
                    string urlModelPath = Path.Combine(baseDir, "url_model.zip");

                    if (!File.Exists(urlDatasetPath))
                    {
                        Log.Error("URL dataset file missing at {Path}", urlDatasetPath);
                        return;
                    }

                    string decompressedURLDataset = DecompressDataset(urlDatasetPath);
                    Log.Information("Training URL model with neural network...");
                    MalwareModel.TrainURLModel(mlContext, decompressedURLDataset, urlModelPath);
                    File.Delete(decompressedURLDataset);

                    Log.Information("Model training completed successfully.");
                    Console.WriteLine($"Models saved to: {peModelPath}, {urlModelPath}");
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error during model training");
                }
                finally
                {
                    Log.CloseAndFlush();
                }
        }

        private static string DecompressDataset(string compressedPath)
        {
            try
            {
                var tempPath = Path.GetTempFileName();
                using (var zipFile = ZipFile.OpenRead(compressedPath))
                {
                    var entry = zipFile.Entries.FirstOrDefault(e => e.FullName.EndsWith(".csv", StringComparison.OrdinalIgnoreCase));
                    if (entry == null)
                    {
                        throw new InvalidOperationException("No CSV file found in the zip archive");
                    }
                    using (var stream = entry.Open())
                    using (var output = File.Create(tempPath))
                    {
                        stream.CopyTo(output);
                    }
                }
                return tempPath;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to decompress dataset: {Path}", compressedPath);
                throw;
            }
        }
    }
}