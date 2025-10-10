using System;
using System.IO;

namespace Granfeldt
{
    /// <summary>
    /// Factory class for creating PowerShell engine instances
    /// </summary>
    public static class PowerShellEngineFactory
    {
        /// <summary>
        /// Creates a PowerShell engine based on the specified version and configuration
        /// </summary>
        /// <param name="powerShellVersion">The PowerShell version to use</param>
        /// <param name="powerShell7ExecutablePath">Path to PowerShell 7+ executable (required if using PowerShell 7+)</param>
        /// <returns>IPowerShellEngine instance</returns>
        public static IPowerShellEngine CreateEngine(string powerShellVersion, string powerShell7ExecutablePath = null)
        {
            Tracer.TraceInformation("creating-powershell-engine version: '{0}'", powerShellVersion);
            
            switch (powerShellVersion?.Trim())
            {
                case "PowerShell 7":
                case "PowerShell 7 Plus":  // Legacy support
                case "PowerShell 7+":      // Legacy support
                    Tracer.TraceInformation("creating-powershell7-engine");
                    ValidatePowerShell7Path(powerShell7ExecutablePath);
                    return new PowerShell7Engine(powerShell7ExecutablePath);
                
                case "Windows PowerShell 5.1":
                case null:
                case "":
                default:
                    Tracer.TraceInformation("creating-windows-powershell-engine");
                    return new WindowsPowerShellEngine();
            }
        }

        /// <summary>
        /// Validates the PowerShell 7+ executable path
        /// </summary>
        /// <param name="powerShell7ExecutablePath">Path to validate</param>
        private static void ValidatePowerShell7Path(string powerShell7ExecutablePath)
        {
            if (string.IsNullOrEmpty(powerShell7ExecutablePath))
            {
                throw new ArgumentException("PowerShell 7+ executable path is required when using PowerShell 7+");
            }

            if (!File.Exists(powerShell7ExecutablePath))
            {
                throw new FileNotFoundException($"PowerShell 7+ executable not found at: {powerShell7ExecutablePath}");
            }

            Tracer.TraceInformation("validated-powershell7-executable-path: '{0}'", powerShell7ExecutablePath);
        }

        /// <summary>
        /// Auto-detects available PowerShell versions on the system
        /// </summary>
        /// <returns>Array of available PowerShell version strings</returns>
        public static string[] DetectAvailablePowerShellVersions()
        {
            var availableVersions = new System.Collections.Generic.List<string>();
            
            // Windows PowerShell 5.1 is always available on Windows
            availableVersions.Add("Windows PowerShell 5.1");
            
            // Check for PowerShell 7+ installations
            string[] possiblePaths = {
                @"C:\Program Files\PowerShell\7\pwsh.exe",
                @"C:\Program Files\PowerShell\6\pwsh.exe",
                @"C:\Users\" + Environment.UserName + @"\AppData\Local\Microsoft\powershell\pwsh.exe"
            };

            foreach (string path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    availableVersions.Add("PowerShell 7+");
                    Tracer.TraceInformation("detected-powershell7-at-path: '{0}'", path);
                    break; // Only need to find one
                }
            }

            Tracer.TraceInformation("detected-powershell-versions: {0}", string.Join(", ", availableVersions));
            return availableVersions.ToArray();
        }

        /// <summary>
        /// Gets the default PowerShell 7+ installation path
        /// </summary>
        /// <returns>Path to PowerShell 7+ executable, or null if not found</returns>
        public static string GetDefaultPowerShell7Path()
        {
            string[] possiblePaths = {
                @"C:\Program Files\PowerShell\7\pwsh.exe",
                @"C:\Program Files\PowerShell\6\pwsh.exe",
                @"C:\Users\" + Environment.UserName + @"\AppData\Local\Microsoft\powershell\pwsh.exe"
            };

            foreach (string path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    Tracer.TraceInformation("found-default-powershell7-path: '{0}'", path);
                    return path;
                }
            }

            Tracer.TraceInformation("no-default-powershell7-path-found");
            return null;
        }
    }
}
