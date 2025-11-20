using System;
using System.IO;
using System.Management.Automation.Runspaces;

namespace Granfeldt
{
    public sealed class PSEngine : PSEngineBase
    {
        public string PwshPath { get; }
        PowerShellEngineVersion powerShellVersion = PowerShellEngineVersion.WindowsPowerShell51;

        public PSEngine(string pwshPath = @"C:\Program Files\PowerShell\7\pwsh.exe", PowerShellEngineVersion powerShellEngine = PowerShellEngineVersion.WindowsPowerShell51)
        {
            PwshPath = pwshPath;
            powerShellVersion = powerShellEngine;
        }

        protected override (Runspace runspace, PowerShellProcessInstance proc) CreateAndOpenRunspace()
        {
            //var smaAsm = typeof(System.Management.Automation.PowerShell).Assembly;
            //Tracer.TraceInformation("Host SMA: {0} @ {1}", smaAsm.GetName().Version, smaAsm.Location);
            //Tracer.TraceInformation("Host bitness: {0}-bit  OS: {1}", Environment.Is64BitProcess ? "64" : "32", Environment.OSVersion);

            Tracer.TraceInformation("powershell-engine-configured: {0}", powerShellVersion.ToString());
            var pspi = new PowerShellProcessInstance();

            Warning += w => Tracer.TraceWarning("WARNING: {0}", -1, w);
            Error += w => Tracer.TraceError("ERROR: {0}", w);
            Verbose += w => Tracer.TraceInformation("VERBOSE: {0}", w);
            Progress += p => Tracer.TraceInformation("PROGRESS: {0}", p);
            Debug += d => Tracer.TraceInformation("DEBUG: {0}", d);

            var si = pspi.Process.StartInfo;

            if (powerShellVersion == PowerShellEngineVersion.PowerShell7)
            {
                if (!File.Exists(PwshPath)) throw new FileNotFoundException($"pwsh/powershell not found: {PwshPath}");
                si.FileName = PwshPath;
                si.Arguments = "-s -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass";
            }

            si.UseShellExecute = false;
            si.RedirectStandardOutput = true;
            si.RedirectStandardError = true;
            si.CreateNoWindow = true;
            si.LoadUserProfile = true;
            //si.WorkingDirectory = string.IsNullOrEmpty(PwshPath) ? @"C:\Windows\System32" : Path.GetDirectoryName(PwshPath);

            // Credentials
            if (ShouldImpersonate())
            {
                si.Domain = string.IsNullOrWhiteSpace(Domain) ? "." : Domain;
                si.UserName = Username;
                si.Password = SecurePassword;
                Tracer.TraceInformation($"Impersonation: Domain='{si.Domain ?? "empty"}', UserName='{si.UserName ?? "(empty)"}', Password={(si.Password == null ? "(empty)" : "***")}");

                // could be simplified since we already handled missing domain in si.Domain above
                // note that if using a local account for impersonation, Domain must be computername and not "."
                var acct = Domain + "\\" + Username;

                // give that account access to Session 0 window station & desktop
                WinStaDesktopAcl.GrantTo(acct);
            }

            // SHOULD WE DO A WHOAMI (from old impersonation) HERE TO LOG THE CONTEXT WE ARE RUNNING AS?

            Tracer.TraceInformation("powershell-executable: '{0}' (exists={1})", si.FileName, File.Exists(si.FileName));
            Tracer.TraceInformation("powershell-args: {0}", si.Arguments);
            Tracer.TraceInformation("powershell-working-directory: '{0}' (exists={1})", si.WorkingDirectory, Directory.Exists(si.WorkingDirectory));
            Tracer.TraceInformation("powershell-environment: systemroot='{0}', windir='{1}', comspec='{2}', path(empty)={3}",
                si.EnvironmentVariables["SystemRoot"], si.EnvironmentVariables["WINDIR"],
                si.EnvironmentVariables["ComSpec"], string.IsNullOrEmpty(si.EnvironmentVariables["Path"]));

            Tracer.TraceInformation("powershell-environment: temp='{0}', tmp='{1}', userprofile='{2}', homedrive='{3}', homepath='{4}'",
                si.EnvironmentVariables["TEMP"], si.EnvironmentVariables["TMP"],
                si.EnvironmentVariables["USERPROFILE"], si.EnvironmentVariables["HOMEDRIVE"], si.EnvironmentVariables["HOMEPATH"]);

            pspi.Process.Exited += (s, e) =>
            {
                try { Tracer.TraceError("pwsh exited. HasExited={0}, ExitCode={1:X8}", pspi.Process.HasExited, pspi.Process.ExitCode); }
                catch { }
            };

            var runspace = RunspaceFactory.CreateOutOfProcessRunspace(new TypeTable(new string[0]), pspi);

            try
            {
                runspace.Open();
                return (runspace, pspi);
            }
            catch (Exception ex)
            {
                bool hasExited = false; int exitCode = 0;
                try { hasExited = pspi.Process.HasExited; exitCode = pspi.Process.ExitCode; } catch { }

                Tracer.TraceError("powershell-runspace-open failed. hasexited={0}, exitcode=0x{1:X8}", hasExited, exitCode);
                Tracer.TraceError("exception: {0}", ex);
                throw;
            }
        }

    }
}
