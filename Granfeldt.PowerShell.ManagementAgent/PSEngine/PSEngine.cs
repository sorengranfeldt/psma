using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Granfeldt
{
    public sealed class PSEngine : PSEngineBase
    {
        public string PwshPath { get; }
        public string ExtraArgs { get; }
        public bool UsePowerShell7 { get; }

        public PSEngine(string pwshPath = @"C:\Program Files\PowerShell\7\pwsh.exe", bool usePS7 = false, string extraArgs = null)
        {
            PwshPath = pwshPath;
            ExtraArgs = extraArgs;
            UsePowerShell7 = usePS7;
        }

        protected override (Runspace runspace, PowerShellProcessInstance proc) CreateAndOpenRunspace()
        {
            var smaAsm = typeof(System.Management.Automation.PowerShell).Assembly;
            Tracer.TraceInformation("Host SMA: {0} @ {1}", smaAsm.GetName().Version, smaAsm.Location);
            Tracer.TraceInformation("Host bitness: {0}-bit  OS: {1}", Environment.Is64BitProcess ? "64" : "32", Environment.OSVersion);

            if (UsePowerShell7 && !System.IO.File.Exists(PwshPath))
                throw new FileNotFoundException("pwsh/powershell not found: " + PwshPath);

            Tracer.TraceInformation("USING-PS7: {0}", UsePowerShell7);

            var pspi = new PowerShellProcessInstance();

            Warning += w => Tracer.TraceInformation("WARNING: {0}", w);
            Error += w => Tracer.TraceError("ERROR: {0}", w);
            Verbose += w => Tracer.TraceInformation("INFO: {0}", w);

            var si = pspi.Process.StartInfo;

            if (UsePowerShell7)
            {
                si.FileName = PwshPath;
                si.Arguments = "-s -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass" + (string.IsNullOrWhiteSpace(ExtraArgs) ? "" : " " + ExtraArgs);
            }

            si.UseShellExecute = false;
            si.RedirectStandardOutput = true;
            si.RedirectStandardError = true;
            si.CreateNoWindow = true;
            si.LoadUserProfile = true;
            si.WorkingDirectory = Path.GetDirectoryName(PwshPath) ?? @"C:\Windows\System32";

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

                // Give that account access to Session 0 window station & desktop
                WinStaDesktopAcl.GrantTo(acct);

                // IMPORTANT: Don't inherit the service env; rebuild a minimal MACHINE env
                //var ev = si.EnvironmentVariables;
                //ev.Clear(); // stop inheriting service account's env

                //// Re-seed essentials from MACHINE scope
                //string sysRoot = Environment.GetEnvironmentVariable("SystemRoot", EnvironmentVariableTarget.Machine);
                //if (string.IsNullOrEmpty(sysRoot)) sysRoot = @"C:\Windows";
                //ev["SystemRoot"] = sysRoot;

                //string winDir = Environment.GetEnvironmentVariable("WINDIR", EnvironmentVariableTarget.Machine);
                //if (string.IsNullOrEmpty(winDir)) winDir = @"C:\Windows";
                //ev["WINDIR"] = winDir;

                //string comSpec = Environment.GetEnvironmentVariable("ComSpec", EnvironmentVariableTarget.Machine);
                //if (string.IsNullOrEmpty(comSpec)) comSpec = @"C:\Windows\System32\cmd.exe";
                //ev["ComSpec"] = comSpec;

                //string path = Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.Machine);
                //if (path == null) path = string.Empty;
                //ev["Path"] = path;
            }
            else
            {
                // Non-impersonated: it's fine to inherit, but still ensure essentials exist
                //if (string.IsNullOrEmpty(si.EnvironmentVariables["SystemRoot"]))
                //    si.EnvironmentVariables["SystemRoot"] = Environment.GetEnvironmentVariable("SystemRoot", EnvironmentVariableTarget.Machine) ?? @"C:\Windows";
                //if (string.IsNullOrEmpty(si.EnvironmentVariables["WINDIR"]))
                //    si.EnvironmentVariables["WINDIR"] = Environment.GetEnvironmentVariable("WINDIR", EnvironmentVariableTarget.Machine) ?? @"C:\Windows";
                //if (string.IsNullOrEmpty(si.EnvironmentVariables["ComSpec"]))
                //    si.EnvironmentVariables["ComSpec"] = Environment.GetEnvironmentVariable("ComSpec", EnvironmentVariableTarget.Machine) ?? @"C:\Windows\System32\cmd.exe";
                //if (string.IsNullOrEmpty(si.EnvironmentVariables["Path"]))
                //    si.EnvironmentVariables["Path"] = Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.Machine) ?? string.Empty;
            }

            Tracer.TraceInformation("using-exe: '{0}'  Exists={1}", si.FileName, System.IO.File.Exists(si.FileName));
            Tracer.TraceInformation("args: {0}", si.Arguments);
            Tracer.TraceInformation("WorkingDirectory: '{0}' Exists={1}", si.WorkingDirectory, Directory.Exists(si.WorkingDirectory));
            Tracer.TraceInformation("UseShellExecute={0}  LoadUserProfile={1}", si.UseShellExecute, si.LoadUserProfile);
            Tracer.TraceInformation("Env: SystemRoot='{0}', WINDIR='{1}', ComSpec='{2}', Path(empty)={3}",
                si.EnvironmentVariables["SystemRoot"], si.EnvironmentVariables["WINDIR"],
                si.EnvironmentVariables["ComSpec"], string.IsNullOrEmpty(si.EnvironmentVariables["Path"]));

            Tracer.TraceInformation("Env: TEMP='{0}', TMP='{1}', USERPROFILE='{2}', HOMEDRIVE='{3}', HOMEPATH='{4}'",
                si.EnvironmentVariables["TEMP"], si.EnvironmentVariables["TMP"],
                si.EnvironmentVariables["USERPROFILE"], si.EnvironmentVariables["HOMEDRIVE"], si.EnvironmentVariables["HOMEPATH"]);

            //pspi.Process.ErrorDataReceived += (s, e) => { if (e.Data != null) Tracer.TraceError("pwsh[stderr]: {0}", e.Data); };
            //pspi.Process.OutputDataReceived += (s, e) => { if (e.Data != null) Tracer.TraceInformation("pwsh[stdout]: {0}", e.Data); };
            //pspi.Process.EnableRaisingEvents = true;
            pspi.Process.Exited += (s, e) =>
            {
                try { Tracer.TraceError("pwsh exited. HasExited={0}, ExitCode={1:X8}", pspi.Process.HasExited, pspi.Process.ExitCode); }
                catch { }
            };

            var runspace = RunspaceFactory.CreateOutOfProcessRunspace(new TypeTable(new string[0]), pspi);

            try
            {
                runspace.Open();

                // whats this about ???
                //try { pspi.Process.BeginErrorReadLine(); } catch { }
                //try { pspi.Process.BeginOutputReadLine(); } catch { }

                //using (var ps = PowerShell.Create())
                //{
                //    ps.Runspace = runspace;
                //    ps.AddScript("$PSVersionTable.PSEdition, $PSVersionTable.PSVersion.ToString()");
                //    var v = ps.Invoke();
                //    Tracer.TraceInformation("Remote engine: {0} {1}", v.Count > 0 ? v[0] : "?", v.Count > 1 ? v[1] : "?");
                //}

                return (runspace, pspi);
            }
            catch (Exception ex)
            {
                bool hasExited = false; int exitCode = 0;
                try { hasExited = pspi.Process.HasExited; exitCode = pspi.Process.ExitCode; } catch { }

                Tracer.TraceError("Runspace.Open failed. HasExited={0}, ExitCode=0x{1:X8}", hasExited, exitCode);
                Tracer.TraceError("FileName='{0}', WD='{1}'", si.FileName, si.WorkingDirectory);
                Tracer.TraceError("Env SystemRoot='{0}', TEMP='{1}', USERPROFILE='{2}'",
                    si.EnvironmentVariables["SystemRoot"], si.EnvironmentVariables["TEMP"], si.EnvironmentVariables["USERPROFILE"]);
                Tracer.TraceError("Exception: {0}", ex);
                Tracer.TraceError("BaseException: {0}", ex.GetBaseException());
                throw;
            }
        }

    }
}
