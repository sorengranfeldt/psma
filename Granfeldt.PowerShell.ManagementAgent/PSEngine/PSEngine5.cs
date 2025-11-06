using System;
using System.Management.Automation.Runspaces;


public sealed class PSEnginePs51 : PSEngineBase
{
    public string PowershellExePath { get; }
    public bool UseWow64 { get; }

    public PSEnginePs51(
        string powershellExePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        bool useWow64 = false)
    { PowershellExePath = powershellExePath; UseWow64 = useWow64; }

    protected override (Runspace runspace, PowerShellProcessInstance proc) CreateAndOpenRunspace()
    {
        //var pspi = new PowerShellProcessInstance(new Version("5.1"), null, null, useWow64: UseWow64);
        var pspi = new PowerShellProcessInstance(null, null, null, useWow64: UseWow64);
        //pspi.Process.StartInfo.FileName = PowershellExePath;
        //pspi.Process.StartInfo.Arguments = "-s -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass";
        pspi.Process.Start();

        var typeTable = new TypeTable(Array.Empty<string>()); // or TypeTable.Empty in newer builds
        var runspace = RunspaceFactory.CreateOutOfProcessRunspace(typeTable, pspi);
        runspace.Open();
        return (runspace, pspi);
    }
}

