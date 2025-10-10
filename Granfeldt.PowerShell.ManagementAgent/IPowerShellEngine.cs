using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Granfeldt
{
    /// <summary>
    /// Interface for PowerShell engine implementations supporting both Windows PowerShell 5.1 and PowerShell 7+
    /// </summary>
    public interface IPowerShellEngine : IDisposable
    {
        /// <summary>
        /// Gets the PowerShell version information
        /// </summary>
        Version PowerShellVersion { get; }

        /// <summary>
        /// Gets the engine type (Windows PowerShell 5.1 or PowerShell 7+)
        /// </summary>
        string EngineType { get; }

        /// <summary>
        /// Gets whether the engine is initialized and ready
        /// </summary>
        bool IsInitialized { get; }

        /// <summary>
        /// Initializes the PowerShell engine
        /// </summary>
        void Initialize();

        /// <summary>
        /// Opens the PowerShell runspace
        /// </summary>
        void OpenRunspace();

        /// <summary>
        /// Closes the PowerShell runspace
        /// </summary>
        void CloseRunspace();

        /// <summary>
        /// Sets a variable in the PowerShell session
        /// </summary>
        /// <param name="name">Variable name</param>
        /// <param name="value">Variable value</param>
        void SetVariable(string name, object value);

        /// <summary>
        /// Gets a variable from the PowerShell session
        /// </summary>
        /// <param name="name">Variable name</param>
        /// <returns>Variable value</returns>
        object GetVariable(string name);

        /// <summary>
        /// Invokes a PowerShell script
        /// </summary>
        /// <param name="command">Command to execute</param>
        /// <param name="pipelineInput">Pipeline input objects</param>
        /// <returns>Collection of PSObjects</returns>
        Collection<PSObject> InvokePowerShellScript(Command command, PSDataCollection<PSObject> pipelineInput);

        /// <summary>
        /// Sets impersonation credentials for out-of-process execution
        /// </summary>
        /// <param name="username">Username</param>
        /// <param name="domain">Domain</param>
        /// <param name="password">Password</param>
        void SetImpersonationCredentials(string username, string domain, string password);

        /// <summary>
        /// Checks if impersonation has been requested for this engine
        /// Used by the main MA to determine if fallback to Windows PowerShell is needed
        /// </summary>
        /// <returns>True if impersonation credentials have been set</returns>
        bool IsImpersonationRequested();

        /// <summary>
        /// Event raised when PowerShell error occurs
        /// </summary>
        event EventHandler<DataAddedEventArgs> PowerShellError;

        /// <summary>
        /// Event raised when PowerShell verbose output occurs
        /// </summary>
        event EventHandler<DataAddedEventArgs> PowerShellVerbose;

        /// <summary>
        /// Event raised when PowerShell warning occurs
        /// </summary>
        event EventHandler<DataAddedEventArgs> PowerShellWarning;

        /// <summary>
        /// Event raised when PowerShell debug output occurs
        /// </summary>
        event EventHandler<DataAddedEventArgs> PowerShellDebug;

        /// <summary>
        /// Event raised when PowerShell progress occurs
        /// </summary>
        event EventHandler<DataAddedEventArgs> PowerShellProgress;
    }
}
