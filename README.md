# PowerShell Management Agent for FIM2010 and MIM2016
The Granfeldt PowerShell Management Agent (PSMA) is a highly flexible ECMA for Forefront Identity Manager 2010 (FIM) R2 and Microsoft Identity Manager 2016. Although the MA can be deployed to perform many different use cases, the basic operation centers around creation, updating, or deletion (CRUD), which can be achieved via PowerShell. By using this framework, these operations can be triggered within the FIM/MIM Synchronization Engine, thereby greatly extending the integration possibilities of the platform while simultaneously reducing the complexity of supporting the solution in the future.

## NEW!! PowerShell 7 Version Support
The PSMA now supports **both Windows PowerShell 5.1 and PowerShell 7.5+** through a hybrid engine selection system:

- **Windows PowerShell 5.1** (default) - Maintains full backward compatibility and handles all impersonated operations
- **PowerShell 7.5+** - Modern features and better performance for non-impersonated operations

### Hybrid Engine Approach

**IMPORTANT**: PowerShell 7 impersonation is not currently implemented. The PowerShell version is user-selectable in the Connectivity parameters:

- **Windows PowerShell 5.1** (default): Always uses Windows PowerShell 5.1 for all operations, including impersonation
- **PowerShell 7**: Uses PowerShell 7 for operations, but automatically falls back to Windows PowerShell 5.1 when impersonation credentials are configured

This hybrid approach gives you PowerShell 7's modern features and performance when possible, with automatic fallback to Windows PowerShell 5.1 only when impersonation is configured.

Windows PowerShell 5.1 remains the default to ensure compatibility with existing implementations. For detailed information, see [PowerShell Version Support](PowerShell-Version-Support.md).

### Configuration Notes

You can configure PowerShell 7 without worrying about impersonation compatibility. When PowerShell 7 is selected:

- **Operations without impersonation credentials**: Executed with PowerShell 7 for best performance
- **Operations with impersonation credentials configured**: Automatically fall back to Windows PowerShell 5.1 for reliable compatibility

No special Windows user rights configuration is required for PowerShell 7 since impersonated operations automatically fall back to Windows PowerShell 5.1.

### ⚠️ Script Compatibility Warning

**IMPORTANT**: When PowerShell 7 is selected and impersonation credentials are configured, ensure your scripts are compatible with **both** PowerShell versions:

- **PowerShell 7-only syntax** (ternary operators `?:`, null coalescing `??`, chain operators `&&` `||`) will **fail** when executed under Windows PowerShell 5.1
- **Error behavior**: Scripts with PowerShell 7-specific syntax will throw `Stopped-DLL-Exception` or similar FIM/MIM errors when fallback occurs
- **Recommendation**: Use PowerShell syntax compatible with both versions, or implement version-specific conditional logic

Example of problematic syntax:
```powershell
# PowerShell 7 only - will fail in Windows PowerShell 5.1
$result = $value ?? "default"
$status = $condition ? "success" : "failure"
```

Example of compatible syntax:
```powershell
# Works in both versions
$result = if ($value) { $value } else { "default" }
$status = if ($condition) { "success" } else { "failure" }
```

**Synchronization Service account**

- **Impersonate a client after authentication** (`SeImpersonatePrivilege`)
- **Adjust memory quotas for a process** (`SeIncreaseQuotaPrivilege`)
- **Profile single process** (`SeProfileSingleProcessPrivilege`)
- **Back up files and directories** (`SeBackupPrivilege`)
- **Restore files and directories** (`SeRestorePrivilege`)

> Microsoft also requires callers of `LoadUserProfile` to run as LocalSystem or a local administrator. If you use a custom service account, ensure it is a local admin on the PSMA server in addition to holding the rights above.

**Run-as/impersonated account**

- **Adjust memory quotas for a process** (`SeIncreaseQuotaPrivilege`)
- **Profile single process** (`SeProfileSingleProcessPrivilege`)

Assign the rights using the option that suits your environment:

1. **Local Security Policy (standalone or lab machines)**
	- Sign in with local administrator rights and start `secpol.msc`.
	- Navigate to `Security Settings ▸ Local Policies ▸ User Rights Assignment`.
	- Add the synchronization service account to each policy listed above (*Impersonate a client after authentication*, *Adjust memory quotas for a process*, *Profile single process*, *Back up files and directories*, *Restore files and directories*).
	- Add the run-as account to *Adjust memory quotas for a process* and *Profile single process* (you can add both accounts to these policies).
	- Select **OK** and restart the Synchronization Service or sign the accounts out/in so the rights become active.
2. **Group Policy (domain-managed servers)**
	- In the Group Policy Management Console, edit or create a GPO linked to the PSMA server.
	- Go to `Computer Configuration ▸ Windows Settings ▸ Security Settings ▸ Local Policies ▸ User Rights Assignment` and add the accounts to the same policies as above.
	- Force a policy refresh with `gpupdate /target:computer /force` or reboot the server.
3. **Command-line automation (secedit)**
	- Create an INF file (for example `C:\Temp\psma-rights.inf`) with your account names:

	  ```ini
	  [Unicode]
	  Unicode=yes
	  [Version]
	  signature="$CHICAGO$"
	  Revision=1
	  [Privilege Rights]
	  SeImpersonatePrivilege = CONTOSO\MIMSyncSvc
	  SeIncreaseQuotaPrivilege = CONTOSO\MIMSyncSvc, CONTOSO\psma-run
	  SeProfileSingleProcessPrivilege = CONTOSO\MIMSyncSvc, CONTOSO\psma-run
	  SeBackupPrivilege = CONTOSO\MIMSyncSvc
	  SeRestorePrivilege = CONTOSO\MIMSyncSvc
	  ```

	- Apply it with elevated PowerShell or Command Prompt:

	  ```powershell
	  secedit /configure /db C:\Windows\Security\psma-rights.sdb /cfg C:\Temp\psma-rights.inf /areas USER_RIGHTS
	  gpupdate /target:computer /force
	  ```

After the rights are applied, validate them by running `whoami /priv` under **both** identities. The Synchronization Service account should show all five privileges as **Enabled**, and the run-as account should show `SeIncreaseQuotaPrivilege` and `SeProfileSingleProcessPrivilege` as **Enabled**.

References:

- [Impersonate a client after authentication](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication)
- [Adjust memory quotas for a process](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/adjust-memory-quotas-for-a-process)
- [Profile single process](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/profile-single-process)
- [Back up files and directories](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories)
- [Restore files and directories](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/restore-files-and-directories)
- [LoadUserProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew)

### Simplified Configuration

PowerShell 7 configuration is greatly simplified:

1. **Install PowerShell 7** - Use the MSI installer from the [official PowerShell releases page](https://github.com/PowerShell/PowerShell/releases)
2. **Configure the PSMA** - Set PowerShell version to "PowerShell 7" in Connectivity parameters
3. **No additional privileges required** - When PowerShell 7 is selected, operations with impersonation credentials automatically fall back to Windows PowerShell 5.1

When PowerShell 7 is selected as the engine, the PSMA automatically falls back to Windows PowerShell 5.1 only when impersonation credentials are configured.

### Troubleshooting PowerShell 7 Installation

If PowerShell 7 fails to initialize for non-impersonated operations:

**Installation issues:**
1. **Missing PowerShell 7**: Ensure PowerShell 7 is installed using the MSI installer from the [official releases page](https://github.com/PowerShell/PowerShell/releases). Avoid Windows Store or other package managers.

2. **Missing Visual C++ Redistributables**: PowerShell 7 requires the Microsoft Visual C++ Redistributable for Visual Studio 2019 (x64). Download and install from the [Microsoft website](https://support.microsoft.com/help/2977003/the-latest-supported-visual-c-downloads).

3. **PowerShell 7.5+ and .NET 9.0 compatibility**: For maximum compatibility, consider using PowerShell 7.4 LTS which uses .NET 8.0. Download from the [PowerShell releases page](https://github.com/PowerShell/PowerShell/releases/tag/v7.4.6).

4. **PATH environment variable**: Ensure PowerShell 7 is properly added to the system PATH. The default installation path is `C:\Program Files\PowerShell\7\`.

If PowerShell 7 fails to initialize, the PSMA will automatically fall back to Windows PowerShell 5.1 for all operations, ensuring your management agent continues to function normally.


The management agent supports
* [Full and Delta Import](https://github.com/sorengranfeldt/psma/wiki/Import)
* [Export and Full Export](https://github.com/sorengranfeldt/psma/wiki/Export)
* [Password Management (PCNS)](https://github.com/sorengranfeldt/psma/wiki/PasswordManagement)
* [Tracing and Logging](https://github.com/sorengranfeldt/psma/wiki/Logging)
* [Flexible Schemas](https://github.com/sorengranfeldt/psma/wiki/Schema)

_NEW_ - Get help from the MA from the [PSMA AI Assistent](https://chatgpt.com/g/g-lxQzqGMp5-granfeldt-powershell-ma-assistent)

## Real-world uses
Below are just a few potential use cases for the MA, although integration can be achieved with almost any system that allow for direct or indirect integration using PowerShell. 

* **Home Directories** - a typical implementation of this MA is the creation and managing of home directories and/or profile drives for users.
* **Skype for Business** - managing Skype for Business/Lync user accounts as well as profiles. By importing the standard [Lync PowerShell cmdlets](https://docs.microsoft.com/en-us/lyncserver/lync-server-2013-lync-server-cmdlets-by-category) or the [Skype for Business Online cmdlets](https://docs.microsoft.com/en-us/office365/enterprise/powershell/manage-skype-for-business-online-with-office-365-powershell) and running appropriate CMDlets, users use this MA for the automation of the entire CSUser lifecycle.
* **SQL Delta Import** - by using a timestamp column as a watermark, users can do delta imports from SQL server tables.
* **Web Service Integration** - with the use of PowerShell many options for integration to REST/SOAP web services become simple. This can be achieved with [Invoke-RestMethod](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod?view=powershell-6), [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-6) and [New-WebServiceProxy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-webserviceproxy?view=powershell-5.1).
* **OpenLDAP** - this MA has been used to replace the old OpenLDAP XMA.
* **Azure Active Directory** - the MA can be used in conjunction with the [Azure AD PowerShell Module](https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0) to automate Azure AD user lifecycle scenarios and even manage Azure B2B guests.
* **Office 365** - this MA is also frequently used for managing users in Office 365 and users can find a link for sample scripts for doing this in the download section.
* **Dynamics AX** - this MA has been used for managing users and roles in Dynamics AX.
* **Human Resource (HR) Information** - this MA has been used to read funny formatted files (and clean up) data coming from various HR systems. Using PowerShell to read the file and maybe enrich it / filter allowing you to pass more clean data to FIM.
* **TCP/IP (DHCP Leases)** - in network related use cases the MA has been used to import DHCP lease information from DHCP servers in order to create computer accounts for use with WPA authentication.
* **Password Management** - a great use case includes the use of the MA for custom password synchronization scenarios, especially if the target system requires some form of custom password hashing before the password is stored. The MA supports password management (PCNS) and will allow for a script to be run for password changes when triggered via [Password Change Notification Services](https://www.microsoft.com/en-za/download/details.aspx?id=19495) events from company domain controllers.

These are only a subset of some of the use cases. Many other implementations of this MA are running around the world and it is used for a wide variety of integration requirements.

## PSMA Implementation Examples
The following are but some examples of users who have used the PSMA in order to automate specific use cases in FIM/MIM. For additional examples, see [Wiki->Samples](https://github.com/sorengranfeldt/psma/wiki/Samples).

* [Workday HR Integration](https://blog.darrenjrobinson.com/building-a-microsoft-identity-manager-powershell-management-agent-for-workday-hr/) 
* [Azure B2B Automation](https://blog.darrenjrobinson.com/automating-azure-ad-b2b-guest-invitations-using-microsoft-identity-manager/)
* [Azure B2B and Exchange Online Automation](https://github.com/puttyq/mim.psma.azureb2b)
* [Hybrid Exchange Provisioning](https://blog.darrenjrobinson.com/provisioning-hybrid-exchangeexchange-online-mailboxes-with-microsoft-identity-manager/)
* [Dynamics 365 Finance & Operations](https://blog.darrenjrobinson.com/a-dynamics-365-finance-operations-management-agent-for-microsoft-identity-manager/)
* [xMatters Integration](https://blog.darrenjrobinson.com/building-a-fimmim-management-agent-for-xmatters/)
* [Pwned Password Detection with MIM](https://blog.darrenjrobinson.com/updated-identifying-active-directory-users-with-pwned-passwords-using-microsoftforefront-identity-manager/)
* [Office 365 Profile Photo Sync](https://blog.darrenjrobinson.com/how-to-synchronize-users-active-directoryazure-active-directory-photo-using-microsoft-identity-manager/)
* [SAP HCM Import](https://www.puttyq.com/sap-integration-using-powershell-part-1/)

## Other Tools and Examples

* [Build Dynamic Schema for PSMA](https://blog.darrenjrobinson.com/automate-the-generation-of-a-granfeldt-powershell-management-agent-schema-definition-file/)

## Usage and Implementation

In order to gain a better understanding of the MA, technical introduction can be found in the following presentation from the July 2013 in the FIM Team User Group meeting. The session recording is available on [YouTube](https://www.youtube.com/watch?v=28jKaLbnTa8). A complete reference on how to [install](https://github.com/sorengranfeldt/psma/wiki/Installing), [configure](https://github.com/sorengranfeldt/psma/wiki/Configuring) and [troubleshoot](https://github.com/sorengranfeldt/psma/wiki/Troubleshooting) the MA can also be found in the project [Wiki](https://github.com/sorengranfeldt/psma/wiki).

# Contributing

Contributing to this project is welcomed and encouraged since the community can benefit from keeping this updated. When contributing to this repository, please first discuss the change you wish to make via the creation of an issue or getting in touch.

Enjoy, Søren Granfeldt ([blog](http://blog.goverco.com) or [twitter](https://twitter.com/MrGranfeldt))
