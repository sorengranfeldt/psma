# PowerShell Management Agent for FIM2010 and MIM2016
The Granfeldt PowerShell Management Agent (PSMA) is a highly flexible ECMA for Forefront Identity Manager 2010 (FIM) R2 and Microsoft Identity Manager 2016. Although the MA can be deployed to perform many different user cases, the basic operation centres around creation, deletion, update or deletion (CRUD) that can be achieved via PowerShell. By using this framework, these operations can be triggered within FIM/MIM Synchronization Engine, thereby greatly extending the integration possibilities of the platform while simultaneously lowering the complexity of supporting the solution in the future.

The management agent supports
* [Full and Delta Import](https://github.com/sorengranfeldt/psma/wiki/Import)
* [Export and Full Export](https://github.com/sorengranfeldt/psma/wiki/Export)
* [Password Management (PCNS)](https://github.com/sorengranfeldt/psma/wiki/PasswordManagement)
* [Tracing and Logging](https://github.com/sorengranfeldt/psma/wiki/Logging)
* [Flexible Schemas](https://github.com/sorengranfeldt/psma/wiki/Schema)

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

* [Workday HR Integration](https://blog.kloud.com.au/2018/09/25/building-a-microsoft-identity-manager-powershell-management-agent-for-workday-hr/)
* [Azure B2B Automation](https://blog.kloud.com.au/2018/08/27/automating-azure-ad-b2b-guest-invitations-using-microsoft-identity-manager/)
* [Azure B2B and Exchange Online Automation](https://github.com/puttyq/mim.psma.azureb2b)
* [Hybrid Exchange Provisioning](https://blog.kloud.com.au/2017/12/19/provisioning-hybrid-exchange-exchange-online-mailboxes-with-microsoft-identity-manager/)
* [xMatters Integration](https://blog.kloud.com.au/2017/11/28/building-a-fim-mim-management-agent-for-xmatters/)
* [Pwned Password Detection with MIM](https://blog.kloud.com.au/2017/08/08/identifying-active-directory-users-with-pwned-passwords-using-microsoftforefront-identity-manager/)
* [Office 365 Profile Photo Sync](https://blog.kloud.com.au/2017/05/23/synchronizing-exchange-onlineoffice-365-user-profile-photos-with-fimmim/)
* [SAP HCM Import](https://www.puttyq.com/sap-integration-using-powershell-part-1/)

## Other Tools and Examples

* [Build Dynmaic Schema.ps1 for PSMA](https://blog.kloud.com.au/2018/09/24/automate-the-generation-of-a-granfeldt-powershell-management-agent-schema-definition-file/)

## Usage and Implementation

In order to gain a better understanding of the MA, technical introduction can be found in the following presentation from the July 2013 in the FIM Team User Group meeting. The session recording is available on [YouTube](https://www.youtube.com/watch?v=28jKaLbnTa8). A complete reference on how to [install](https://github.com/sorengranfeldt/psma/wiki/Installing), [configure](https://github.com/sorengranfeldt/psma/wiki/Configuring) and [troubleshoot](https://github.com/sorengranfeldt/psma/wiki/Troubleshooting) the MA can also be found in the project [Wiki](https://github.com/sorengranfeldt/psma/wiki).

# Contributing

Contributing to this project is welcomed and encouraged since the community can benefit from keeping this updated. When contributing to this repository, please first discuss the change you wish to make via the creation of an issue or getting in touch.

Enjoy, Søren Granfeldt ([blog](http://blog.goverco.com) or [twitter](https://twitter.com/MrGranfeldt))
