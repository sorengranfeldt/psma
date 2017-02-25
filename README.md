# Powershell Management Agent for FIM2010 and MIM2016
The Granfeldt PowerShell Management Agent (MA) is a diverse MA for Forefront Identity Manager 2010 (FIM) R2 and Microsoft Identity Manager 2016. It can be used for many different purposes. Basically, any task that can be done in PowerShell can be triggered through this MA, making it very flexible and a regular hybrid.

It supports -
* Full and delta import
* Export and Full Export
* Password Management (PCNS)

## Real-world uses
Below is just a few ideas of uses for this MA. Many implementations are running with this MA around the world and it is used for numerous purposes.

* Home Directories - a typical purpose of this MA is the creation and managing of home directories and/or profile drives for users.
* Lync - this MA has been used for managing Lync-specific details for users. By importing Lync modules and running appropriate CMDlets, you can use this MA for Lync enabling/disabling.
* SQL Delta import - by using a timestamp column in a clever way, you can do delta imports from SQL server tables with this MA. Sample scripts for a small SQL user database with some sample property calculations can be found in the download section.
* OpenLDAP - this MA has been used to replace the old OpenLDAP XMA.
* Office 365 - this MA is also frequently used for managing users in Office 365 and you can find a link for sample scripts for doing this in the download section.
* Dynamics AX 2012 - this MA has been used for managing users and roles in Dynamics AX 2012.
* Human Resource (HR) data - this MA has been used to read funny formatted files (and clean up) data coming from various HR systems. Using PowerShell to read the file and maybe enrich it / filter allowing you to pass more clean data to FIM.
* TCP/IP (DHCP leases) - this MA has been used for importing DHCP lease information from DHCP servers in order to create computer account for use with WPA authentication.
* Password Management - this MA supports password management (PCNS) and will allow for a script to be run for password changes using Password Change Notification Services.

## Video introduction to the MA
You can get a technical introduction to the MA through the presentation from the July 2013 FIM Team User Group meeting.

You can watch the video presentation here on  [YouTube](https://www.youtube.com/watch?v=28jKaLbnTa8)

Enjoy, Søren Granfeldt ([blog](http://blog.goverco.com) or [twitter](https://twitter.com/MrGranfeldt))

