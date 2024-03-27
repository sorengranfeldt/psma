# Author: Soren Granfeldt
# Date: October 11, 2015
# Version: 5.5.0.3501
# Description: This script copies necessary files for Granfeldt PowerShell Management Agent to FIM/MIM installation folders.

# November 8, 2015 - Update
# Author: Soren Granfeldt
# Version: 5.5.1.1017
# Description: Updated version of the script.

# Define filenames for the PowerShell Management Agent files
$maxmlfilename = "Granfeldt.PowerShell.ManagementAgent.xml"
$mafilename = "Granfeldt.PowerShell.ManagementAgent.dll"

# Attempt to retrieve the installation location of FIM/MIM from the registry
try
{
	$location = get-itemproperty "hklm:\software\microsoft\forefront identity manager\2010\synchronization service" -erroraction stop | select -expand location
}
catch
{
	write-error "Cannot get FIM/MIM installation folder path from registry"
	break
}

# Append necessary paths to the installation location
$location = join-path $location "synchronization service"
write-debug "install-location: $location"
$extensionsfolder = join-path $location "extensions"
write-debug "install-location: $extensionsfolder"
$packagedmafolder = join-path $location "uishell\xmls\packagedmas"
write-debug "install-location: $packagedmafolder"

# Copy PowerShell Management Agent files to their respective folders
write-debug "copying $mafilename to $extensionsfolder"
copy-item "$mafilename" -destination "$extensionsfolder"
write-debug "copying $maxmlfilename to $packagedmafolder"
copy-item "$maxmlfilename" -destination "$packagedmafolder"
