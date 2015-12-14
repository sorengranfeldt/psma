# october 11, 2015 | soren granfeldt
#	- version 5.5.0.3501
# november 8, 2015 | soren granfeldt
#	- version 5.5.1.1017
param
(
)

$maxmlfilename = "Granfeldt.PowerShell.ManagementAgent.xml"
$mafilename = "Granfeldt.PowerShell.ManagementAgent.dll"
try
{
	$location = get-itemproperty "hklm:\software\microsoft\forefront identity manager\2010\synchronization service" -erroraction stop | select -expand location
}
catch
{
	write-error "Cannot get FIM/MIM installation folder path from registry"
	break
}

$location = join-path $location "synchronization service"
write-debug "install-location: $location"
$extensionsfolder = join-path $location "extensions"
write-debug "install-location: $extensionsfolder"
$packagedmafolder = join-path $location "uishell\xmls\packagedmas"
write-debug "install-location: $packagedmafolder"

write-debug "copying $mafilename to $extensionsfolder"
copy-item "$mafilename" -destination "$extensionsfolder"
write-debug "copying $maxmlfilename to $packagedmafolder"
copy-item "$maxmlfilename" -destination "$packagedmafolder"
