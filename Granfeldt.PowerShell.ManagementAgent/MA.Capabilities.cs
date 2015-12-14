using Microsoft.MetadirectoryServices;
using System;

namespace Granfeldt
{
	public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
	{
		MACapabilities IMAExtensible2GetCapabilities.Capabilities
		{
			get
			{
				Tracer.Enter("capabilities");
				MACapabilities cap = new MACapabilities();
				cap.ConcurrentOperation = true;
				cap.DeltaImport = true;
				cap.DistinguishedNameStyle = MADistinguishedNameStyle.Generic;
				cap.ExportType = MAExportType.ObjectReplace;
				cap.FullExport = true;
				cap.ObjectConfirmation = MAObjectConfirmation.Normal;
				cap.ObjectRename = false;
				cap.NoReferenceValuesInFirstExport = false;
				Tracer.Exit("capabilities");
				return cap;
			}
		}
	}

}
