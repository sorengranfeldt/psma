// march 27, 2024 | soren granfeldt
//  - code review and optimization

using Microsoft.MetadirectoryServices;
using System;

namespace Granfeldt
{
	public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
	{
        public MACapabilities Capabilities => new MACapabilities
        {
            ConcurrentOperation = true,
            DeltaImport = true,
            DistinguishedNameStyle = MADistinguishedNameStyle.Generic,
            ExportType = MAExportType.ObjectReplace,
            FullExport = true,
            ObjectConfirmation = MAObjectConfirmation.Normal,
            ObjectRename = false,
            NoReferenceValuesInFirstExport = false
        };
    }

}
