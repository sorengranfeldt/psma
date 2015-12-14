using Microsoft.MetadirectoryServices;
using System;
using System.Security;

namespace Granfeldt
{
	public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
	{
		// we could consider implementing this option
		// http://blogs.msdn.com/b/alejacma/archive/2007/12/20/how-to-call-createprocesswithlogonw-createprocessasuser-in-net.aspx

		bool ShouldImpersonate()
		{
			bool impersonate = !string.IsNullOrEmpty(impersonationUsername) && !string.IsNullOrEmpty(impersonationUserPassword);
			Tracer.TraceInformation("should-impersonate '{0}'", impersonate);
			return impersonate;
		}

		IntPtr SetupImpersonationToken()
		{
			Tracer.Enter("setupimpersonationtoken");
			IntPtr token = IntPtr.Zero;

			bool success = NativeMethods.LogonUser(impersonationUsername, impersonationUserDomain, impersonationUserPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out token);
			if (!success)
			{
				SecurityException ex = new SecurityException(string.Format("failed-to-impersonate: domain: '{0}', username: '{1}', password: **secret***", impersonationUserDomain, impersonationUsername));
				Tracer.TraceError(ex.ToString());
				throw ex;
			}
			else
			{
				Tracer.TraceInformation("succeeded-in-impersonating: domain: '{0}', username: '{1}', password: **secret***", impersonationUserDomain, impersonationUsername);
			}

			Tracer.Exit("setupimpersonationtoken");
			return token;
		}

	}

}
