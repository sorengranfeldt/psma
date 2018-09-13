using Microsoft.MetadirectoryServices;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;

// may 11, 2016, soren granfeldt
//	-rewritten using http://www.codeproject.com/Articles/125810/A-complete-Impersonation-Demo-in-C-NET
//	-added additional logging around group membership for service account running scripts (either impersonated account or sync service account)
// may 18, 2016, soren granfeldt
//	-changed impersonation logon type to cleartext creds and logon provider to use winnt5 to enable non-restricted token

namespace Granfeldt
{
	public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
	{
		static class NativeMethods
		{
			[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

			[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
			public static extern int DuplicateToken(IntPtr hToken, int impersonationLevel, ref IntPtr hNewToken);

			[DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
			public static extern bool LoadUserProfile(IntPtr hToken, ref ProfileInfo lpProfileInfo);

			[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
			public static extern bool CloseHandle(IntPtr handle);
		}

		// we could consider implementing this option
		// http://blogs.msdn.com/b/alejacma/archive/2007/12/20/how-to-call-createprocesswithlogonw-createprocessasuser-in-net.aspx

		[StructLayout(LayoutKind.Sequential)]
		public struct ProfileInfo
		{
			///
			/// Specifies the size of the structure, in bytes.
			///
			public int dwSize;

			///
			/// This member can be one of the following flags: 
			/// PI_NOUI or PI_APPLYPOLICY
			///
			public int dwFlags;

			///
			/// Pointer to the name of the user.
			/// This member is used as the base name of the directory 
			/// in which to store a new profile.
			///
			public string lpUserName;

			///
			/// Pointer to the roaming user profile path.
			/// If the user does not have a roaming profile, this member can be NULL.
			///
			public string lpProfilePath;

			///
			/// Pointer to the default user profile path. This member can be NULL.
			///
			public string lpDefaultPath;

			///
			/// Pointer to the name of the validating domain controller, in NetBIOS format.
			/// If this member is NULL, the Windows NT 4.0-style policy will not be applied.
			///
			public string lpServerName;

			///
			/// Pointer to the path of the Windows NT 4.0-style policy file. 
			/// This member can be NULL.
			///
			public string lpPolicyPath;

			///
			/// Handle to the HKEY_CURRENT_USER registry key.
			///
			public IntPtr hProfile;
		}

		public enum ImpersonationLevel
		{
			SecurityAnonymous = 0,
			SecurityIdentification = 1,
			SecurityImpersonation = 2,
			SecurityDelegation = 3
		}
		public enum LogonType
		{
			LOGON32_LOGON_INTERACTIVE = 2,
			LOGON32_LOGON_NETWORK = 3,
			LOGON32_LOGON_BATCH = 4,
			LOGON32_LOGON_SERVICE = 5,
			LOGON32_LOGON_UNLOCK = 7,
			LOGON32_LOGON_NETWORK_CLEARTEXT = 8, // Win2K or higher
			LOGON32_LOGON_NEW_CREDENTIALS = 9 // Win2K or higher
		};

		public enum LogonProvider
		{
			LOGON32_PROVIDER_DEFAULT = 0,
			LOGON32_PROVIDER_WINNT35 = 1,
			LOGON32_PROVIDER_WINNT40 = 2,
			LOGON32_PROVIDER_WINNT50 = 3
		};

		IntPtr impersonationToken = IntPtr.Zero;
		IntPtr tokenDuplicate = IntPtr.Zero;
		WindowsImpersonationContext m_ImpersonationContext;

		bool ShouldImpersonate()
		{
			bool impersonate = !string.IsNullOrEmpty(impersonationUsername) && !string.IsNullOrEmpty(impersonationUserPassword);
			Tracer.TraceInformation("should-impersonate '{0}'", impersonate);
			return impersonate;
		}

		void SetupImpersonationToken()
		{
			Tracer.Enter("setupimpersonationtoken");
			try
			{
				if (!ShouldImpersonate())
				{
					Tracer.TraceInformation("impersonation-not-configured-running-as-sync-service-account");
					WhoAmI();
					return;
				}
				WindowsIdentity m_ImpersonatedUser;

				Tracer.TraceInformation("user-before-impersonation: {0}", WindowsIdentity.GetCurrent(TokenAccessLevels.MaximumAllowed).Name);

				//bool success = NativeMethods.LogonUser(impersonationUsername, impersonationUserDomain, impersonationUserPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out impersonationToken);
				bool success = NativeMethods.LogonUser(impersonationUsername, impersonationUserDomain, impersonationUserPassword, (int)LogonType.LOGON32_LOGON_NETWORK_CLEARTEXT, (int)LogonProvider.LOGON32_PROVIDER_WINNT50, out impersonationToken);
				if (!success)
				{
					SecurityException ex = new SecurityException(string.Format("failed-to-impersonate: domain: '{0}', username: '{1}', password: **secret***", impersonationUserDomain, impersonationUsername));
					Tracer.TraceError(ex.ToString());
					throw ex;
				}
				else
				{
					Tracer.TraceInformation("succeeded-in-impersonating: domain: '{0}', username: '{1}', password: **secret***", impersonationUserDomain, impersonationUsername);
					if (NativeMethods.DuplicateToken(impersonationToken, (int)ImpersonationLevel.SecurityImpersonation, ref tokenDuplicate) != 0)
					{
						m_ImpersonatedUser = new WindowsIdentity(tokenDuplicate);
						m_ImpersonationContext = m_ImpersonatedUser.Impersonate();
						Tracer.TraceInformation("succeeded-in-duplicating-impersonation-token");
						if (m_ImpersonationContext != null)
						{
							Tracer.TraceInformation("user-after-impersonation: {0}", WindowsIdentity.GetCurrent(TokenAccessLevels.MaximumAllowed).Name);
							WhoAmI();
						}
						else
						{
							throw new Exception("impersonation-context-is-null");
						}
					}
					else
					{
						throw new Exception("could-not-duplicate-impersonation-token");
					}
				}
			}
			catch (Exception ex)
			{
				Tracer.TraceError("setupimpersonationtoken", ex);
				throw;
			}
			finally
			{
				Tracer.Exit("setupimpersonationtoken");
			}
		}

		void RevertImpersonation()
		{
			if (!ShouldImpersonate())
			{
				return;
			}

			Tracer.Enter("revertimpersonation");
			try
			{
				Tracer.TraceInformation("closing-impersonation-context");
				m_ImpersonationContext.Undo();

				Tracer.TraceInformation("closing-impersonation-tokenhandle {0}", impersonationToken);
				NativeMethods.CloseHandle(impersonationToken);
				Tracer.TraceInformation("closing-impersonation-duplicated-tokenhandle {0}", tokenDuplicate);
				NativeMethods.CloseHandle(tokenDuplicate);
			}
			catch (Exception ex)
			{
				Tracer.TraceError("revertimpersonation", ex);
				throw;
			}
			finally
			{
				Tracer.Exit("revertimpersonation");
			}
		}

	}

}
