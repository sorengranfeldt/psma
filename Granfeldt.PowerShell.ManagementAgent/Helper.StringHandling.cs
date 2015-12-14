using System;
using System.Runtime.InteropServices;
using System.Security;

namespace Granfeldt
{
	static class StringHandling
	{
		/// <summary>
		/// Converts a SecureString to a normal string
		/// </summary>
		/// <param name="securePassword">The encrypted string to be converted</param>
		/// <returns></returns>
		public static string ConvertToUnsecureString(this SecureString securePassword)
		{
			if (securePassword == null)
				throw new ArgumentNullException("securePassword");

			IntPtr unmanagedString = IntPtr.Zero;
			try
			{
				unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(securePassword);
				return Marshal.PtrToStringUni(unmanagedString);
			}
			finally
			{
				Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
			}
		}
	}
}
