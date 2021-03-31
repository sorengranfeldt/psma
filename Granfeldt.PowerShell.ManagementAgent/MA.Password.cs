using Microsoft.MetadirectoryServices;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security;

namespace Granfeldt
{
	public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
	{
		string PasswordManagementScript = null;
		Collection<PSObject> passwordResults;
		enum PasswordOperation
		{
			Set,
			Change
		}

		ConnectionSecurityLevel IMAExtensible2Password.GetConnectionSecurityLevel()
		{
			return ConnectionSecurityLevel.Secure;
		}
		void IMAExtensible2Password.OpenPasswordConnection(KeyedCollection<string, ConfigParameter> configParameters, Partition partition)
		{
			Tracer.Enter("openpasswordconnection");
			try
			{
				InitializeConfigParameters(configParameters);

				OpenRunspace();
			}
			catch (Exception ex)
			{
				Tracer.TraceError("openpasswordconnection", ex);
				throw;
			}
			finally
			{
				Tracer.Exit("openpasswordconnection");
			}
		}
		void IMAExtensible2Password.ChangePassword(CSEntry csentry, SecureString oldPassword, SecureString newPassword)
		{
			Tracer.Enter("changepassword");
			try
			{
				CallPasswordScript(PasswordOperation.Change, csentry, oldPassword, newPassword, PasswordOptions.None);
			}
			catch (Exception ex)
			{
				Tracer.TraceError("changepassword", ex);
				throw;
			}
			finally
			{
				Tracer.Exit("changepassword");
			}
		}
		void CallPasswordScript(PasswordOperation Action, CSEntry csentry, SecureString oldPassword, SecureString newPassword, PasswordOptions options)
		{
			Tracer.Enter("callpasswordscript");
			PSDataCollection<PSObject> passwordPipeline = new PSDataCollection<PSObject>();
			try
			{
				Command cmd = new Command(Path.GetFullPath(PasswordManagementScript));
				cmd.Parameters.Add(new CommandParameter("Username", Username));
				cmd.Parameters.Add(new CommandParameter("Password", Password));
				cmd.Parameters.Add(new CommandParameter("Credentials", GetSecureCredentials(Username, SecureStringPassword)));

				cmd.Parameters.Add(new CommandParameter("AuxUsernameAux", UsernameAux));
				cmd.Parameters.Add(new CommandParameter("AuxPasswordAux", PasswordAux));
				cmd.Parameters.Add(new CommandParameter("AuxCredentialsAux", GetSecureCredentials(UsernameAux, SecureStringPasswordAux)));

				cmd.Parameters.Add(new CommandParameter("ConfigurationParameter", ConfigurationParameter));

				cmd.Parameters.Add(new CommandParameter("Action", Action.ToString()));

				if (options.HasFlag(PasswordOptions.UnlockAccount)) cmd.Parameters.Add(new CommandParameter("UnlockAccount"));
				if (options.HasFlag(PasswordOptions.ForceChangeAtLogOn)) cmd.Parameters.Add(new CommandParameter("ForceChangeAtLogOn"));
				if (options.HasFlag(PasswordOptions.ValidatePassword)) cmd.Parameters.Add(new CommandParameter("ValidatePassword"));
				cmd.Parameters.Add(new CommandParameter("NewPassword", newPassword.ConvertToUnsecureString()));
				if (Action == PasswordOperation.Change)
				{
					cmd.Parameters.Add(new CommandParameter("OldPassword", oldPassword.ConvertToUnsecureString()));
				}
				passwordPipeline.Add(new PSObject(csentry));
				passwordResults = InvokePowerShellScript(cmd, passwordPipeline);
			}
			catch (Exception ex)
			{
				Tracer.TraceError("callpasswordscript", ex);
				throw;
			}
			finally
			{
				passwordPipeline = null;
				Tracer.TraceInformation("callpasswordscript");
			}
		}
		void IMAExtensible2Password.SetPassword(CSEntry csentry, SecureString newPassword, PasswordOptions options)
		{
			Tracer.Enter("setpassword");
			try
			{
				CallPasswordScript(PasswordOperation.Set, csentry, new SecureString(), newPassword, options);
			}
			catch (Exception ex)
			{
				Tracer.TraceError("setpassword", ex);
				throw;
			}
			finally
			{
				Tracer.Exit("setpassword");
			}
		}
		void IMAExtensible2Password.ClosePasswordConnection()
		{
			Tracer.Enter("closepasswordconnection");
			try
			{
				CloseRunspace();
				Dispose();
			}
			catch (Exception ex)
			{
				Tracer.TraceError("closepasswordconnection", ex);
				throw;
			}
			finally
			{
				Tracer.Exit("closepasswordconnection");
			}
		}

	}
}
