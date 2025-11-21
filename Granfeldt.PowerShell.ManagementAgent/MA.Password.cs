using Microsoft.MetadirectoryServices;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Management.Automation;
using System.Security;

namespace Granfeldt
{
    public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
    {
        enum PasswordOperation { Set, Change }

        ConnectionSecurityLevel IMAExtensible2Password.GetConnectionSecurityLevel() => ConnectionSecurityLevel.Secure;

        PSObject ToPsSimpleObject(CSEntry csentry)
        {
            var obj = new PSObject();

            // basic metadata
            obj.Properties.Add(new PSNoteProperty("[DN]", csentry.DN?.ToString()));
            obj.Properties.Add(new PSNoteProperty("[RDN]", csentry.RDN));
            obj.Properties.Add(new PSNoteProperty("DN", csentry.DN?.ToString())); // for legacy scripts / support
            obj.Properties.Add(new PSNoteProperty("[ObjectType]", csentry.ObjectType));

            // enumerate attribute *names*
            foreach (string attrName in csentry)
            {
                Attrib attr = csentry[attrName];
                if (attr == null || !attr.IsPresent) continue;

                if (attr.IsMultivalued)
                {
                    var values = new List<object>();
                    foreach (var v in attr.Values) // ValueCollection
                    {
                        values.Add(v);
                    }
                    obj.Properties.Add(new PSNoteProperty(attrName, values.ToArray()));
                }
                else
                {
                    obj.Properties.Add(new PSNoteProperty(attrName, attr.Value));
                }
            }

            return obj;
        }

        void IMAExtensible2Password.OpenPasswordConnection(KeyedCollection<string, ConfigParameter> configParameters, Partition partition)
        {
            Tracer.Enter("openpasswordconnection");
            try
            {
                InitializeConfigParameters(configParameters);
                EnsurePowerShellEngine();
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
            try
            {
                Dictionary<string, object> parameters = GetDefaultScriptParameters();
                parameters.Add("Action", Action.ToString());

                if (options.HasFlag(PasswordOptions.UnlockAccount)) parameters.Add("UnlockAccount", true);
                if (options.HasFlag(PasswordOptions.ForceChangeAtLogOn)) parameters.Add("ForceChangeAtLogOn", true);
                if (options.HasFlag(PasswordOptions.ValidatePassword)) parameters.Add("ValidatePassword", true);
                parameters.Add("NewPassword", newPassword.ConvertToUnsecureString());

                if (Action == PasswordOperation.Change)
                {
                    parameters.Add("OldPassword", oldPassword.ConvertToUnsecureString());
                }

                var pipeline = new[] { ToPsSimpleObject(csentry) };
                var result = engine.InvokeCommand(Path.GetFullPath(passwordManagementScriptPath), parameters, pipeline);
            }
            catch (Exception ex)
            {
                Tracer.TraceError("callpasswordscript", ex);
                throw;
            }
            finally
            {
                Tracer.Exit("callpasswordscript");
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
                Dispose();
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore disposal
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
