using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class AccessControlVuln
    {
        // ========================= EXISTING (complexified) =========================

        // 1) BOLA – no owner check + naive suffix check (bypass with crafted name)
        public static void BrokenObjectLevelAuthorization(string filePath)
        {
            // ❌ No validation of current user ownership; naive allow if endswith ".own"
            // Attacker can still read arbitrary files.
            try
            {
                if (filePath.EndsWith(".own", StringComparison.OrdinalIgnoreCase))
                {
                    // pretend "owner-only" but not actually checking owner
                }
                string content = File.ReadAllText(filePath);
                MessageBox.Show(content, "BOLA");
            }
            catch (Exception ex)
            {
                MessageBox.Show("BOLA error: " + ex.Message, "BOLA");
            }
        }

        // 2) IDOR – "current" resolves to local user, anything else reads other user's file
        public static void InsecureDirectObjectReference(string userId)
        {
            try
            {
                string resolved = userId == "current" ? Environment.UserName : userId; // ❌ user-controlled
                string path = @"C:\Users\" + resolved + @"\private.txt";
                if (File.Exists(path))
                    MessageBox.Show(File.ReadAllText(path), "IDOR");
                else
                    MessageBox.Show("Not found: " + path, "IDOR");
            }
            catch (Exception ex)
            {
                MessageBox.Show("IDOR error: " + ex.Message, "IDOR");
            }
        }

        // 3) Vertical Privilege Escalation – shells out without any role/identity check
        public static void VerticalPrivilegeEscalation(string command)
        {
            try
            {
                // ❌ Anyone can execute privileged command (demo)
                Process.Start("cmd.exe", "/C " + command);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Exec error: " + ex.Message, "Vertical Escalation");
            }
        }

        // 4) Horizontal Privilege Escalation – access sibling's data
        public static void HorizontalPrivilegeEscalation(string victimUsername)
        {
            try
            {
                string dataPath = @"C:\Users\" + victimUsername + @"\data.txt";
                if (File.Exists(dataPath))
                    MessageBox.Show(File.ReadAllText(dataPath), "Horizontal Escalation");
                else
                    MessageBox.Show("No data for " + victimUsername, "Horizontal Escalation");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Horizontal error: " + ex.Message, "Horizontal Escalation");
            }
        }

        // 5) Forced Browsing – hidden feature not protected
        public static void ForcedBrowsing(string featureName)
        {
            try
            {
                // ❌ "Security by hiding" – no authorization gate
                if (string.Equals(featureName, "HiddenAdmin", StringComparison.OrdinalIgnoreCase))
                    OpenAdminFeature();
                else
                    MessageBox.Show("Feature not found", "Forced Browsing");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Forced error: " + ex.Message, "Forced Browsing");
            }
        }

        // 6) Missing Function Level Access Control – destructive op exposed
        public static void MissingFunctionLevelAccessControl(string function)
        {
            try
            {
                // ❌ No role check; dangerous branch by magic string
                if (function == "DangerDeleteAll")
                {
                    var path = Path.Combine(Environment.CurrentDirectory, "all_users.txt");
                    if (File.Exists(path)) File.Delete(path);
                    MessageBox.Show("All users deleted (demo)!", "Missing FLAC");
                }
                else
                {
                    MessageBox.Show("Unknown function", "Missing FLAC");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("FLAC error: " + ex.Message, "Missing FLAC");
            }
        }

        // 7) Role Tampering – lets caller overwrite Thread.CurrentPrincipal
        public static void RoleTampering(string newRole)
        {
            try
            {
                var identity = new ClaimsIdentity("custom");
                identity.AddClaim(new Claim(ClaimTypes.Name, "user"));
                identity.AddClaim(new Claim(ClaimTypes.Role, newRole)); // ❌ user-controlled role
                Thread.CurrentPrincipal = new ClaimsPrincipal(identity);

                var principal = Thread.CurrentPrincipal as ClaimsPrincipal;
                var roles = principal != null
                    ? principal.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToArray()
                    : new string[0];

                MessageBox.Show("Your roles: " + string.Join(",", roles), "Role Tampering");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Role tamper error: " + ex.Message, "Role Tampering");
            }
        }

        // 8) Unprotected Event Handler – critical delegate reachable
        public static void UnprotectedEventHandler()
        {
            try
            {
                DangerousDelegate(); // ❌ no check
            }
            catch (Exception ex)
            {
                MessageBox.Show("Handler error: " + ex.Message, "Event Handler");
            }
        }

        public static void DangerousDelegate()
        {
            MessageBox.Show("Critical event executed!", "Event Handler");
        }

        // 9) Security Through Obscurity – guessable secret string
        public static void SecurityThroughObscurity(string secret)
        {
            if (secret == "opensecret")
                MessageBox.Show("Secret admin path hit!", "Obscurity");
            else
                MessageBox.Show("Nope.", "Obscurity");
        }

        // 10) Role Confusion / Misconfiguration – unsafe composite roles
        public static void RoleConfusion(string rolesCsv)
        {
            // ❌ Grants admin if both "manager" and "admin" are present (arbitrary combo)
            var roles = (rolesCsv ?? "").Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                                        .Select(r => r.Trim().ToLowerInvariant()).ToArray();
            if (roles.Contains("manager") && roles.Contains("admin"))
                OpenAdminFeature();
            else
                MessageBox.Show("Not enough roles.", "Role Confusion");
        }

        // ========================= NEW (5 added) =========================

        // 11) AuthN-as-AuthZ – confuse "authenticated" with "authorized"
        public static void AuthenticatedIsAdmin()
        {
            var p = Thread.CurrentPrincipal;
            // ❌ If authenticated => treat as admin (no role check)
            if (p != null && p.Identity != null && p.Identity.IsAuthenticated)
                OpenAdminFeature();
            else
                MessageBox.Show("Not authenticated => denied (but roles ignored).", "AuthN-as-AuthZ");
        }

        // 12) Weak Role Check (substring) – e.g., "readmin123" passes
        public static void WeakRoleCheckContains(string userOrRoles)
        {
            // ❌ Substring match instead of strict role check
            if (!string.IsNullOrEmpty(userOrRoles) &&
                userOrRoles.IndexOf("admin", StringComparison.OrdinalIgnoreCase) >= 0)
                OpenAdminFeature();
            else
                MessageBox.Show("Role check failed (needs 'admin' substring).", "Weak Role Check");
        }

        // 13) Multi-tenant isolation bypass – user-controlled tenantId/resource
        public static void MultiTenantBypass(string tenantId, string resource)
        {
            try
            {
                // ❌ No tenant ownership check
                string path = @"C:\Tenants\" + tenantId + @"\" + resource + ".json";
                if (File.Exists(path))
                    MessageBox.Show(File.ReadAllText(path), "Tenant Bypass");
                else
                    MessageBox.Show("No resource: " + path, "Tenant Bypass");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Tenant error: " + ex.Message, "Tenant Bypass");
            }
        }

        // 14) Config flag override – trust local file "isAdmin=true"
        public static void ConfigFlagOverride(string cfgPath)
        {
            try
            {
                // ❌ Local, user-writable config decides admin
                if (File.Exists(cfgPath))
                {
                    var text = File.ReadAllText(cfgPath);
                    if (text.IndexOf("isAdmin=true", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        OpenAdminFeature();
                        return;
                    }
                }
                MessageBox.Show("Config does not grant admin.", "Config Flag Override");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Config error: " + ex.Message, "Config Flag Override");
            }
        }

        // 15) Path-prefix policy bypass – StartsWith on case-insensitive FS
        public static void CaseInsensitivePathPolicy(string targetPath)
        {
            try
            {
                // ❌ Approves any path starting with "C:\Secure\Admin" (e.g., AdminBackup\*)
                if (targetPath != null &&
                    targetPath.StartsWith(@"C:\Secure\Admin", StringComparison.OrdinalIgnoreCase))
                {
                    // Demo side-effect to make the sink visible for SAST
                    if (File.Exists(targetPath)) File.Delete(targetPath);
                    MessageBox.Show("Operation allowed on: " + targetPath, "Path Policy Bypass");
                }
                else
                {
                    MessageBox.Show("Denied by prefix policy.", "Path Policy Bypass");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Path policy error: " + ex.Message, "Path Policy Bypass");
            }
        }

        // ========================= Shared "admin" entry =========================
        public static void OpenAdminFeature()
        {
            MessageBox.Show("Admin feature accessed!", "Admin");
        }
    }
}
