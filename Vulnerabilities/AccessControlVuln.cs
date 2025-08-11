using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Permissions;
using System.Security.Principal;
using System.Threading;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class AccessControlVuln
    {
        // 1. Broken Object Level Authorization (BOLA)
        public static void BrokenObjectLevelAuthorization(string filePath)
        {
            // Vulnérabilité : Pas de check sur l'utilisateur courant
            // (Utilisé pour lire un fichier qui devrait être réservé à "Owner")
            string content = File.ReadAllText(filePath);
            MessageBox.Show(content, "BOLA");
        }

        // 2. Insecure Direct Object Reference (IDOR)
        public static void InsecureDirectObjectReference(string userId)
        {
            // Vulnérabilité : Utilise un ID fourni sans contrôle
            string path = $"C:\\Users\\{userId}\\private.txt";
            if (File.Exists(path))
                MessageBox.Show(File.ReadAllText(path), "IDOR");
            else
                MessageBox.Show("Not found", "IDOR");
        }

        // 3. Vertical Privilege Escalation (Manque [PrincipalPermission])
        public static void VerticalPrivilegeEscalation(string command)
        {
            // Vulnérabilité : Processus admin sans contrôle explicite
            // (exploitable par n'importe qui)
            Process.Start("cmd.exe", "/C " + command);
        }

        // 4. Horizontal Privilege Escalation
        public static void HorizontalPrivilegeEscalation(string victimUsername)
        {
            // Vulnérabilité : Accès aux données d'un autre utilisateur (même rôle)
            string dataPath = $"C:\\Users\\{victimUsername}\\data.txt";
            if (File.Exists(dataPath))
                MessageBox.Show(File.ReadAllText(dataPath), "Horizontal Escalation");
            else
                MessageBox.Show("No data", "Horizontal Escalation");
        }

        // 5. Forced Browsing / Hidden Feature
        public static void ForcedBrowsing(string featureName)
        {
            // Vulnérabilité : Fonction cachée, pas d'attribut de sécurité
            if (featureName == "HiddenAdmin")
                OpenAdminFeature();
            else
                MessageBox.Show("Feature not found", "Forced Browsing");
        }

        // Pattern positif (pour comparaison SAST) : ici on protège la fonction (mais pas son appel)
        public static void OpenAdminFeature()
        {
            // Contrôle manuel d'accès (role-based)
            var principal = Thread.CurrentPrincipal as ClaimsPrincipal;
            if (principal == null || !principal.IsInRole("Admin"))
            {
                MessageBox.Show("Access denied. Admin role required.", "Authorization");
                return;
            }

            MessageBox.Show("Admin feature accessed!", "Admin");
        }

        // 6. Missing Function Level Access Control
        public static void MissingFunctionLevelAccessControl(string function)
        {
            // Vulnérabilité : pas de [PrincipalPermission], pas de vérif manuelle
            if (function == "DangerDeleteAll")
            {
                File.Delete("all_users.txt");
                MessageBox.Show("All users deleted!", "Missing FLAC");
            }
            else
                MessageBox.Show("Unknown function", "Missing FLAC");
        }

        // 7. Role Tampering (CurrentPrincipal modifiable)
        public static void RoleTampering(string newRole)
        {
            var identity = new ClaimsIdentity("custom");
            identity.AddClaim(new Claim(ClaimTypes.Name, "user"));
            identity.AddClaim(new Claim(ClaimTypes.Role, newRole));
            Thread.CurrentPrincipal = new ClaimsPrincipal(identity);
            var principal = Thread.CurrentPrincipal as ClaimsPrincipal;
            var roles = principal?.Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => c.Value)
                .ToArray();
            MessageBox.Show($"Your roles: {string.Join(",", roles ?? new string[0])}", "Role Tampering");
        }

        // 8. Unprotected Event Handler/IPC (Delegate/Command non limité)
        public static void UnprotectedEventHandler()
        {
            // Vulnérabilité : Handler critique accessible sans vérification
            DangerousDelegate();
        }
        // (pattern SAST : absence de contrôle)
        public static void DangerousDelegate()
        {
            MessageBox.Show("Critical event executed!", "Event Handler");
        }

        // 9. Security Through Obscurity (nom de chemin ou méthode)
        public static void SecurityThroughObscurity(string secret)
        {
            // Vulnérabilité : la fonction critique est accessible par devinette
            if (secret == "opensecret")
                MessageBox.Show("Secret admin path hit!", "Obscurity");
            else
                MessageBox.Show("Nope.", "Obscurity");
        }

        // 10. Role Confusion/Misconfiguration
        public static void RoleConfusion(string roles)
        {
            // Vulnérabilité : mauvaise gestion des rôles combinés
            // L'utilisateur reçoit des droits admin s'il a "manager" + "admin"
            if (roles.Contains("manager") && roles.Contains("admin"))
                OpenAdminFeature();
            else
                MessageBox.Show("Not enough roles.", "Role Confusion");
        }
    }
}
