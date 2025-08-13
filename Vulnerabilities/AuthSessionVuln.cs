using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Runtime.Serialization.Formatters.Binary;
using System.Collections.Specialized;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class AuthSessionVuln
    {
        // --- Démo d'état global de session (non thread-safe, jamais invalidée)
        private static string GlobalSessionId = null;        // CWE-613 approx / shared global
        private static string LastUserReusedSession = null;  // Reuse across users
        private static DateTime? SessionCreatedAt = null;    // Jamais expirée

        // 1) Secret/mot de passe en dur (CWE-798)
        public static void HardcodedPassword()
        {
            string password = "SuperSecret123"; // ❌ en dur
            MessageBox.Show($"Hardcoded password: {password}");
        }

        // 2) Session globale (jamais invalidée)
        public static void GlobalSession()
        {
            if (GlobalSessionId == null)
            {
                GlobalSessionId = "GLOBAL-" + Guid.NewGuid().ToString("N");
                SessionCreatedAt = DateTime.Now;
            }
            MessageBox.Show($"Global session in memory:\nID = {GlobalSessionId}\nCreatedAt = {SessionCreatedAt}");
        }

        // 3) Pas d’expiration (CWE-613)
        public static void NoSessionExpiration()
        {
            if (GlobalSessionId == null)
            {
                GlobalSessionId = "GLOBAL-" + Guid.NewGuid().ToString("N");
                SessionCreatedAt = DateTime.Now;
            }
            MessageBox.Show($"No expiration policy:\nID = {GlobalSessionId}\nCreatedAt = {SessionCreatedAt}\n(never expires)");
        }

        // 4) Jeton prévisible (CWE-330/338) — complexifié avec Random + horloge
        public static void PredictableToken()
        {
            var rnd = new Random(); // ❌ non cryptographique
            string token = $"SESSION-{DateTime.Now.Ticks}-{rnd.Next(1000, 9999)}";
            MessageBox.Show($"Predictable session token: {token}");
        }

        // 5) Réutilisation de session entre utilisateurs
        public static void ReuseSession()
        {
            if (GlobalSessionId == null)
            {
                GlobalSessionId = "GLOBAL-" + Guid.NewGuid().ToString("N");
                SessionCreatedAt = DateTime.Now;
                LastUserReusedSession = "alice";
            }
            else
            {
                LastUserReusedSession = LastUserReusedSession == "alice" ? "bob" : "alice";
            }
            MessageBox.Show($"Session reused across users:\nID = {GlobalSessionId}\nCurrentUser = {LastUserReusedSession}");
        }

        // 6) Bypass auth (CWE-287/285)
        public static void BypassAuth()
        {
            bool isAuthenticated = false;
            if (!isAuthenticated || true) // ❌ backdoor
                MessageBox.Show("Authentication bypassed: access granted!");
        }

        // 7) Pas de protection brute-force
        public static void NoBruteForceProtection()
        {
            string username = "admin";
            string passwordInput = "password";
            if (username == "admin" && passwordInput == "password") // ❌ aucune limite d’essais
                MessageBox.Show("Authenticated (no brute force protection)!");
            else
                MessageBox.Show("Access denied");
        }

        // 8) Session Fixation (CWE-384)
        public static void SessionFixation(string attackerProvidedId)
        {
            GlobalSessionId = attackerProvidedId; // ❌ accepte ID fourni par l’attaquant
            if (SessionCreatedAt == null) SessionCreatedAt = DateTime.Now;
            MessageBox.Show("Session ID fixed to: " + GlobalSessionId);
        }

        // 9) Login sans MFA + MD5 (CWE-327 + absence MFA)
        public static void LoginWithoutMfa(string username, string password)
        {
            // md5("secret") = 5ebe2294ecd0e0f08eab7690d2a6ee69
            const string storedUser = "bob";
            const string storedHash = "5ebe2294ecd0e0f08eab7690d2a6ee69";

            using (var md5 = MD5.Create()) // ❌ MD5 faible
            {
                var hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
                var inputHashHex = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();

                if (username == storedUser && inputHashHex == storedHash)
                {
                    MessageBox.Show("Login WITHOUT MFA (weak MD5 password check).");
                }
                else
                {
                    MessageBox.Show("Login failed.");
                }
            }
        }

        // 10) ID de session faible (Random + base36 court)
        public static void WeakSessionIdGeneration()
        {
            var rnd = new Random(); // ❌ non crypto
            const string alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
            var buf = new char[8]; // ❌ taille faible
            for (int i = 0; i < buf.Length; i++) buf[i] = alphabet[rnd.Next(alphabet.Length)];
            var sid = new string(buf);
            MessageBox.Show("Weak session ID: " + sid);
        }

        // 11) Token de reset de mot de passe prévisible (horodatage + base64)
        public static void InsecureResetToken(string username)
        {
            // ❌ prévisible et forgeable : username + ticks
            var raw = username + ":" + DateTime.UtcNow.Ticks;
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
            MessageBox.Show("Password reset token: " + token);
        }

        // 12) "Remember me" persistant en clair, lisible par tous
        public static void RememberMePersist(string username)
        {
            var token = "RM-" + Guid.NewGuid().ToString("N"); // ❌ pas lié à un device, pas signé
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments), "remember.token"); // ❌ world-readable
            File.WriteAllText(path, username + "|" + token + "|expires=" + DateTime.UtcNow.AddYears(5).ToString("o"));
            MessageBox.Show("Remember-me token stored at: " + path);
        }

        // 13) Login SHA1 (hash faible alternatif)
        public static void LoginSha1(string username, string password)
        {
            const string storedUser = "alice";
            const string storedHash = "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4"; // sha1("secret")
            using (var sha1 = SHA1.Create()) // ❌
            {
                var h = sha1.ComputeHash(Encoding.UTF8.GetBytes(password));
                var hex = BitConverter.ToString(h).Replace("-", "").ToLowerInvariant();
                MessageBox.Show(username == storedUser && hex == storedHash ? "Login (SHA1, no MFA)" : "Login failed");
            }
        }

        // 14) Désactivation validation TLS (trust-all) + envoi creds (CWE-295)
        public static void InsecureTlsLogin(string url, string username, string password)
        {
            // ❌ désactive la vérif du cert
            ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => true;

            try
            {
                using (var wc = new WebClient())
                {
                    var form = new NameValueCollection
                    {
                        ["username"] = username,
                        ["password"] = password
                    };
                    var response = wc.UploadValues(url, "POST", form);
                    var preview = Encoding.UTF8.GetString(response);
                    if (preview.Length > 300) preview = preview.Substring(0, 300) + "...";
                    MessageBox.Show("Login request sent to: " + url + "\nResponse (preview):\n" + preview);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("TLS/Login error: " + ex.Message);
            }
        }

        // 15) Journalisation d’un token sensible (CWE-532)
        public static void LogSensitiveToken(string token)
        {
            var log = Path.Combine(Path.GetTempPath(), "app.log");
            File.AppendAllText(log, DateTime.Now.ToString("O") + " - TOKEN=" + token + Environment.NewLine);
            MessageBox.Show("Token logged to: " + log);
        }

        // 16) Chiffrement de session en AES-ECB (CWE-327)
        public static void EncryptSessionWithEcb(string json)
        {
            try
            {
                using (var aes = new AesManaged())
                {
                    aes.Mode = CipherMode.ECB; // ❌ ECB
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef"); // ❌ clé en dur (32 octets)

                    var enc = aes.CreateEncryptor();
                    var input = Encoding.UTF8.GetBytes(json);
                    var cipher = enc.TransformFinalBlock(input, 0, input.Length);
                    var b64 = Convert.ToBase64String(cipher);
                    MessageBox.Show("ECB cipher (base64): " + b64);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("ECB error: " + ex.Message);
            }
        }

        // 17) Désérialisation non sécurisée (CWE-502) - BinaryFormatter
        public static void InsecureDeserializeSession(string base64)
        {
            try
            {
                var bytes = Convert.FromBase64String(base64);
                using (var ms = new MemoryStream(bytes))
                {
                    var bf = new BinaryFormatter(); // ❌ vulnérable
                    var obj = bf.Deserialize(ms);
                    MessageBox.Show("Deserialized session object: " + (obj?.ToString() ?? "<null>"));
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Deserialization error: " + ex.Message);
            }
        }
    }
}
