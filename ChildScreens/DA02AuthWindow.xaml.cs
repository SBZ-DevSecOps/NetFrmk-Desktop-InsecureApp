using NetFrmk_Desktop_InsecureApp.Vulnerabilities;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA02AuthWindow : Window
    {
        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            // Title / Intro
            { "Title", Tuple.Create("DA02 – Broken Authentication", "DA02 – Authentification non sécurisée") },
            { "Intro", Tuple.Create(
                "Test various broken auth & session flaws: hardcoded secret, weak/predictable tokens, no lockout, session fixation, missing MFA, weak crypto, insecure transport, insecure deserialization.",
                "Testez des failles d’authentification et de session : secret en dur, jetons faibles/prévisibles, absence de verrouillage, fixation de session, absence de MFA, crypto faible, transport non sécurisé, désérialisation non sécurisée."
            )},

            // 1. Password in Cleartext (demo hardcoded secret)
            { "PwClearLabel",   Tuple.Create("1. Password in Cleartext", "1. Mot de passe en clair") },
            { "PwClearDesc",    Tuple.Create("Password is stored/checked in cleartext (hardcoded).", "Mot de passe stocké/vérifié en clair (en dur).") },
            { "TriggerPwClear", Tuple.Create("Login (Insecure)", "Connexion (Non sécurisée)") },

            // 2. Weak/Predictable Token
            { "TokenLabel",     Tuple.Create("2. Weak Token Generation", "2. Génération de jeton faible") },
            { "TokenDesc",      Tuple.Create("Token is predictable (time + Random).", "Jeton prévisible (horloge + Random).") },
            { "TriggerToken",   Tuple.Create("Generate Token", "Générer le jeton") },

            // 3. No Brute Force Protection
            { "NoLockoutLabel",   Tuple.Create("3. No Brute Force Protection", "3. Pas de verrouillage (bruteforce)") },
            { "NoLockoutDesc",    Tuple.Create("No failed login limit enables brute-force.", "Aucune limite d’échecs permet le bruteforce.") },
            { "TriggerNoLockout", Tuple.Create("Try Login", "Essayer la connexion") },

            // 4. Session Fixation
            { "SessFixLabel",   Tuple.Create("4. Session Fixation", "4. Fixation de session") },
            { "SessFixDesc",    Tuple.Create("Accepts attacker-provided session ID (no regeneration).", "Accepte un ID de session fourni par l’attaquant (non régénéré).") },
            { "TriggerSessFix", Tuple.Create("Fix Session ID", "Fixer l’ID de session") },

            // 5. Missing MFA + MD5
            { "MfaLabel",   Tuple.Create("5. Missing MFA + Weak Hash", "5. Absence de MFA + hash faible") },
            { "MfaDesc",    Tuple.Create("MD5 password check, no MFA step.", "Vérification MD5, aucune étape MFA.") },
            { "TriggerMfa", Tuple.Create("Login Without MFA", "Connexion sans MFA") },

            // 6. Global Session
            { "GlobalSessLabel",   Tuple.Create("6. Global Session (never invalidated)", "6. Session globale (jamais invalidée)") },
            { "GlobalSessDesc",    Tuple.Create("Single in-memory session shared by all.", "Session en mémoire, partagée par tous.") },
            { "TriggerGlobalSess", Tuple.Create("Show Global Session", "Afficher la session globale") },

            // 7. No Session Expiration
            { "NoExpiryLabel",   Tuple.Create("7. No Session Expiration", "7. Absence d’expiration de session") },
            { "NoExpiryDesc",    Tuple.Create("No timeout/expiry mechanics.", "Aucun timeout / aucune expiration.") },
            { "TriggerNoExpiry", Tuple.Create("Show No-Expiry", "Afficher No-Expiry") },

            // 8. Reuse Session Across Users
            { "ReuseSessLabel",   Tuple.Create("8. Reuse Session Across Users", "8. Réutilisation de session entre utilisateurs") },
            { "ReuseSessDesc",    Tuple.Create("Same ID reused for another user.", "Même ID réutilisé pour un autre utilisateur.") },
            { "TriggerReuseSess", Tuple.Create("Reuse Session", "Réutiliser la session") },

            // 9. Weak Session ID
            { "WeakSidLabel",    Tuple.Create("9. Weak Session ID", "9. ID de session faible") },
            { "WeakSidDesc",     Tuple.Create("Generate a short, predictable session ID.", "Génère un ID de session court et prévisible.") },
            { "TriggerWeakSid",  Tuple.Create("Generate Weak SID", "Générer un SID faible") },

            // 10. Predictable Password Reset Token
            { "ResetLabel",           Tuple.Create("10. Predictable Password Reset Token", "10. Jeton de réinitialisation prévisible") },
            { "ResetDesc",            Tuple.Create("Token = Base64(username:utcTicks) — predictable & forgeable.", "Jeton = Base64(username:utcTicks) — prévisible et falsifiable.") },
            { "TriggerResetToken",    Tuple.Create("Generate Reset Token", "Générer le jeton de reset") },
            { "ResetUserPlaceholder", Tuple.Create("alice", "alice") },

            // 11. Remember-Me persisted in clear
            { "RememberLabel",            Tuple.Create("11. Remember-Me (plaintext, world-readable)", "11. Remember-Me (clair, lisible par tous)") },
            { "RememberDesc",             Tuple.Create("Stores a long-lived token under Public Documents.", "Stocke un token longue durée dans Documents publics.") },
            { "TriggerRememberMe",        Tuple.Create("Persist Remember-Me", "Persister le Remember-Me") },
            { "RememberUserPlaceholder",  Tuple.Create("bob", "bob") },

            // 12. Insecure TLS Login (trust-all)
            { "TlsLabel",          Tuple.Create("12. Insecure TLS Login (trust-all)", "12. Connexion TLS non sécurisée (trust-all)") },
            { "TlsDesc",           Tuple.Create("Disables certificate validation and POSTs credentials.", "Désactive la vérification du certificat et envoie les identifiants en POST.") },
            { "TriggerTlsLogin",   Tuple.Create("Send Insecure Login", "Envoyer la connexion non sécurisée") },
            { "TlsUrlPlaceholder", Tuple.Create("https://self-signed.local/login", "https://self-signed.local/login") },
            { "TlsUserPlaceholder",Tuple.Create("user", "utilisateur") },
            { "TlsPwPlaceholder",  Tuple.Create("secret", "secret") },

            // 13. Insecure Deserialization
            { "DeserializeLabel",       Tuple.Create("13. Insecure Deserialization (BinaryFormatter)", "13. Désérialisation non sécurisée (BinaryFormatter)") },
            { "DeserializeDesc",        Tuple.Create("Base64 input is deserialized via BinaryFormatter.", "L’entrée Base64 est désérialisée via BinaryFormatter.") },
            { "TriggerDeserialize",     Tuple.Create("Deserialize", "Désérialiser") },
            { "DeserializePlaceholder", Tuple.Create("AAEAAAD/////AQAAAAAAAAAEAQAA...", "AAEAAAD/////AQAAAAAAAAAEAQAA...") },

            // 14. AES-ECB for Session Data
            { "EcbLabel",           Tuple.Create("14. AES-ECB for Session Data", "14. AES-ECB pour les données de session") },
            { "EcbDesc",            Tuple.Create("Encrypts JSON with AES-ECB (hardcoded key).", "Chiffre du JSON en AES-ECB (clé en dur).") },
            { "TriggerEcb",         Tuple.Create("Encrypt (ECB)", "Chiffrer (ECB)") },
            { "EcbJsonPlaceholder", Tuple.Create("{ \"sid\": \"abc123\", \"role\": \"admin\" }", "{ \"sid\": \"abc123\", \"role\": \"admin\" }") },

            // 15. Log Sensitive Token
            { "LogLabel",            Tuple.Create("15. Log Sensitive Token", "15. Journaliser un jeton sensible") },
            { "LogDesc",             Tuple.Create("Writes token into a temp log file (PII leak).", "Écrit le jeton dans un fichier de log temporaire (fuite PII).") },
            { "TriggerLogToken",     Tuple.Create("Log Token", "Journaliser le jeton") },
            { "LogTokenPlaceholder", Tuple.Create("eyJhbGciOi...", "eyJhbGciOi...") },
        };


        private string _lang = "en";
        private int noLockoutAttempts = 0;
        private string fixedSessionId = "";

        public DA02AuthWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage("en");

            // Payloads par défaut
            PwClearInput.Text = "password123";
            SessFixInput.Text = "SESSIONID-ATTACKER";
            NoLockoutUserInput.Text = "admin";
            NoLockoutPwInput.Text = "wrong";
            MfaUserInput.Text = "bob";
            MfaPwInput.Text = "secret";
        }

        private void LanguageSelector_Changed(object sender, SelectionChangedEventArgs e)
        {
            var lang = (LanguageSelector.SelectedIndex == 1) ? "fr" : "en";
            SetLanguage(lang);
        }
        private string GetLabel(string key, string lang)
        {
            return lang == "fr" ? labels[key].Item2 : labels[key].Item1;
        }

        private void SetLanguage(string lang)
        {
            _lang = lang;

            // Title / Intro
            Title = GetLabel("Title", lang);
            (FindName("TitleText") as TextBlock).Text = GetLabel("Title", lang);
            (FindName("IntroText") as TextBlock).Text = GetLabel("Intro", lang);

            // 1. Pw clear (hardcoded)
            (FindName("PwClearLabel") as TextBlock).Text = GetLabel("PwClearLabel", lang);
            (FindName("PwClearDesc") as TextBlock).Text = GetLabel("PwClearDesc", lang);
            (FindName("PwClearButton") as Button).Content = GetLabel("TriggerPwClear", lang);

            // 2. Weak token
            (FindName("TokenLabel") as TextBlock).Text = GetLabel("TokenLabel", lang);
            (FindName("TokenDesc") as TextBlock).Text = GetLabel("TokenDesc", lang);
            (FindName("TokenButton") as Button).Content = GetLabel("TriggerToken", lang);

            // 3. No lockout
            (FindName("NoLockoutLabel") as TextBlock).Text = GetLabel("NoLockoutLabel", lang);
            (FindName("NoLockoutDesc") as TextBlock).Text = GetLabel("NoLockoutDesc", lang);
            (FindName("NoLockoutButton") as Button).Content = GetLabel("TriggerNoLockout", lang);

            // 4. Session Fixation
            (FindName("SessFixLabel") as TextBlock).Text = GetLabel("SessFixLabel", lang);
            (FindName("SessFixDesc") as TextBlock).Text = GetLabel("SessFixDesc", lang);
            (FindName("SessFixButton") as Button).Content = GetLabel("TriggerSessFix", lang);

            // 5. Missing MFA + MD5
            (FindName("MfaLabel") as TextBlock).Text = GetLabel("MfaLabel", lang);
            (FindName("MfaDesc") as TextBlock).Text = GetLabel("MfaDesc", lang);
            (FindName("MfaButton") as Button).Content = GetLabel("TriggerMfa", lang);

            // 6. Global Session
            if (FindName("GlobalSessLabel") is TextBlock gsl)
            {
                gsl.Text = GetLabel("GlobalSessLabel", lang);
                (FindName("GlobalSessDesc") as TextBlock).Text = GetLabel("GlobalSessDesc", lang);
                (FindName("GlobalSessButton") as Button).Content = GetLabel("TriggerGlobalSess", lang);
            }

            // 7. No Session Expiration
            if (FindName("NoExpiryLabel") is TextBlock nel)
            {
                nel.Text = GetLabel("NoExpiryLabel", lang);
                (FindName("NoExpiryDesc") as TextBlock).Text = GetLabel("NoExpiryDesc", lang);
                (FindName("NoExpiryButton") as Button).Content = GetLabel("TriggerNoExpiry", lang);
            }

            // 8. Reuse Session Across Users
            if (FindName("ReuseSessLabel") is TextBlock rsl)
            {
                rsl.Text = GetLabel("ReuseSessLabel", lang);
                (FindName("ReuseSessDesc") as TextBlock).Text = GetLabel("ReuseSessDesc", lang);
                (FindName("ReuseSessButton") as Button).Content = GetLabel("TriggerReuseSess", lang);
            }

            // 9. Weak SID
            if (FindName("WeakSidLabel") is TextBlock wsl)
            {
                wsl.Text = GetLabel("WeakSidLabel", lang);
                (FindName("WeakSidDesc") as TextBlock).Text = GetLabel("WeakSidDesc", lang);
                (FindName("WeakSidButton") as Button).Content = GetLabel("TriggerWeakSid", lang);
            }

            // 10. Predictable Reset Token
            if (FindName("ResetLabel") is TextBlock rl)
            {
                rl.Text = GetLabel("ResetLabel", lang);
                (FindName("ResetDesc") as TextBlock).Text = GetLabel("ResetDesc", lang);
                (FindName("ResetTokenButton") as Button).Content = GetLabel("TriggerResetToken", lang);
                if (FindName("ResetUserInput") is TextBox rui)
                    rui.Text = GetLabel("ResetUserPlaceholder", lang);
            }

            // 11. Remember-Me plaintext
            if (FindName("RememberLabel") is TextBlock rml)
            {
                rml.Text = GetLabel("RememberLabel", lang);
                (FindName("RememberDesc") as TextBlock).Text = GetLabel("RememberDesc", lang);
                (FindName("RememberMeButton") as Button).Content = GetLabel("TriggerRememberMe", lang);
                if (FindName("RememberUserInput") is TextBox rmui)
                    rmui.Text = GetLabel("RememberUserPlaceholder", lang);
            }

            // 12. Insecure TLS Login
            if (FindName("TlsLabel") is TextBlock tl)
            {
                tl.Text = GetLabel("TlsLabel", lang);
                (FindName("TlsDesc") as TextBlock).Text = GetLabel("TlsDesc", lang);
                (FindName("TlsLoginButton") as Button).Content = GetLabel("TriggerTlsLogin", lang);
                if (FindName("TlsUrlInput") is TextBox turl) turl.Text = GetLabel("TlsUrlPlaceholder", lang);
                if (FindName("TlsUserInput") is TextBox tusr) tusr.Text = GetLabel("TlsUserPlaceholder", lang);
                if (FindName("TlsPwInput") is TextBox tpw) tpw.Text = GetLabel("TlsPwPlaceholder", lang);
            }

            // 13. Insecure Deserialization
            if (FindName("DeserializeLabel") is TextBlock dl)
            {
                dl.Text = GetLabel("DeserializeLabel", lang);
                (FindName("DeserializeDesc") as TextBlock).Text = GetLabel("DeserializeDesc", lang);
                (FindName("DeserializeButton") as Button).Content = GetLabel("TriggerDeserialize", lang);
                if (FindName("DeserializeInput") is TextBox din)
                    din.Text = GetLabel("DeserializePlaceholder", lang);
            }

            // 14. AES-ECB
            if (FindName("EcbLabel") is TextBlock el)
            {
                el.Text = GetLabel("EcbLabel", lang);
                (FindName("EcbDesc") as TextBlock).Text = GetLabel("EcbDesc", lang);
                (FindName("EcbButton") as Button).Content = GetLabel("TriggerEcb", lang);
                if (FindName("EcbJsonInput") is TextBox ejson)
                    ejson.Text = GetLabel("EcbJsonPlaceholder", lang);
            }

            // 15. Log Sensitive Token
            if (FindName("LogLabel") is TextBlock ll)
            {
                ll.Text = GetLabel("LogLabel", lang);
                (FindName("LogDesc") as TextBlock).Text = GetLabel("LogDesc", lang);
                (FindName("LogTokenButton") as Button).Content = GetLabel("TriggerLogToken", lang);
                if (FindName("LogTokenInput") is TextBox lti)
                    lti.Text = GetLabel("LogTokenPlaceholder", lang);
            }
        }

    }

    public partial class DA02AuthWindow
    {
        private void PwClearButton_Click(object sender, RoutedEventArgs e)
        {
            AuthSessionVuln.HardcodedPassword();
            if (FindName("PwClearResult") is TextBlock r)
                r.Text = _lang == "fr" ? "Voir pop-up (secret en dur)." : "See popup (hardcoded secret).";
        }

        private void TokenButton_Click(object sender, RoutedEventArgs e)
        {
            AuthSessionVuln.PredictableToken();
            if (FindName("TokenResult") is TextBlock r)
                r.Text = _lang == "fr" ? "Jeton prévisible (voir pop-up)." : "Predictable token (see popup).";
        }

        private void NoLockoutButton_Click(object sender, RoutedEventArgs e)
        {
            AuthSessionVuln.NoBruteForceProtection();
            if (FindName("NoLockoutResult") is TextBlock r)
                r.Text = _lang == "fr" ? "Aucun verrouillage (voir pop-up)." : "No lockout (see popup).";
        }

        private void SessFixButton_Click(object sender, RoutedEventArgs e)
        {
            var attackerId = (FindName("SessFixInput") as TextBox)?.Text ?? "FIXED-123";
            AuthSessionVuln.SessionFixation(attackerId);
            if (FindName("SessFixResult") is TextBlock r)
                r.Text = _lang == "fr" ? $"Session fixée (voir pop-up): {attackerId}"
                                       : $"Session fixed (see popup): {attackerId}";
        }

        private void MfaButton_Click(object sender, RoutedEventArgs e)
        {
            var u = (FindName("MfaUserInput") as TextBox)?.Text ?? "bob";
            var p = (FindName("MfaPwInput") as TextBox)?.Text ?? "secret";
            AuthSessionVuln.LoginWithoutMfa(u, p);
            if (FindName("MfaResult") is TextBlock r)
                r.Text = _lang == "fr" ? "Connexion sans MFA (voir pop-up)." : "Login without MFA (see popup).";
        }

        private void GlobalSessButton_Click(object sender, RoutedEventArgs e)
        {
            AuthSessionVuln.GlobalSession();
            if (FindName("GlobalSessResult") is TextBlock r)
                r.Text = _lang == "fr" ? "Session globale affichée." : "Global session shown.";
        }

        private void NoExpiryButton_Click(object sender, RoutedEventArgs e)
        {
            AuthSessionVuln.NoSessionExpiration();
            if (FindName("NoExpiryResult") is TextBlock r)
                r.Text = _lang == "fr" ? "Session sans expiration affichée." : "No-expiry session shown.";
        }

        private void ReuseSessButton_Click(object sender, RoutedEventArgs e)
        {
            AuthSessionVuln.ReuseSession();
            if (FindName("ReuseSessResult") is TextBlock r)
                r.Text = _lang == "fr" ? "Session réutilisée (voir pop-up)." : "Session reused (see popup).";
        }

        private void WeakSidButton_Click(object sender, RoutedEventArgs e)
        {
            AuthSessionVuln.WeakSessionIdGeneration();
            (FindName("WeakSidResult") as TextBlock).Text = _lang == "fr" ? "SID faible généré (voir pop-up)." : "Weak SID generated (see popup).";
        }

        private void ResetTokenButton_Click(object sender, RoutedEventArgs e)
        {
            var user = (FindName("ResetUserInput") as TextBox)?.Text ?? "alice";
            AuthSessionVuln.InsecureResetToken(user);
            (FindName("ResetResult") as TextBlock).Text = _lang == "fr" ? "Token de reset généré." : "Reset token generated.";
        }

        private void RememberMeButton_Click(object sender, RoutedEventArgs e)
        {
            var user = (FindName("RememberUserInput") as TextBox)?.Text ?? "bob";
            AuthSessionVuln.RememberMePersist(user);
            (FindName("RememberResult") as TextBlock).Text = _lang == "fr" ? "Token remember-me stocké." : "Remember-me token stored.";
        }

        private void TlsLoginButton_Click(object sender, RoutedEventArgs e)
        {
            var url = (FindName("TlsUrlInput") as TextBox)?.Text ?? "https://self-signed.local/login";
            var u = (FindName("TlsUserInput") as TextBox)?.Text ?? "user";
            var p = (FindName("TlsPwInput") as TextBox)?.Text ?? "secret";
            AuthSessionVuln.InsecureTlsLogin(url, u, p);
            (FindName("TlsResult") as TextBlock).Text = _lang == "fr" ? "Requête envoyée (voir pop-up)." : "Request sent (see popup).";
        }

        private void DeserializeButton_Click(object sender, RoutedEventArgs e)
        {
            var b64 = (FindName("DeserializeInput") as TextBox)?.Text ?? "";
            AuthSessionVuln.InsecureDeserializeSession(b64);
            (FindName("DeserializeResult") as TextBlock).Text = _lang == "fr" ? "Désérialisation effectuée." : "Deserialization attempted.";
        }

        private void EcbButton_Click(object sender, RoutedEventArgs e)
        {
            var json = (FindName("EcbJsonInput") as TextBox)?.Text ?? "{}";
            AuthSessionVuln.EncryptSessionWithEcb(json);
            (FindName("EcbResult") as TextBlock).Text = _lang == "fr" ? "Chiffrement ECB effectué." : "ECB encryption done.";
        }

        private void LogTokenButton_Click(object sender, RoutedEventArgs e)
        {
            var tok = (FindName("LogTokenInput") as TextBox)?.Text ?? "<empty>";
            AuthSessionVuln.LogSensitiveToken(tok);
            (FindName("LogResult") as TextBlock).Text = _lang == "fr" ? "Token écrit dans le log." : "Token written to log.";
        }

    }
}
