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
            { "Title", Tuple.Create("DA02 – Broken Authentication", "DA02 – Authentification non sécurisée") },
            { "Intro", Tuple.Create("Test various broken authentication flaws: password in cleartext, weak token, no lockout, session fixation, missing MFA.",
                         "Testez plusieurs failles d'authentification : mot de passe en clair, token faible, pas de verrouillage, fixation de session, absence de MFA.") },
            { "PwClearLabel", Tuple.Create("1. Password in Cleartext", "1. Mot de passe en clair") },
            { "PwClearDesc", Tuple.Create("Password is stored and compared in cleartext!", "Le mot de passe est stocké et comparé en clair !") },
            { "TriggerPwClear", Tuple.Create("Login (Insecure)", "Connexion (Non sécurisé)") },
            { "TokenLabel", Tuple.Create("2. Weak Token Generation", "2. Génération de jeton faible") },
            { "TokenDesc", Tuple.Create("Token is just a predictable string.", "Le jeton est une simple chaîne prévisible.") },
            { "TriggerToken", Tuple.Create("Generate Token", "Générer le jeton") },
            { "NoLockoutLabel", Tuple.Create("3. No Account Lockout", "3. Aucun verrouillage de compte") },
            { "NoLockoutDesc", Tuple.Create("Unlimited login attempts allowed (no lockout)", "Nombre illimité d'essais de connexion (aucun verrouillage)") },
            { "TriggerNoLockout", Tuple.Create("Login (Bruteforce)", "Connexion (bruteforce)") },
            { "SessFixLabel", Tuple.Create("4. Session Fixation", "4. Fixation de session") },
            { "SessFixDesc", Tuple.Create("Session ID reused if attacker sets it before login.", "L'ID de session est réutilisé si l'attaquant le définit avant connexion.") },
            { "TriggerSessFix", Tuple.Create("Fix Session", "Fixer la session") },
            { "MfaLabel", Tuple.Create("5. Missing MFA", "5. Absence de MFA") },
            { "MfaDesc", Tuple.Create("Login has no MFA step.", "Aucune vérification MFA à la connexion.") },
            { "TriggerMfa", Tuple.Create("Login", "Connexion") },
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
            Title= GetLabel("Title",lang);
            TitleText.Text= GetLabel("Title",lang);
            IntroText.Text= GetLabel("Intro",lang);

            PwClearLabel.Text= GetLabel("PwClearLabel",lang);
            PwClearDesc.Text= GetLabel("PwClearDesc",lang);
            PwClearButton.Content= GetLabel("TriggerPwClear",lang);

            TokenLabel.Text= GetLabel("TokenLabel",lang);
            TokenDesc.Text= GetLabel("TokenDesc",lang);
            TokenButton.Content= GetLabel("TriggerToken",lang);

            NoLockoutLabel.Text= GetLabel("NoLockoutLabel",lang);
            NoLockoutDesc.Text= GetLabel("NoLockoutDesc",lang);
            NoLockoutButton.Content= GetLabel("TriggerNoLockout",lang);

            SessFixLabel.Text= GetLabel("SessFixLabel",lang);
            SessFixDesc.Text= GetLabel("SessFixDesc",lang);
            SessFixButton.Content= GetLabel("TriggerSessFix",lang);

            MfaLabel.Text= GetLabel("MfaLabel",lang);
            MfaDesc.Text= GetLabel("MfaDesc",lang);
            MfaButton.Content= GetLabel("TriggerMfa",lang);

            // Réinitialise aussi les payloads pour chaque langue si besoin
            if (lang == "fr")
            {
                PwClearInput.Text = "motdepasse123";
                SessFixInput.Text = "SESSIONID-ATTAQUANT";
                NoLockoutUserInput.Text = "admin";
                NoLockoutPwInput.Text = "erreur";
                MfaUserInput.Text = "bob";
                MfaPwInput.Text = "secret";
            }
            else
            {
                PwClearInput.Text = "password123";
                SessFixInput.Text = "SESSIONID-ATTACKER";
                NoLockoutUserInput.Text = "admin";
                NoLockoutPwInput.Text = "wrong";
                MfaUserInput.Text = "bob";
                MfaPwInput.Text = "secret";
            }
        }
    }

    public partial class DA02AuthWindow
    {
        private void PwClearButton_Click(object sender, RoutedEventArgs e)
        {
            // Vulnérabilité: mot de passe stocké/comparé en clair
            string pwd = PwClearInput.Text;
            if (pwd == "password123" || pwd == "motdepasse123")
                PwClearResult.Text = _lang == "fr" ? "Connexion réussie (en clair) !" : "Login success (cleartext)!";
            else
                PwClearResult.Text = _lang == "fr" ? "Échec de connexion." : "Login failed.";
        }

        private void TokenButton_Click(object sender, RoutedEventArgs e)
        {
            // Vulnérabilité: jeton faible/prévisible
            var rnd = new Random();
            var token = "token_" + rnd.Next(1000, 9999);
            TokenOutput.Text = token;
            TokenResult.Text = _lang == "fr" ? "Jeton généré (non sécurisé)." : "Token generated (not secure).";
        }

        private void NoLockoutButton_Click(object sender, RoutedEventArgs e)
        {
            // Vulnérabilité: aucune limite d'essais (bruteforce possible)
            noLockoutAttempts++;
            if ((NoLockoutUserInput.Text == "admin") && (NoLockoutPwInput.Text == "bruteforce"))
            {
                NoLockoutResult.Text = _lang == "fr" ? "Connexion admin réussie !" : "Admin login success!";
                noLockoutAttempts = 0;
            }
            else
            {
                NoLockoutResult.Text = string.Format(
                    _lang == "fr" ? "Tentative #{0} – toujours aucun verrouillage." : "Attempt #{0} – still no lockout.",
                    noLockoutAttempts);
            }
        }

        private void SessFixButton_Click(object sender, RoutedEventArgs e)
        {
            // Vulnérabilité: session fixation
            fixedSessionId = SessFixInput.Text;
            SessFixResult.Text = _lang == "fr"
                ? $"Session fixée sur : {fixedSessionId} (risque de fixation)"
                : $"Session fixed to: {fixedSessionId} (fixation risk)";
        }

        private void MfaButton_Click(object sender, RoutedEventArgs e)
        {
            // Vulnérabilité: pas de MFA
            if (MfaUserInput.Text == "bob" && MfaPwInput.Text == "secret")
                MfaResult.Text = _lang == "fr" ? "Connexion SANS MFA !" : "Login WITHOUT MFA!";
            else
                MfaResult.Text = _lang == "fr" ? "Échec de connexion." : "Login failed.";
        }
    }
}
