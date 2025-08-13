using NetFrmk_Desktop_InsecureApp.Vulnerabilities;
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA08MisconfigWindow : Window
    {
        private string _lang = "en";

        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA08 – Security Misconfiguration", "DA08 – Mauvaise configuration sécurité") },
            { "Intro", Tuple.Create("Common misconfigurations in .NET desktop apps. Sinks are intentionally vulnerable for SAST demos.", "Mauvaises configurations fréquentes dans les applis .NET desktop. Sinks volontairement vulnérables pour les démos SAST.") },

            { "AppConfigLabel", Tuple.Create("1. Plaintext secrets in App.config", "1. Secrets en clair dans App.config") },
            { "AppConfigDesc", Tuple.Create("Sensitive keys/passwords stored unencrypted in config.", "Clés/mots de passe sensibles stockés non chiffrés.") },
            { "AppConfigButton", Tuple.Create("Test Config Secret", "Tester secret config") },

            { "AbsPathLabel", Tuple.Create("2. Hardcoded absolute path", "2. Chemin absolu codé en dur") },
            { "AbsPathDesc", Tuple.Create("Files referenced with fixed drive/root paths.", "Fichiers/répertoires référencés avec des chemins fixes.") },
            { "AbsPathButton", Tuple.Create("Test Abs Path", "Tester chemin absolu") },

            { "VerboseLogLabel", Tuple.Create("3. Verbose logging in production", "3. Logs verbeux en production") },
            { "VerboseLogDesc", Tuple.Create("Debug logs left enabled in prod builds.", "Traces debug actives en production.") },
            { "VerboseLogButton", Tuple.Create("Test Verbose Log", "Tester logs verbeux") },

            { "TempDirLabel", Tuple.Create("4. Global/shared temp directory", "4. Répertoire temporaire partagé") },
            { "TempDirDesc", Tuple.Create("Use of world-writable temp folders for critical files.", "Usage de dossiers temp accessibles à tous.") },
            { "TempDirButton", Tuple.Create("Test Temp Dir", "Tester temp partagé") },

            { "PrivKeyLabel", Tuple.Create("5. Private key/cert in project", "5. Clé privée/certificat dans le projet") },
            { "PrivKeyDesc", Tuple.Create("Sensitive credentials shipped with the app.", "Identifiants sensibles inclus dans le binaire.") },
            { "PrivKeyButton", Tuple.Create("Test Private Key", "Tester clé privée") },

            { "WidePermLabel", Tuple.Create("6. Wide permissions (Everyone)", "6. Permissions larges (Everyone)") },
            { "WidePermDesc", Tuple.Create("Critical files/folders with world access rights.", "Fichiers/répertoires sensibles accessibles à tous.") },
            { "WidePermButton", Tuple.Create("Test Wide Perm", "Tester droits Everyone") },

            { "HostsLabel", Tuple.Create("7. Writable hosts/system files", "7. Fichiers hosts/système éditables") },
            { "HostsDesc", Tuple.Create("App or user can edit system config like hosts.", "L’application ou l’utilisateur peut éditer les fichiers système.") },
            { "HostsButton", Tuple.Create("Test Hosts Write", "Tester écriture hosts") },

            { "DebugLabel", Tuple.Create("8. Debug mode enabled in prod", "8. Mode debug actif en prod") },
            { "DebugDesc", Tuple.Create("Debug compilation or runtime flags enabled in release.", "Flags debug actifs en production.") },
            { "DebugButton", Tuple.Create("Test Debug", "Tester debug") },

            { "CryptoLabel", Tuple.Create("9. Weak cryptography", "9. Crypto faible") },
            { "CryptoDesc", Tuple.Create("Use of outdated/insecure algorithms (e.g., MD5, DES).", "Utilisation d’algorithmes obsolètes (MD5, DES…).") },
            { "CryptoButton", Tuple.Create("Test Crypto", "Tester crypto") },

            { "IPCLabel", Tuple.Create("10. Insecure IPC", "10. IPC non sécurisé") },
            { "IPCDesc", Tuple.Create("IPC endpoints with no auth or encryption.", "Points de communication inter-processus sans auth ni chiffrement.") },
            { "IPCButton", Tuple.Create("Test IPC", "Tester IPC") },

            { "AdminLabel", Tuple.Create("11. Runs as admin by default", "11. Exécution admin par défaut") },
            { "AdminDesc", Tuple.Create("App runs with administrator privileges by default.", "L’app tourne par défaut avec les droits admin.") },
            { "AdminButton", Tuple.Create("Test Admin", "Tester admin") },

            // New 12..15
            { "CertLabel", Tuple.Create("12. TLS: accept-all certificates (global bypass)", "12. TLS : accepter tous les certificats (contournement global)") },
            { "CertDesc", Tuple.Create("Disables TLS certificate validation via ServicePointManager.", "Désactive la validation des certificats TLS via ServicePointManager.") },
            { "CertButton", Tuple.Create("Disable & Test", "Désactiver & Tester") },

            { "ListenerLabel", Tuple.Create("13. HTTP listener on 0.0.0.0", "13. Écoute HTTP sur 0.0.0.0") },
            { "ListenerDesc", Tuple.Create("Binds HttpListener to all interfaces (http://+:port/).", "Lie HttpListener à toutes les interfaces (http://+:port/).") },
            { "ListenerButton", Tuple.Create("Bind & Stop", "Lier & Arrêter") },

            { "JsonNetLabel", Tuple.Create("14. Json.NET TypeNameHandling=All", "14. Json.NET TypeNameHandling=All") },
            { "JsonNetDesc", Tuple.Create("Deserializes with type binding enabled (dangerous).", "Désérialise avec résolution de type activée (dangereux).") },
            { "JsonNetButton", Tuple.Create("Deserialize", "Désérialiser") },

            { "DefaultCredsLabel", Tuple.Create("15. Default credentials (admin/admin)", "15. Identifiants par défaut (admin/admin)") },
            { "DefaultCredsDesc", Tuple.Create("Hardcoded default admin credentials are accepted.", "Des identifiants admin par défaut sont acceptés.") },
            { "DefaultCredsButton", Tuple.Create("Login", "Se connecter") },
        };

        public DA08MisconfigWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage(_lang);
            SetPlaceholders();
        }

        private string GetLabel(string key) => _lang == "fr" ? labels[key].Item2 : labels[key].Item1;

        private void LanguageSelector_Changed(object sender, SelectionChangedEventArgs e)
        {
            _lang = LanguageSelector.SelectedIndex == 1 ? "fr" : "en";
            SetLanguage(_lang);
        }

        private void SetLanguage(string lang)
        {
            Title = GetLabel("Title");
            TitleText.Text = GetLabel("Title");
            IntroText.Text = GetLabel("Intro");

            AppConfigLabel.Text = GetLabel("AppConfigLabel"); AppConfigDesc.Text = GetLabel("AppConfigDesc"); AppConfigButton.Content = GetLabel("AppConfigButton");
            AbsPathLabel.Text = GetLabel("AbsPathLabel"); AbsPathDesc.Text = GetLabel("AbsPathDesc"); AbsPathButton.Content = GetLabel("AbsPathButton");
            VerboseLogLabel.Text = GetLabel("VerboseLogLabel"); VerboseLogDesc.Text = GetLabel("VerboseLogDesc"); VerboseLogButton.Content = GetLabel("VerboseLogButton");
            TempDirLabel.Text = GetLabel("TempDirLabel"); TempDirDesc.Text = GetLabel("TempDirDesc"); TempDirButton.Content = GetLabel("TempDirButton");
            PrivKeyLabel.Text = GetLabel("PrivKeyLabel"); PrivKeyDesc.Text = GetLabel("PrivKeyDesc"); PrivKeyButton.Content = GetLabel("PrivKeyButton");
            WidePermLabel.Text = GetLabel("WidePermLabel"); WidePermDesc.Text = GetLabel("WidePermDesc"); WidePermButton.Content = GetLabel("WidePermButton");
            HostsLabel.Text = GetLabel("HostsLabel"); HostsDesc.Text = GetLabel("HostsDesc"); HostsButton.Content = GetLabel("HostsButton");
            DebugLabel.Text = GetLabel("DebugLabel"); DebugDesc.Text = GetLabel("DebugDesc"); DebugButton.Content = GetLabel("DebugButton");
            CryptoLabel.Text = GetLabel("CryptoLabel"); CryptoDesc.Text = GetLabel("CryptoDesc"); CryptoButton.Content = GetLabel("CryptoButton");
            IPCLabel.Text = GetLabel("IPCLabel"); IPCDesc.Text = GetLabel("IPCDesc"); IPCButton.Content = GetLabel("IPCButton");
            AdminLabel.Text = GetLabel("AdminLabel"); AdminDesc.Text = GetLabel("AdminDesc"); AdminButton.Content = GetLabel("AdminButton");

            CertLabel.Text = GetLabel("CertLabel"); CertDesc.Text = GetLabel("CertDesc"); CertButton.Content = GetLabel("CertButton");
            ListenerLabel.Text = GetLabel("ListenerLabel"); ListenerDesc.Text = GetLabel("ListenerDesc"); ListenerButton.Content = GetLabel("ListenerButton");
            JsonNetLabel.Text = GetLabel("JsonNetLabel"); JsonNetDesc.Text = GetLabel("JsonNetDesc"); JsonNetButton.Content = GetLabel("JsonNetButton");
            DefaultCredsLabel.Text = GetLabel("DefaultCredsLabel"); DefaultCredsDesc.Text = GetLabel("DefaultCredsDesc"); DefaultCredsButton.Content = GetLabel("DefaultCredsButton");
        }

        private void SetPlaceholders()
        {
            TrySet("CertUrlInput", "https://self-signed.badssl.com/"); // example HTTPS
            TrySet("ListenerPrefixInput", "http://+:8081/test/");
            TrySet("JsonNetInput", "{\"$type\":\"System.Version, mscorlib\",\"Major\":1,\"Minor\":2,\"Build\":3,\"Revision\":4}");
            TrySet("DefaultUserInput", "admin");
            TrySet("DefaultPassInput", "admin");
        }

        private void TrySet(string name, string value)
        {
            var tb = FindName(name) as TextBox;
            if (tb != null) tb.Text = value;
        }

        // ===== Handlers =====
        private void AppConfigButton_Click(object sender, RoutedEventArgs e) => MisconfigVuln.AppConfigSecret();
        private void AbsPathButton_Click(object sender, RoutedEventArgs e) => MisconfigVuln.HardcodedAbsolutePath();
        private void VerboseLogButton_Click(object sender, RoutedEventArgs e) => MisconfigVuln.VerboseLogging();
        private void TempDirButton_Click(object sender, RoutedEventArgs e) => MisconfigVuln.GlobalTempDir();
        private void PrivKeyButton_Click(object sender, RoutedEventArgs e) => MisconfigVuln.PrivateKeyInProject();
        private void WidePermButton_Click(object sender, RoutedEventArgs e) => MisconfigVuln.WidePermissions();
        private void HostsButton_Click(object sender, RoutedEventArgs e) => MisconfigVuln.WritableHosts();
        private void DebugButton_Click(object sender, RoutedEventArgs e) => MisconfigVuln.DebugModeEnabled();
        private void CryptoButton_Click(object sender, RoutedEventArgs e) => MisconfigVuln.WeakCryptography();
        private void IPCButton_Click(object sender, RoutedEventArgs e) => MisconfigVuln.InsecureIPC();
        private void AdminButton_Click(object sender, RoutedEventArgs e) => MisconfigVuln.RunAsAdmin();

        private void CertButton_Click(object sender, RoutedEventArgs e) => CertResult.Text = MisconfigVuln.DisableCertValidation(CertUrlInput.Text);
        private void ListenerButton_Click(object sender, RoutedEventArgs e) => ListenerResult.Text = MisconfigVuln.HttpListenerAnyHost(ListenerPrefixInput.Text);
        private void JsonNetButton_Click(object sender, RoutedEventArgs e) => JsonNetResult.Text = MisconfigVuln.JsonNetTypeNameHandlingAll(JsonNetInput.Text);
        private void DefaultCredsButton_Click(object sender, RoutedEventArgs e) => DefaultCredsResult.Text = MisconfigVuln.DefaultCredentials(DefaultUserInput.Text, DefaultPassInput.Text);
    }
}
