using NetFrmk_Desktop_InsecureApp.Vulnerabilities;
using System;
using System.Collections.Generic;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA08MisconfigWindow : Window
    {
        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA08 – Security Misconfiguration", "DA08 – Mauvaise configuration sécurité") },
            { "Intro", Tuple.Create("This module demonstrates common security misconfigurations in .NET desktop apps.", "Ce module illustre les mauvaises configurations courantes dans les applis .NET desktop.") },

            { "AppConfigLabel", Tuple.Create("Plaintext secrets in App.config", "Secrets en clair dans App.config") },
            { "AppConfigDesc", Tuple.Create("Sensitive keys/passwords stored unencrypted in config.", "Clés/mots de passe sensibles stockés non chiffrés.") },
            { "AppConfigButton", Tuple.Create("Test Config Secret", "Tester secret config") },

            { "AbsPathLabel", Tuple.Create("Hardcoded absolute path", "Chemin absolu codé en dur") },
            { "AbsPathDesc", Tuple.Create("Files referenced with fixed drive/root paths.", "Fichiers/répertoires référencés avec des chemins fixes.") },
            { "AbsPathButton", Tuple.Create("Test Abs Path", "Tester chemin absolu") },

            { "VerboseLogLabel", Tuple.Create("Verbose logging in production", "Logs verbeux en production") },
            { "VerboseLogDesc", Tuple.Create("Debug logs left enabled in prod builds.", "Traces debug actives en production.") },
            { "VerboseLogButton", Tuple.Create("Test Verbose Log", "Tester logs verbeux") },

            { "TempDirLabel", Tuple.Create("Global/shared temp directory", "Répertoire temporaire partagé") },
            { "TempDirDesc", Tuple.Create("Use of world-writable temp folders for critical files.", "Usage de dossiers temp accessibles à tous.") },
            { "TempDirButton", Tuple.Create("Test Temp Dir", "Tester temp partagé") },

            { "PrivKeyLabel", Tuple.Create("Private key/cert in project", "Clé privée/certificat dans le projet") },
            { "PrivKeyDesc", Tuple.Create("Sensitive credentials shipped with the app.", "Credentials sensibles inclus dans le binaire.") },
            { "PrivKeyButton", Tuple.Create("Test Private Key", "Tester clé privée") },

            { "WidePermLabel", Tuple.Create("Wide permissions (Everyone)", "Permissions larges (Everyone)") },
            { "WidePermDesc", Tuple.Create("Critical files/folders with world access rights.", "Fichiers/répertoires sensibles accessibles à tous.") },
            { "WidePermButton", Tuple.Create("Test Wide Perm", "Tester droits Everyone") },

            { "HostsLabel", Tuple.Create("Writable hosts/system files", "Fichiers hosts/système éditables") },
            { "HostsDesc", Tuple.Create("App or user can edit system config like hosts.", "L’application ou l’utilisateur peut éditer les fichiers système.") },
            { "HostsButton", Tuple.Create("Test Hosts Write", "Tester écriture hosts") },

            { "DebugLabel", Tuple.Create("Debug mode enabled in prod", "Mode debug actif en prod") },
            { "DebugDesc", Tuple.Create("Debug compilation or runtime flags enabled in release.", "Flags debug actifs en production.") },
            { "DebugButton", Tuple.Create("Test Debug", "Tester debug") },

            { "CryptoLabel", Tuple.Create("Weak cryptography", "Crypto faible") },
            { "CryptoDesc", Tuple.Create("Use of outdated/insecure algorithms (e.g., MD5, DES).", "Utilisation d’algorithmes obsolètes (MD5, DES…).") },
            { "CryptoButton", Tuple.Create("Test Crypto", "Tester crypto") },

            { "IPCLabel", Tuple.Create("Insecure IPC", "IPC non sécurisé") },
            { "IPCDesc", Tuple.Create("IPC endpoints with no auth or encryption.", "Points de communication inter-processus sans auth ni chiffrement.") },
            { "IPCButton", Tuple.Create("Test IPC", "Tester IPC") },

            { "AdminLabel", Tuple.Create("Runs as admin by default", "Exécution admin par défaut") },
            { "AdminDesc", Tuple.Create("App runs with administrator privileges by default.", "L’app tourne par défaut avec les droits admin.") },
            { "AdminButton", Tuple.Create("Test Admin", "Tester admin") },
        };


        private string _lang = "en";
        public DA08MisconfigWindow()
        {
            InitializeComponent();
            SetLanguage(_lang);
        }

        private void LanguageSelector_Changed(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            _lang = LanguageSelector.SelectedIndex == 1 ? "fr" : "en";
            SetLanguage(_lang);
        }
        private string GetLabel(string key, string lang)
        {
            return lang == "fr" ? labels[key].Item2 : labels[key].Item1;
        }

        private void SetLanguage(string lang)
        {
            Title = GetLabel("Title", lang);
            TitleText.Text = GetLabel("Title", lang);
            IntroText.Text = GetLabel("Intro", lang);

            AppConfigLabel.Text = GetLabel("AppConfigLabel", lang);
            AppConfigDesc.Text = GetLabel("AppConfigDesc", lang);
            AppConfigButton.Content = GetLabel("AppConfigButton", lang);

            AbsPathLabel.Text = GetLabel("AbsPathLabel", lang);
            AbsPathDesc.Text = GetLabel("AbsPathDesc", lang);
            AbsPathButton.Content = GetLabel("AbsPathButton", lang);

            VerboseLogLabel.Text = GetLabel("VerboseLogLabel", lang);
            VerboseLogDesc.Text = GetLabel("VerboseLogDesc", lang);
            VerboseLogButton.Content = GetLabel("VerboseLogButton", lang);

            TempDirLabel.Text = GetLabel("TempDirLabel", lang);
            TempDirDesc.Text = GetLabel("TempDirDesc", lang);
            TempDirButton.Content = GetLabel("TempDirButton", lang);

            PrivKeyLabel.Text = GetLabel("PrivKeyLabel", lang);
            PrivKeyDesc.Text = GetLabel("PrivKeyDesc", lang);
            PrivKeyButton.Content = GetLabel("PrivKeyButton", lang);

            WidePermLabel.Text = GetLabel("WidePermLabel", lang);
            WidePermDesc.Text = GetLabel("WidePermDesc", lang);
            WidePermButton.Content = GetLabel("WidePermButton", lang);

            HostsLabel.Text = GetLabel("HostsLabel", lang);
            HostsDesc.Text = GetLabel("HostsDesc", lang);
            HostsButton.Content = GetLabel("HostsButton", lang);

            DebugLabel.Text = GetLabel("DebugLabel", lang);
            DebugDesc.Text = GetLabel("DebugDesc", lang);
            DebugButton.Content = GetLabel("DebugButton", lang);

            CryptoLabel.Text = GetLabel("CryptoLabel", lang);
            CryptoDesc.Text = GetLabel("CryptoDesc", lang);
            CryptoButton.Content = GetLabel("CryptoButton", lang);

            IPCLabel.Text = GetLabel("IPCLabel", lang);
            IPCDesc.Text = GetLabel("IPCDesc", lang);
            IPCButton.Content = GetLabel("IPCButton", lang);

            AdminLabel.Text = GetLabel("AdminLabel", lang);
            AdminDesc.Text = GetLabel("AdminDesc", lang);
            AdminButton.Content = GetLabel("AdminButton", lang);
        }


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
    }
}
