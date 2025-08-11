using NetFrmk_Desktop_InsecureApp.Vulnerabilities;
using System;
using System.Collections.Generic;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA10LoggingWindow : Window
    {
        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA10 – Insufficient Logging & Monitoring", "DA10 – Journalisation et monitoring insuffisants") },
            { "Intro", Tuple.Create("Common failures to properly log/monitor security events in desktop apps.", "Défauts fréquents de journalisation et monitoring en sécurité applicative desktop.") },

            { "NoFileLogLabel", Tuple.Create("No log on sensitive file access", "Aucun log sur accès fichier sensible") },
            { "NoFileLogDesc", Tuple.Create("Sensitive file is read without logging the access.", "Lecture d’un fichier sensible sans traçabilité.") },
            { "NoFileLogButton", Tuple.Create("Test file access", "Tester lecture fichier") },

            { "NoAdminLogLabel", Tuple.Create("No admin access log", "Pas de log accès admin") },
            { "NoAdminLogDesc", Tuple.Create("Admin area accessed, no log or alert.", "Zone admin visitée, pas de log ni alerte.") },
            { "NoAdminLogButton", Tuple.Create("Test admin access", "Tester accès admin") },

            { "NoConfigLogLabel", Tuple.Create("No config change log", "Aucun log changement config") },
            { "NoConfigLogDesc", Tuple.Create("Config change not logged or traced.", "Modification de config non tracée.") },
            { "NoConfigLogButton", Tuple.Create("Test config change", "Tester modif config") },

            { "NoAuthLogLabel", Tuple.Create("No log on login failure", "Pas de log échec login") },
            { "NoAuthLogDesc", Tuple.Create("Login failure not logged (bruteforce undetectable).", "Échec login jamais loggé (bruteforce invisible).") },
            { "NoAuthLogButton", Tuple.Create("Test login fail", "Tester login fail") },

            { "NoForbiddenLabel", Tuple.Create("No forbidden action alert", "Pas d’alerte action interdite") },
            { "NoForbiddenDesc", Tuple.Create("Forbidden action not logged or alerted.", "Action interdite ni loggée ni alertée.") },
            { "NoForbiddenButton", Tuple.Create("Test forbidden", "Tester interdit") },

            { "NoDeletionLogLabel", Tuple.Create("No log on deletion", "Pas de log sur suppression") },
            { "NoDeletionLogDesc", Tuple.Create("Deletion of file/data not logged.", "Suppression non tracée.") },
            { "NoDeletionLogButton", Tuple.Create("Test deletion", "Tester suppression") },

            { "NoCritErrorLogLabel", Tuple.Create("No log on critical error/crash", "Pas de log sur plantage/erreur") },
            { "NoCritErrorLogDesc", Tuple.Create("Crash or critical error never logged.", "Erreur/plantage non loggé.") },
            { "NoCritErrorLogButton", Tuple.Create("Test error/crash", "Tester crash/erreur") },

            { "DebugOnlyLabel", Tuple.Create("Log only if DEBUG", "Log uniquement en DEBUG") },
            { "DebugOnlyDesc", Tuple.Create("Logs only written in debug builds.", "Log écrit seulement en DEBUG.") },
            { "DebugOnlyButton", Tuple.Create("Test debug-only", "Tester debug-only") },

            { "NoRotationLabel", Tuple.Create("No log rotation/backup", "Pas de rotation/sauvegarde") },
            { "NoRotationDesc", Tuple.Create("All events logged in single file, never rotated.", "Tout dans un seul fichier, jamais archivé.") },
            { "NoRotationButton", Tuple.Create("Test log rotation", "Tester rotation") },

            { "WorldWriteLabel", Tuple.Create("World-writable log file", "Log accessible à tous (écriture)") },
            { "WorldWriteDesc", Tuple.Create("Log file created with ‘Everyone’ rights.", "Fichier log créé accessible à tous.") },
            { "WorldWriteButton", Tuple.Create("Test world-writable", "Tester world-writable") },

            { "OpenFolderLabel", Tuple.Create("Log folder open to all", "Dossier log accessible à tous") },
            { "OpenFolderDesc", Tuple.Create("Log folder created full access to Everyone.", "Dossier log créé avec droits everyone.") },
            { "OpenFolderButton", Tuple.Create("Test log folder", "Tester dossier log") },

            { "CleartextSecretsLabel", Tuple.Create("Secrets/creds in cleartext logs", "Secrets/identifiants loggés en clair") },
            { "CleartextSecretsDesc", Tuple.Create("User/password logged in cleartext.", "User/mot de passe loggé en clair.") },
            { "CleartextSecretsButton", Tuple.Create("Test secrets log", "Tester log secrets") },
        };

        private string _lang = "en";
        public DA10LoggingWindow()
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
            Title= GetLabel("Title",lang);
            TitleText.Text= GetLabel("Title",lang);
            IntroText.Text= GetLabel("Intro",lang);

            NoFileLogLabel.Text= GetLabel("NoFileLogLabel",lang);
            NoFileLogDesc.Text= GetLabel("NoFileLogDesc",lang);
            NoFileLogButton.Content= GetLabel("NoFileLogButton",lang);

            NoAdminLogLabel.Text= GetLabel("NoAdminLogLabel",lang);
            NoAdminLogDesc.Text= GetLabel("NoAdminLogDesc",lang);
            NoAdminLogButton.Content= GetLabel("NoAdminLogButton",lang);

            NoConfigLogLabel.Text= GetLabel("NoConfigLogLabel",lang);
            NoConfigLogDesc.Text= GetLabel("NoConfigLogDesc",lang);
            NoConfigLogButton.Content= GetLabel("NoConfigLogButton",lang);

            NoAuthLogLabel.Text= GetLabel("NoAuthLogLabel",lang);
            NoAuthLogDesc.Text= GetLabel("NoAuthLogDesc",lang);
            NoAuthLogButton.Content= GetLabel("NoAuthLogButton",lang);

            NoForbiddenLabel.Text= GetLabel("NoForbiddenLabel",lang);
            NoForbiddenDesc.Text= GetLabel("NoForbiddenDesc",lang);
            NoForbiddenButton.Content= GetLabel("NoForbiddenButton",lang);

            NoDeletionLogLabel.Text= GetLabel("NoDeletionLogLabel",lang);
            NoDeletionLogDesc.Text= GetLabel("NoDeletionLogDesc",lang);
            NoDeletionLogButton.Content= GetLabel("NoDeletionLogButton",lang);

            NoCritErrorLogLabel.Text= GetLabel("NoCritErrorLogLabel",lang);
            NoCritErrorLogDesc.Text= GetLabel("NoCritErrorLogDesc",lang);
            NoCritErrorLogButton.Content= GetLabel("NoCritErrorLogButton",lang);

            DebugOnlyLabel.Text= GetLabel("DebugOnlyLabel",lang);
            DebugOnlyDesc.Text= GetLabel("DebugOnlyDesc",lang);
            DebugOnlyButton.Content= GetLabel("DebugOnlyButton",lang);

            NoRotationLabel.Text= GetLabel("NoRotationLabel",lang);
            NoRotationDesc.Text= GetLabel("NoRotationDesc",lang);
            NoRotationButton.Content= GetLabel("NoRotationButton",lang);

            WorldWriteLabel.Text= GetLabel("WorldWriteLabel",lang);
            WorldWriteDesc.Text= GetLabel("WorldWriteDesc",lang);
            WorldWriteButton.Content= GetLabel("WorldWriteButton",lang);

            OpenFolderLabel.Text= GetLabel("OpenFolderLabel",lang);
            OpenFolderDesc.Text= GetLabel("OpenFolderDesc",lang);
            OpenFolderButton.Content= GetLabel("OpenFolderButton",lang);

            CleartextSecretsLabel.Text= GetLabel("CleartextSecretsLabel",lang);
            CleartextSecretsDesc.Text= GetLabel("CleartextSecretsDesc",lang);
            CleartextSecretsButton.Content= GetLabel("CleartextSecretsButton",lang);
        }

        // Handlers (tous branchés sur la classe LoggingVuln)
        private void NoFileLogButton_Click(object sender, RoutedEventArgs e)
            => LoggingVuln.NoFileAccessLog(NoFileLogInput.Text);

        private void NoAdminLogButton_Click(object sender, RoutedEventArgs e)
            => LoggingVuln.NoAdminAccessLog(NoAdminLogInput.Text);

        private void NoConfigLogButton_Click(object sender, RoutedEventArgs e)
            => LoggingVuln.NoConfigChangeLog(NoConfigKeyInput.Text, NoConfigValInput.Text);

        private void NoAuthLogButton_Click(object sender, RoutedEventArgs e)
            => LoggingVuln.NoAuthFailureLog(NoAuthLogUserInput.Text, NoAuthLogPwdInput.Text);

        private void NoForbiddenButton_Click(object sender, RoutedEventArgs e)
            => LoggingVuln.NoForbiddenAccessAlert(NoForbiddenUserInput.Text, NoForbiddenActionInput.Text);

        private void NoDeletionLogButton_Click(object sender, RoutedEventArgs e)
            => LoggingVuln.NoDeletionLog(NoDeletionInput.Text);

        private void NoCritErrorLogButton_Click(object sender, RoutedEventArgs e)
            => LoggingVuln.NoCriticalErrorLog();

        private void DebugOnlyButton_Click(object sender, RoutedEventArgs e)
            => LoggingVuln.DebugOnlyLog(DebugOnlyInput.Text);

        private void NoRotationButton_Click(object sender, RoutedEventArgs e)
            => LoggingVuln.NoLogRotation(NoRotationInput.Text);

        private void WorldWriteButton_Click(object sender, RoutedEventArgs e)
            => LoggingVuln.WorldWritableLog();

        private void OpenFolderButton_Click(object sender, RoutedEventArgs e)
            => LoggingVuln.OpenLogFolder();

        private void CleartextSecretsButton_Click(object sender, RoutedEventArgs e)
            => LoggingVuln.LogCleartextSecrets(CleartextSecretsUserInput.Text, CleartextSecretsPwdInput.Text);
    }
}
