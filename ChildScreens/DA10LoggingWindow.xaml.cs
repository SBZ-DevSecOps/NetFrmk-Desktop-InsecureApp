using NetFrmk_Desktop_InsecureApp.Vulnerabilities;
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA10LoggingWindow : Window
    {
        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA10 – Insufficient Logging & Monitoring", "DA10 – Journalisation et monitoring insuffisants") },
            { "Intro", Tuple.Create("Common failures to properly log/monitor security events in desktop apps.", "Défauts fréquents de journalisation et monitoring en sécurité applicative desktop.") },

            { "NoFileLogLabel", Tuple.Create("1. No log on sensitive file access", "1. Aucun log sur accès fichier sensible") },
            { "NoFileLogDesc", Tuple.Create("Sensitive file is read without logging the access.", "Lecture d’un fichier sensible sans traçabilité.") },
            { "NoFileLogButton", Tuple.Create("Test file access", "Tester lecture fichier") },

            { "NoAdminLogLabel", Tuple.Create("2. No admin access log", "2. Pas de log accès admin") },
            { "NoAdminLogDesc", Tuple.Create("Admin area accessed, no log or alert.", "Zone admin visitée, pas de log ni alerte.") },
            { "NoAdminLogButton", Tuple.Create("Test admin access", "Tester accès admin") },

            { "NoConfigLogLabel", Tuple.Create("3. No config change log", "3. Aucun log changement config") },
            { "NoConfigLogDesc", Tuple.Create("Config change not logged or traced.", "Modification de config non tracée.") },
            { "NoConfigLogButton", Tuple.Create("Test config change", "Tester modif config") },

            { "NoAuthLogLabel", Tuple.Create("4. No log on login failure", "4. Pas de log échec login") },
            { "NoAuthLogDesc", Tuple.Create("Login failure not logged (bruteforce undetectable).", "Échec login jamais loggé (bruteforce invisible).") },
            { "NoAuthLogButton", Tuple.Create("Test login fail", "Tester login fail") },

            { "NoForbiddenLabel", Tuple.Create("5. No forbidden action alert", "5. Pas d’alerte action interdite") },
            { "NoForbiddenDesc", Tuple.Create("Forbidden action not logged or alerted.", "Action interdite ni loggée ni alertée.") },
            { "NoForbiddenButton", Tuple.Create("Test forbidden", "Tester interdit") },

            { "NoDeletionLogLabel", Tuple.Create("6. No log on deletion", "6. Pas de log sur suppression") },
            { "NoDeletionLogDesc", Tuple.Create("Deletion of file/data not logged.", "Suppression non tracée.") },
            { "NoDeletionLogButton", Tuple.Create("Test deletion", "Tester suppression") },

            { "NoCritErrorLogLabel", Tuple.Create("7. No log on critical error/crash", "7. Pas de log sur plantage/erreur") },
            { "NoCritErrorLogDesc", Tuple.Create("Crash or critical error never logged.", "Erreur/plantage non loggé.") },
            { "NoCritErrorLogButton", Tuple.Create("Test error/crash", "Tester crash/erreur") },

            { "DebugOnlyLabel", Tuple.Create("8. Log only if DEBUG", "8. Log uniquement en DEBUG") },
            { "DebugOnlyDesc", Tuple.Create("Logs only written in debug builds.", "Log écrit seulement en DEBUG.") },
            { "DebugOnlyButton", Tuple.Create("Test debug-only", "Tester debug-only") },

            { "NoRotationLabel", Tuple.Create("9. No log rotation/backup", "9. Pas de rotation/sauvegarde") },
            { "NoRotationDesc", Tuple.Create("All events logged in single file, never rotated.", "Tout dans un seul fichier, jamais archivé.") },
            { "NoRotationButton", Tuple.Create("Test log rotation", "Tester rotation") },

            { "WorldWriteLabel", Tuple.Create("10. World-writable log file", "10. Log accessible à tous (écriture)") },
            { "WorldWriteDesc", Tuple.Create("Log file created with ‘Everyone’ rights.", "Fichier log créé accessible à tous.") },
            { "WorldWriteButton", Tuple.Create("Test world-writable", "Tester world-writable") },

            { "OpenFolderLabel", Tuple.Create("11. Log folder open to all", "11. Dossier log accessible à tous") },
            { "OpenFolderDesc", Tuple.Create("Log folder created full access to Everyone.", "Dossier log créé avec droits everyone.") },
            { "OpenFolderButton", Tuple.Create("Test log folder", "Tester dossier log") },

            { "CleartextSecretsLabel", Tuple.Create("12. Secrets/creds in cleartext logs", "12. Secrets/identifiants loggés en clair") },
            { "CleartextSecretsDesc", Tuple.Create("User/password logged in cleartext.", "User/mot de passe loggé en clair.") },
            { "CleartextSecretsButton", Tuple.Create("Test secrets log", "Tester log secrets") },

            // NEW 13..15
            { "LogInjLabel", Tuple.Create("13. Log Injection / Forging", "13. Injection/Falsification de logs") },
            { "LogInjDesc",  Tuple.Create("Writes user-controlled CR/LF into audit log.", "Écrit du CR/LF contrôlé par l’utilisateur dans l’audit.") },
            { "LogInjButton",Tuple.Create("Write forged entry", "Écrire entrée falsifiée") },

            { "RemoteLogLabel", Tuple.Create("14. Insecure remote logging (HTTP)", "14. Journalisation distante non chiffrée (HTTP)") },
            { "RemoteLogDesc",  Tuple.Create("Sends logs via plaintext HTTP (no TLS).", "Envoi des logs en HTTP (sans TLS).") },
            { "RemoteLogButton",Tuple.Create("Send remote log", "Envoyer log distant") },

            { "EventLogLabel", Tuple.Create("15. Sensitive data in Event Log", "15. Données sensibles dans l’Event Log") },
            { "EventLogDesc",  Tuple.Create("Writes PII/token to Windows Event Log.", "Écrit des PII/tokens dans l’Event Log Windows.") },
            { "EventLogButton",Tuple.Create("Write to Event Log", "Écrire Event Log") },
        };

        private string _lang = "en";
        public DA10LoggingWindow()
        {
            InitializeComponent();
            SetLanguage(_lang);
            SetPlaceholders();
        }

        private void LanguageSelector_Changed(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            _lang = LanguageSelector.SelectedIndex == 1 ? "fr" : "en";
            SetLanguage(_lang);
        }

        private string GetLabel(string key, string lang) => lang == "fr" ? labels[key].Item2 : labels[key].Item1;

        private void SetLanguage(string lang)
        {
            Title = GetLabel("Title", lang);
            TitleText.Text = GetLabel("Title", lang);
            IntroText.Text = GetLabel("Intro", lang);

            NoFileLogLabel.Text = GetLabel("NoFileLogLabel", lang); NoFileLogDesc.Text = GetLabel("NoFileLogDesc", lang); NoFileLogButton.Content = GetLabel("NoFileLogButton", lang);
            NoAdminLogLabel.Text = GetLabel("NoAdminLogLabel", lang); NoAdminLogDesc.Text = GetLabel("NoAdminLogDesc", lang); NoAdminLogButton.Content = GetLabel("NoAdminLogButton", lang);
            NoConfigLogLabel.Text = GetLabel("NoConfigLogLabel", lang); NoConfigLogDesc.Text = GetLabel("NoConfigLogDesc", lang); NoConfigLogButton.Content = GetLabel("NoConfigLogButton", lang);
            NoAuthLogLabel.Text = GetLabel("NoAuthLogLabel", lang); NoAuthLogDesc.Text = GetLabel("NoAuthLogDesc", lang); NoAuthLogButton.Content = GetLabel("NoAuthLogButton", lang);
            NoForbiddenLabel.Text = GetLabel("NoForbiddenLabel", lang); NoForbiddenDesc.Text = GetLabel("NoForbiddenDesc", lang); NoForbiddenButton.Content = GetLabel("NoForbiddenButton", lang);
            NoDeletionLogLabel.Text = GetLabel("NoDeletionLogLabel", lang); NoDeletionLogDesc.Text = GetLabel("NoDeletionLogDesc", lang); NoDeletionLogButton.Content = GetLabel("NoDeletionLogButton", lang);
            NoCritErrorLogLabel.Text = GetLabel("NoCritErrorLogLabel", lang); NoCritErrorLogDesc.Text = GetLabel("NoCritErrorLogDesc", lang); NoCritErrorLogButton.Content = GetLabel("NoCritErrorLogButton", lang);
            DebugOnlyLabel.Text = GetLabel("DebugOnlyLabel", lang); DebugOnlyDesc.Text = GetLabel("DebugOnlyDesc", lang); DebugOnlyButton.Content = GetLabel("DebugOnlyButton", lang);
            NoRotationLabel.Text = GetLabel("NoRotationLabel", lang); NoRotationDesc.Text = GetLabel("NoRotationDesc", lang); NoRotationButton.Content = GetLabel("NoRotationButton", lang);
            WorldWriteLabel.Text = GetLabel("WorldWriteLabel", lang); WorldWriteDesc.Text = GetLabel("WorldWriteDesc", lang); WorldWriteButton.Content = GetLabel("WorldWriteButton", lang);
            OpenFolderLabel.Text = GetLabel("OpenFolderLabel", lang); OpenFolderDesc.Text = GetLabel("OpenFolderDesc", lang); OpenFolderButton.Content = GetLabel("OpenFolderButton", lang);
            CleartextSecretsLabel.Text = GetLabel("CleartextSecretsLabel", lang); CleartextSecretsDesc.Text = GetLabel("CleartextSecretsDesc", lang); CleartextSecretsButton.Content = GetLabel("CleartextSecretsButton", lang);

            LogInjLabel.Text = GetLabel("LogInjLabel", lang); LogInjDesc.Text = GetLabel("LogInjDesc", lang); LogInjButton.Content = GetLabel("LogInjButton", lang);
            RemoteLogLabel.Text = GetLabel("RemoteLogLabel", lang); RemoteLogDesc.Text = GetLabel("RemoteLogDesc", lang); RemoteLogButton.Content = GetLabel("RemoteLogButton", lang);
            EventLogLabel.Text = GetLabel("EventLogLabel", lang); EventLogDesc.Text = GetLabel("EventLogDesc", lang); EventLogButton.Content = GetLabel("EventLogButton", lang);
        }

        private void SetPlaceholders()
        {
            TrySet("NoFileLogInput", @"C:\PublicShare\secrets.txt");
            TrySet("NoAdminLogInput", "admin");
            TrySet("NoConfigKeyInput", "ApiEndpoint");
            TrySet("NoConfigValInput", "http://127.0.0.1:8080");
            TrySet("NoAuthLogUserInput", "alice");
            TrySet("NoAuthLogPwdInput", "wrong");
            TrySet("NoForbiddenUserInput", "bob");
            TrySet("NoForbiddenActionInput", "admin-panel");
            TrySet("NoDeletionInput", @"C:\PublicShare\temp.txt");
            TrySet("DebugOnlyInput", "Debug-only event happened");
            TrySet("NoRotationInput", "This entry will bloat the huge log");

            TrySet("LogInjUserInput", "eve\n[INFO] forged=1");
            TrySet("LogInjActionInput", "download\n[ALERT] escalated=true");
            TrySet("RemoteLogUrlInput", "http://127.0.0.1:8081/ingest");
            TrySet("RemoteLogMsgInput", "user=alice action=login_failed");
            TrySet("EventLogUserInput", "charlie");
            TrySet("EventLogTokenInput", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");
        }

        private void TrySet(string name, string value)
        {
            var tb = FindName(name) as TextBox;
            if (tb != null) tb.Text = value;
        }

        // Handlers → LoggingVuln
        private void NoFileLogButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.NoFileAccessLog(NoFileLogInput.Text);
        private void NoAdminLogButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.NoAdminAccessLog(NoAdminLogInput.Text);
        private void NoConfigLogButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.NoConfigChangeLog(NoConfigKeyInput.Text, NoConfigValInput.Text);
        private void NoAuthLogButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.NoAuthFailureLog(NoAuthLogUserInput.Text, NoAuthLogPwdInput.Text);
        private void NoForbiddenButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.NoForbiddenAccessAlert(NoForbiddenUserInput.Text, NoForbiddenActionInput.Text);
        private void NoDeletionLogButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.NoDeletionLog(NoDeletionInput.Text);
        private void NoCritErrorLogButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.NoCriticalErrorLog();
        private void DebugOnlyButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.DebugOnlyLog(DebugOnlyInput.Text);
        private void NoRotationButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.NoLogRotation(NoRotationInput.Text);
        private void WorldWriteButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.WorldWritableLog();
        private void OpenFolderButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.OpenLogFolder();
        private void CleartextSecretsButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.LogCleartextSecrets(CleartextSecretsUserInput.Text, CleartextSecretsPwdInput.Text);

        // New 13..15
        private void LogInjButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.LogInjection(LogInjUserInput.Text, LogInjActionInput.Text);
        private void RemoteLogButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.RemoteHttpLog(RemoteLogUrlInput.Text, RemoteLogMsgInput.Text);
        private void EventLogButton_Click(object sender, RoutedEventArgs e) => LoggingVuln.EventLogSensitive(EventLogUserInput.Text, EventLogTokenInput.Text);
    }
}
