using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA03DataExposureWindow : Window
    {
        private string _lang = "en";
        private string logFile = "app.log";
        private string publicShareFile = "C:\\PublicShare\\exposed.txt";
        private string csvFile = "export.csv";

        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA03 – Sensitive Data Exposure", "DA03 – Exposition de données sensibles") },
            { "Intro", Tuple.Create("Demonstrates various forms of sensitive data exposure in a desktop app.",
                "Montre différentes formes d'exposition de données sensibles dans une application desktop.") },
            { "MemoryLabel", Tuple.Create("1. Sensitive Data in Memory", "1. Données sensibles en mémoire") },
            { "MemoryDesc", Tuple.Create("Secret is stored in RAM (never cleared).", "Le secret reste stocké en RAM (jamais effacé).") },
            { "TriggerMemory", Tuple.Create("Store in Memory", "Stocker en mémoire") },
            { "CsvLabel", Tuple.Create("2. Export Data in Plain CSV", "2. Export CSV en clair") },
            { "CsvDesc", Tuple.Create("Sensitive data exported to unencrypted CSV.", "Donnée exportée dans un fichier CSV non chiffré.") },
            { "TriggerCsv", Tuple.Create("Export CSV", "Exporter CSV") },
            { "LogLabel", Tuple.Create("3. Logging Sensitive Data", "3. Journalisation de données sensibles") },
            { "LogDesc", Tuple.Create("Sensitive input is logged in clear text.", "Entrée sensible journalisée en clair.") },
            { "TriggerLog", Tuple.Create("Log Data", "Logger la donnée") },
            { "ShareLabel", Tuple.Create("4. Public File Share", "4. Partage de fichier public") },
            { "ShareDesc", Tuple.Create("Secret written to a public share.", "Secret écrit dans un dossier partagé.") },
            { "TriggerShare", Tuple.Create("Share File", "Partager le fichier") },
            { "ClipboardLabel", Tuple.Create("5. Clipboard Data Exposure", "5. Fuite via le presse-papiers") },
            { "ClipboardDesc", Tuple.Create("Sensitive data copied to clipboard.", "Secret copié dans le presse-papiers.") },
            { "TriggerClipboard", Tuple.Create("Copy to Clipboard", "Copier dans presse-papiers") },
            { "CryptoLabel", Tuple.Create("6. Weak Crypto", "6. Chiffrement faible") },
            { "CryptoDesc", Tuple.Create("Data 'encrypted' using base64 (not real crypto).", "Donnée 'chiffrée' par base64 (pas du vrai chiffrement).") },
            { "TriggerCrypto", Tuple.Create("Encrypt Data", "Chiffrer la donnée") },
            { "HardcodedLabel", Tuple.Create("7. Hardcoded Secret", "7. Secret codé en dur") },
            { "HardcodedDesc", Tuple.Create("Secret value is hardcoded in app.", "Valeur secrète codée en dur dans l'app.") },
            { "TriggerHardcoded", Tuple.Create("Show Secret", "Afficher le secret") },
            { "TempLabel", Tuple.Create("8. Sensitive Data in Temp File", "8. Donnée sensible dans un fichier temporaire") },
            { "TempDesc", Tuple.Create("Secret written to a temporary file.", "Secret écrit dans un fichier temporaire.") },
            { "TriggerTemp", Tuple.Create("Write Temp File", "Écrire le fichier temp") },
            { "TitleLabel", Tuple.Create("9. Sensitive Data in Window Title", "9. Donnée dans le titre de la fenêtre") },
            { "TitleDesc", Tuple.Create("Secret appears in window title.", "Secret affiché dans le titre de la fenêtre.") },
            { "TriggerTitle", Tuple.Create("Set Title", "Définir le titre") },
            { "ExceptionLabel", Tuple.Create("10. Verbose Exception With Secret", "10. Exception verbeuse avec secret") },
            { "ExceptionDesc", Tuple.Create("Error/exception message exposes secret.", "Message d'erreur affiche une info sensible.") },
            { "TriggerException", Tuple.Create("Trigger Exception", "Déclencher exception") },
        };

        public DA03DataExposureWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage("en");

            // Payloads initiaux
            MemoryInput.Text = "SensitiveSecret";
            LogInput.Text = "credit-card=1234-5678-9012-3456";
            ShareInput.Text = "TOP_SECRET";
            ClipboardInput.Text = "Token=1234abcd";
            CryptoInput.Text = "password123";
            TitleSecretInput.Text = "SecretInTitle";
            ExceptionSecretInput.Text = "StackTraceWithSecret";
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

            MemoryLabel.Text= GetLabel("MemoryLabel",lang);
            MemoryDesc.Text= GetLabel("MemoryDesc",lang);
            MemoryButton.Content= GetLabel("TriggerMemory",lang);

            CsvLabel.Text= GetLabel("CsvLabel",lang);
            CsvDesc.Text= GetLabel("CsvDesc",lang);
            CsvButton.Content= GetLabel("TriggerCsv",lang);

            LogLabel.Text= GetLabel("LogLabel",lang);
            LogDesc.Text= GetLabel("LogDesc",lang);
            LogButton.Content= GetLabel("TriggerLog",lang);

            ShareLabel.Text= GetLabel("ShareLabel",lang);
            ShareDesc.Text= GetLabel("ShareDesc",lang);
            ShareButton.Content= GetLabel("TriggerShare",lang);

            ClipboardLabel.Text= GetLabel("ClipboardLabel",lang);
            ClipboardDesc.Text= GetLabel("ClipboardDesc",lang);
            ClipboardButton.Content= GetLabel("TriggerClipboard",lang);

            CryptoLabel.Text= GetLabel("CryptoLabel",lang);
            CryptoDesc.Text= GetLabel("CryptoDesc",lang);
            CryptoButton.Content= GetLabel("TriggerCrypto",lang);

            HardcodedLabel.Text= GetLabel("HardcodedLabel",lang);
            HardcodedDesc.Text= GetLabel("HardcodedDesc",lang);
            HardcodedButton.Content= GetLabel("TriggerHardcoded",lang);

            TempLabel.Text= GetLabel("TempLabel",lang);
            TempDesc.Text= GetLabel("TempDesc",lang);
            TempButton.Content= GetLabel("TriggerTemp",lang);

            TitleLabel.Text= GetLabel("TitleLabel",lang);
            TitleDesc.Text= GetLabel("TitleDesc",lang);
            TitleButton.Content= GetLabel("TriggerTitle",lang);

            ExceptionLabel.Text= GetLabel("ExceptionLabel",lang);
            ExceptionDesc.Text= GetLabel("ExceptionDesc",lang);
            ExceptionButton.Content= GetLabel("TriggerException",lang);

            // Payloads par langue
            if (lang == "fr")
            {
                MemoryInput.Text = "SecretSens";
                LogInput.Text = "cb=1234-5678-9012-3456";
                ShareInput.Text = "TOP_SECRET";
                ClipboardInput.Text = "Jeton=1234abcd";
                CryptoInput.Text = "motdepasse123";
                TitleSecretInput.Text = "SecretDansTitre";
                ExceptionSecretInput.Text = "TraceAvecSecret";
            }
            else
            {
                MemoryInput.Text = "SensitiveSecret";
                LogInput.Text = "credit-card=1234-5678-9012-3456";
                ShareInput.Text = "TOP_SECRET";
                ClipboardInput.Text = "Token=1234abcd";
                CryptoInput.Text = "password123";
                TitleSecretInput.Text = "SecretInTitle";
                ExceptionSecretInput.Text = "StackTraceWithSecret";
            }
        }

        private string _memorySecret = "";

        private void MemoryButton_Click(object sender, RoutedEventArgs e)
        {
            _memorySecret = MemoryInput.Text;
            MemoryResult.Text = _lang == "fr"
                ? "Secret stocké en mémoire, non protégé."
                : "Secret stored in memory, not protected.";
        }

        private void CsvButton_Click(object sender, RoutedEventArgs e)
        {
            var csv = $"id,secret\n1,{MemoryInput.Text}\n";
            File.WriteAllText(csvFile, csv);
            CsvResult.Text = _lang == "fr"
                ? $"Export CSV non chiffré : {csvFile}"
                : $"Unencrypted CSV exported: {csvFile}";
        }

        private void LogButton_Click(object sender, RoutedEventArgs e)
        {
            File.AppendAllText(logFile, LogInput.Text + Environment.NewLine);
            LogResult.Text = _lang == "fr"
                ? $"Saisie ajoutée au log : {logFile}"
                : $"Input appended to log: {logFile}";
        }

        private void ShareButton_Click(object sender, RoutedEventArgs e)
        {
            Directory.CreateDirectory("C:\\PublicShare");
            File.WriteAllText(publicShareFile, ShareInput.Text);
            ShareResult.Text = _lang == "fr"
                ? $"Fichier partagé en public : {publicShareFile}"
                : $"File publicly shared: {publicShareFile}";
        }

        private void ClipboardButton_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(ClipboardInput.Text);
            ClipboardResult.Text = _lang == "fr"
                ? "Copié dans le presse-papiers (attention à la fuite !)"
                : "Copied to clipboard (data leak risk)!";
        }

        private void CryptoButton_Click(object sender, RoutedEventArgs e)
        {
            var clear = CryptoInput.Text;
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(clear));
            CryptoResult.Text = _lang == "fr"
                ? $"Donnée chiffrée (faible): {encoded}"
                : $"Weak 'encrypted' data: {encoded}";
        }

        private void HardcodedButton_Click(object sender, RoutedEventArgs e)
        {
            string hardSecret = "HARD_SECRET_XYZ";
            HardcodedResult.Text = _lang == "fr"
                ? $"Secret codé en dur : {hardSecret}"
                : $"Hardcoded secret: {hardSecret}";
        }

        private void TempButton_Click(object sender, RoutedEventArgs e)
        {
            string temp = Path.GetTempFileName();
            File.WriteAllText(temp, "SECRET_TEMP_DATA");
            TempResult.Text = _lang == "fr"
                ? $"Secret écrit dans fichier temporaire : {temp}"
                : $"Secret written to temp file: {temp}";
        }

        private void TitleButton_Click(object sender, RoutedEventArgs e)
        {
            string secret = TitleSecretInput.Text;
            this.Title = secret;
            TitleResult.Text = _lang == "fr"
                ? $"Titre de la fenêtre mis à jour avec le secret !"
                : $"Window title updated with secret!";
        }

        private void ExceptionButton_Click(object sender, RoutedEventArgs e)
        {
            string secret = ExceptionSecretInput.Text;
            try
            {
                throw new Exception($"Critical: {secret} exposed in error!");
            }
            catch (Exception ex)
            {
                ExceptionResult.Text = ex.Message;
            }
        }
    }
}
