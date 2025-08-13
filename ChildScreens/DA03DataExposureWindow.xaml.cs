using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using NetFrmk_Desktop_InsecureApp.Vulnerabilities;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA03DataExposureWindow : Window
    {
        private string _lang = "en";

        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA03 – Sensitive Data Exposure", "DA03 – Exposition de données sensibles") },
            { "Intro", Tuple.Create("Demonstrates common data-exposure pitfalls in desktop apps. All sinks are intentionally unsafe for SAST demos.", "Démontre des mauvaises pratiques d'exposition de données dans une application desktop. Les sinks sont volontairement vulnérables pour les démos SAST.") },

            { "MemoryLabel", Tuple.Create("1. Sensitive Data in Memory", "1. Données sensibles en mémoire") },
            { "MemoryDesc",  Tuple.Create("Secret is stored in RAM and never cleared.", "Le secret est conservé en RAM, jamais effacé.") },
            { "MemoryButton", Tuple.Create("Store in Memory", "Stocker en mémoire") },

            { "CsvLabel", Tuple.Create("2. Export Data in Plain CSV", "2. Export CSV en clair") },
            { "CsvDesc",  Tuple.Create("Sensitive data exported to an unencrypted CSV.", "Données sensibles exportées dans un CSV non chiffré.") },
            { "CsvButton", Tuple.Create("Export CSV", "Exporter CSV") },

            { "LogLabel", Tuple.Create("3. Logging Sensitive Data", "3. Journalisation de données sensibles") },
            { "LogDesc",  Tuple.Create("Sensitive input is appended to application log.", "Entrée sensible ajoutée au journal de l'application.") },
            { "LogButton", Tuple.Create("Log Data", "Logger la donnée") },

            { "ShareLabel", Tuple.Create("4. Public File Share", "4. Partage de fichier public") },
            { "ShareDesc",  Tuple.Create("Drop a secret in a world-readable folder.", "Dépose un secret dans un dossier lisible par tous.") },
            { "ShareButton", Tuple.Create("Drop to Share", "Déposer dans le partage") },

            { "CryptoLabel", Tuple.Create("5. Weak Crypto (Base64)", "5. Crypto faible (Base64)") },
            { "CryptoDesc",  Tuple.Create("Pretend-crypto by Base64-encoding sensitive data.", "Faux chiffrement en encodant en Base64 des données sensibles.") },
            { "CryptoButton", Tuple.Create("Encode Base64", "Encoder Base64") },

            { "HardcodedLabel", Tuple.Create("6. Hardcoded Secret/Key", "6. Secret/clé en dur") },
            { "HardcodedDesc",  Tuple.Create("Demonstrates hardcoded keys/secrets.", "Démontre l'utilisation de clés/secrets en dur.") },
            { "HardcodedButton", Tuple.Create("Show Hardcoded", "Montrer le secret") },

            { "TempLabel", Tuple.Create("7. Sensitive Data in Temp File", "7. Données sensibles en fichier Temp") },
            { "TempDesc",  Tuple.Create("Write sensitive data to %TEMP% without protection.", "Écrit des données sensibles dans %TEMP% sans protection.") },
            { "TempButton", Tuple.Create("Write Temp File", "Écrire fichier Temp") },

            { "ExceptionLabel", Tuple.Create("8. Verbose Exception With Secret", "8. Exception verbeuse avec secret") },
            { "ExceptionDesc",  Tuple.Create("Secrets leaked in exception messages/stack traces.", "Secrets divulgués dans les messages/stack traces d'exception.") },
            { "ExceptionButton", Tuple.Create("Trigger Exception", "Déclencher exception") },

            { "HttpLabel", Tuple.Create("9. Insecure HTTP Transport (POST)", "9. Transport HTTP non sécurisé (POST)") },
            { "HttpDesc",  Tuple.Create("Send sensitive data over HTTP.", "Envoie des données sensibles en HTTP.") },
            { "HttpButton", Tuple.Create("Send HTTP POST", "Envoyer HTTP POST") },

            { "ClearLabel", Tuple.Create("10. Store Cleartext on Disk", "10. Stockage en clair sur disque") },
            { "ClearDesc",  Tuple.Create("Write plaintext secret to local disk.", "Écrit un secret en clair sur le disque local.") },
            { "ClearButton", Tuple.Create("Write Cleartext", "Écrire en clair") },

            { "Rot13Label", Tuple.Create("11. Weak Encryption (ROT13)", "11. Chiffrement faible (ROT13)") },
            { "Rot13Desc",  Tuple.Create("ROT13 as ersatz encryption.", "ROT13 utilisé comme pseudo-chiffrement.") },
            { "Rot13Button", Tuple.Create("Apply ROT13", "Appliquer ROT13") },

            { "HttpGetLabel", Tuple.Create("12. Insecure HTTP Transport (GET)", "12. Transport HTTP non sécurisé (GET)") },
            { "HttpGetDesc",  Tuple.Create("Send query params with secrets over HTTP.", "Envoie des paramètres (avec secrets) en HTTP.") },
            { "HttpGetButton", Tuple.Create("Send HTTP GET", "Envoyer HTTP GET") },

            { "CfgLabel", Tuple.Create("13. Plaintext Connection String (.config)", "13. Chaîne de connexion en clair (.config)") },
            { "CfgDesc",  Tuple.Create("Write a plaintext connection string to a config file.", "Écrit une chaîne de connexion en clair dans un fichier de config.") },
            { "CfgButton", Tuple.Create("Write Config", "Écrire config") },

            { "RegLabel", Tuple.Create("14. Windows Registry (plaintext)", "14. Registre Windows (texte en clair)") },
            { "RegDesc",  Tuple.Create("Write secret to HKCU without protection.", "Écrit un secret sous HKCU sans protection.") },
            { "RegButton", Tuple.Create("Write Registry", "Écrire registre") },

            { "DesLabel", Tuple.Create("15. Weak Encryption (DES-ECB)", "15. Chiffrement faible (DES-ECB)") },
            { "DesDesc",  Tuple.Create("Encrypt with DES in ECB mode (hardcoded key).", "Chiffrement DES en mode ECB (clé en dur).") },
            { "DesButton", Tuple.Create("Encrypt (DES-ECB)", "Chiffrer (DES-ECB)") },
        };

        public DA03DataExposureWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage("en");
            SetDefaultPlaceholders();
        }

        private void SetDefaultPlaceholders()
        {
            TrySetText("MemoryInput", "SECRET_TOKEN=abc123");
            TrySetText("LogInput", "User=alice; Pass=SuperSecret!");
            TrySetText("ShareInput", "SHARED_SECRET=123456");
            TrySetText("CryptoInput", "SensitiveValue");
            TrySetText("ExceptionSecretInput", "API_KEY=XYZ-123-SECRET");
            TrySetText("HttpUrlInput", "http://127.0.0.1:8080/api");
            TrySetText("HttpDataInput", "token=SECRET&email=user@example.com");
            TrySetText("ClearInput", "dbPassword=Pa$$w0rd");
            TrySetText("Rot13Input", "HighlySensitive");
            TrySetText("HttpGetUrlInput", "http://127.0.0.1:8080/report");
            TrySetText("HttpGetQueryInput", "token=SECRET&email=user@example.com");
            TrySetText("RegNameInput", "API_KEY");
            TrySetText("RegValueInput", "SECRET-ABC-999");
            TrySetText("DesInput", "very secret payload");
        }

        private void TrySetText(string name, string value)
        {
            var tb = FindName(name) as TextBox;
            if (tb != null) tb.Text = value;
        }

        private string GetLabel(string key, string lang)
        {
            Tuple<string, string> t;
            if (labels.TryGetValue(key, out t))
                return lang == "fr" ? t.Item2 : t.Item1;
            return key;
        }

        private void LanguageSelector_Changed(object sender, SelectionChangedEventArgs e)
        {
            var lang = (LanguageSelector.SelectedIndex == 1) ? "fr" : "en";
            SetLanguage(lang);
        }

        private void SetLanguage(string lang)
        {
            _lang = lang;

            this.Title = GetLabel("Title", lang);
            var title = FindName("TitleText") as TextBlock; if (title != null) title.Text = GetLabel("Title", lang);
            var intro = FindName("IntroText") as TextBlock; if (intro != null) intro.Text = GetLabel("Intro", lang);

            Action<string, string> L = (name, key) => { var c = FindName(name) as TextBlock; if (c != null) c.Text = GetLabel(key, lang); };
            Action<string, string> B = (name, key) => { var c = FindName(name) as Button; if (c != null) c.Content = GetLabel(key, lang); };

            L("MemoryLabel", "MemoryLabel"); L("MemoryDesc", "MemoryDesc"); B("MemoryButton", "MemoryButton");
            L("CsvLabel", "CsvLabel"); L("CsvDesc", "CsvDesc"); B("CsvButton", "CsvButton");
            L("LogLabel", "LogLabel"); L("LogDesc", "LogDesc"); B("LogButton", "LogButton");
            L("ShareLabel", "ShareLabel"); L("ShareDesc", "ShareDesc"); B("ShareButton", "ShareButton");
            L("CryptoLabel", "CryptoLabel"); L("CryptoDesc", "CryptoDesc"); B("CryptoButton", "CryptoButton");
            L("HardcodedLabel", "HardcodedLabel"); L("HardcodedDesc", "HardcodedDesc"); B("HardcodedButton", "HardcodedButton");
            L("TempLabel", "TempLabel"); L("TempDesc", "TempDesc"); B("TempButton", "TempButton");
            L("ExceptionLabel", "ExceptionLabel"); L("ExceptionDesc", "ExceptionDesc"); B("ExceptionButton", "ExceptionButton");
            L("HttpLabel", "HttpLabel"); L("HttpDesc", "HttpDesc"); B("HttpButton", "HttpButton");
            L("ClearLabel", "ClearLabel"); L("ClearDesc", "ClearDesc"); B("ClearButton", "ClearButton");
            L("Rot13Label", "Rot13Label"); L("Rot13Desc", "Rot13Desc"); B("Rot13Button", "Rot13Button");
            L("HttpGetLabel", "HttpGetLabel"); L("HttpGetDesc", "HttpGetDesc"); B("HttpGetButton", "HttpGetButton");
            L("CfgLabel", "CfgLabel"); L("CfgDesc", "CfgDesc"); B("CfgButton", "CfgButton");
            L("RegLabel", "RegLabel"); L("RegDesc", "RegDesc"); B("RegButton", "RegButton");
            L("DesLabel", "DesLabel"); L("DesDesc", "DesDesc"); B("DesButton", "DesButton");
        }

        // ===== Handlers (UI -> DataExposureVuln) =====

        private void MemoryButton_Click(object sender, RoutedEventArgs e)
        {
            try { var r = DataExposureVuln.StoreInMemory(GetText("MemoryInput")); SetResult("MemoryResult", Ok(r)); }
            catch (Exception ex) { SetResult("MemoryResult", ex.Message); }
        }

        private void CsvButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "export.csv");
                var r = DataExposureVuln.ExportCsvPlain(path);
                SetResult("CsvResult", Ok(r));
            }
            catch (Exception ex) { SetResult("CsvResult", ex.Message); }
        }

        private void LogButton_Click(object sender, RoutedEventArgs e)
        {
            try { var r = DataExposureVuln.LogSensitive(GetText("LogInput")); SetResult("LogResult", Ok(r)); }
            catch (Exception ex) { SetResult("LogResult", ex.Message); }
        }

        private void ShareButton_Click(object sender, RoutedEventArgs e)
        {
            try { var r = DataExposureVuln.PublicShareDrop(GetText("ShareInput")); SetResult("ShareResult", Ok(r)); }
            catch (Exception ex) { SetResult("ShareResult", ex.Message); }
        }

        private void CryptoButton_Click(object sender, RoutedEventArgs e)
        {
            try { var b64 = DataExposureVuln.WeakEncryptionBase64(GetText("CryptoInput")); SetResult("CryptoResult", Ok("Base64: " + b64)); }
            catch (Exception ex) { SetResult("CryptoResult", ex.Message); }
        }

        private void HardcodedButton_Click(object sender, RoutedEventArgs e)
        {
            try { var r = DataExposureVuln.HardcodedKey("demo"); SetResult("HardcodedResult", Ok(r)); }
            catch (Exception ex) { SetResult("HardcodedResult", ex.Message); }
        }

        private void TempButton_Click(object sender, RoutedEventArgs e)
        {
            try { var r = DataExposureVuln.TempWrite("TEMP_SECRET=" + DateTime.Now.Ticks); SetResult("TempResult", Ok(r)); }
            catch (Exception ex) { SetResult("TempResult", ex.Message); }
        }

        private void ExceptionButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Intentionally throws and leaks the secret in the message
                DataExposureVuln.VerboseError(GetText("ExceptionSecretInput"));
                SetResult("ExceptionResult", Ok("No exception?")); // unlikely path
            }
            catch (Exception ex) { SetResult("ExceptionResult", ex.Message); }
        }

        private void HttpButton_Click(object sender, RoutedEventArgs e)
        {
            try { var r = DataExposureVuln.HttpPostInsecure(GetText("HttpUrlInput"), GetText("HttpDataInput")); SetResult("HttpResult", Ok(r)); }
            catch (Exception ex) { SetResult("HttpResult", ex.Message); }
        }

        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            try { var r = DataExposureVuln.StoreCleartext(GetText("ClearInput")); SetResult("ClearResult", Ok(r)); }
            catch (Exception ex) { SetResult("ClearResult", ex.Message); }
        }

        private void Rot13Button_Click(object sender, RoutedEventArgs e)
        {
            try { var r = DataExposureVuln.WeakEncryptionRot13(GetText("Rot13Input")); SetResult("Rot13Result", Ok(r)); }
            catch (Exception ex) { SetResult("Rot13Result", ex.Message); }
        }

        private void HttpGetButton_Click(object sender, RoutedEventArgs e)
        {
            try { var r = DataExposureVuln.HttpGetInsecure(GetText("HttpGetUrlInput"), GetText("HttpGetQueryInput")); SetResult("HttpGetResult", Ok(r)); }
            catch (Exception ex) { SetResult("HttpGetResult", ex.Message); }
        }

        private void CfgButton_Click(object sender, RoutedEventArgs e)
        {
            try { var r = DataExposureVuln.WritePlainConfig(); SetResult("CfgResult", Ok(r)); }
            catch (Exception ex) { SetResult("CfgResult", ex.Message); }
        }

        private void RegButton_Click(object sender, RoutedEventArgs e)
        {
            try { var r = DataExposureVuln.RegistryWritePlain(GetText("RegNameInput"), GetText("RegValueInput")); SetResult("RegResult", Ok(r)); }
            catch (Exception ex) { SetResult("RegResult", ex.Message); }
        }

        private void DesButton_Click(object sender, RoutedEventArgs e)
        {
            try { var b64 = DataExposureVuln.DesEcbEncrypt(GetText("DesInput")); SetResult("DesResult", Ok("DES-ECB (Base64): " + b64)); }
            catch (Exception ex) { SetResult("DesResult", ex.Message); }
        }

        // ===== helpers =====

        private string GetText(string name)
        {
            var tb = FindName(name) as TextBox;
            return tb != null ? (tb.Text ?? string.Empty) : string.Empty;
        }

        private void SetResult(string name, string text)
        {
            var tb = FindName(name) as TextBlock;
            if (tb != null) tb.Text = text;
        }

        private string Ok(string s)
        {
            return _lang == "fr" ? "OK : " + s : "OK: " + s;
        }
    }
}
