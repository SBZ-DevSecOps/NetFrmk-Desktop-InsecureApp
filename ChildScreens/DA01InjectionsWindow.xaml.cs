using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA01InjectionsWindow : Window
    {
        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA01 – Injections", "DA01 – Injections") },
            { "Intro", Tuple.Create("Test the main injection flaws (SQL, OS, LDAP, NoSQL, Path, XSS, etc.) in WPF context.",
                         "Testez les principales failles d'injection (SQL, OS, LDAP, NoSQL, Path, XSS, etc.) dans un contexte WPF.") },
            { "SqlLabel", Tuple.Create("1. SQL Injection", "1. Injection SQL") },
            { "SqlDesc", Tuple.Create("Simulate classic SQL injection on a user lookup.", "Simulez une injection SQL classique sur une recherche utilisateur.") },
            { "TriggerSql", Tuple.Create("Test SQL Injection", "Tester l'injection SQL") },
            { "CmdLabel", Tuple.Create("2. OS Command Injection", "2. Injection de commandes OS") },
            { "CmdDesc", Tuple.Create("Run an OS command based on user input.", "Exécute une commande système basée sur l'entrée utilisateur.") },
            { "TriggerCmd", Tuple.Create("Test OS Command", "Tester l'injection commande OS") },
            { "LdapLabel", Tuple.Create("3. LDAP Injection", "3. Injection LDAP") },
            { "LdapDesc", Tuple.Create("Inject LDAP filter characters to bypass authentication.", "Injectez des caractères LDAP pour contourner l'authentification.") },
            { "TriggerLdap", Tuple.Create("Test LDAP Injection", "Tester l'injection LDAP") },
            { "XmlLabel", Tuple.Create("4. XML/XXE Injection", "4. Injection XML/XXE") },
            { "XmlDesc", Tuple.Create("Test external entity expansion (XXE) via XML input.", "Testez l'expansion d'entité externe (XXE) via une entrée XML.") },
            { "TriggerXml", Tuple.Create("Test XXE Injection", "Tester l'injection XXE") },
            { "NoSqlLabel", Tuple.Create("5. NoSQL Injection", "5. Injection NoSQL") },
            { "NoSqlDesc", Tuple.Create("Inject MongoDB operators into query.", "Injectez des opérateurs MongoDB dans une requête.") },
            { "TriggerNoSql", Tuple.Create("Test NoSQL Injection", "Tester l'injection NoSQL") },
            { "PathLabel", Tuple.Create("6. Path Traversal", "6. Traversée de répertoire") },
            { "PathDesc", Tuple.Create("Try to read a file outside of allowed directory.", "Essayez de lire un fichier hors du dossier autorisé.") },
            { "TriggerPath", Tuple.Create("Test Path Traversal", "Tester la traversée de chemin") },
            { "XssLabel", Tuple.Create("7. XSS (WebView)", "7. XSS (WebView)") },
            { "XssDesc", Tuple.Create("Inject untrusted HTML/JS into a web view.", "Injectez du HTML/JS non fiable dans une webview.") },
            { "TriggerXss", Tuple.Create("Test XSS", "Tester XSS") },
        };

        private string _lang = "en";

        public DA01InjectionsWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage("en");

            // Initialisation des payloads pour tous les TextBox, côté C#
            SqlInput.Text = "1 OR 1=1";
            CmdInput.Text = "calc.exe";
            LdapInput.Text = "*)(|(user=*))";
            XmlInput.Text = "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///C:/Windows/win.ini' > ]><root>&xxe;</root>";
            NoSqlInput.Text = "{ \"username\": { \"$ne\": null } }";
            PathInput.Text = "../secret.txt";
            XssInput.Text = "<script>alert('xss')</script>";
        }

        private void LanguageSelector_Changed(object sender, SelectionChangedEventArgs e)
        {
            var lang = (LanguageSelector.SelectedIndex == 1) ? "fr" : "en";
            SetLanguage(lang);
        }

        // Ouvre le menu au clic n’importe où sur le border
        private void LanguageSelectorBorder_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            LanguageSelector.IsDropDownOpen = true;
        }

        private string GetLabel(string key, string lang)
        {
            return lang == "fr" ? labels[key].Item2 : labels[key].Item1;
        }

        private void SetLanguage(string lang)
        {
            _lang = lang;
            Title = GetLabel("Title",lang);
            TitleText.Text = GetLabel("Title",lang);
            IntroText.Text = GetLabel("Intro",lang);

            SqlLabel.Text = GetLabel("SqlLabel",lang);
            SqlDesc.Text = GetLabel("SqlDesc",lang);
            SqlButton.Content = GetLabel("TriggerSql",lang);

            CmdLabel.Text = GetLabel("CmdLabel",lang);
            CmdDesc.Text = GetLabel("CmdDesc",lang);
            CmdButton.Content = GetLabel("TriggerCmd",lang);

            LdapLabel.Text = GetLabel("LdapLabel",lang);
            LdapDesc.Text = GetLabel("LdapDesc",lang);
            LdapButton.Content = GetLabel("TriggerLdap",lang);

            XmlLabel.Text = GetLabel("XmlLabel",lang);
            XmlDesc.Text = GetLabel("XmlDesc",lang);
            XmlButton.Content = GetLabel("TriggerXml",lang);

            NoSqlLabel.Text = GetLabel("NoSqlLabel",lang);
            NoSqlDesc.Text = GetLabel("NoSqlDesc",lang);
            NoSqlButton.Content = GetLabel("TriggerNoSql",lang);

            PathLabel.Text = GetLabel("PathLabel",lang);
            PathDesc.Text = GetLabel("PathDesc",lang);
            PathButton.Content = GetLabel("TriggerPath",lang);

            XssLabel.Text = GetLabel("XssLabel",lang);
            XssDesc.Text = GetLabel("XssDesc",lang);
            XssButton.Content = GetLabel("TriggerXss",lang);

            // --- Payloads selon la langue
            SqlInput.Text = (lang == "fr") ? "1 OU 1=1" : "1 OR 1=1";
            CmdInput.Text = (lang == "fr") ? "calc.exe" : "calc.exe";
            LdapInput.Text = (lang == "fr") ? "*)(|(utilisateur=*))" : "*)(|(user=*))";
            XmlInput.Text = (lang == "fr")
                ? "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///C:/Windows/win.ini' > ]><root>&xxe;</root>"
                : "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///C:/Windows/win.ini' > ]><root>&xxe;</root>";
            NoSqlInput.Text = (lang == "fr")
                ? "{ \"utilisateur\": { \"$ne\": null } }"
                : "{ \"username\": { \"$ne\": null } }";
            PathInput.Text = (lang == "fr") ? "../secret.txt" : "../secret.txt";
            XssInput.Text = (lang == "fr") ? "<script>alert('xss')</script>" : "<script>alert('xss')</script>";
        }

    }

    // Logique vulnérable (démonstrative uniquement)
    public partial class DA01InjectionsWindow
    {
        private void SqlButton_Click(object sender, RoutedEventArgs e)
        {
            string input = SqlInput.Text;
            if (input.Contains("1=1") || input.ToLower().Contains("' or"))
                SqlResult.Text = _lang == "fr" ? "Tous les utilisateurs affichés ! (bypass)" : "All users displayed! (bypass)";
            else
                SqlResult.Text = _lang == "fr" ? "Aucun utilisateur." : "No user.";
        }
        private void CmdButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo("cmd.exe", $"/c {CmdInput.Text}") { UseShellExecute = false });
                CmdResult.Text = _lang == "fr" ? "Commande lancée." : "Command executed.";
            }
            catch (Exception ex)
            {
                CmdResult.Text = ex.Message;
            }
        }
        private void LdapButton_Click(object sender, RoutedEventArgs e)
        {
            string input = LdapInput.Text;
            if (input.Contains("*)"))
                LdapResult.Text = _lang == "fr" ? "Bypass LDAP !" : "LDAP bypass!";
            else
                LdapResult.Text = _lang == "fr" ? "Authentification échouée." : "Authentication failed.";
        }
        private void XmlButton_Click(object sender, RoutedEventArgs e)
        {
            string input = XmlInput.Text;
            if (input.Contains("<!ENTITY"))
                XmlResult.Text = _lang == "fr" ? "XXE potentielle !" : "Potential XXE!";
            else
                XmlResult.Text = _lang == "fr" ? "XML safe." : "XML safe.";
        }
        private void NoSqlButton_Click(object sender, RoutedEventArgs e)
        {
            string input = NoSqlInput.Text;
            if (input.Contains("$ne") || input.Contains("$gt"))
                NoSqlResult.Text = _lang == "fr" ? "Bypass NoSQL !" : "NoSQL bypass!";
            else
                NoSqlResult.Text = _lang == "fr" ? "Pas de correspondance." : "No match.";
        }
        private void PathButton_Click(object sender, RoutedEventArgs e)
        {
            string input = PathInput.Text;
            try
            {
                string file = Path.GetFullPath(input);
                PathResult.Text = File.Exists(file) ?
                    (_lang == "fr" ? "Fichier trouvé (lecture possible) !" : "File found (readable)!") :
                    (_lang == "fr" ? "Fichier introuvable." : "File not found.");
            }
            catch
            {
                PathResult.Text = _lang == "fr" ? "Erreur de chemin." : "Invalid path.";
            }
        }
        private void XssButton_Click(object sender, RoutedEventArgs e)
        {
            string input = XssInput.Text;
            if (input.Contains("<script>"))
                XssResult.Text = _lang == "fr" ? "Script exécuté dans la WebView (XSS) !" : "Script executed in WebView (XSS)!";
            else
                XssResult.Text = _lang == "fr" ? "Pas de XSS détectée." : "No XSS detected.";
        }
    }

}
