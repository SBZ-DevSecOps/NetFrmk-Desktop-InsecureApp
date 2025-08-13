using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using NetFrmk_Desktop_InsecureApp.Vulnerabilities;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA01InjectionsWindow : Window
    {
        private string _lang = "en";

        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA01 – Injections", "DA01 – Injections") },
            { "Intro", Tuple.Create("Fifteen classic injection sinks. Purposely vulnerable for SAST demo.", "Quinze sinks d’injection classiques. Volontairement vulnérables pour démo SAST.") },

            { "SqlLabel", Tuple.Create("1. SQL Injection", "1. Injection SQL") },
            { "SqlDesc",  Tuple.Create("Concatenate input into a SQL command (ADO.NET).", "Concatène l'entrée dans une requête SQL (ADO.NET).") },
            { "SqlButton", Tuple.Create("Run SQL", "Exécuter SQL") },

            { "CmdLabel", Tuple.Create("2. OS Command Injection", "2. Injection de commande OS") },
            { "CmdDesc",  Tuple.Create("Execute cmd.exe /C with user input.", "Exécute cmd.exe /C avec l'entrée utilisateur.") },
            { "CmdButton", Tuple.Create("Run Command", "Exécuter la commande") },

            { "LdapLabel", Tuple.Create("3. LDAP Injection", "3. Injection LDAP") },
            { "LdapDesc",  Tuple.Create("Unsafe DirectorySearcher filter.", "Filtre DirectorySearcher non sécurisé.") },
            { "LdapButton", Tuple.Create("Search LDAP", "Rechercher LDAP") },

            { "XpathLabel", Tuple.Create("4. XPath Injection", "4. Injection XPath") },
            { "XpathDesc",  Tuple.Create("User-controlled XPath in SelectNodes.", "XPath fourni par l'utilisateur dans SelectNodes.") },
            { "XpathButton", Tuple.Create("Run XPath", "Exécuter XPath") },

            { "XxeLabel", Tuple.Create("5. XXE / XML Injection", "5. XXE / Injection XML") },
            { "XxeDesc",  Tuple.Create("DTD + XmlResolver enabled.", "DTD + XmlResolver activés.") },
            { "XxeButton", Tuple.Create("Parse XML", "Parser XML") },

            { "XsltLabel", Tuple.Create("6. XSLT Injection", "6. Injection XSLT") },
            { "XsltDesc",  Tuple.Create("User-controlled stylesheet applied.", "Feuille de style contrôlée par l'utilisateur.") },
            { "XsltButton", Tuple.Create("Apply XSLT", "Appliquer XSLT") },

            { "PathLabel", Tuple.Create("7. OS Path Injection", "7. Injection de chemin OS") },
            { "PathDesc",  Tuple.Create("User path used for file write.", "Chemin utilisateur utilisé pour écriture fichier.") },
            { "PathButton", Tuple.Create("Write File", "Écrire fichier") },

            { "ExprLabel", Tuple.Create("8. Expression Language Injection", "8. Injection d'expression") },
            { "ExprDesc",  Tuple.Create("DataTable.Compute(expression).", "DataTable.Compute(expression).") },
            { "ExprButton", Tuple.Create("Compute", "Calculer") },

            { "RegexLabel", Tuple.Create("9. Regex Injection / ReDoS", "9. Injection Regex / ReDoS") },
            { "RegexDesc",  Tuple.Create("User pattern compiled and evaluated.", "Motif utilisateur compilé et évalué.") },
            { "RegexButton", Tuple.Create("Test Regex", "Tester Regex") },

            { "ArgsLabel", Tuple.Create("10. Process Arguments Injection", "10. Injection d'arguments de processus") },
            { "ArgsDesc",  Tuple.Create("Start an exe with user-provided args.", "Démarre un exe avec des arguments fournis.") },
            { "ArgsButton", Tuple.Create("Start Process", "Démarrer processus") },

            { "CsvLabel", Tuple.Create("11. CSV Formula Injection", "11. Injection de formule CSV") },
            { "CsvDesc",  Tuple.Create("Write cell that may start with =,+,-,@.", "Écrit une cellule pouvant commencer par =,+,-,@.") },
            { "CsvButton", Tuple.Create("Write CSV", "Écrire CSV") },

            { "PsLabel", Tuple.Create("12. PowerShell Injection", "12. Injection PowerShell") },
            { "PsDesc",  Tuple.Create("powershell.exe -Command <input>.", "powershell.exe -Command <entrée>.") },
            { "PsButton", Tuple.Create("Run PowerShell", "Exécuter PowerShell") },

            { "XamlLabel", Tuple.Create("13. XAML Injection", "13. Injection XAML") },
            { "XamlDesc",  Tuple.Create("XamlReader.Parse on user XAML.", "XamlReader.Parse sur XAML utilisateur.") },
            { "XamlButton", Tuple.Create("Parse XAML", "Parser XAML") },

            { "ReflLabel", Tuple.Create("14. Reflection Type Injection", "14. Injection de type (Reflection)") },
            { "ReflDesc",  Tuple.Create("Type.GetType + Activator.CreateInstance.", "Type.GetType + Activator.CreateInstance.") },
            { "ReflButton", Tuple.Create("Instantiate", "Instancier") },

            { "AsmLabel", Tuple.Create("15. Assembly Load Injection", "15. Injection via chargement d'assembly") },
            { "AsmDesc",  Tuple.Create("Assembly.LoadFrom on user path.", "Assembly.LoadFrom sur chemin fourni.") },
            { "AsmButton", Tuple.Create("Load Assembly", "Charger l'assembly") },
        };

        public DA01InjectionsWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage("en");

            // Placeholders
            SqlInput.Text = "bob' OR '1'='1";
            CmdInput.Text = "calc.exe";
            LdapInput.Text = "*) (|(cn=admin)(cn=*))("; // intentionally funky
            XpathInput.Text = "//user[@name='alice' or '1'='1']";
            XxeInput.Text = "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><r>&xxe;</r>";
            XsltInput.Text = "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:template match='/'><out><xsl:value-of select='//msg'/></out></xsl:template></xsl:stylesheet>";
            PathInput.Text = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\..\\exposed\\inj.txt";
            ExprInput.Text = "1+2*3";
            RegexPatternInput.Text = "(a+)+$";
            RegexSampleInput.Text = new string('a', 5000);
            ArgsExeInput.Text = "ping.exe";
            ArgsArgsInput.Text = "127.0.0.1 & calc.exe";
            CsvInput.Text = "=2+2";
            PsInput.Text = "Start-Process calc";
            XamlInput.Text = "<Button xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' Content='XAML!' />";
            ReflInput.Text = "System.Text.StringBuilder, mscorlib";
            AsmInput.Text = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\demo.dll";
        }

        private string GetLabel(string key, string lang)
        {
            Tuple<string, string> t = labels[key];
            return lang == "fr" ? t.Item2 : t.Item1;
        }

        private void LanguageSelector_Changed(object sender, SelectionChangedEventArgs e)
        {
            string lang = (LanguageSelector.SelectedIndex == 1) ? "fr" : "en";
            SetLanguage(lang);
        }

        private void SetLanguage(string lang)
        {
            _lang = lang;

            Action<string, string> L = (name, key) => { var c = FindName(name) as TextBlock; if (c != null) c.Text = GetLabel(key, lang); };
            Action<string, string> B = (name, key) => { var c = FindName(name) as Button; if (c != null) c.Content = GetLabel(key, lang); };

            var title = FindName("TitleText") as TextBlock; if (title != null) title.Text = GetLabel("Title", lang);
            var intro = FindName("IntroText") as TextBlock; if (intro != null) intro.Text = GetLabel("Intro", lang);
            this.Title = GetLabel("Title", lang);

            L("SqlLabel", "SqlLabel"); L("SqlDesc", "SqlDesc"); B("SqlButton", "SqlButton");
            L("CmdLabel", "CmdLabel"); L("CmdDesc", "CmdDesc"); B("CmdButton", "CmdButton");
            L("LdapLabel", "LdapLabel"); L("LdapDesc", "LdapDesc"); B("LdapButton", "LdapButton");
            L("XpathLabel", "XpathLabel"); L("XpathDesc", "XpathDesc"); B("XpathButton", "XpathButton");
            L("XxeLabel", "XxeLabel"); L("XxeDesc", "XxeDesc"); B("XxeButton", "XxeButton");
            L("XsltLabel", "XsltLabel"); L("XsltDesc", "XsltDesc"); B("XsltButton", "XsltButton");
            L("PathLabel", "PathLabel"); L("PathDesc", "PathDesc"); B("PathButton", "PathButton");
            L("ExprLabel", "ExprLabel"); L("ExprDesc", "ExprDesc"); B("ExprButton", "ExprButton");
            L("RegexLabel", "RegexLabel"); L("RegexDesc", "RegexDesc"); B("RegexButton", "RegexButton");
            L("ArgsLabel", "ArgsLabel"); L("ArgsDesc", "ArgsDesc"); B("ArgsButton", "ArgsButton");
            L("CsvLabel", "CsvLabel"); L("CsvDesc", "CsvDesc"); B("CsvButton", "CsvButton");
            L("PsLabel", "PsLabel"); L("PsDesc", "PsDesc"); B("PsButton", "PsButton");
            L("XamlLabel", "XamlLabel"); L("XamlDesc", "XamlDesc"); B("XamlButton", "XamlButton");
            L("ReflLabel", "ReflLabel"); L("ReflDesc", "ReflDesc"); B("ReflButton", "ReflButton");
            L("AsmLabel", "AsmLabel"); L("AsmDesc", "AsmDesc"); B("AsmButton", "AsmButton");
        }

        // -------- Handlers --------

        private void SqlButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunSqlInjection(SqlInput.Text); SqlResult.Text = _lang == "fr" ? "Requête SQL exécutée." : "SQL executed."; }

        private void CmdButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunCommandInjection(CmdInput.Text); CmdResult.Text = _lang == "fr" ? "Commande lancée." : "Command launched."; }

        private void LdapButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunLdapInjection(LdapInput.Text); LdapResult.Text = _lang == "fr" ? "Recherche LDAP effectuée." : "LDAP search executed."; }

        private void XpathButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunXpathInjection(XpathInput.Text); XpathResult.Text = _lang == "fr" ? "XPath exécuté." : "XPath executed."; }

        private void XxeButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunXxeInjection(XxeInput.Text); XxeResult.Text = _lang == "fr" ? "XML parsé (XXE possible)." : "XML parsed (XXE possible)."; }

        private void XsltButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunXsltInjection(XsltInput.Text); XsltResult.Text = _lang == "fr" ? "XSLT appliqué." : "XSLT applied."; }

        private void PathButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunOsPathInjection(PathInput.Text); PathResult.Text = _lang == "fr" ? "Écriture effectuée." : "Write done."; }

        private void ExprButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunExpressionInjection(ExprInput.Text); ExprResult.Text = _lang == "fr" ? "Expression calculée." : "Expression computed."; }

        private void RegexButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunRegexInjection(RegexPatternInput.Text, RegexSampleInput.Text); RegexResult.Text = _lang == "fr" ? "Regex testée." : "Regex tested."; }

        private void ArgsButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunProcessArgsInjection(ArgsExeInput.Text, ArgsArgsInput.Text); ArgsResult.Text = _lang == "fr" ? "Processus lancé." : "Process started."; }

        private void CsvButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunCsvFormulaInjection(CsvInput.Text); CsvResult.Text = _lang == "fr" ? "CSV écrit (Documents)." : "CSV written (Documents)."; }

        private void PsButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunPowershellInjection(PsInput.Text); PsResult.Text = _lang == "fr" ? "PowerShell exécuté." : "PowerShell executed."; }

        private void XamlButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunXamlInjection(XamlInput.Text); XamlResult.Text = _lang == "fr" ? "XAML parsé." : "XAML parsed."; }

        private void ReflButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunReflectionInjection(ReflInput.Text); ReflResult.Text = _lang == "fr" ? "Reflection exécutée." : "Reflection executed."; }

        private void AsmButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunAssemblyLoadInjection(AsmInput.Text); AsmResult.Text = _lang == "fr" ? "Assembly chargé." : "Assembly loaded."; }
    }
}
