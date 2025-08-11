using NetFrmk_Desktop_InsecureApp.Vulnerabilities;
using System;
using System.Collections.Generic;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA09ErrorHandlingWindow : Window
    {
        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA09 – Improper Error & Exception Handling", "DA09 – Gestion inadéquate des erreurs/exceptions") },
            { "Intro", Tuple.Create("Demonstrates poor error/exception handling patterns in desktop .NET.", "Démontre les mauvaises pratiques de gestion d’erreur dans les applis desktop .NET.") },

            { "StacktraceLabel", Tuple.Create("Stacktrace to UI", "Stacktrace à l’utilisateur") },
            { "StacktraceDesc", Tuple.Create("Shows full .NET stacktrace on error.", "Affiche la stacktrace complète à l’utilisateur.") },
            { "StacktraceButton", Tuple.Create("Show Stacktrace", "Afficher stacktrace") },

            { "UncaughtLabel", Tuple.Create("Uncaught exception (crash)", "Exception non catchée (crash)") },
            { "UncaughtDesc", Tuple.Create("App closes/crashes on error, no handler.", "L’appli ferme/crash sans gestion.") },
            { "UncaughtButton", Tuple.Create("Crash Now", "Provoquer crash") },

            { "SilentSwallowLabel", Tuple.Create("Silent catch (swallow)", "Catch silencieux (swallow)") },
            { "SilentSwallowDesc", Tuple.Create("Exceptions are caught but ignored.", "Exceptions attrapées mais ignorées.") },
            { "SilentSwallowButton", Tuple.Create("Swallow Error", "Swallow l’erreur") },

            { "TechErrorLabel", Tuple.Create("Technical error in UI", "Erreur technique à l’écran") },
            { "TechErrorDesc", Tuple.Create("Technical/debug info shown to users.", "Infos techniques/debug à l’utilisateur.") },
            { "TechErrorButton", Tuple.Create("Tech Error", "Erreur technique") },

            { "VerboseLogLabel", Tuple.Create("Verbose log in prod", "Logs verbeux en prod") },
            { "VerboseLogDesc", Tuple.Create("Writes full errors in logs, even prod.", "Logs complets, même en prod.") },
            { "VerboseLogButton", Tuple.Create("Log Verbose", "Log verbeux") },

            { "SystemInfoLabel", Tuple.Create("Leak system info", "Fuite infos système") },
            { "SystemInfoDesc", Tuple.Create("Shows system/path/user info in error.", "Montre infos système/chemin/utilisateur.") },
            { "SystemInfoButton", Tuple.Create("Leak Info", "Fuite d’infos") },

            { "InnerExceptionLabel", Tuple.Create("Show inner exception", "Affiche inner exception") },
            { "InnerExceptionDesc", Tuple.Create("Displays nested exception details.", "Montre détail d’exception imbriquée.") },
            { "InnerExceptionButton", Tuple.Create("Inner Exception", "Exception imbriquée") },

            { "ThrowLabel", Tuple.Create("Throw w/o handler", "Throw sans handler") },
            { "ThrowDesc", Tuple.Create("Throws error, not handled globally.", "Throw, pas de gestion globale.") },
            { "ThrowButton", Tuple.Create("Throw Error", "Throw l’erreur") },

            { "NoGlobalHandlerLabel", Tuple.Create("No global error handler", "Pas de gestion globale") },
            { "NoGlobalHandlerDesc", Tuple.Create("App has no AppDomain/Dispatcher handler.", "Aucun handler global, crash sur erreur.") },
            { "NoGlobalHandlerButton", Tuple.Create("Test No Handler", "Tester sans handler") },

            { "PoorIoNetLabel", Tuple.Create("Poor IO/Network error handling", "Mauvaise gestion IO/Réseau") },
            { "PoorIoNetDesc", Tuple.Create("Minimal or generic error handling for files/network.", "Peu/pas de gestion IO/réseau.") },
            { "PoorIoNetButton", Tuple.Create("IO/Net Error", "Erreur IO/Réseau") },

            { "SensitiveLogLabel", Tuple.Create("Sensitive info in log", "Infos sensibles dans log") },
            { "SensitiveLogDesc", Tuple.Create("Logs credentials or secrets in error details.", "Log credentials/secrets dans erreur.") },
            { "SensitiveLogButton", Tuple.Create("Sensitive Log", "Log sensible") },

            { "CrashDumpLabel", Tuple.Create("Crash dump world-readable", "Crash dump accessible à tous") },
            { "CrashDumpDesc", Tuple.Create("Crash dump file is written with Everyone rights.", "Crash dump écrit avec droits Everyone.") },
            { "CrashDumpButton", Tuple.Create("Crash Dump", "Crash dump") },
        };

        private string _lang = "en";
        public DA09ErrorHandlingWindow()
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

            StacktraceLabel.Text= GetLabel("StacktraceLabel",lang);
            StacktraceDesc.Text= GetLabel("StacktraceDesc",lang);
            StacktraceButton.Content= GetLabel("StacktraceButton",lang);

            UncaughtLabel.Text= GetLabel("UncaughtLabel",lang);
            UncaughtDesc.Text= GetLabel("UncaughtDesc",lang);
            UncaughtButton.Content= GetLabel("UncaughtButton",lang);

            SilentSwallowLabel.Text= GetLabel("SilentSwallowLabel",lang);
            SilentSwallowDesc.Text= GetLabel("SilentSwallowDesc",lang);
            SilentSwallowButton.Content= GetLabel("SilentSwallowButton",lang);

            TechErrorLabel.Text= GetLabel("TechErrorLabel",lang);
            TechErrorDesc.Text= GetLabel("TechErrorDesc",lang);
            TechErrorButton.Content= GetLabel("TechErrorButton",lang);

            VerboseLogLabel.Text= GetLabel("VerboseLogLabel",lang);
            VerboseLogDesc.Text= GetLabel("VerboseLogDesc",lang);
            VerboseLogButton.Content= GetLabel("VerboseLogButton",lang);

            SystemInfoLabel.Text= GetLabel("SystemInfoLabel",lang);
            SystemInfoDesc.Text= GetLabel("SystemInfoDesc",lang);
            SystemInfoButton.Content= GetLabel("SystemInfoButton",lang);

            InnerExceptionLabel.Text= GetLabel("InnerExceptionLabel",lang);
            InnerExceptionDesc.Text= GetLabel("InnerExceptionDesc",lang);
            InnerExceptionButton.Content= GetLabel("InnerExceptionButton",lang);

            ThrowLabel.Text= GetLabel("ThrowLabel",lang);
            ThrowDesc.Text= GetLabel("ThrowDesc",lang);
            ThrowButton.Content= GetLabel("ThrowButton",lang);

            NoGlobalHandlerLabel.Text= GetLabel("NoGlobalHandlerLabel",lang);
            NoGlobalHandlerDesc.Text= GetLabel("NoGlobalHandlerDesc",lang);
            NoGlobalHandlerButton.Content= GetLabel("NoGlobalHandlerButton",lang);

            PoorIoNetLabel.Text= GetLabel("PoorIoNetLabel",lang);
            PoorIoNetDesc.Text= GetLabel("PoorIoNetDesc",lang);
            PoorIoNetButton.Content= GetLabel("PoorIoNetButton",lang);

            SensitiveLogLabel.Text= GetLabel("SensitiveLogLabel",lang);
            SensitiveLogDesc.Text= GetLabel("SensitiveLogDesc",lang);
            SensitiveLogButton.Content= GetLabel("SensitiveLogButton",lang);

            CrashDumpLabel.Text= GetLabel("CrashDumpLabel",lang);
            CrashDumpDesc.Text= GetLabel("CrashDumpDesc",lang);
            CrashDumpButton.Content= GetLabel("CrashDumpButton",lang);
        }

        // Handlers
        private void StacktraceButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.StacktraceToUI();
        private void UncaughtButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.UncaughtException();
        private void SilentSwallowButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.SilentSwallow();
        private void TechErrorButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.TechnicalErrorUI();
        private void VerboseLogButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.VerboseProdLog();
        private void SystemInfoButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.LeakSystemInfo();
        private void InnerExceptionButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.InnerExceptions();
        private void ThrowButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.ThrowUncaught();
        private void NoGlobalHandlerButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.NoGlobalHandler();
        private void PoorIoNetButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.PoorIoNetworkHandling();
        private void SensitiveLogButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.SensitiveLog();
        private void CrashDumpButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.DumpWorldReadable();
    }
}
