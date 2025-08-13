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

            { "StacktraceLabel", Tuple.Create("1. Stacktrace to UI", "1. Stacktrace à l’utilisateur") },
            { "StacktraceDesc", Tuple.Create("Shows full .NET stacktrace on error.", "Affiche la stacktrace complète à l’utilisateur.") },
            { "StacktraceButton", Tuple.Create("Show Stacktrace", "Afficher stacktrace") },

            { "UncaughtLabel", Tuple.Create("2. Uncaught exception (crash)", "2. Exception non catchée (crash)") },
            { "UncaughtDesc", Tuple.Create("App closes/crashes on error, no handler.", "L’appli ferme/crash sans gestion.") },
            { "UncaughtButton", Tuple.Create("Crash Now", "Provoquer crash") },

            { "SilentSwallowLabel", Tuple.Create("3. Silent catch (swallow)", "3. Catch silencieux (swallow)") },
            { "SilentSwallowDesc", Tuple.Create("Exceptions are caught but ignored.", "Exceptions attrapées mais ignorées.") },
            { "SilentSwallowButton", Tuple.Create("Swallow Error", "Swallow l’erreur") },

            { "TechErrorLabel", Tuple.Create("4. Technical error in UI", "4. Erreur technique à l’écran") },
            { "TechErrorDesc", Tuple.Create("Technical/debug info shown to users.", "Infos techniques/debug à l’utilisateur.") },
            { "TechErrorButton", Tuple.Create("Tech Error", "Erreur technique") },

            { "VerboseLogLabel", Tuple.Create("5. Verbose log in prod", "5. Logs verbeux en prod") },
            { "VerboseLogDesc", Tuple.Create("Writes full errors in logs, even prod.", "Logs complets, même en prod.") },
            { "VerboseLogButton", Tuple.Create("Log Verbose", "Log verbeux") },

            { "SystemInfoLabel", Tuple.Create("6. Leak system info", "6. Fuite infos système") },
            { "SystemInfoDesc", Tuple.Create("Shows system/path/user info in error.", "Montre infos système/chemin/utilisateur.") },
            { "SystemInfoButton", Tuple.Create("Leak Info", "Fuite d’infos") },

            { "InnerExceptionLabel", Tuple.Create("7. Show inner exception", "7. Affiche inner exception") },
            { "InnerExceptionDesc", Tuple.Create("Displays nested exception details.", "Montre détail d’exception imbriquée.") },
            { "InnerExceptionButton", Tuple.Create("Inner Exception", "Exception imbriquée") },

            { "ThrowLabel", Tuple.Create("8. Throw w/o handler", "8. Throw sans handler") },
            { "ThrowDesc", Tuple.Create("Throws error, not handled globally.", "Throw, pas de gestion globale.") },
            { "ThrowButton", Tuple.Create("Throw Error", "Throw l’erreur") },

            { "NoGlobalHandlerLabel", Tuple.Create("9. No global error handler", "9. Pas de gestion globale") },
            { "NoGlobalHandlerDesc", Tuple.Create("App has no AppDomain/Dispatcher handler.", "Aucun handler global, crash sur erreur.") },
            { "NoGlobalHandlerButton", Tuple.Create("Test No Handler", "Tester sans handler") },

            { "PoorIoNetLabel", Tuple.Create("10. Poor IO/Network error handling", "10. Mauvaise gestion IO/Réseau") },
            { "PoorIoNetDesc", Tuple.Create("Minimal or generic error handling for files/network.", "Peu/pas de gestion IO/réseau.") },
            { "PoorIoNetButton", Tuple.Create("IO/Net Error", "Erreur IO/Réseau") },

            { "SensitiveLogLabel", Tuple.Create("11. Sensitive info in log", "11. Infos sensibles dans log") },
            { "SensitiveLogDesc", Tuple.Create("Logs credentials or secrets in error details.", "Log credentials/secrets dans erreur.") },
            { "SensitiveLogButton", Tuple.Create("Sensitive Log", "Log sensible") },

            { "CrashDumpLabel", Tuple.Create("12. Crash dump world-readable", "12. Crash dump accessible à tous") },
            { "CrashDumpDesc", Tuple.Create("Crash dump file is written with Everyone rights.", "Crash dump écrit avec droits Everyone.") },
            { "CrashDumpButton", Tuple.Create("Crash Dump", "Crash dump") },

            // Nouveaux 13..15
            { "RethrowLabel", Tuple.Create("13. Rethrow with lost stack (throw ex)", "13. Rethrow avec perte de stack (throw ex)") },
            { "RethrowDesc", Tuple.Create("Re-throws with 'throw ex;', losing original stack trace.", "Relance avec 'throw ex;' et perd la stack d’origine.") },
            { "RethrowButton", Tuple.Create("Rethrow (bad)", "Rethrow (mauvais)") },

            { "FinallyMaskLabel", Tuple.Create("14. Exception in finally masks original", "14. Exception dans finally masque l’originale") },
            { "FinallyMaskDesc", Tuple.Create("Finally throws and hides root cause.", "Le finally lance une exception et masque la cause racine.") },
            { "FinallyMaskButton", Tuple.Create("Trigger Finally", "Déclencher finally") },

            { "FireForgetLabel", Tuple.Create("15. Unobserved Task (fire-and-forget)", "15. Tâche non observée (fire-and-forget)") },
            { "FireForgetDesc", Tuple.Create("Background task throws; no await/handler.", "Tâche en arrière-plan jette une exception; aucun await/handler.") },
            { "FireForgetButton", Tuple.Create("Start Faulted Task", "Démarrer tâche fautive") },
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

        private string GetLabel(string key, string lang) => lang == "fr" ? labels[key].Item2 : labels[key].Item1;

        private void SetLanguage(string lang)
        {
            Title = GetLabel("Title", lang);
            TitleText.Text = GetLabel("Title", lang);
            IntroText.Text = GetLabel("Intro", lang);

            StacktraceLabel.Text = GetLabel("StacktraceLabel", lang);
            StacktraceDesc.Text = GetLabel("StacktraceDesc", lang);
            StacktraceButton.Content = GetLabel("StacktraceButton", lang);

            UncaughtLabel.Text = GetLabel("UncaughtLabel", lang);
            UncaughtDesc.Text = GetLabel("UncaughtDesc", lang);
            UncaughtButton.Content = GetLabel("UncaughtButton", lang);

            SilentSwallowLabel.Text = GetLabel("SilentSwallowLabel", lang);
            SilentSwallowDesc.Text = GetLabel("SilentSwallowDesc", lang);
            SilentSwallowButton.Content = GetLabel("SilentSwallowButton", lang);

            TechErrorLabel.Text = GetLabel("TechErrorLabel", lang);
            TechErrorDesc.Text = GetLabel("TechErrorDesc", lang);
            TechErrorButton.Content = GetLabel("TechErrorButton", lang);

            VerboseLogLabel.Text = GetLabel("VerboseLogLabel", lang);
            VerboseLogDesc.Text = GetLabel("VerboseLogDesc", lang);
            VerboseLogButton.Content = GetLabel("VerboseLogButton", lang);

            SystemInfoLabel.Text = GetLabel("SystemInfoLabel", lang);
            SystemInfoDesc.Text = GetLabel("SystemInfoDesc", lang);
            SystemInfoButton.Content = GetLabel("SystemInfoButton", lang);

            InnerExceptionLabel.Text = GetLabel("InnerExceptionLabel", lang);
            InnerExceptionDesc.Text = GetLabel("InnerExceptionDesc", lang);
            InnerExceptionButton.Content = GetLabel("InnerExceptionButton", lang);

            ThrowLabel.Text = GetLabel("ThrowLabel", lang);
            ThrowDesc.Text = GetLabel("ThrowDesc", lang);
            ThrowButton.Content = GetLabel("ThrowButton", lang);

            NoGlobalHandlerLabel.Text = GetLabel("NoGlobalHandlerLabel", lang);
            NoGlobalHandlerDesc.Text = GetLabel("NoGlobalHandlerDesc", lang);
            NoGlobalHandlerButton.Content = GetLabel("NoGlobalHandlerButton", lang);

            PoorIoNetLabel.Text = GetLabel("PoorIoNetLabel", lang);
            PoorIoNetDesc.Text = GetLabel("PoorIoNetDesc", lang);
            PoorIoNetButton.Content = GetLabel("PoorIoNetButton", lang);

            SensitiveLogLabel.Text = GetLabel("SensitiveLogLabel", lang);
            SensitiveLogDesc.Text = GetLabel("SensitiveLogDesc", lang);
            SensitiveLogButton.Content = GetLabel("SensitiveLogButton", lang);

            CrashDumpLabel.Text = GetLabel("CrashDumpLabel", lang);
            CrashDumpDesc.Text = GetLabel("CrashDumpDesc", lang);
            CrashDumpButton.Content = GetLabel("CrashDumpButton", lang);

            RethrowLabel.Text = GetLabel("RethrowLabel", lang);
            RethrowDesc.Text = GetLabel("RethrowDesc", lang);
            RethrowButton.Content = GetLabel("RethrowButton", lang);

            FinallyMaskLabel.Text = GetLabel("FinallyMaskLabel", lang);
            FinallyMaskDesc.Text = GetLabel("FinallyMaskDesc", lang);
            FinallyMaskButton.Content = GetLabel("FinallyMaskButton", lang);

            FireForgetLabel.Text = GetLabel("FireForgetLabel", lang);
            FireForgetDesc.Text = GetLabel("FireForgetDesc", lang);
            FireForgetButton.Content = GetLabel("FireForgetButton", lang);
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

        private void RethrowButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.RethrowLostStack();
        private void FinallyMaskButton_Click(object sender, RoutedEventArgs e) => ErrorHandlingVuln.FinallyMasksOriginal();
        private void FireForgetButton_Click(object sender, RoutedEventArgs e) => FireForgetResult.Text = ErrorHandlingVuln.FireAndForgetTask();
    }
}
