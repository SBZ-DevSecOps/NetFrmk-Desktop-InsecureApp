using NetFrmk_Desktop_InsecureApp.Vulnerabilities;
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA07UnsafeApiWindow : Window
    {
        // Dictionnaire de dictionnaires : [clé][langue] = valeur
        private Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            // Titres
            { "Title", Tuple.Create("DA07 – Poor Code Quality / Unsafe APIs", "DA07 – Faible qualité de code / APIs dangereuses") },
            { "Intro", Tuple.Create("Test intentionally unsafe code in WPF – each colored panel is a real vulnerability scenario.",
                                    "Testez du code délibérément non sécurisé – chaque panneau coloré correspond à un scénario de vulnérabilité.") },
            // Scénario 1
            { "UnsafeBufferLabel", Tuple.Create("1. Unsafe Buffer Manipulation", "1. Dépassement de mémoire (Buffer Overflow)") },
            { "UnsafeBufferDesc", Tuple.Create("Direct memory access (unsafe) can allow buffer overflow.",
                                              "L'accès direct à la mémoire (unsafe) peut entraîner un dépassement de mémoire.") },
            { "TriggerUnsafeBuffer", Tuple.Create("Trigger Unsafe Buffer", "Déclencher Buffer Overflow") },
            // Scénario 2
            { "BinaryFormatterLabel", Tuple.Create("2. BinaryFormatter Deserialization", "2. Désérialisation BinaryFormatter") },
            { "BinaryFormatterDesc", Tuple.Create("Deserializing untrusted data can allow code execution (RCE).",
                                                 "La désérialisation de données non fiables peut permettre l'exécution de code (RCE).") },
            { "TriggerDeserialize", Tuple.Create("Deserialize", "Désérialiser") },
            // Scénario 3
            { "IntOverflowLabel", Tuple.Create("3. Integer Overflow", "3. Dépassement d'entier") },
            { "IntOverflowDesc", Tuple.Create("Unchecked arithmetic can result in integer overflow.",
                                             "Une arithmétique non contrôlée peut entraîner un dépassement d'entier.") },
            { "TestOverflow", Tuple.Create("Test Overflow", "Tester le dépassement") },
            // Scénario 4
            { "PInvokeLabel", Tuple.Create("4. Unsafe P/Invoke", "4. P/Invoke dangereux") },
            { "PInvokeDesc", Tuple.Create("Calling unmanaged APIs directly can cause stability issues.",
                                         "Appeler des APIs non managées peut entraîner des problèmes de stabilité.") },
            { "CallAPI", Tuple.Create("Call API", "Appeler API") },
            // Scénario 5
            { "EvalLabel", Tuple.Create("5. Eval / Dynamic Code Execution", "5. Eval / Exécution de code dynamique") },
            { "EvalDesc", Tuple.Create("Evaluating user-controlled code can lead to code execution.",
                                      "Évaluer du code contrôlé par l'utilisateur peut permettre une exécution de code.") },
            { "Eval", Tuple.Create("Eval", "Évaluer") },
            // Scénario 6
            { "RaceLabel", Tuple.Create("6. Race Condition (File Write)", "6. Condition de course (écriture fichier)") },
            { "RaceDesc", Tuple.Create("Simulate concurrent writes to a file: may cause corruption.",
                                      "Simule des écritures concurrentes sur un fichier : peut provoquer de la corruption.") },
            { "TriggerRace", Tuple.Create("Trigger Race", "Déclencher la course") },
            // Scénario 7
            { "StackLabel", Tuple.Create("7. Stack Overflow (Recursion)", "7. Dépassement de pile (récursivité)") },
            { "StackDesc", Tuple.Create("Calling a recursive function without exit can crash the app.",
                                       "Appeler une fonction récursive sans sortie peut faire planter l'application.") },
            { "TriggerStack", Tuple.Create("Trigger Stack Overflow", "Déclencher le dépassement de pile") },
        };


        private string _lang = "en";

        public DA07UnsafeApiWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage("en");
        }

        private string GetLabel(string key, string lang)
        {
            return lang == "fr" ? labels[key].Item2 : labels[key].Item1;
        }

        private void LanguageSelector_Changed(object sender, SelectionChangedEventArgs e)
        {
            var lang = (LanguageSelector.SelectedIndex == 1) ? "fr" : "en";
            SetLanguage(lang);
        }

        private void SetLanguage(string lang)
        {
            _lang = lang;
            Title = GetLabel("Title", lang);
            TitleText.Text = GetLabel("Title", lang);
            IntroText.Text = GetLabel("Intro", lang);

            // Panel 1
            UnsafeBufferLabel.Text = GetLabel("UnsafeBufferLabel", lang);
            UnsafeBufferDesc.Text = GetLabel("UnsafeBufferDesc", lang);
            UnsafeBufferButton.Content = GetLabel("TriggerUnsafeBuffer", lang);

            // Panel 2
            BinaryFormatterLabel.Text = GetLabel("BinaryFormatterLabel", lang);
            BinaryFormatterDesc.Text = GetLabel("BinaryFormatterDesc", lang);
            BinaryFormatterButton.Content = GetLabel("TriggerDeserialize", lang);

            // Panel 3
            IntOverflowLabel.Text = GetLabel("IntOverflowLabel", lang);
            IntOverflowDesc.Text = GetLabel("IntOverflowDesc", lang);
            IntOverflowButton.Content = GetLabel("TestOverflow", lang);

            // Panel 4
            PInvokeLabel.Text = GetLabel("PInvokeLabel", lang);
            PInvokeDesc.Text = GetLabel("PInvokeDesc", lang);
            PInvokeButton.Content = GetLabel("CallAPI", lang);

            // Panel 5
            EvalLabel.Text = GetLabel("EvalLabel", lang);
            EvalDesc.Text = GetLabel("EvalDesc", lang);
            EvalButton.Content = GetLabel("Eval", lang);

            // Panel 6
            RaceLabel.Text = GetLabel("RaceLabel", lang);
            RaceDesc.Text = GetLabel("RaceDesc", lang);
            RaceButton.Content = GetLabel("TriggerRace", lang);

            // Panel 7
            StackLabel.Text = GetLabel("StackLabel", lang);
            StackDesc.Text = GetLabel("StackDesc", lang);
            StackButton.Content = GetLabel("TriggerStack", lang);
        }


        // Liens panels -> code vulnérable (identiques à la version précédente)
        private void UnsafeBufferButton_Click(object sender, RoutedEventArgs e)
            => UnsafeBufferResult.Text = UnsafeApiVuln.UnsafeBuffer(UnsafeBufferInput.Text);

        private void BinaryFormatterButton_Click(object sender, RoutedEventArgs e)
            => BinaryFormatterResult.Text = UnsafeApiVuln.BinaryFormatterDeserialize(BinaryFormatterInput.Text);

        private void IntOverflowButton_Click(object sender, RoutedEventArgs e)
            => IntOverflowResult.Text = UnsafeApiVuln.IntegerOverflow(IntOverflowInput.Text);

        private void PInvokeButton_Click(object sender, RoutedEventArgs e)
            => PInvokeResult.Text = UnsafeApiVuln.UnsafePInvoke(PInvokeInput.Text);

        private void EvalButton_Click(object sender, RoutedEventArgs e)
            => EvalResult.Text = UnsafeApiVuln.DynamicEval(EvalInput.Text);

        private void RaceButton_Click(object sender, RoutedEventArgs e)
            => RaceResult.Text = UnsafeApiVuln.RaceCondition(RaceInput.Text);

        private void StackButton_Click(object sender, RoutedEventArgs e)
            => StackResult.Text = UnsafeApiVuln.StackOverflow(StackInput.Text);
    }
}
