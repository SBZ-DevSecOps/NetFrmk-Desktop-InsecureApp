using NetFrmk_Desktop_InsecureApp.Vulnerabilities;
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA07UnsafeApiWindow : Window
    {
        private string _lang = "en";

        // [key] -> (EN, FR)
        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA07 – Poor Code Quality / Unsafe APIs", "DA07 – Faible qualité de code / APIs dangereuses") },
            { "Intro", Tuple.Create("Intentionally unsafe API usage and fragile patterns. Each card triggers a vulnerable sink for SAST demos.", "Utilisation d’APIs dangereuses et de motifs fragiles. Chaque carte déclenche un sink vulnérable pour les démos SAST.") },

            // 1..7 (existants)
            { "UnsafeBufferLabel", Tuple.Create("1. Unsafe Buffer Manipulation", "1. Dépassement de mémoire (Buffer Overflow)") },
            { "UnsafeBufferDesc",  Tuple.Create("Direct memory access can overflow a buffer.", "L’accès direct mémoire peut provoquer un dépassement.") },
            { "UnsafeBufferButton",Tuple.Create("Trigger Unsafe Buffer", "Déclencher Buffer Overflow") },

            { "BinaryFormatterLabel", Tuple.Create("2. BinaryFormatter Deserialization", "2. Désérialisation BinaryFormatter") },
            { "BinaryFormatterDesc",  Tuple.Create("Deserializing untrusted data can lead to RCE.", "La désérialisation de données non fiables peut mener à une exécution de code.") },
            { "BinaryFormatterButton",Tuple.Create("Deserialize (BinaryFormatter)", "Désérialiser (BinaryFormatter)") },

            { "IntOverflowLabel", Tuple.Create("3. Integer Overflow", "3. Dépassement d'entier") },
            { "IntOverflowDesc",  Tuple.Create("Unchecked arithmetic causes overflow.", "Un calcul non contrôlé provoque un dépassement.") },
            { "IntOverflowButton",Tuple.Create("Test Overflow", "Tester le dépassement") },

            { "PInvokeLabel", Tuple.Create("4. Unsafe P/Invoke", "4. P/Invoke dangereux") },
            { "PInvokeDesc",  Tuple.Create("Calling unmanaged APIs directly.", "Appel direct d’APIs non managées.") },
            { "PInvokeButton",Tuple.Create("Call API", "Appeler API") },

            { "EvalLabel", Tuple.Create("5. Eval / Dynamic Code Execution", "5. Eval / Exécution de code dynamique") },
            { "EvalDesc",  Tuple.Create("DataTable.Compute abused as eval.", "Detournement de DataTable.Compute comme eval.") },
            { "EvalButton",Tuple.Create("Eval", "Évaluer") },

            { "RaceLabel", Tuple.Create("6. Race Condition (File Write)", "6. Condition de course (écriture fichier)") },
            { "RaceDesc",  Tuple.Create("Concurrent writes without locking.", "Écritures concurrentes sans verrou.") },
            { "RaceButton",Tuple.Create("Trigger Race", "Déclencher la course") },

            { "StackLabel", Tuple.Create("7. Stack Overflow (Recursion)", "7. Dépassement de pile (récursivité)") },
            { "StackDesc",  Tuple.Create("Recursive call without exit.", "Appel récursif sans sortie.") },
            { "StackButton",Tuple.Create("Trigger Stack Overflow", "Déclencher le dépassement de pile") },

            // 8..15 (nouveaux)
            { "RegexLabel", Tuple.Create("8. Regex ReDoS (no timeout)", "8. Regex ReDoS (sans timeout)") },
            { "RegexDesc",  Tuple.Create("Catastrophic backtracking can hang the app.", "Le backtracking catastrophique peut bloquer l’appli.") },
            { "RegexButton",Tuple.Create("Run Regex", "Exécuter Regex") },

            { "XxeLabel", Tuple.Create("9. XML External Entity (XXE)", "9. XML External Entity (XXE)") },
            { "XxeDesc",  Tuple.Create("DTD + resolver enable external entities.", "DTD + resolver permettent des entités externes.") },
            { "XxeButton",Tuple.Create("Load XML", "Charger XML") },

            { "ReflectLabel", Tuple.Create("10. Insecure Reflection Invoke", "10. Reflection non sécurisée") },
            { "ReflectDesc",  Tuple.Create("Type/method names from user.", "Noms de type/méthode fournis par l’utilisateur.") },
            { "ReflectButton",Tuple.Create("Invoke", "Invoquer") },

            { "WeakRndLabel", Tuple.Create("11. Weak Random Token", "11. Jeton aléatoire faible") },
            { "WeakRndDesc",  Tuple.Create("Predictable System.Random.", "System.Random prévisible.") },
            { "WeakRndButton",Tuple.Create("Generate", "Générer") },

            { "Md5Label", Tuple.Create("12. Insecure Hash (MD5)", "12. Hachage non sûr (MD5)") },
            { "Md5Desc",  Tuple.Create("Fast unsalted MD5.", "MD5 rapide, sans sel.") },
            { "Md5Button",Tuple.Create("Hash (MD5)", "Hacher (MD5)") },

            { "ZipSlipLabel", Tuple.Create("13. ZipSlip Extract", "13. ZipSlip Extract") },
            { "ZipSlipDesc",  Tuple.Create("No path sanitization on entries.", "Aucune validation des chemins d’entrées.") },
            { "ZipSlipButton",Tuple.Create("Extract ZIP", "Extraire ZIP") },

            { "ShellLabel", Tuple.Create("14. Unsafe Shell Exec", "14. Exécution shell non sûre") },
            { "ShellDesc",  Tuple.Create("cmd.exe /C <user input>.", "cmd.exe /C <entrée utilisateur>.") },
            { "ShellButton",Tuple.Create("Execute", "Exécuter") },

            { "SoapLabel", Tuple.Create("15. SoapFormatter Deserialization", "15. Désérialisation SoapFormatter") },
            { "SoapDesc",  Tuple.Create("Insecure deserialization via SoapFormatter.", "Désérialisation non sûre via SoapFormatter.") },
            { "SoapButton",Tuple.Create("Deserialize (SoapFormatter)", "Désérialiser (SoapFormatter)") },
        };

        public DA07UnsafeApiWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage("en");
            SetPlaceholders();
        }

        private string GetLabel(string key, string lang) => lang == "fr" ? labels[key].Item2 : labels[key].Item1;

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

            // 1..7
            UnsafeBufferLabel.Text = GetLabel("UnsafeBufferLabel", lang);
            UnsafeBufferDesc.Text = GetLabel("UnsafeBufferDesc", lang);
            UnsafeBufferButton.Content = GetLabel("UnsafeBufferButton", lang);

            BinaryFormatterLabel.Text = GetLabel("BinaryFormatterLabel", lang);
            BinaryFormatterDesc.Text = GetLabel("BinaryFormatterDesc", lang);
            BinaryFormatterButton.Content = GetLabel("BinaryFormatterButton", lang);

            IntOverflowLabel.Text = GetLabel("IntOverflowLabel", lang);
            IntOverflowDesc.Text = GetLabel("IntOverflowDesc", lang);
            IntOverflowButton.Content = GetLabel("IntOverflowButton", lang);

            PInvokeLabel.Text = GetLabel("PInvokeLabel", lang);
            PInvokeDesc.Text = GetLabel("PInvokeDesc", lang);
            PInvokeButton.Content = GetLabel("PInvokeButton", lang);

            EvalLabel.Text = GetLabel("EvalLabel", lang);
            EvalDesc.Text = GetLabel("EvalDesc", lang);
            EvalButton.Content = GetLabel("EvalButton", lang);

            RaceLabel.Text = GetLabel("RaceLabel", lang);
            RaceDesc.Text = GetLabel("RaceDesc", lang);
            RaceButton.Content = GetLabel("RaceButton", lang);

            StackLabel.Text = GetLabel("StackLabel", lang);
            StackDesc.Text = GetLabel("StackDesc", lang);
            StackButton.Content = GetLabel("StackButton", lang);

            // 8..15
            RegexLabel.Text = GetLabel("RegexLabel", lang);
            RegexDesc.Text = GetLabel("RegexDesc", lang);
            RegexButton.Content = GetLabel("RegexButton", lang);

            XxeLabel.Text = GetLabel("XxeLabel", lang);
            XxeDesc.Text = GetLabel("XxeDesc", lang);
            XxeButton.Content = GetLabel("XxeButton", lang);

            ReflectLabel.Text = GetLabel("ReflectLabel", lang);
            ReflectDesc.Text = GetLabel("ReflectDesc", lang);
            ReflectButton.Content = GetLabel("ReflectButton", lang);

            WeakRndLabel.Text = GetLabel("WeakRndLabel", lang);
            WeakRndDesc.Text = GetLabel("WeakRndDesc", lang);
            WeakRndButton.Content = GetLabel("WeakRndButton", lang);

            Md5Label.Text = GetLabel("Md5Label", lang);
            Md5Desc.Text = GetLabel("Md5Desc", lang);
            Md5Button.Content = GetLabel("Md5Button", lang);

            ZipSlipLabel.Text = GetLabel("ZipSlipLabel", lang);
            ZipSlipDesc.Text = GetLabel("ZipSlipDesc", lang);
            ZipSlipButton.Content = GetLabel("ZipSlipButton", lang);

            ShellLabel.Text = GetLabel("ShellLabel", lang);
            ShellDesc.Text = GetLabel("ShellDesc", lang);
            ShellButton.Content = GetLabel("ShellButton", lang);

            SoapLabel.Text = GetLabel("SoapLabel", lang);
            SoapDesc.Text = GetLabel("SoapDesc", lang);
            SoapButton.Content = GetLabel("SoapButton", lang);
        }

        private void SetPlaceholders()
        {
            TrySet("UnsafeBufferInput", "HELLO");
            TrySet("BinaryFormatterInput", "BASE64_PAYLOAD_HERE");
            TrySet("IntOverflowInput", "2147483647");
            TrySet("PInvokeInput", "MessageBox");
            TrySet("EvalInput", "1+2*3");
            TrySet("RaceInput", @"C:\PublicShare\race.txt");
            TrySet("StackInput", "1000");

            TrySet("RegexPatternInput", "(a+)+$");
            TrySet("RegexTextInput", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX");
            TrySet("XxeInput", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///C:/Windows/win.ini\">]><root>&xxe;</root>");
            TrySet("ReflectTypeInput", "System.Guid");
            TrySet("ReflectMethodInput", "NewGuid");
            TrySet("WeakRndLenInput", "16");
            TrySet("Md5Input", "password");
            TrySet("ZipPathInput", @"C:\PublicShare\evil.zip");
            TrySet("ZipDestInput", @"C:\PublicShare\extract");
            TrySet("ShellInput", "whoami");
            TrySet("SoapFormatterInput", "BASE64_PAYLOAD_HERE");
        }

        private void TrySet(string name, string value)
        {
            var tb = FindName(name) as TextBox;
            if (tb != null) tb.Text = value;
        }

        // ===== Handlers (UI -> UnsafeApiVuln) =====
        private void UnsafeBufferButton_Click(object s, RoutedEventArgs e) => UnsafeBufferResult.Text = UnsafeApiVuln.UnsafeBuffer(UnsafeBufferInput.Text);
        private void BinaryFormatterButton_Click(object s, RoutedEventArgs e) => BinaryFormatterResult.Text = UnsafeApiVuln.BinaryFormatterDeserialize(BinaryFormatterInput.Text);
        private void IntOverflowButton_Click(object s, RoutedEventArgs e) => IntOverflowResult.Text = UnsafeApiVuln.IntegerOverflow(IntOverflowInput.Text);
        private void PInvokeButton_Click(object s, RoutedEventArgs e) => PInvokeResult.Text = UnsafeApiVuln.UnsafePInvoke(PInvokeInput.Text);
        private void EvalButton_Click(object s, RoutedEventArgs e) => EvalResult.Text = UnsafeApiVuln.DynamicEval(EvalInput.Text);
        private void RaceButton_Click(object s, RoutedEventArgs e) => RaceResult.Text = UnsafeApiVuln.RaceCondition(RaceInput.Text);
        private void StackButton_Click(object s, RoutedEventArgs e) => StackResult.Text = UnsafeApiVuln.StackOverflow(StackInput.Text);

        private void RegexButton_Click(object s, RoutedEventArgs e) => RegexResult.Text = UnsafeApiVuln.RegexReDoS(RegexPatternInput.Text, RegexTextInput.Text);
        private void XxeButton_Click(object s, RoutedEventArgs e) => XxeResult.Text = UnsafeApiVuln.XxeLoad(XxeInput.Text);
        private void ReflectButton_Click(object s, RoutedEventArgs e) => ReflectResult.Text = UnsafeApiVuln.ReflectInvoke(ReflectTypeInput.Text, ReflectMethodInput.Text);
        private void WeakRndButton_Click(object s, RoutedEventArgs e) => WeakRndResult.Text = UnsafeApiVuln.WeakRandomToken(WeakRndLenInput.Text);
        private void Md5Button_Click(object s, RoutedEventArgs e) => Md5Result.Text = UnsafeApiVuln.InsecureMd5(Md5Input.Text);
        private void ZipSlipButton_Click(object s, RoutedEventArgs e) => ZipSlipResult.Text = UnsafeApiVuln.UnsafeZipExtract(ZipPathInput.Text, ZipDestInput.Text);
        private void ShellButton_Click(object s, RoutedEventArgs e) => ShellResult.Text = UnsafeApiVuln.ShellExec(ShellInput.Text);
        private void SoapButton_Click(object s, RoutedEventArgs e) => SoapResult.Text = UnsafeApiVuln.SoapFormatterDeserialize(SoapFormatterInput.Text);
    }
}
