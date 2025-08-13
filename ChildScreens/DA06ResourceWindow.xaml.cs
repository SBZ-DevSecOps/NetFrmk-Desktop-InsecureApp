using NetFrmk_Desktop_InsecureApp.Vulnerabilities;
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA06ResourceWindow : Window
    {
        private string _lang = "en";

        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA06 – Insecure Resources & Dependency Management", "DA06 – Gestion des ressources et dépendances non sécurisées") },
            { "Intro", Tuple.Create("Resource loading and dependency management anti-patterns for SAST demos.", "Anti-patterns de chargement de ressources et gestion de dépendances pour démos SAST.") },

            { "VulnDllLabel", Tuple.Create("1. Call Vulnerable DLL", "1. Appel DLL vulnérable") },
            { "VulnDllDesc",  Tuple.Create("Loads and invokes a method from an outdated or vulnerable DLL.", "Charge et invoque une méthode depuis une DLL obsolète/vulnérable.") },
            { "VulnDllButton",Tuple.Create("Test Vuln DLL", "Tester DLL vulnérable") },

            { "DynamicLoadLabel", Tuple.Create("2. Dynamic Assembly Load", "2. Chargement d'assembly dynamique") },
            { "DynamicLoadDesc",  Tuple.Create("Loads an assembly from a user path without verification.", "Charge un assembly depuis un chemin utilisateur sans vérification.") },
            { "DynamicLoadButton",Tuple.Create("Test Dynamic Load", "Tester chargement dynamique") },

            { "LoadPluginsLabel", Tuple.Create("3. Load All Plugins (No Check)", "3. Charger tous les plugins (aucun contrôle)") },
            { "LoadPluginsDesc",  Tuple.Create("Executes all .dll files from a directory (no whitelist).", "Exécute toutes les .dll d’un dossier (sans liste blanche).") },
            { "LoadPluginsButton",Tuple.Create("Test Load Plugins", "Tester chargement plugins") },

            { "DownloadExecLabel", Tuple.Create("4. Download & Execute DLL", "4. Télécharger & exécuter une DLL") },
            { "DownloadExecDesc",  Tuple.Create("Downloads a DLL over HTTP and loads it unverified.", "Télécharge une DLL en HTTP et la charge sans vérification.") },
            { "DownloadExecButton",Tuple.Create("Test Download/Execute", "Tester téléchargement/exécution") },

            { "ManifestLabel", Tuple.Create("5. Load From Manifest", "5. Charger via manifest") },
            { "ManifestDesc",  Tuple.Create("Loads dependencies listed in user-editable manifest.json.", "Charge des dépendances listées dans un manifest.json modifiable.") },
            { "ManifestButton",Tuple.Create("Test Manifest Load", "Tester chargement manifest") },

            { "UserImportLabel", Tuple.Create("6. User Import DLL", "6. Import DLL utilisateur") },
            { "UserImportDesc",  Tuple.Create("Imports and runs a user-chosen DLL (BYO).", "Importe et exécute une DLL choisie par l’utilisateur.") },
            { "UserImportButton",Tuple.Create("Test User Import", "Tester import utilisateur") },

            { "DllHijackingLabel", Tuple.Create("7. DLL Hijacking", "7. DLL hijacking") },
            { "DllHijackingDesc",  Tuple.Create("Starts an EXE that may side-load evil.dll in its folder.", "Lance un EXE susceptible de charger evil.dll du même dossier.") },
            { "DllHijackingButton",Tuple.Create("Test DLL Hijacking", "Tester DLL hijacking") },

            { "VulnNugetLabel", Tuple.Create("8. Vulnerable NuGet Package", "8. Package NuGet vulnérable") },
            { "VulnNugetDesc",  Tuple.Create("Invokes an insecure API from a vulnerable package.", "Appelle une API non sûre d’un package vulnérable.") },
            { "VulnNugetButton",Tuple.Create("Test Vulnerable NuGet", "Tester NuGet vulnérable") },

            { "HttpResourceLabel", Tuple.Create("9. Download External Resource (HTTP)", "9. Télécharger ressource externe (HTTP)") },
            { "HttpResourceDesc",  Tuple.Create("Fetches config/script over HTTP and uses it.", "Récupère config/script en HTTP et l’utilise.") },
            { "HttpResourceButton",Tuple.Create("Test HTTP Resource", "Tester ressource HTTP") },

            { "PsScriptLabel", Tuple.Create("10. Dynamic PowerShell Exec", "10. Exécution PowerShell dynamique") },
            { "PsScriptDesc",  Tuple.Create("Executes a user-supplied PowerShell command.", "Exécute une commande PowerShell fournie par l’utilisateur.") },
            { "PsScriptButton",Tuple.Create("Test PowerShell", "Tester PowerShell") },

            { "RelativeDllLabel", Tuple.Create("11. Load DLL via Relative Path", "11. Charger DLL par chemin relatif") },
            { "RelativeDllDesc",  Tuple.Create("Loads DLL using relative path (planting risk).", "Charge une DLL via un chemin relatif (risque de planting).") },
            { "RelativeDllButton",Tuple.Create("Test Relative Load", "Tester chargement relatif") },

            { "PartialNameLabel", Tuple.Create("12. Load With Partial Name (GAC)", "12. Chargement par nom partiel (GAC)") },
            { "PartialNameDesc",  Tuple.Create("Uses deprecated partial-name load (ambiguous).", "Utilise le chargement par nom partiel déprécié (ambigu).") },
            { "PartialNameButton",Tuple.Create("Test Partial Name", "Tester nom partiel") },

            { "ResolveHijackLabel", Tuple.Create("13. AssemblyResolve Hijack", "13. Détournement AssemblyResolve") },
            { "ResolveHijackDesc",  Tuple.Create("Resolves missing assemblies from untrusted folder.", "Résout les dépendances manquantes depuis un dossier non fiable.") },
            { "ResolveHijackButton",Tuple.Create("Hook & Trigger", "Accrocher & déclencher") },

            { "XamlLoadLabel", Tuple.Create("14. Load XAML From URL", "14. Charger XAML depuis URL") },
            { "XamlLoadDesc",  Tuple.Create("Downloads & parses remote XAML into objects.", "Télécharge & parse du XAML distant en objets.") },
            { "XamlLoadButton",Tuple.Create("Test Remote XAML", "Tester XAML distant") },

            { "NativeLoadLabel", Tuple.Create("15. Native LoadLibrary", "15. LoadLibrary natif") },
            { "NativeLoadDesc",  Tuple.Create("P/Invoke LoadLibrary on arbitrary path.", "P/Invoke LoadLibrary sur un chemin arbitraire.") },
            { "NativeLoadButton",Tuple.Create("Test Native Load", "Tester chargement natif") },
        };

        public DA06ResourceWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage(_lang);
            SetPlaceholders();
        }

        private void LanguageSelector_Changed(object sender, SelectionChangedEventArgs e)
        {
            _lang = LanguageSelector.SelectedIndex == 1 ? "fr" : "en";
            SetLanguage(_lang);
        }

        private string L(string key) => (_lang == "fr") ? labels[key].Item2 : labels[key].Item1;

        private void SetLanguage(string lang)
        {
            Title = L("Title");
            TitleText.Text = L("Title");
            IntroText.Text = L("Intro");

            VulnDllLabel.Text = L("VulnDllLabel"); VulnDllDesc.Text = L("VulnDllDesc"); VulnDllButton.Content = L("VulnDllButton");
            DynamicLoadLabel.Text = L("DynamicLoadLabel"); DynamicLoadDesc.Text = L("DynamicLoadDesc"); DynamicLoadButton.Content = L("DynamicLoadButton");
            LoadPluginsLabel.Text = L("LoadPluginsLabel"); LoadPluginsDesc.Text = L("LoadPluginsDesc"); LoadPluginsButton.Content = L("LoadPluginsButton");
            DownloadExecLabel.Text = L("DownloadExecLabel"); DownloadExecDesc.Text = L("DownloadExecDesc"); DownloadExecButton.Content = L("DownloadExecButton");
            ManifestLabel.Text = L("ManifestLabel"); ManifestDesc.Text = L("ManifestDesc"); ManifestButton.Content = L("ManifestButton");
            UserImportLabel.Text = L("UserImportLabel"); UserImportDesc.Text = L("UserImportDesc"); UserImportButton.Content = L("UserImportButton");
            DllHijackingLabel.Text = L("DllHijackingLabel"); DllHijackingDesc.Text = L("DllHijackingDesc"); DllHijackingButton.Content = L("DllHijackingButton");
            VulnNugetLabel.Text = L("VulnNugetLabel"); VulnNugetDesc.Text = L("VulnNugetDesc"); VulnNugetButton.Content = L("VulnNugetButton");
            HttpResourceLabel.Text = L("HttpResourceLabel"); HttpResourceDesc.Text = L("HttpResourceDesc"); HttpResourceButton.Content = L("HttpResourceButton");
            PsScriptLabel.Text = L("PsScriptLabel"); PsScriptDesc.Text = L("PsScriptDesc"); PsScriptButton.Content = L("PsScriptButton");
            RelativeDllLabel.Text = L("RelativeDllLabel"); RelativeDllDesc.Text = L("RelativeDllDesc"); RelativeDllButton.Content = L("RelativeDllButton");
            PartialNameLabel.Text = L("PartialNameLabel"); PartialNameDesc.Text = L("PartialNameDesc"); PartialNameButton.Content = L("PartialNameButton");
            ResolveHijackLabel.Text = L("ResolveHijackLabel"); ResolveHijackDesc.Text = L("ResolveHijackDesc"); ResolveHijackButton.Content = L("ResolveHijackButton");
            XamlLoadLabel.Text = L("XamlLoadLabel"); XamlLoadDesc.Text = L("XamlLoadDesc"); XamlLoadButton.Content = L("XamlLoadButton");
            NativeLoadLabel.Text = L("NativeLoadLabel"); NativeLoadDesc.Text = L("NativeLoadDesc"); NativeLoadButton.Content = L("NativeLoadButton");
        }

        private void SetPlaceholders()
        {
            TrySet("VulnDllInput", @"C:\PublicShare\VulnLib.dll");
            TrySet("DynamicLoadInput", @"C:\PublicShare\AnyLib.dll");
            TrySet("LoadPluginsInput", @"C:\PublicShare\Plugins");
            TrySet("DownloadExecInput", "http://127.0.0.1:8000/BadLib.dll");
            TrySet("ManifestInput", @"C:\PublicShare\manifest.json");
            TrySet("UserImportInput", @"C:\PublicShare\UserPick.dll");
            TrySet("DllHijackingInput", @"C:\PublicShare\Victim.exe");
            TrySet("HttpResourceInput", "http://127.0.0.1:8000/config.txt");
            TrySet("PsScriptInput", "Get-ChildItem . | Select-Object -First 1");
            TrySet("RelativeDllInput", @".\RelLib.dll");
            TrySet("PartialNameInput", "System.Xml"); // example partial
            TrySet("ResolveHijackInput", @"C:\PublicShare\UntrustedDeps");
            TrySet("XamlLoadInput", "http://127.0.0.1:8000/view.xaml");
            TrySet("NativeLoadInput", @"C:\PublicShare\native.dll");
        }

        private void TrySet(string name, string value)
        {
            var tb = FindName(name) as TextBox;
            if (tb != null) tb.Text = value;
        }

        // ===== Handlers (UI → ResourceVuln) =====
        private void VulnDllButton_Click(object s, RoutedEventArgs e) => ResourceVuln.CallVulnerableDll(VulnDllInput.Text);
        private void DynamicLoadButton_Click(object s, RoutedEventArgs e) => ResourceVuln.DynamicLoad(DynamicLoadInput.Text);
        private void LoadPluginsButton_Click(object s, RoutedEventArgs e) => ResourceVuln.LoadAllPlugins(LoadPluginsInput.Text);
        private void DownloadExecButton_Click(object s, RoutedEventArgs e) => ResourceVuln.DownloadAndExecute(DownloadExecInput.Text);
        private void ManifestButton_Click(object s, RoutedEventArgs e) => ResourceVuln.LoadFromManifest(ManifestInput.Text);
        private void UserImportButton_Click(object s, RoutedEventArgs e) => ResourceVuln.UserImportDll(UserImportInput.Text);
        private void DllHijackingButton_Click(object s, RoutedEventArgs e) => ResourceVuln.DllHijacking(DllHijackingInput.Text);
        private void VulnNugetButton_Click(object s, RoutedEventArgs e) => ResourceVuln.CallVulnerableNuGet();
        private void HttpResourceButton_Click(object s, RoutedEventArgs e) => ResourceVuln.HttpResourceLoad(HttpResourceInput.Text);
        private void PsScriptButton_Click(object s, RoutedEventArgs e) => ResourceVuln.ExecutePowerShell(PsScriptInput.Text);
        private void RelativeDllButton_Click(object s, RoutedEventArgs e) => ResourceVuln.RelativeDllLoad(RelativeDllInput.Text);
        private void PartialNameButton_Click(object s, RoutedEventArgs e) => ResourceVuln.PartialNameLoad(PartialNameInput.Text);
        private void ResolveHijackButton_Click(object s, RoutedEventArgs e) => ResourceVuln.AssemblyResolveHijack(ResolveHijackInput.Text);
        private void XamlLoadButton_Click(object s, RoutedEventArgs e) => ResourceVuln.LoadXamlFromUrl(XamlLoadInput.Text);
        private void NativeLoadButton_Click(object s, RoutedEventArgs e) => ResourceVuln.NativeLoadLibrary(NativeLoadInput.Text);
    }
}
