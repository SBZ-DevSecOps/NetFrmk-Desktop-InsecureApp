using Microsoft.Win32;
using NetFrmk_Desktop_InsecureApp.Vulnerabilities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp
{
    /// <summary>
    /// Interaction logic for DA06ResourceWindow.xaml
    /// </summary>
    public partial class DA06ResourceWindow : Window
    {
        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA06 – Insecure Resources & Dependency Management", "DA06 – Gestion des ressources et dépendances non sécurisées") },
            { "Intro", Tuple.Create("This module demonstrates insecure dependency management and resource loading scenarios in .NET desktop apps.", "Ce module montre des scénarios d'utilisation de dépendances et ressources non sécurisées dans les applications .NET desktop.") },

            { "VulnDllLabel", Tuple.Create("Call Vulnerable DLL", "Appel DLL vulnérable") },
            { "VulnDllDesc", Tuple.Create("Loads and executes a method from an outdated or vulnerable DLL.", "Charge et exécute une méthode depuis une DLL vulnérable/obsolète.") },
            { "VulnDllButton", Tuple.Create("Test Vuln DLL", "Tester DLL vulnérable") },

            { "DynamicLoadLabel", Tuple.Create("Dynamic Assembly Load", "Chargement d'assembly dynamique") },
            { "DynamicLoadDesc", Tuple.Create("Loads an assembly from a user-supplied path with no verification.", "Charge un assembly depuis un chemin sans vérification.") },
            { "DynamicLoadButton", Tuple.Create("Test Dynamic Load", "Tester chargement dynamique") },

            { "LoadPluginsLabel", Tuple.Create("Load All Plugins (No Check)", "Charger tous les plugins (aucun contrôle)") },
            { "LoadPluginsDesc", Tuple.Create("Loads and executes all .dll files from a directory with no whitelist.", "Charge et exécute tous les .dll d'un dossier sans whitelist.") },
            { "LoadPluginsButton", Tuple.Create("Test Load Plugins", "Tester chargement plugins") },

            { "DownloadExecLabel", Tuple.Create("Download & Execute DLL", "Télécharger & exécuter une DLL") },
            { "DownloadExecDesc", Tuple.Create("Downloads a DLL from a remote URL and loads it without validation.", "Télécharge une DLL d'une URL et la charge sans validation.") },
            { "DownloadExecButton", Tuple.Create("Test Download/Execute", "Tester téléchargement/exécution") },

            { "ManifestLabel", Tuple.Create("Load From Manifest", "Charger via manifest") },
            { "ManifestDesc", Tuple.Create("Loads dependencies listed in a manifest.json file (modifiable by user).", "Charge des dépendances listées dans un manifest.json modifiable.") },
            { "ManifestButton", Tuple.Create("Test Manifest Load", "Tester chargement manifest") },

            { "UserImportLabel", Tuple.Create("User Import DLL", "Import DLL utilisateur") },
            { "UserImportDesc", Tuple.Create("Imports and loads a DLL chosen by the user (BYOVD scenario).", "Importe et charge une DLL choisie par l'utilisateur (BYOVD).") },
            { "UserImportButton", Tuple.Create("Test User Import", "Tester import utilisateur") },

            { "DllHijackingLabel", Tuple.Create("DLL Hijacking", "DLL hijacking") },
            { "DllHijackingDesc", Tuple.Create("Launches an .exe, which will load any evil.dll present in the same directory.", "Lance un .exe, qui chargera toute evil.dll présente dans le dossier.") },
            { "DllHijackingButton", Tuple.Create("Test DLL Hijacking", "Tester DLL hijacking") },

            { "VulnNugetLabel", Tuple.Create("Call Vulnerable NuGet Package", "Appel package NuGet vulnérable") },
            { "VulnNugetDesc", Tuple.Create("Invokes a known-vulnerable function from a fake NuGet package.", "Appelle une fonction vulnérable d'un package NuGet fictif.") },
            { "VulnNugetButton", Tuple.Create("Test NuGet Vulnerable", "Tester NuGet vulnérable") },

            { "HttpResourceLabel", Tuple.Create("Download External Resource via HTTP", "Télécharger une ressource externe (HTTP)") },
            { "HttpResourceDesc", Tuple.Create("Downloads and loads a config/script file over insecure HTTP.", "Télécharge et charge un fichier config/script via HTTP non sécurisé.") },
            { "HttpResourceButton", Tuple.Create("Test HTTP Resource", "Tester ressource HTTP") },

            { "PsScriptLabel", Tuple.Create("Dynamic PowerShell Script Execution", "Exécution dynamique de script PowerShell") },
            { "PsScriptDesc", Tuple.Create("Executes a PowerShell command supplied by the user.", "Exécute une commande PowerShell fournie par l'utilisateur.") },
            { "PsScriptButton", Tuple.Create("Test PowerShell", "Tester PowerShell") },

            { "RelativeDllLabel", Tuple.Create("Load DLL via Relative Path", "Charger DLL par chemin relatif") },
            { "RelativeDllDesc", Tuple.Create("Loads a DLL using a relative path (prone to hijacking/planting).", "Charge une DLL par chemin relatif (risque de planting/hijack).") },
            { "RelativeDllButton", Tuple.Create("Test Relative Path Load", "Tester chemin relatif") },
        };


        private string _lang = "en";
        public DA06ResourceWindow()
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
            Title = GetLabel("Title", lang);
            TitleText.Text = GetLabel("Title", lang);
            IntroText.Text = GetLabel("Intro", lang);

            VulnDllLabel.Text = GetLabel("VulnDllLabel", lang);
            VulnDllDesc.Text = GetLabel("VulnDllDesc", lang);
            VulnDllButton.Content = GetLabel("VulnDllButton", lang);

            DynamicLoadLabel.Text = GetLabel("DynamicLoadLabel", lang);
            DynamicLoadDesc.Text = GetLabel("DynamicLoadDesc", lang);
            DynamicLoadButton.Content = GetLabel("DynamicLoadButton", lang);

            LoadPluginsLabel.Text = GetLabel("LoadPluginsLabel", lang);
            LoadPluginsDesc.Text = GetLabel("LoadPluginsDesc", lang);
            LoadPluginsButton.Content = GetLabel("LoadPluginsButton", lang);

            DownloadExecLabel.Text = GetLabel("DownloadExecLabel", lang);
            DownloadExecDesc.Text = GetLabel("DownloadExecDesc", lang);
            DownloadExecButton.Content = GetLabel("DownloadExecButton", lang);

            ManifestLabel.Text = GetLabel("ManifestLabel", lang);
            ManifestDesc.Text = GetLabel("ManifestDesc", lang);
            ManifestButton.Content = GetLabel("ManifestButton", lang);

            UserImportLabel.Text = GetLabel("UserImportLabel", lang);
            UserImportDesc.Text = GetLabel("UserImportDesc", lang);
            UserImportButton.Content = GetLabel("UserImportButton", lang);

            DllHijackingLabel.Text = GetLabel("DllHijackingLabel", lang);
            DllHijackingDesc.Text = GetLabel("DllHijackingDesc", lang);
            DllHijackingButton.Content = GetLabel("DllHijackingButton", lang);

            VulnNugetLabel.Text = GetLabel("VulnNugetLabel", lang);
            VulnNugetDesc.Text = GetLabel("VulnNugetDesc", lang);
            VulnNugetButton.Content = GetLabel("VulnNugetButton", lang);

            HttpResourceLabel.Text = GetLabel("HttpResourceLabel", lang);
            HttpResourceDesc.Text = GetLabel("HttpResourceDesc", lang);
            HttpResourceButton.Content = GetLabel("HttpResourceButton", lang);

            PsScriptLabel.Text = GetLabel("PsScriptLabel", lang);
            PsScriptDesc.Text = GetLabel("PsScriptDesc", lang);
            PsScriptButton.Content = GetLabel("PsScriptButton", lang);

            RelativeDllLabel.Text = GetLabel("RelativeDllLabel", lang);
            RelativeDllDesc.Text = GetLabel("RelativeDllDesc", lang);
            RelativeDllButton.Content = GetLabel("RelativeDllButton", lang);
        }


        // Handlers → branchés sur la classe ResourceVuln (la tienne, inchangée)
        private void VulnDllButton_Click(object sender, RoutedEventArgs e)
            => ResourceVuln.CallVulnerableDll(VulnDllInput.Text);

        private void DynamicLoadButton_Click(object sender, RoutedEventArgs e)
            => ResourceVuln.DynamicLoad(DynamicLoadInput.Text);

        private void LoadPluginsButton_Click(object sender, RoutedEventArgs e)
            => ResourceVuln.LoadAllPlugins(LoadPluginsInput.Text);

        private void DownloadExecButton_Click(object sender, RoutedEventArgs e)
            => ResourceVuln.DownloadAndExecute(DownloadExecInput.Text);

        private void ManifestButton_Click(object sender, RoutedEventArgs e)
            => ResourceVuln.LoadFromManifest(ManifestInput.Text);

        private void UserImportButton_Click(object sender, RoutedEventArgs e)
            => ResourceVuln.UserImportDll(UserImportInput.Text);

        private void DllHijackingButton_Click(object sender, RoutedEventArgs e)
            => ResourceVuln.DllHijacking(DllHijackingInput.Text);

        // 8. "NuGet vulnérable"
        private void VulnNugetButton_Click(object sender, RoutedEventArgs e)
        {
            // Appelle une méthode d'une "fake" librairie vulnérable.
            try
            {
                var result = VulnerableNuGetLib.DoInsecureStuff();
                MessageBox.Show(result, "Vulnérable NuGet");
            }
            catch (System.Exception ex)
            {
                MessageBox.Show(ex.Message, "Vulnérable NuGet");
            }
        }

        // 9. Ressource HTTP
        private void HttpResourceButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var client = new WebClient();
                var data = client.DownloadString(HttpResourceInput.Text);
                MessageBox.Show($"Downloaded resource content:\n{data}", "HTTP Resource");
            }
            catch (System.Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "HTTP Resource");
            }
        }

        // 10. Script PowerShell
        private void PsScriptButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", $"-NoProfile -Command \"{PsScriptInput.Text}\"")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                var process = Process.Start(psi);
                string output = process.StandardOutput.ReadToEnd();
                MessageBox.Show("PowerShell output:\n" + output, "PowerShell Script");
            }
            catch (System.Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "PowerShell Script");
            }
        }

        // 11. DLL chemin relatif
        private void RelativeDllButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var asm = Assembly.LoadFrom(RelativeDllInput.Text);
                MessageBox.Show("Loaded assembly: " + asm.FullName, "Relative Path Load");
            }
            catch (System.Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Relative Path Load");
            }
        }
    }

}



