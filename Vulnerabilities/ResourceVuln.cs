using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class ResourceVuln
    {
        // 1. Appel d’une DLL vulnérable (méthode exposée)
        public static void CallVulnerableDll(string dllName)
        {
            try
            {
                Assembly asm = Assembly.LoadFrom(dllName);
                var t = asm.GetType("VulnLib.ExposedClass");
                var mi = t?.GetMethod("VulnerableMethod");
                var result = mi?.Invoke(null, null);
                MessageBox.Show("Vulnerable method result: " + result, "Outdated/Vulnerable DLL");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Outdated/Vulnerable DLL");
            }
        }

        // 2. Chargement dynamique d’assembly non fiable
        public static void DynamicLoad(string dllPath)
        {
            try
            {
                Assembly asm = Assembly.LoadFrom(dllPath);
                MessageBox.Show("Assembly loaded: " + asm.FullName, "Dynamic Assembly Load");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Dynamic Assembly Load");
            }
        }

        // 3. Charger tous les plugins d’un dossier (sans contrôle)
        public static void LoadAllPlugins(string folder)
        {
            try
            {
                foreach (var dll in Directory.GetFiles(folder, "*.dll"))
                {
                    Assembly asm = Assembly.LoadFrom(dll);
                    var type = asm.GetType("Plugin.Entry");
                    type?.GetMethod("Run")?.Invoke(null, null);
                }
                MessageBox.Show("All plugins loaded from: " + folder, "Load All Plugins");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Load All Plugins");
            }
        }

        // 4. Télécharger et charger une DLL depuis une URL (sans vérif)
        public static void DownloadAndExecute(string url)
        {
            try
            {
                string local = Path.Combine(Path.GetTempPath(), Path.GetFileName(url));
                using (var client = new WebClient())
                {
                    client.DownloadFile(url, local);
                }
                Assembly asm = Assembly.LoadFrom(local);
                MessageBox.Show("Downloaded and loaded: " + local, "Remote Dependency");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Remote Dependency");
            }
        }

        // 5. Charger des dépendances listées dans un manifest.json (modifié par l’utilisateur)
        public static void LoadFromManifest(string manifestPath)
        {
            try
            {
                string json = File.ReadAllText(manifestPath);
                var j = JArray.Parse(json);
                foreach (var dep in j)
                {
                    string dll = dep.ToString();
                    Assembly asm = Assembly.LoadFrom(dll);
                    // Appelle une méthode "Init" si présente
                    var t = asm.GetType("ManifestDep.Entry");
                    t?.GetMethod("Init")?.Invoke(null, null);
                }
                MessageBox.Show("All dependencies loaded from manifest.", "Manifest Load");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Manifest Load");
            }
        }

        // 6. Importer et charger une DLL choisie par l’utilisateur (BYOVD)
        public static void UserImportDll(string path)
        {
            try
            {
                Assembly asm = Assembly.LoadFrom(path);
                var t = asm.GetType("UserDll.Entry");
                t?.GetMethod("Exec")?.Invoke(null, null);
                MessageBox.Show("User DLL imported and executed.", "User Import DLL");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "User Import DLL");
            }
        }

        // 7. DLL hijacking : lancer un .exe, charge "evil.dll" si présente dans le même dossier
        public static void DllHijacking(string exePath)
        {
            try
            {
                Process.Start(new ProcessStartInfo(exePath)
                {
                    UseShellExecute = false
                });
                MessageBox.Show("Started app, hijacking possible if evil.dll is present!", "DLL Hijacking");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "DLL Hijacking");
            }
        }
    }
}
