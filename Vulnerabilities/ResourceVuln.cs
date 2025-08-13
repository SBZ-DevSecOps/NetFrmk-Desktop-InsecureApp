using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Markup;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class ResourceVuln
    {
        // 1) Call outdated/vulnerable DLL by path (user-controlled)
        public static void CallVulnerableDll(string dllPath)
        {
            try
            {
                Assembly asm = Assembly.LoadFrom(dllPath); // ❌ untrusted path
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

        // 2) Dynamic assembly load (no verification)
        public static void DynamicLoad(string dllPath)
        {
            try
            {
                Assembly asm = Assembly.LoadFrom(dllPath); // ❌ no signature/policy check
                MessageBox.Show("Assembly loaded: " + asm.FullName, "Dynamic Assembly Load");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Dynamic Assembly Load");
            }
        }

        // 3) Load all plugins from directory (no whitelist)
        public static void LoadAllPlugins(string folder)
        {
            try
            {
                foreach (var dll in Directory.GetFiles(folder, "*.dll"))
                {
                    Assembly asm = Assembly.LoadFrom(dll); // ❌ arbitrary plugin
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

        // 4) Download DLL over HTTP and load
        public static void DownloadAndExecute(string url)
        {
            try
            {
                string local = Path.Combine(Path.GetTempPath(), Path.GetFileName(url));
                using (var client = new WebClient())
                {
                    client.DownloadFile(url, local); // ❌ no TLS / integrity check
                }
                Assembly asm = Assembly.LoadFrom(local); // ❌ unverified
                MessageBox.Show("Downloaded and loaded: " + local, "Remote Dependency");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Remote Dependency");
            }
        }

        // 5) Load dependencies from a user-editable manifest.json (array of dll paths)
        public static void LoadFromManifest(string manifestPath)
        {
            try
            {
                string json = File.ReadAllText(manifestPath);
                var j = JArray.Parse(json);
                foreach (var dep in j)
                {
                    string dll = dep.ToString();
                    Assembly asm = Assembly.LoadFrom(dll); // ❌ no allowlist
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

        // 6) BYO DLL (user-provided)
        public static void UserImportDll(string path)
        {
            try
            {
                Assembly asm = Assembly.LoadFrom(path); // ❌ untrusted
                var t = asm.GetType("UserDll.Entry");
                t?.GetMethod("Exec")?.Invoke(null, null);
                MessageBox.Show("User DLL imported and executed.", "User Import DLL");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "User Import DLL");
            }
        }

        // 7) DLL hijacking simulation (start EXE that may prefer local evil.dll)
        public static void DllHijacking(string exePath)
        {
            try
            {
                Process.Start(new ProcessStartInfo(exePath) { UseShellExecute = false });
                MessageBox.Show("Started app; hijacking possible if evil.dll is present!", "DLL Hijacking");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "DLL Hijacking");
            }
        }

        // 8) Vulnerable NuGet package call (fake)
        public static void CallVulnerableNuGet()
        {
            try
            {
                // ❌ simulate calling known vulnerable API from a package
                var result = VulnerableNuGetLib.DoInsecureStuff();
                MessageBox.Show(result, "Vulnerable NuGet");
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Vulnerable NuGet");
            }
        }

        // 9) Download external resource via HTTP and "load" (config/script)
        public static void HttpResourceLoad(string url)
        {
            try
            {
                var client = new WebClient();
                var data = client.DownloadString(url); // ❌ HTTP clear / no integrity
                MessageBox.Show("Downloaded resource content:\n" + Trunc(data), "HTTP Resource");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "HTTP Resource");
            }
        }

        // 10) Execute PowerShell supplied by user
        public static void ExecutePowerShell(string command)
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"" + command + "\"")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                var process = Process.Start(psi);
                string output = process.StandardOutput.ReadToEnd();
                MessageBox.Show("PowerShell output:\n" + Trunc(output), "PowerShell Script");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "PowerShell Script");
            }
        }

        // 11) Load DLL using relative path (planting risk)
        public static void RelativeDllLoad(string relativePath)
        {
            try
            {
                Assembly asm = Assembly.LoadFrom(relativePath); // ❌ relative search paths
                MessageBox.Show("Loaded assembly: " + asm.FullName, "Relative Path Load");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Relative Path Load");
            }
        }

        // 12) Partial-name (GAC) load (obsolete/ambiguous)
        public static void PartialNameLoad(string partialName)
        {
            try
            {
#pragma warning disable 618
                Assembly asm = Assembly.LoadWithPartialName(partialName); // ❌ ambiguous/legacy
#pragma warning restore 618
                MessageBox.Show("Loaded (partial): " + (asm != null ? asm.FullName : "(null)"), "Partial Name Load");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Partial Name Load");
            }
        }

        // 13) AssemblyResolve hijack: load missing deps from untrusted folder
        private static bool _resolveHooked;
        public static void AssemblyResolveHijack(string folder)
        {
            try
            {
                if (!_resolveHooked)
                {
                    AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
                    {
                        // ❌ resolve any missing assembly from the provided folder
                        var simple = new AssemblyName(e.Name).Name + ".dll";
                        var candidate = Path.Combine(folder, simple);
                        if (File.Exists(candidate))
                        {
                            return Assembly.LoadFrom(candidate);
                        }
                        return null;
                    };
                    _resolveHooked = true;
                }

                // Force a resolve of a (likely) missing assembly name
                try { Assembly.Load("Hijacked.Dependency"); } catch { /* will trigger resolve */ }

                MessageBox.Show("AssemblyResolve hooked to folder: " + folder, "AssemblyResolve Hijack");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "AssemblyResolve Hijack");
            }
        }

        // 14) Load XAML from external source (RDI)
        public static void LoadXamlFromUrl(string xamlUrl)
        {
            try
            {
                var wc = new WebClient();
                string xaml = wc.DownloadString(xamlUrl); // ❌ remote UI injection
                var obj = XamlReader.Parse(xaml);        // load arbitrary XAML
                MessageBox.Show("XAML parsed into object: " + (obj != null ? obj.GetType().FullName : "null"), "Remote XAML Load");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Remote XAML Load");
            }
        }

        // 15) Native LoadLibrary on arbitrary path (P/Invoke)
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        public static void NativeLoadLibrary(string dllFullPath)
        {
            try
            {
                IntPtr h = LoadLibrary(dllFullPath); // ❌ untrusted native library
                if (h == IntPtr.Zero)
                {
                    MessageBox.Show("LoadLibrary failed for: " + dllFullPath, "Native LoadLibrary");
                }
                else
                {
                    MessageBox.Show("Native library loaded: " + dllFullPath, "Native LoadLibrary");
                    FreeLibrary(h);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Native LoadLibrary");
            }
        }

        private static string Trunc(string s)
        {
            if (s == null) return string.Empty;
            if (s.Length <= 600) return s;
            return s.Substring(0, 600) + "...";
        }
    }
}
