using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Xml;
using System.IO.Compression;
using System.Runtime.Serialization.Formatters.Soap;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class UnsafeApiVuln
    {
        // 1. Unsafe buffer manipulation (C# unsafe, buffer overflow)
        public static string UnsafeBuffer(string input)
        {
            try
            {
                unsafe
                {
                    byte[] buffer = Encoding.ASCII.GetBytes(input);
                    fixed (byte* ptr = buffer)
                    {
                        ptr[100] = 0x42; // ❌ Dépassement volontaire
                    }
                }
                return "Buffer overrun attempted (no crash = memory unsafe, bug possible).";
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 2. BinaryFormatter deserialization (danger: RCE possible)
        public static string BinaryFormatterDeserialize(string base64)
        {
            try
            {
                byte[] data = Convert.FromBase64String(base64);
                using (var ms = new MemoryStream(data))
                {
#pragma warning disable SYSLIB0011
                    var bf = new BinaryFormatter(); // ❌ Insecure deserialization
                    object obj = bf.Deserialize(ms);
#pragma warning restore SYSLIB0011
                    return "Object deserialized (BinaryFormatter): " + (obj == null ? "(null)" : obj.ToString());
                }
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 3. Integer overflow (unchecked arithmetic)
        public static string IntegerOverflow(string input)
        {
            try
            {
                int val = int.Parse(input);
                int result = unchecked(val + 100); // ❌ unchecked
                return "Input: " + val + ", After unchecked +100: " + result;
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 4. Unsafe P/Invoke (user32.dll::MessageBox)
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);

        public static string UnsafePInvoke(string apiName)
        {
            try
            {
                if (apiName.Equals("MessageBox", StringComparison.OrdinalIgnoreCase))
                {
                    MessageBoxW(IntPtr.Zero, "P/Invoke unsafe!", "user32.dll", 0); // ❌ unmanaged call
                    return "Called user32.dll:MessageBoxW (see popup).";
                }
                return "API '" + apiName + "' not supported for demo.";
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 5. Eval / Dynamic code execution (DataTable.Compute)
        public static string DynamicEval(string expr)
        {
            try
            {
                var dt = new System.Data.DataTable(); // ❌ misuse as "eval"
                var v = dt.Compute(expr, "");
                return "Eval result: " + v;
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 6. Race condition (simulate concurrent file writes)
        public static string RaceCondition(string filePath)
        {
            try
            {
                void WriteData(string data)
                {
                    for (int i = 0; i < 100; i++)
                        File.AppendAllText(filePath, data);
                }
                var t1 = Task.Run(() => WriteData("A"));
                var t2 = Task.Run(() => WriteData("B"));
                Task.WaitAll(t1, t2); // ❌ no locking
                return "Race condition simulated on file: " + filePath;
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 7. Stack overflow (unbounded recursion)
        public static string StackOverflow(string input)
        {
            try
            {
                int depth = int.Parse(input);
                void Recurse(int d)
                {
                    if (d > 0) Recurse(d - 1);
                    else Recurse(d); // ❌ infinite at 0
                }
                Recurse(depth);
                return "Stack overflow triggered (if app crashed, it worked!)";
            }
            catch (StackOverflowException)
            {
                return "StackOverflowException: application crashed (expected).";
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 8. Regex ReDoS (no timeout)
        public static string RegexReDoS(string pattern, string input)
        {
            try
            {
                var rx = new Regex(pattern); // ❌ no TimeOut
                bool matched = rx.IsMatch(input);
                return "Regex match = " + matched + " ; length=" + (input == null ? 0 : input.Length);
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 9. XML External Entity (XXE) – enable DTD + resolver
        public static string XxeLoad(string xml)
        {
            try
            {
                var settings = new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Parse,               // ❌ allow DTD
                    XmlResolver = new XmlUrlResolver()                 // ❌ allow external entities
                };
                using (var sr = new StringReader(xml))
                using (var xr = XmlReader.Create(sr, settings))
                {
                    var doc = new XmlDocument();
                    doc.XmlResolver = new XmlUrlResolver();            // ❌
                    doc.Load(xr);
                    var name = (doc.DocumentElement != null) ? doc.DocumentElement.Name : "(null)";
                    return "XML loaded; root=" + name + " (XXE possible).";
                }
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 10. Insecure reflection invoke (type/method from user)
        public static string ReflectInvoke(string typeName, string methodName)
        {
            try
            {
                var t = Type.GetType(typeName, true); // ❌ user-controlled
                var mi = t.GetMethod(methodName, System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Instance);
                object instance = (mi.IsStatic) ? null : Activator.CreateInstance(t);
                object result = mi.Invoke(instance, null); // ❌ no restrictions
                return "Reflect call → " + (result == null ? "(null)" : result.ToString());
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 11. Weak random token (System.Random)
        public static string WeakRandomToken(string lengthStr)
        {
            try
            {
                int len = int.Parse(lengthStr);
                var rand = new Random(); // ❌ predictable
                const string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                var sb = new StringBuilder();
                for (int i = 0; i < len; i++)
                    sb.Append(alphabet[rand.Next(alphabet.Length)]);
                return "Weak token: " + sb.ToString();
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 12. Insecure MD5 (no salt)
        public static string InsecureMd5(string input)
        {
            try
            {
                using (var md5 = MD5.Create()) // ❌ weak hash
                {
                    var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input ?? ""));
                    return "MD5: " + BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 13. ZipSlip extraction (no path sanitization)
        public static string UnsafeZipExtract(string zipPath, string destDir)
        {
            try
            {
                Directory.CreateDirectory(destDir);
                using (var fs = File.OpenRead(zipPath))
                using (var zip = new ZipArchive(fs, ZipArchiveMode.Read))
                {
                    foreach (var entry in zip.Entries)
                    {
                        // ❌ No validation of entry.FullName (may contain ..\)
                        var full = Path.Combine(destDir, entry.FullName);
                        var dir = Path.GetDirectoryName(full);
                        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                        using (var es = entry.Open())
                        using (var outFs = File.Create(full))
                        {
                            es.CopyTo(outFs);
                        }
                    }
                }
                return "Zip extracted to: " + destDir + " (no sanitization).";
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 14. Unsafe process execution (shell)
        public static string ShellExec(string command)
        {
            try
            {
                Process.Start("cmd.exe", "/C " + command); // ❌ command injection vector
                return "Executed shell command: " + command;
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }

        // 15. SoapFormatter deserialization (also dangerous)
        public static string SoapFormatterDeserialize(string base64)
        {
            try
            {
                var data = Convert.FromBase64String(base64);
                using (var ms = new MemoryStream(data))
                {
#pragma warning disable SYSLIB0011
                    var sf = new SoapFormatter(); // ❌ insecure deserialization
                    var obj = sf.Deserialize(ms);
#pragma warning restore SYSLIB0011
                    return "Object deserialized (SoapFormatter): " + (obj == null ? "(null)" : obj.ToString());
                }
            }
            catch (Exception ex)
            {
                return "Error (caught): " + ex.Message;
            }
        }
    }
}
