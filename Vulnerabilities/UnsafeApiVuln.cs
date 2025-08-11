using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;

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
                        ptr[100] = 0x42; // Dépassement volontaire
                    }
                }
                return "Buffer overrun attempted (no crash = memory unsafe, bug possible).";
            }
            catch (Exception ex)
            {
                return $"Error (caught): {ex.Message}";
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
#pragma warning disable SYSLIB0011 // BinaryFormatter obsolete warning
                    BinaryFormatter bf = new BinaryFormatter();
                    object obj = bf.Deserialize(ms);
#pragma warning restore SYSLIB0011
                    return $"Object deserialized: {obj?.ToString() ?? "(null)"}";
                }
            }
            catch (Exception ex)
            {
                return $"Error (caught): {ex.Message}";
            }
        }

        // 3. Integer overflow (unchecked arithmétique)
        public static string IntegerOverflow(string input)
        {
            try
            {
                int val = int.Parse(input);
                int result = unchecked(val + 100);
                return $"Input: {val}, After unchecked +100: {result}";
            }
            catch (Exception ex)
            {
                return $"Error (caught): {ex.Message}";
            }
        }

        // 4. Unsafe P/Invoke (user32.dll::MessageBox)
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);

        public static string UnsafePInvoke(string apiName)
        {
            try
            {
                if (apiName.Equals("MessageBox", StringComparison.OrdinalIgnoreCase))
                {
                    MessageBoxW(IntPtr.Zero, "P/Invoke unsafe!", "user32.dll", 0);
                    return "Called user32.dll:MessageBoxW (see popup).";
                }
                else
                {
                    return $"API '{apiName}' not supported for demo.";
                }
            }
            catch (Exception ex)
            {
                return $"Error (caught): {ex.Message}";
            }
        }

        // 5. Eval / Dynamic code execution
        public static string DynamicEval(string expr)
        {
            try
            {
                var dt = new System.Data.DataTable();
                var v = dt.Compute(expr, "");
                return $"Eval result: {v}";
            }
            catch (Exception ex)
            {
                return $"Error (caught): {ex.Message}";
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
                Task.WaitAll(t1, t2);
                return $"Race condition simulated on file: {filePath}";
            }
            catch (Exception ex)
            {
                return $"Error (caught): {ex.Message}";
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
                    if (d > 0)
                        Recurse(d - 1);
                    else
                        Recurse(d); // infinite loop at d == 0
                }
                Recurse(depth);
                return "Stack overflow triggered (if app crashed, it worked!)";
            }
            catch (StackOverflowException)
            {
                // Impossible to catch, app crash expected
                return "StackOverflowException: application crashed (expected).";
            }
            catch (Exception ex)
            {
                return $"Error (caught): {ex.Message}";
            }
        }
    }
}
