using System;
using System.IO;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class DataExposureVuln
    {
        // 1. Stockage en clair
        public static void StoreCleartext(string data)
        {
            File.WriteAllText("sensitive_clear.txt", data);
            MessageBox.Show("Sensitive data written to disk in cleartext.", "Sensitive Data Exposure");
        }

        // 2. Data in logs
        public static void LogSensitive(string data)
        {
            File.AppendAllText("app.log", $"Sensitive log: {data}\n");
            MessageBox.Show("Sensitive data written to log file.", "Sensitive Data Exposure");
        }

        // 3. Data in memory (jamais nettoyée)
        private static string InsecureSecret;
        public static void StoreInMemory(string data)
        {
            InsecureSecret = data;
            MessageBox.Show("Sensitive data stored in memory (field never cleared).", "Sensitive Data Exposure");
        }

        // 4. Chiffrement faible
        public static void WeakEncryption(string data)
        {
            // Ex : "chiffrement" maison (ici ROT13)
            string weak = Rot13(data);
            MessageBox.Show("Weak encryption result: " + weak, "Sensitive Data Exposure");
        }
        private static string Rot13(string input)
        {
            char[] array = input.ToCharArray();
            for (int i = 0; i < array.Length; i++)
            {
                int number = array[i];
                if (number >= 'a' && number <= 'z')
                {
                    if (number > 'm') array[i] -= (char)13;
                    else array[i] += (char)13;
                }
                else if (number >= 'A' && number <= 'Z')
                {
                    if (number > 'M') array[i] -= (char)13;
                    else array[i] += (char)13;
                }
            }
            return new string(array);
        }

        // 5. Hardcoded Key
        public static void HardcodedKey(string data)
        {
            const string KEY = "1234567890abcdef";
            MessageBox.Show($"Hardcoded key: {KEY}\nSample usage: {data}", "Sensitive Data Exposure");
        }

        // 6. Secret exposé dans le code
        public static void ExposedSecret(string data)
        {
            const string AWS_SECRET = "AKIAIOSFODNN7EXAMPLE";
            MessageBox.Show($"Exposed secret: {AWS_SECRET}\nSample: {data}", "Sensitive Data Exposure");
        }

        // 7. Insecure Transmission
        public static void InsecureTransport(string data)
        {
            MessageBox.Show("Data sent over insecure (HTTP, not HTTPS): " + data, "Sensitive Data Exposure");
        }

        // 8. Verbose Error Message / Data Leak
        public static void VerboseError(string data)
        {
            try
            {
                throw new NullReferenceException("This is a test verbose exception with sensitive info: " + data);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Verbose error message: " + ex.ToString(), "Sensitive Data Exposure");
            }
        }
    }
}
