using System;
using Microsoft.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Xml;
using Newtonsoft.Json;
using System.Linq.Dynamic.Core;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class InjectionVuln
    {
        // 1. SQL Injection
        /// <summary>
        /// FR: Injection SQL basique, requête non paramétrée. 
        /// EN: Basic SQL Injection, raw query (not parameterized).
        /// Exemple de payload : admin'--
        /// </summary>
        public static void RunSqlInjection(string userInput)
        {
            string connStr = "Server=(localdb)\\MSSQLLocalDB;Database=master;Trusted_Connection=True;";
            string query = $"SELECT * FROM Users WHERE Name = '{userInput}'";
            MessageBox.Show("Requête SQL exécutée : " + query, "SQL Injection", MessageBoxButton.OK);
            using (var conn = new SqlConnection(connStr))
            {
                conn.Open();
                SqlCommand cmd = new SqlCommand(query, conn);
                try { var reader = cmd.ExecuteReader(); } catch { }
            }
                
        }

        // 2. Command Injection (Windows)
        /// <summary>
        /// FR: Exécution d'une commande OS via input utilisateur.
        /// EN: OS Command execution via user input.
        /// Exemple de payload : 127.0.0.1 & calc.exe
        /// </summary>
        public static void RunCommandInjection(string userInput)
        {
            Process.Start("cmd.exe", $"/C ping {userInput}");
        }

        // 3. LDAP Injection (pseudo code)
        /// <summary>
        /// FR: Filtre LDAP vulnérable à l'injection.
        /// EN: LDAP search filter vulnerable to injection.
        /// Exemple de payload : *)(uid=*)
        /// </summary>
        public static void RunLdapInjection(string userInput)
        {
            string ldapFilter = $"(&(uid={userInput}))";
            MessageBox.Show("Filtre LDAP utilisé : " + ldapFilter, "LDAP Injection", MessageBoxButton.OK);
            // Pour une démo réelle, utiliser System.DirectoryServices.DirectorySearcher
        }

        // 4. XML Injection (XXE)
        /// <summary>
        /// FR: Parseur XML vulnérable à XXE.
        /// EN: XML parser vulnerable to XXE.
        /// Exemple de payload : <!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'> ]><root>&xxe;</root>
        /// </summary>
        public static void RunXmlInjection(string xmlInput)
        {
            var xml = new XmlDocument();
            xml.XmlResolver = new XmlUrlResolver(); // Vulnérabilité XXE
            try { xml.LoadXml(xmlInput); } catch { }
            MessageBox.Show("XML chargé (voir exceptions pour attaques XXE).", "XML/XXE", MessageBoxButton.OK);
        }

        // 5. NoSQL Injection (ex MongoDB)
        /// <summary>
        /// FR: Query NoSQL vulnérable (injection directe dans la requête).
        /// EN: NoSQL query injection (direct input in query).
        /// Exemple de payload : {$ne:null}
        /// </summary>
        public static void RunNoSqlInjection(string userInput)
        {
            string query = $"{{ \"name\": \"{userInput}\" }}";
            MessageBox.Show("NoSQL Query utilisée : " + query, "NoSQL Injection", MessageBoxButton.OK);
            // Pour MongoDB réel : collection.Find(query)
            // Ici on peut désérialiser pour la démo SCA
            try { JsonConvert.DeserializeObject(query); } catch { }
        }

        // 6. Path Traversal
        /// <summary>
        /// FR: Lecture d'un fichier dont le chemin est contrôlé par l'utilisateur.
        /// EN: Read file, path fully controlled by user (path traversal).
        /// Exemple de payload : ..\..\Windows\win.ini
        /// </summary>
        public static void RunPathTraversal(string fileName)
        {
            string filePath = $"C:\\Data\\{fileName}";
            try { File.ReadAllText(filePath); } catch { }
            MessageBox.Show("Lecture du fichier : " + filePath, "Path Traversal", MessageBoxButton.OK);
        }

        // 7. OS Path Injection
        /// <summary>
        /// FR: Exécution d’un binaire dont le chemin est fourni par l’utilisateur.
        /// EN: Execute a binary, path supplied by user.
        /// Exemple de payload : c:\windows\system32\notepad.exe
        /// </summary>
        public static void RunOsPathInjection(string userInput)
        {
            try { Process.Start(userInput); } catch { }
            MessageBox.Show("Tentative de lancement : " + userInput, "OS Path Injection", MessageBoxButton.OK);
        }

        // 8. XSS (WebView / WPF)
        /// <summary>
        /// FR: Affichage HTML dans WebBrowser, contenu non échappé (XSS desktop).
        /// EN: HTML rendered in WebBrowser, unescaped content (Desktop XSS).
        /// Exemple de payload : <script>alert('xss')</script>
        /// </summary>
        public static void RunDesktopXss(string html)
        {
            var win = new Window() { Title = "XSS WebView", Width = 500, Height = 250 };
            var browser = new WebBrowser();
            win.Content = browser;
            win.Show();
            browser.NavigateToString($"<html><body>{html}</body></html>");
        }

        // 9. Expression Language Injection (.NET Dynamic)
        /// <summary>
        /// FR: Exécution d'expression dynamique fournie par l'utilisateur.
        /// EN: Dynamic expression evaluation from user input.
        /// Exemple de payload : x == 1 || true
        /// </summary>
        public static void RunExpressionInjection(string userExpression)
        {
            try
            {
                var lambda = DynamicExpressionParser.ParseLambda(
                    new[] { System.Linq.Expressions.Expression.Parameter(typeof(int), "x") },
                    typeof(bool), userExpression);
                var result = lambda.Compile().DynamicInvoke(1);
                MessageBox.Show("Résultat de l'expression : " + result, "Expression Injection", MessageBoxButton.OK);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erreur lors de l'exécution : " + ex.Message, "Expression Injection", MessageBoxButton.OK);
            }
        }
    }
}
