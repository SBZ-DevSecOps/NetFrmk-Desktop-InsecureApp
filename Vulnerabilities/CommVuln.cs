using System;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Text;
using System.Windows;
using System.IO.Pipes;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class CommVuln
    {
        // 1) HTTP POST en clair + trust-all TLS + entêtes sensibles (SAST: UploadString + http:// + cert callback)
        public static void HttpPostInsecure(string url)
        {
            ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => true; // ❌ trust-all
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls | SecurityProtocolType.Tls11; // ❌ protocoles faibles/legacy
            try
            {
                using (var wc = new WebClient())
                {
                    wc.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                    wc.Headers[HttpRequestHeader.Authorization] = "Bearer verySensitiveToken123";     // ❌ token en clair
                    wc.Headers[HttpRequestHeader.Cookie] = "SESSIONID=abc123; PREF=uid=42";          // ❌ cookie sensible
                    var resp = wc.UploadString(url, "POST", "secret=Passw0rd!&scope=all");
                    if (resp.Length > 300) resp = resp.Substring(0, 300) + "...";
                    MessageBox.Show("HTTP POST sent to: " + url + "\nResponse (preview):\n" + resp, "Insecure Communication");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("HTTP error: " + ex.Message, "Insecure Communication");
            }
        }

        // 2) TCP non chiffré (petit handshake + data)
        public static void TcpSendPlain(string host, int port, string data)
        {
            try
            {
                using (var client = new TcpClient(host, port))
                using (var stream = client.GetStream())
                {
                    var auth = Encoding.UTF8.GetBytes("AUTH username=admin password=Passw0rd!\r\n"); // ❌ creds en clair
                    stream.Write(auth, 0, auth.Length);

                    var payload = Encoding.UTF8.GetBytes("DATA " + data + "\r\n");
                    stream.Write(payload, 0, payload.Length);
                }
                MessageBox.Show("Plain TCP data sent to " + host + ":" + port, "Insecure Communication");
            }
            catch (Exception ex)
            {
                MessageBox.Show("TCP error: " + ex.Message, "Insecure Communication");
            }
        }

        // 3) UDP non chiffré (2 datagrammes)
        public static void UdpSendPlain(string host, int port, string data)
        {
            try
            {
                using (var udp = new UdpClient())
                {
                    var p1 = Encoding.UTF8.GetBytes("HEADER secret=udpToken\r\n");
                    var p2 = Encoding.UTF8.GetBytes(data);
                    udp.Send(p1, p1.Length, host, port);
                    udp.Send(p2, p2.Length, host, port);
                }
                MessageBox.Show("UDP packets sent to " + host + ":" + port, "Insecure Communication");
            }
            catch (Exception ex)
            {
                MessageBox.Show("UDP error: " + ex.Message, "Insecure Communication");
            }
        }

        // 4) WebSocket "insecure" (simulation ws:// — SAST verra le littéral ws://)
        public static void WebSocketSendInsecure(string wsUrl, string data)
        {
            MessageBox.Show("Simulated WebSocket send over: " + wsUrl + "\nData: " + data, "Insecure Communication");
        }

        // 5) NamedPipe sans ACL (client)
        public static void NamedPipeWriteInsecure(string pipeName, string data)
        {
            try
            {
                using (var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.Out))
                {
                    pipe.Connect(1000);
                    var bytes = Encoding.UTF8.GetBytes(data);
                    pipe.Write(bytes, 0, bytes.Length);
                }
                MessageBox.Show("Data sent via NamedPipe (no ACL): " + pipeName, "Insecure IPC");
            }
            catch (Exception ex)
            {
                MessageBox.Show("NamedPipe error: " + ex.Message, "Insecure IPC");
            }
        }

        // 6) Dépôt fichier dans un dossier partagé/public
        public static void WriteSharedFile(string folder, string fileName, string content)
        {
            try
            {
                Directory.CreateDirectory(folder);
                var path = Path.Combine(folder, fileName);
                File.WriteAllText(path, content);
                MessageBox.Show("Secret dropped to shared folder: " + path, "Insecure External Interaction");
            }
            catch (Exception ex)
            {
                MessageBox.Show("File drop error: " + ex.Message, "Insecure External Interaction");
            }
        }

        // 7) Exécution de commande non filtrée (injection via cmd.exe /C)
        public static void ExecuteCommandUnsafe(string payload)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/C " + payload, // ❌ injection possible si payload contient & || etc.
                    UseShellExecute = true
                });
                MessageBox.Show("External command executed: " + payload, "Unsafe Process Execution");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Process error: " + ex.Message, "Unsafe Process Execution");
            }
        }

        // 8) Appel natif (DllImport) sans contrôle
        [DllImport("user32.dll")]
        private static extern int MessageBeep(uint uType);

        public static void NativeBeep()
        {
            try
            {
                MessageBeep(0);
                MessageBox.Show("Native call executed via DllImport.", "Unsafe Native Interaction");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Native call error: " + ex.Message, "Unsafe Native Interaction");
            }
        }

        // 9) Copie presse-papiers globale
        public static void ClipboardCopy(string data)
        {
            Clipboard.SetText(data);
            MessageBox.Show("Secret copied to global clipboard.", "Insecure Communication");
        }

        // 10) SMTP sans TLS
        public static void SmtpSendNoTls(string host, int port, string from, string to, string subject, string body)
        {
            try
            {
                var client = new SmtpClient(host, port) { EnableSsl = false }; // ❌ pas de TLS
                client.Send(from, to, subject, body);
                MessageBox.Show("SMTP mail sent without TLS to " + host + ":" + port, "Insecure Communication");
            }
            catch (Exception ex)
            {
                MessageBox.Show("SMTP error: " + ex.Message, "Insecure Communication");
            }
        }

        // 11) Ecriture registre sans restriction
        public static void RegistryWriteInsecure(string nameValueLine)
        {
            try
            {
                var parts = nameValueLine.Split(new[] { '=' }, 2);
                var name = parts.Length > 0 ? parts[0] : "secret";
                var val = parts.Length > 1 ? parts[1] : "value";
                using (var key = Registry.CurrentUser.CreateSubKey(@"Software\DA04CommDemo"))
                {
                    if (key != null) key.SetValue(name, val, RegistryValueKind.String);
                }
                MessageBox.Show(@"Registry write: HKCU\Software\DA04CommDemo -> " + name, "Unsafe External Interaction");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Registry error: " + ex.Message, "Unsafe External Interaction");
            }
        }

        // 12) Fichier temporaire local (IPC)
        public static void TempIpcWrite(string data)
        {
            try
            {
                var temp = Path.Combine(Path.GetTempPath(), "ipc_secret.txt");
                File.WriteAllText(temp, data);
                MessageBox.Show("IPC temp file written: " + temp, "Insecure IPC");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Temp IPC error: " + ex.Message, "Insecure IPC");
            }
        }

        // 14) FTP en clair (ftp://) upload fichier
        public static void FtpUploadInsecure(string ftpUrl, string username, string password, string content)
        {
            try
            {
                var req = (FtpWebRequest)WebRequest.Create(ftpUrl); // ex: ftp://127.0.0.1/upload.txt
                req.Method = WebRequestMethods.Ftp.UploadFile;
                req.Credentials = new NetworkCredential(username, password); // ❌ creds FTP en clair
                req.EnableSsl = false; // ❌ pas de FTPS
                var bytes = Encoding.UTF8.GetBytes(content);
                using (var s = req.GetRequestStream())
                {
                    s.Write(bytes, 0, bytes.Length);
                }
                using (var resp = (FtpWebResponse)req.GetResponse())
                {
                    MessageBox.Show("FTP upload complete: " + resp.StatusDescription, "Insecure Communication");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("FTP error: " + ex.Message, "Insecure Communication");
            }
        }

        // 15) SOAP/XML sur HTTP (clair) avec SOAPAction
        public static void SoapOverHttpInsecure(string url, string soapAction, string bodyXml)
        {
            ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => true; // ❌ trust-all
            try
            {
                using (var wc = new WebClient())
                {
                    wc.Headers["Content-Type"] = "text/xml; charset=utf-8";
                    if (!string.IsNullOrEmpty(soapAction)) wc.Headers["SOAPAction"] = soapAction;
                    var resp = wc.UploadString(url, "POST", bodyXml); // ❌ HTTP clair
                    if (resp.Length > 300) resp = resp.Substring(0, 300) + "...";
                    MessageBox.Show("SOAP over HTTP sent to: " + url + "\nResponse (preview):\n" + resp, "Insecure Communication");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("SOAP error: " + ex.Message, "Insecure Communication");
            }
        }

        // 16) Désérialisation binaire non sécurisée
        public static void InsecureDeserializeBinary(string base64)
        {
            try
            {
                var bytes = Convert.FromBase64String(base64);
#pragma warning disable SYSLIB0011
                var bf = new BinaryFormatter(); // ❌ Insecure deserialization
                using (var ms = new MemoryStream(bytes))
                {
                    var obj = bf.Deserialize(ms);
                    MessageBox.Show("Deserialized type: " + (obj != null ? obj.GetType().FullName : "null"), "Unsafe Deserialization");
                }
#pragma warning restore SYSLIB0011
            }
            catch (Exception ex)
            {
                MessageBox.Show("Deserialize error: " + ex.Message, "Unsafe Deserialization");
            }
        }
    }
}
