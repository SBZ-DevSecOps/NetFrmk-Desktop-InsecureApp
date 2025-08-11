using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Mail;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA04CommWindow : Window
    {
        private string _lang = "en";
        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA04 – Insecure Communication & Unsafe Interactions", "DA04 – Communications & Interactions non sécurisées") },
            { "Intro", Tuple.Create(
                "Demonstrates real-world insecure communication, IPC, and unsafe process/file/registry interactions.",
                "Démontre des communications, IPC et interactions process/fichier/registre non sécurisées rencontrées en desktop.") },
            { "HttpLabel", Tuple.Create("1. Plain HTTP Request", "1. Requête HTTP non sécurisée") },
            { "HttpDesc", Tuple.Create("Send sensitive data over HTTP (no TLS/SSL).", "Envoi de données sensibles en HTTP (pas de TLS/SSL).") },
            { "TcpLabel", Tuple.Create("2. Plain TCP Socket (no TLS)", "2. Socket TCP sans TLS") },
            { "TcpDesc", Tuple.Create("Send data over plain TCP (no encryption).", "Envoi de données sur TCP sans chiffrement.") },
            { "UdpLabel", Tuple.Create("3. UDP Packet", "3. Paquet UDP") },
            { "UdpDesc", Tuple.Create("Send data over UDP (no encryption).", "Envoi de données via UDP (aucun chiffrement).") },
            { "WebSocketLabel", Tuple.Create("4. WebSocket (no encryption)", "4. WebSocket non sécurisé") },
            { "WebSocketDesc", Tuple.Create("Send data over unencrypted WebSocket.", "Envoi de données sur WebSocket non chiffré.") },
            { "PipeLabel", Tuple.Create("5. Named Pipe Communication (no ACL)", "5. Communication NamedPipe non sécurisée") },
            { "PipeDesc", Tuple.Create("Send/receive data over named pipe with no ACL.", "Échange de données sur NamedPipe sans ACL.") },
            { "FileDropLabel", Tuple.Create("6. Insecure File Drop (Shared Folder)", "6. Dépôt fichier non sécurisé (dossier partagé)") },
            { "FileDropDesc", Tuple.Create("Drop file with secrets in shared/public folder.", "Dépose un fichier avec secret dans un dossier partagé/public.") },
            { "CmdLabel", Tuple.Create("7. Unsafe Command Execution (Shell/External App)", "7. Exécution de commande externe non sécurisée") },
            { "CmdDesc", Tuple.Create("Run shell/external app with unsanitized input.", "Exécute une commande/app externe avec entrée non filtrée.") },
            { "DllLabel", Tuple.Create("8. Unsafe Use of DllImport / COM", "8. Utilisation risquée de DllImport/COM") },
            { "DllDesc", Tuple.Create("Call native code without validation.", "Appelle du code natif sans validation.") },
            { "ClipboardLabel", Tuple.Create("9. Dangerous Clipboard Broadcast / Global Hotkey", "9. Diffusion presse-papiers / hotkey globale") },
            { "ClipboardDesc", Tuple.Create("Copy secret to clipboard, readable by any app.", "Copie un secret dans le presse-papiers global.") },
            { "MailLabel", Tuple.Create("10. SMTP Mail Send (no TLS)", "10. Envoi mail SMTP non chiffré") },
            { "MailDesc", Tuple.Create("Send sensitive info by SMTP without encryption.", "Envoie de l’info sensible par SMTP sans chiffrement.") },
            { "RegistryLabel", Tuple.Create("11. Registry Write (no ACL)", "11. Écriture dans le registre (pas de restriction)") },
            { "RegistryDesc", Tuple.Create("Write secret to registry, no access control.", "Écrit un secret dans le registre, sans contrôle d'accès.") },
            { "TempIpcLabel", Tuple.Create("12. Local Temp File for IPC", "12. Fichier temporaire local pour IPC") },
            { "TempIpcDesc", Tuple.Create("Write secret to local temp file for process comm.", "Écrit un secret dans un fichier temporaire pour IPC.") },

            { "HttpButton", Tuple.Create("Trigger Unsafe Buffer", "Envoyer Requête HTTP") },
            { "TcpButton", Tuple.Create("Trigger TCP Socket", "Connexion TCP") },
            { "UdpButton", Tuple.Create("Send UDP Packet", "Envoyer paquet UDP") },
            { "WebSocketButton", Tuple.Create("Send WebSocket Data", "Envoyer WebSocket") },
            { "PipeButton", Tuple.Create("Open Named Pipe", "Ouvrir NamedPipe") },
            { "FileDropButton", Tuple.Create("Drop Secret File", "Déposer fichier") },
            { "CmdButton", Tuple.Create("Run Command", "Exécuter commande") },
            { "DllButton", Tuple.Create("Call DLL", "Appeler DLL") },
            { "ClipboardButton", Tuple.Create("Copy to Clipboard", "Copier dans presse-papiers") },
            { "MailButton", Tuple.Create("Send Email", "Envoyer Email") },
            { "RegistryButton", Tuple.Create("Write Registry", "Écrire Registre") },
            { "TempIpcButton", Tuple.Create("Write Temp IPC File", "Fichier IPC Temporaire") },
        };

        public DA04CommWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage("en");

            HttpUrlInput.Text = "http://httpbin.org/post";
            TcpHostInput.Text = "localhost:8080";
            UdpHostInput.Text = "127.0.0.1:9876";
            WebSocketInput.Text = "ws://echo.websocket.events";
            CmdInput.Text = "calc.exe";
            MailServerInput.Text = "smtp4dev.local:25";
            RegistryInput.Text = "SECRET_REGISTRY=abc123";
            TempIpcInput.Text = "ipc_secret_token";

        }

        private void LanguageSelector_Changed(object sender, SelectionChangedEventArgs e)
        {
            var lang = (LanguageSelector.SelectedIndex == 1) ? "fr" : "en";
            SetLanguage(lang);
        }
        private string GetLabel(string key, string lang)
        {
            return lang == "fr" ? labels[key].Item2 : labels[key].Item1;
        }
        private void SetLanguage(string lang)
        {
            _lang = lang;
            Title= GetLabel("Title",lang);
            TitleText.Text= GetLabel("Title",lang);
            IntroText.Text= GetLabel("Intro",lang);

            HttpLabel.Text= GetLabel("HttpLabel",lang);
            HttpDesc.Text= GetLabel("HttpDesc",lang);

            TcpLabel.Text= GetLabel("TcpLabel",lang);
            TcpDesc.Text= GetLabel("TcpDesc",lang);

            UdpLabel.Text= GetLabel("UdpLabel",lang);
            UdpDesc.Text= GetLabel("UdpDesc",lang);

            WebSocketLabel.Text= GetLabel("WebSocketLabel",lang);
            WebSocketDesc.Text= GetLabel("WebSocketDesc",lang);

            PipeLabel.Text= GetLabel("PipeLabel",lang);
            PipeDesc.Text= GetLabel("PipeDesc",lang);

            FileDropLabel.Text= GetLabel("FileDropLabel",lang);
            FileDropDesc.Text= GetLabel("FileDropDesc",lang);

            CmdLabel.Text= GetLabel("CmdLabel",lang);
            CmdDesc.Text= GetLabel("CmdDesc",lang);

            DllLabel.Text= GetLabel("DllLabel",lang);
            DllDesc.Text= GetLabel("DllDesc",lang);

            ClipboardLabel.Text= GetLabel("ClipboardLabel",lang);
            ClipboardDesc.Text= GetLabel("ClipboardDesc",lang);

            MailLabel.Text= GetLabel("MailLabel",lang);
            MailDesc.Text= GetLabel("MailDesc",lang);

            RegistryLabel.Text= GetLabel("RegistryLabel",lang);
            RegistryDesc.Text= GetLabel("RegistryDesc",lang);

            TempIpcLabel.Text= GetLabel("TempIpcLabel",lang);
            TempIpcDesc.Text= GetLabel("TempIpcDesc",lang);

            HttpButton.Content= GetLabel("HttpButton",lang);
            TcpButton.Content= GetLabel("TcpButton",lang);
            UdpButton.Content= GetLabel("UdpButton",lang);
            WebSocketButton.Content= GetLabel("WebSocketButton",lang);
            PipeButton.Content= GetLabel("PipeButton",lang);
            FileDropButton.Content= GetLabel("FileDropButton",lang);
            CmdButton.Content= GetLabel("CmdButton",lang);
            DllButton.Content= GetLabel("DllButton",lang);
            ClipboardButton.Content= GetLabel("ClipboardButton",lang);
            MailButton.Content= GetLabel("MailButton",lang);
            RegistryButton.Content= GetLabel("RegistryButton",lang);
            TempIpcButton.Content= GetLabel("TempIpcButton",lang);

        }

        // 1. HTTP non sécurisé
        private async void HttpButton_Click(object sender, RoutedEventArgs e)
        {
            string url = HttpUrlInput.Text;
            try
            {
                var client = new System.Net.Http.HttpClient();
                var response = await client.PostAsync(url, new System.Net.Http.StringContent("sensitive_data=leaked"));
                HttpResult.Text = _lang == "fr"
                    ? "Donnée envoyée sur HTTP (pas de TLS/SSL)."
                    : "Data sent over HTTP (no TLS/SSL).";
            }
            catch (Exception ex)
            {
                HttpResult.Text = ex.Message;
            }
        }

        // 2. TCP socket sans TLS
        private void TcpButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var hostParts = TcpHostInput.Text.Split(':');
                var client = new TcpClient(hostParts[0], int.Parse(hostParts[1]));
                using (var stream = client.GetStream())
                {
                    byte[] buffer = System.Text.Encoding.UTF8.GetBytes("sensitive_data_over_tcp");
                    stream.Write(buffer, 0, buffer.Length);
                }
                TcpResult.Text = _lang == "fr"
                    ? "Donnée envoyée sur socket TCP non chiffré."
                    : "Data sent over plain TCP socket (no TLS).";
            }
            catch (Exception ex)
            {
                TcpResult.Text = ex.Message;
            }
        }

        // 3. UDP packet
        private void UdpButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var parts = UdpHostInput.Text.Split(':');
                using (var udp = new UdpClient())
                {
                    var data = System.Text.Encoding.UTF8.GetBytes("sensitive_udp_data");
                    udp.Send(data, data.Length, parts[0], int.Parse(parts[1]));
                }
                UdpResult.Text = _lang == "fr"
                    ? "Paquet UDP envoyé (pas de chiffrement, broadcast possible)."
                    : "UDP packet sent (no encryption, possible broadcast).";
            }
            catch (Exception ex)
            {
                UdpResult.Text = ex.Message;
            }
        }

        // 4. WebSocket (simulation sans TLS, pas de lib ws pure)
        private void WebSocketButton_Click(object sender, RoutedEventArgs e)
        {
            WebSocketResult.Text = _lang == "fr"
                ? "Donnée envoyée sur WebSocket non chiffré (simulation)."
                : "Data sent over unencrypted WebSocket (simulated).";
        }

        // 5. Named pipe sans ACL
        private void PipeButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string pipeName = "DemoPipe";
                using (var pipe = new System.IO.Pipes.NamedPipeClientStream(".", pipeName, System.IO.Pipes.PipeDirection.Out))
                {
                    pipe.Connect(1000); // Attend 1 seconde max
                    byte[] data = System.Text.Encoding.UTF8.GetBytes("sensitive_pipe_data");
                    pipe.Write(data, 0, data.Length);
                }
                PipeResult.Text = _lang == "fr"
                    ? "Donnée envoyée par NamedPipe (aucune restriction/ACL)."
                    : "Data sent over named pipe (no ACL/restriction).";
            }
            catch (Exception ex)
            {
                PipeResult.Text = ex.Message;
            }
        }

        // 6. Dépôt fichier non sécurisé
        private void FileDropButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string folder = "C:\\PublicShare";
                Directory.CreateDirectory(folder);
                File.WriteAllText(Path.Combine(folder, "exposed_comm.txt"), "SHARED_SECRET=123456");
                FileDropResult.Text = _lang == "fr"
                    ? "Secret déposé dans le dossier partagé C:\\PublicShare."
                    : "Secret dropped in shared folder C:\\PublicShare.";
            }
            catch (Exception ex)
            {
                FileDropResult.Text = ex.Message;
            }
        }

        // 7. Commande shell/externes non filtrée
        private void CmdButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var proc = Process.Start(new ProcessStartInfo
                {
                    FileName = CmdInput.Text,
                    Arguments = "",
                    UseShellExecute = true,
                });
                CmdResult.Text = _lang == "fr"
                    ? "Commande externe exécutée (non filtrée)."
                    : "External command executed (unsanitized input).";
            }
            catch (Exception ex)
            {
                CmdResult.Text = ex.Message;
            }
        }

        // 8. DllImport/COM non sécurisé
        [DllImport("user32.dll")]
        public static extern int MessageBeep(uint uType);

        private void DllButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                MessageBeep(0);
                DllResult.Text = _lang == "fr"
                    ? "Appel natif exécuté sans contrôle."
                    : "Native call executed with no input validation.";
            }
            catch (Exception ex)
            {
                DllResult.Text = ex.Message;
            }
        }

        // 9. Diffusion clipboard/hotkey globale
        private void ClipboardButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText("SECRET_CLIPBOARD_BROADCAST");
                ClipboardResult.Text = _lang == "fr"
                    ? "Secret copié dans le presse-papiers global."
                    : "Secret copied to global clipboard.";
            }
            catch (Exception ex)
            {
                ClipboardResult.Text = ex.Message;
            }
        }

        // 10. Envoi mail SMTP non chiffré
        private void MailButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var parts = MailServerInput.Text.Split(':');
                var client = new SmtpClient(parts[0], int.Parse(parts[1]))
                {
                    EnableSsl = false
                };
                client.Send("from@local", "to@local", "Subject", "Mail body containing secret=9876");
                MailResult.Text = _lang == "fr"
                    ? "Email envoyé par SMTP non chiffré (pas de TLS/SSL)."
                    : "Email sent via SMTP without encryption (no TLS/SSL).";
            }
            catch (Exception ex)
            {
                MailResult.Text = ex.Message;
            }
        }

        // 11. Ecriture registre sans restriction
        private void RegistryButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                RegistryKey key = Registry.CurrentUser.CreateSubKey("Software\\DA04CommDemo");
                key.SetValue("secret", RegistryInput.Text);
                key.Close();
                RegistryResult.Text = _lang == "fr"
                    ? "Secret écrit dans la clé registre HKCU\\Software\\DA04CommDemo."
                    : "Secret written to registry HKCU\\Software\\DA04CommDemo.";
            }
            catch (Exception ex)
            {
                RegistryResult.Text = ex.Message;
            }
        }

        // 12. Fichier temp pour IPC
        private void TempIpcButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string temp = Path.Combine(Path.GetTempPath(), "ipc_secret.txt");
                File.WriteAllText(temp, TempIpcInput.Text);
                TempIpcResult.Text = _lang == "fr"
                    ? $"Secret écrit dans {temp} (IPC temp file)."
                    : $"Secret written in {temp} (IPC temp file).";
            }
            catch (Exception ex)
            {
                TempIpcResult.Text = ex.Message;
            }
        }
    }
}
