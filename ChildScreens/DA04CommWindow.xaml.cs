using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using NetFrmk_Desktop_InsecureApp.Vulnerabilities;

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

            // Nouveaux cas
            { "HttpBasicLabel",  Tuple.Create("13. HTTP Basic Auth (clear)", "13. HTTP Basic Auth (en clair)") },
            { "HttpBasicDesc",   Tuple.Create("Send Basic credentials over HTTP.", "Envoi d'identifiants Basic sur HTTP.") },
            { "FtpLabel",        Tuple.Create("14. FTP Upload (no TLS)", "14. Upload FTP (sans TLS)") },
            { "FtpDesc",         Tuple.Create("Upload file content over FTP in clear.", "Transfert de fichier via FTP en clair.") },
            { "SoapLabel",       Tuple.Create("15. SOAP/XML over HTTP (clear)", "15. SOAP/XML sur HTTP (clair)") },
            { "SoapDesc",        Tuple.Create("Send SOAP XML over HTTP with SOAPAction.", "Envoi d’un XML SOAP sur HTTP avec SOAPAction.") },
            { "DeserializeLabel",Tuple.Create("16. Insecure Binary Deserialization", "16. Désérialisation binaire non sécurisée") },
            { "DeserializeDesc", Tuple.Create("Deserialize untrusted Base64 payload.", "Désérialise un payload Base64 non fiable.") },

            // Boutons
            { "HttpButton", Tuple.Create("Send HTTP", "Envoyer HTTP") },
            { "TcpButton", Tuple.Create("Send TCP", "Connexion TCP") },
            { "UdpButton", Tuple.Create("Send UDP", "Envoyer UDP") },
            { "WebSocketButton", Tuple.Create("Send WebSocket", "Envoyer WebSocket") },
            { "PipeButton", Tuple.Create("Open Named Pipe", "Ouvrir NamedPipe") },
            { "FileDropButton", Tuple.Create("Drop Secret File", "Déposer fichier") },
            { "CmdButton", Tuple.Create("Run Command", "Exécuter commande") },
            { "DllButton", Tuple.Create("Call DLL", "Appeler DLL") },
            { "ClipboardButton", Tuple.Create("Copy to Clipboard", "Copier dans presse-papiers") },
            { "MailButton", Tuple.Create("Send Email", "Envoyer Email") },
            { "RegistryButton", Tuple.Create("Write Registry", "Écrire Registre") },
            { "TempIpcButton", Tuple.Create("Write Temp IPC File", "Fichier IPC Temporaire") },

            { "HttpBasicButton", Tuple.Create("Send Basic HTTP", "Envoyer Basic HTTP") },
            { "FtpButton",       Tuple.Create("Upload FTP", "Uploader FTP") },
            { "SoapButton",      Tuple.Create("Send SOAP", "Envoyer SOAP") },
            { "DeserializeButton",Tuple.Create("Deserialize", "Désérialiser") },
        };

        public DA04CommWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage("en");

            // Placeholders (seront surchargés si tu veux via SetLanguage)
            HttpUrlInput.Text = "http://httpbin.org/post";
            TcpHostInput.Text = "localhost:8080";
            UdpHostInput.Text = "127.0.0.1:9876";
            WebSocketInput.Text = "ws://echo.websocket.events";
            CmdInput.Text = "calc.exe";
            MailServerInput.Text = "smtp4dev.local:25";
            RegistryInput.Text = "SECRET_REGISTRY=abc123";
            TempIpcInput.Text = "ipc_secret_token";

            // Nouveaux

            FtpUrlInput.Text = "ftp://127.0.0.1/upload.txt";
            FtpUserInput.Text = "ftpuser";
            FtpPwInput.Text = "ftppass";
            FtpContentInput.Text = "token=XYZ123";

            SoapUrlInput.Text = "http://127.0.0.1:8080/soap";
            SoapActionInput.Text = "urn:TestAction";
            SoapBodyInput.Text = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><Test>Secret</Test></soap:Body></soap:Envelope>";

            DeserializeB64Input.Text = "AAEAAAD/////AQAAAAAAAAAMAgAAAFNTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTk0ZTllYQMAAAACAAAABVRlc3QHAAAAR2FkZ2V0"; // harmless string
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

            Title = GetLabel("Title", lang);
            TitleText.Text = GetLabel("Title", lang);
            IntroText.Text = GetLabel("Intro", lang);

            // Helpers pour éviter la répétition
            Action<string, string> L = (name, key) => { var c = FindName(name) as TextBlock; if (c != null) c.Text = GetLabel(key, lang); };
            Action<string, string> B = (name, key) => { var c = FindName(name) as Button; if (c != null) c.Content = GetLabel(key, lang); };

            // 1..12
            L("HttpLabel", "HttpLabel"); L("HttpDesc", "HttpDesc"); B("HttpButton", "HttpButton");
            L("TcpLabel", "TcpLabel"); L("TcpDesc", "TcpDesc"); B("TcpButton", "TcpButton");
            L("UdpLabel", "UdpLabel"); L("UdpDesc", "UdpDesc"); B("UdpButton", "UdpButton");
            L("WebSocketLabel", "WebSocketLabel"); L("WebSocketDesc", "WebSocketDesc"); B("WebSocketButton", "WebSocketButton");
            L("PipeLabel", "PipeLabel"); L("PipeDesc", "PipeDesc"); B("PipeButton", "PipeButton");
            L("FileDropLabel", "FileDropLabel"); L("FileDropDesc", "FileDropDesc"); B("FileDropButton", "FileDropButton");
            L("CmdLabel", "CmdLabel"); L("CmdDesc", "CmdDesc"); B("CmdButton", "CmdButton");
            L("DllLabel", "DllLabel"); L("DllDesc", "DllDesc"); B("DllButton", "DllButton");
            L("ClipboardLabel", "ClipboardLabel"); L("ClipboardDesc", "ClipboardDesc"); B("ClipboardButton", "ClipboardButton");
            L("MailLabel", "MailLabel"); L("MailDesc", "MailDesc"); B("MailButton", "MailButton");
            L("RegistryLabel", "RegistryLabel"); L("RegistryDesc", "RegistryDesc"); B("RegistryButton", "RegistryButton");
            L("TempIpcLabel", "TempIpcLabel"); L("TempIpcDesc", "TempIpcDesc"); B("TempIpcButton", "TempIpcButton");

            // 13..16
            L("HttpBasicLabel", "HttpBasicLabel"); L("HttpBasicDesc", "HttpBasicDesc"); B("HttpBasicButton", "HttpBasicButton");
            L("FtpLabel", "FtpLabel"); L("FtpDesc", "FtpDesc"); B("FtpButton", "FtpButton");
            L("SoapLabel", "SoapLabel"); L("SoapDesc", "SoapDesc"); B("SoapButton", "SoapButton");
            L("DeserializeLabel", "DeserializeLabel"); L("DeserializeDesc", "DeserializeDesc"); B("DeserializeButton", "DeserializeButton");
        }

        // -------- Handlers (UI -> CommVuln) --------

        private void HttpButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CommVuln.HttpPostInsecure(HttpUrlInput.Text);
                HttpResult.Text = _lang == "fr" ? "Requête HTTP envoyée (clair / TLS trust-all)." : "HTTP request sent (clear / TLS trust-all).";
            }
            catch (Exception ex) { HttpResult.Text = ex.Message; }
        }

        private void TcpButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var parts = (TcpHostInput.Text ?? "localhost:8080").Split(':');
                var host = parts[0];
                var port = (parts.Length > 1) ? int.Parse(parts[1]) : 8080;
                CommVuln.TcpSendPlain(host, port, "sensitive_data_over_tcp");
                TcpResult.Text = _lang == "fr" ? "Donnée envoyée (TCP non chiffré)." : "Data sent (plain TCP).";
            }
            catch (Exception ex) { TcpResult.Text = ex.Message; }
        }

        private void UdpButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var parts = (UdpHostInput.Text ?? "127.0.0.1:9876").Split(':');
                var host = parts[0];
                var port = (parts.Length > 1) ? int.Parse(parts[1]) : 9876;
                CommVuln.UdpSendPlain(host, port, "sensitive_udp_data");
                UdpResult.Text = _lang == "fr" ? "Paquets UDP envoyés (non chiffrés)." : "UDP packets sent (unencrypted).";
            }
            catch (Exception ex) { UdpResult.Text = ex.Message; }
        }

        private void WebSocketButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CommVuln.WebSocketSendInsecure(WebSocketInput.Text, "sensitive_ws_data");
                WebSocketResult.Text = _lang == "fr" ? "WebSocket non chiffré (simulation)." : "Unencrypted WebSocket (simulated).";
            }
            catch (Exception ex) { WebSocketResult.Text = ex.Message; }
        }

        private void PipeButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CommVuln.NamedPipeWriteInsecure("DemoPipe", "sensitive_pipe_data");
                PipeResult.Text = _lang == "fr" ? "Donnée envoyée via NamedPipe (sans ACL)." : "Data sent over NamedPipe (no ACL).";
            }
            catch (Exception ex) { PipeResult.Text = ex.Message; }
        }

        private void FileDropButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CommVuln.WriteSharedFile(@"C:\PublicShare", "exposed_comm.txt", "SHARED_SECRET=123456");
                FileDropResult.Text = _lang == "fr" ? @"Secret déposé dans C:\PublicShare." : @"Secret dropped to C:\PublicShare.";
            }
            catch (Exception ex) { FileDropResult.Text = ex.Message; }
        }

        private void CmdButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CommVuln.ExecuteCommandUnsafe(CmdInput.Text);
                CmdResult.Text = _lang == "fr" ? "Commande externe exécutée (non filtrée)." : "External command executed (unsanitized).";
            }
            catch (Exception ex) { CmdResult.Text = ex.Message; }
        }

        private void DllButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CommVuln.NativeBeep();
                DllResult.Text = _lang == "fr" ? "Appel natif exécuté." : "Native call executed.";
            }
            catch (Exception ex) { DllResult.Text = ex.Message; }
        }

        private void ClipboardButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CommVuln.ClipboardCopy("SECRET_CLIPBOARD_BROADCAST");
                ClipboardResult.Text = _lang == "fr" ? "Secret copié dans presse-papiers global." : "Secret copied to global clipboard.";
            }
            catch (Exception ex) { ClipboardResult.Text = ex.Message; }
        }

        private void MailButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var parts = (MailServerInput.Text ?? "smtp4dev.local:25").Split(':');
                var host = parts[0];
                var port = (parts.Length > 1) ? int.Parse(parts[1]) : 25;
                CommVuln.SmtpSendNoTls(host, port, "from@local", "to@local", "Subject", "Mail body containing secret=9876");
                MailResult.Text = _lang == "fr" ? "SMTP non chiffré envoyé." : "Clear SMTP sent.";
            }
            catch (Exception ex) { MailResult.Text = ex.Message; }
        }

        private void RegistryButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CommVuln.RegistryWriteInsecure(RegistryInput.Text);
                RegistryResult.Text = _lang == "fr" ? @"Écriture registre: HKCU\Software\DA04CommDemo." : @"Registry write: HKCU\Software\DA04CommDemo.";
            }
            catch (Exception ex) { RegistryResult.Text = ex.Message; }
        }

        private void TempIpcButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CommVuln.TempIpcWrite(TempIpcInput.Text);
                TempIpcResult.Text = _lang == "fr" ? "Fichier IPC temp écrit." : "IPC temp file written.";
            }
            catch (Exception ex) { TempIpcResult.Text = ex.Message; }
        }

        // --- Nouveaux cas ---

        private void FtpButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CommVuln.FtpUploadInsecure(FtpUrlInput.Text, FtpUserInput.Text, FtpPwInput.Text, FtpContentInput.Text);
                FtpResult.Text = _lang == "fr" ? "Upload FTP effectué (clair)." : "FTP upload done (clear).";
            }
            catch (Exception ex) { FtpResult.Text = ex.Message; }
        }

        private void SoapButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CommVuln.SoapOverHttpInsecure(SoapUrlInput.Text, SoapActionInput.Text, SoapBodyInput.Text);
                SoapResult.Text = _lang == "fr" ? "SOAP envoyé sur HTTP (clair)." : "SOAP sent over HTTP (clear).";
            }
            catch (Exception ex) { SoapResult.Text = ex.Message; }
        }

        private void DeserializeButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CommVuln.InsecureDeserializeBinary(DeserializeB64Input.Text);
                DeserializeResult.Text = _lang == "fr" ? "Désérialisation effectuée (dangereuse)." : "Deserialization done (dangerous).";
            }
            catch (Exception ex) { DeserializeResult.Text = ex.Message; }
        }
    }
}
