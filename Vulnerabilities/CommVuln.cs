using System.Net;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class CommVuln
    {
        // 1. No TLS
        public static void NoTlsComm(string url)
        {
            MessageBox.Show("Sending data in cleartext: " + url, "Insecure Communication");
            // HttpClient client = new HttpClient();
            // client.PostAsync(url, ...);
        }

        // 2. Accepts invalid SSL certs
        public static void AcceptInvalidCert(string url)
        {
            // Accept all certificates (very insecure)
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            MessageBox.Show("Any SSL cert accepted for: " + url, "Insecure Communication");
        }

        // 3. Unsafe IPC
        public static void UnsafeIpc(string message)
        {
            MessageBox.Show("IPC message sent without security: " + message, "Insecure Communication");
            // (Simule absence d’authentification ou d’ACL sur un canal IPC)
        }

        // 4. Command/Process Injection via IPC
        public static void ProcInject(string payload)
        {
            MessageBox.Show("Payload passed to process: " + payload, "Insecure IPC Command Injection");
            // System.Diagnostics.Process.Start("cmd.exe", "/C " + payload);
        }

        // 5. Unprotected named pipe/socket
        public static void UnprotectedPipe(string pipeName)
        {
            MessageBox.Show("Connecting to unprotected pipe/socket: " + pipeName, "Insecure Communication");
        }

        // 6. Dangerous port/service
        public static void ExposeDangerousPort(string portInfo)
        {
            MessageBox.Show("Service exposed: " + portInfo, "Insecure Communication");
        }

        // 7. Unauthenticated communication
        public static void UnauthComm(string req)
        {
            MessageBox.Show("Request sent without authentication: " + req, "Insecure Communication");
        }

        // 8. Send secret in clear
        public static void ClearSecretTransport(string data)
        {
            MessageBox.Show("Secret sent in clear over network: " + data, "Insecure Communication");
        }
    }
}
