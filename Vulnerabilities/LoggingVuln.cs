using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class LoggingVuln
    {
        // 1. No logging of sensitive file access
        public static void NoFileAccessLog(string file)
        {
            File.ReadAllText(file); // ❌ No log/trace
            MessageBox.Show("Sensitive file accessed (no log).", "No File Log");
        }

        // 2. No admin access logging
        public static void NoAdminAccessLog(string user)
        {
            if (user == "admin")
                MessageBox.Show("Admin area accessed (no log).", "No Admin Log");
        }

        // 3. No config change logging
        public static void NoConfigChangeLog(string setting, string value)
        {
            File.WriteAllText("config.txt", setting + "=" + value);
            MessageBox.Show("Config changed (no log).", "No Config Log");
        }

        // 4. No auth failure log
        public static void NoAuthFailureLog(string username, string pwd)
        {
            if (pwd != "admin123")
                MessageBox.Show("Login failed! (no log)", "No Auth Log");
        }

        // 5. No alert on forbidden access
        public static void NoForbiddenAccessAlert(string user, string action)
        {
            if (user != "admin" && action == "admin-panel")
                MessageBox.Show("Forbidden action attempted (no alert/log).", "No Alert");
        }

        // 6. No deletion log
        public static void NoDeletionLog(string filename)
        {
            File.Delete(filename);
            MessageBox.Show("File deleted (no log).", "No Deletion Log");
        }

        // 7. No log on critical error/crash
        public static void NoCriticalErrorLog()
        {
            try { throw new Exception("Fatal: OutOfMemory"); }
            catch { MessageBox.Show("Critical error! (not logged)", "No Error Log"); }
        }

        // 8. Logging only in DEBUG mode
        public static void DebugOnlyLog(string eventMsg)
        {
#if DEBUG
            File.AppendAllText("debug-only.log", eventMsg + Environment.NewLine);
#endif
            MessageBox.Show("Event occurred (log only if DEBUG build).", "Debug Only Log");
        }

        // 9. No log rotation/backup
        public static void NoLogRotation(string msg)
        {
            File.AppendAllText("huge-logfile.log", msg + Environment.NewLine);
            MessageBox.Show("Log appended (never rotated/archived).", "No Rotation");
        }

        // 10. World-writable log file
        public static void WorldWritableLog()
        {
            string logfile = "world-write.log";
            File.WriteAllText(logfile, "Sensitive log entry" + Environment.NewLine);
            try
            {
                var fi = new FileInfo(logfile);
                var acl = fi.GetAccessControl();
                acl.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));
                fi.SetAccessControl(acl);
            }
            catch { /* ignore demo ACL failures */ }
            MessageBox.Show("Log file created world-writable!", "World Writable");
        }

        // 11. Log folder open to all users
        public static void OpenLogFolder()
        {
            string folder = "PublicLogs";
            Directory.CreateDirectory(folder);
            try
            {
                var dirInfo = new DirectoryInfo(folder);
                var acl = dirInfo.GetAccessControl();
                acl.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));
                dirInfo.SetAccessControl(acl);
            }
            catch { /* ignore demo ACL failures */ }
            File.AppendAllText(Path.Combine(folder, "event.log"), "Some log entry" + Environment.NewLine);
            MessageBox.Show("Log folder is world-writable!", "Open Log Folder");
        }

        // 12. Logging secrets/credentials in cleartext
        public static void LogCleartextSecrets(string username, string password)
        {
            File.AppendAllText("sensitive-log.log", "LOGIN=" + username + " ; PASSWORD=" + password + Environment.NewLine);
            MessageBox.Show("Credentials written in log!", "Log Secrets");
        }

        // =================== NEW CASES ===================

        // 13. Log Injection / Log Forging (no sanitization of CR/LF)
        public static void LogInjection(string user, string action)
        {
            // ❌ User-controlled text written raw → allows forged/multi-line log entries
            string line = DateTime.Now.ToString("s") + " | user=" + user + " | action=" + action + Environment.NewLine;
            File.AppendAllText("audit.log", line, Encoding.UTF8);
            MessageBox.Show("Audit written without sanitization (possible log forging).", "Log Injection");
        }

        // 14. Insecure remote logging over HTTP (no TLS, no integrity)
        public static void RemoteHttpLog(string url, string message)
        {
            try
            {
                using (var wc = new WebClient())
                {
                    // ❌ Sends logs via plaintext HTTP, querystring/body leakage possible
                    string response = wc.UploadString(url, "msg=" + Uri.EscapeDataString(message ?? ""));
                    MessageBox.Show("Sent log to: " + url + "\nResponse length: " + (response == null ? 0 : response.Length), "Remote HTTP Log");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Remote log failed: " + ex.Message, "Remote HTTP Log");
            }
        }

        // 15. Sensitive data in Windows Event Log (PII/token)
        public static void EventLogSensitive(string username, string token)
        {
            try
            {
                const string src = "DA10InsecureSource";
                if (!EventLog.SourceExists(src))
                {
                    // ⚠️ may require admin; errors are swallowed for demo
                    try { EventLog.CreateEventSource(src, "Application"); } catch { }
                }
                // ❌ Writes sensitive values into system event log
                EventLog.WriteEntry(src, "User=" + username + " ; BearerToken=" + token, EventLogEntryType.Information);
                MessageBox.Show("Wrote sensitive data to Windows Event Log.", "Event Log Sensitive");
            }
            catch (Exception ex)
            {
                MessageBox.Show("EventLog write failed (likely permissions): " + ex.Message, "Event Log Sensitive");
            }
        }
    }
}
