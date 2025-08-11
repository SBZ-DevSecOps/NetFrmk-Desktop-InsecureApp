using System;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class LoggingVuln
    {
        // 1. No logging of sensitive file access
        public static void NoFileAccessLog(string file)
        {
            File.ReadAllText(file); // No log
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
            File.WriteAllText("config.txt", $"{setting}={value}");
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
            File.AppendAllText("debug-only.log", eventMsg + "\n");
#endif
            MessageBox.Show("Event occurred (log only if debug build).", "Debug Only Log");
        }

        // 9. No log rotation/backup
        public static void NoLogRotation(string msg)
        {
            File.AppendAllText("huge-logfile.log", msg + "\n");
            MessageBox.Show("Log appended (never rotated/archived).", "No Rotation");
        }

        // 10. World-writable log file
        public static void WorldWritableLog()
        {
            string logfile = "world-write.log";
            File.WriteAllText(logfile, "Sensitive log entry\n");
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
            catch { }
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
            catch { }
            File.AppendAllText(Path.Combine(folder, "event.log"), "Some log entry\n");
            MessageBox.Show("Log folder is world-writable!", "Open Log Folder");
        }

        // 12. Logging secrets/credentials in cleartext
        public static void LogCleartextSecrets(string username, string password)
        {
            File.AppendAllText("sensitive-log.log", $"LOGIN: {username} / PASSWORD: {password}\n");
            MessageBox.Show("Credentials written in log!", "Log Secrets");
        }
    }
}
