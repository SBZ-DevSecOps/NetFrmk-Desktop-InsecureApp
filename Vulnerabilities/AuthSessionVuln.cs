using System;
using System.Collections.Generic;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class AuthSessionVuln
    {
        // 1. Hardcoded password in code
        public static void HardcodedPassword()
        {
            string password = "SuperSecret123"; // CWE-798
            MessageBox.Show($"Hardcoded password: {password}");
        }

        // 2. Global session variable (non thread-safe, never invalidated)
        private static string SessionUser = null;
        public static void GlobalSession()
        {
            SessionUser = "admin";
            MessageBox.Show($"User connected (global): {SessionUser}");
        }

        // 3. No session expiration
        private static DateTime SessionStart = DateTime.Now;
        public static void NoSessionExpiration()
        {
            SessionStart = DateTime.Now;
            // No timeout, session never invalidated
            MessageBox.Show($"Session started at {SessionStart}, never expires.");
        }

        // 4. Predictable session token (timestamp)
        public static void PredictableToken()
        {
            string token = "SESSION-" + DateTime.Now.Ticks;
            MessageBox.Show($"Predictable session token: {token}");
        }

        // 5. Session reuse after logout
        private static string LastSessionToken = null;
        public static void ReuseSession()
        {
            LastSessionToken = "SESSION-abcdef";
            // Simulates a logout without token invalidation
            MessageBox.Show($"Old session still valid: {LastSessionToken}");
        }

        // 6. Authentication bypass via variable
        private static bool isAuthenticated = false;
        public static void BypassAuth()
        {
            // Vulnerable code: always grants access
            if (!isAuthenticated || true)
                MessageBox.Show("Authentication bypassed: access granted!");
        }

        // 7. Poor multi-user session management
        private static Dictionary<string, string> Sessions = new Dictionary<string, string>();
        public static void BadMultiUser()
        {
            Sessions["alice"] = "SESSION-alice";
            Sessions["bob"] = "SESSION-alice"; // Shared session!
            MessageBox.Show("Bob's session = " + Sessions["bob"]);
        }

        // 8. No brute force protection
        public static void NoBruteForceProtection()
        {
            string username = "admin";
            string passwordInput = "password";
            // No failed login limit
            if (username == "admin" && passwordInput == "password")
                MessageBox.Show("Authenticated (no brute force protection)!");
            else
                MessageBox.Show("Access denied");
        }
    }
}
