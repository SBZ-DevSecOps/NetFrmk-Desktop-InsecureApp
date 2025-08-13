using NetFrmk_Desktop_InsecureApp.Vulnerabilities;
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA05AccessControlWindow : Window
    {
        private string _lang = "en";

        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA05 – Insufficient Authorization / Access Control", "DA05 – Autorisation insuffisante / Contrôle d'accès") },
            { "Intro", Tuple.Create("Common broken authorization patterns in desktop apps. Sinks are intentionally vulnerable for SAST demos.", "Modèles d’autorisation cassés dans les apps desktop. Sinks volontairement vulnérables pour démos SAST.") },

            // 1..10 (existing)
            { "HttpLabel", Tuple.Create("Broken Object Level Authorization (BOLA)", "Broken Object Level Authorization (BOLA)") },
            { "HttpDesc",  Tuple.Create("Access unauthorized user data by manipulating object IDs/paths.", "Accès non autorisé en manipulant des IDs/chemins.") },

            { "TcpLabel", Tuple.Create("Insecure Direct Object Reference (IDOR)", "Insecure Direct Object Reference (IDOR)") },
            { "TcpDesc",  Tuple.Create("Read another user's private file via userId.", "Lecture d’un fichier privé via userId.") },

            { "UdpLabel", Tuple.Create("Privilege Escalation - Vertical", "Escalade de privilèges - verticale") },
            { "UdpDesc",  Tuple.Create("Gain admin-like capabilities via command execution.", "Obtenir des capacités admin via exécution de commande.") },

            { "WebSocketLabel", Tuple.Create("Privilege Escalation - Horizontal", "Escalade de privilèges - horizontale") },
            { "WebSocketDesc",  Tuple.Create("Access other users' data with same role.", "Accès aux données d’autres utilisateurs du même rôle.") },

            { "PipeLabel", Tuple.Create("Forced Browsing / Hidden Feature", "Navigation forcée / fonctionnalité cachée") },
            { "PipeDesc",  Tuple.Create("Reach hidden admin feature by guessing name.", "Atteindre une fonctionnalité admin par devinette.") },

            { "FileDropLabel", Tuple.Create("Missing Function Level Access Control", "Contrôle fonctionnel insuffisant") },
            { "FileDropDesc",  Tuple.Create("Dangerous function exposed without checks.", "Fonction dangereuse exposée sans vérifications.") },

            { "CmdLabel", Tuple.Create("Unprotected Admin Function", "Fonction admin non protégée") },
            { "CmdDesc",  Tuple.Create("Invoke sensitive admin-like action with magic string.", "Appel d’action sensible via chaîne magique.") },

            { "DllLabel", Tuple.Create("Missing Authorization on Event Handler", "Autorisation manquante sur le gestionnaire d’événements") },
            { "DllDesc",  Tuple.Create("Critical delegate/command executed without checks.", "Délégué/commande critique exécuté sans vérifications.") },

            { "ClipboardLabel", Tuple.Create("Security Through Obscurity", "Contrôle d'accès par obscurcissement") },
            { "ClipboardDesc",  Tuple.Create("Authorization based on a guessable 'secret' string.", "Autorisation basée sur une chaîne 'secrète' devinable.") },

            { "MailLabel", Tuple.Create("Role Confusion / Misconfiguration", "Confusion / mauvaise configuration des rôles") },
            { "MailDesc",  Tuple.Create("Composite roles accidentally grant admin.", "Rôles composites accordent accidentellement admin.") },

            // Buttons 1..10
            { "HttpButton", Tuple.Create("Test BOLA", "Tester BOLA") },
            { "TcpButton", Tuple.Create("Test IDOR", "Tester IDOR") },
            { "UdpButton", Tuple.Create("Run Command", "Exécuter commande") },
            { "WebSocketButton", Tuple.Create("Read Peer Data", "Lire données pair") },
            { "PipeButton", Tuple.Create("Open Hidden Feature", "Ouvrir fonctionnalité cachée") },
            { "FileDropButton", Tuple.Create("Invoke Function", "Invoquer fonction") },
            { "CmdButton", Tuple.Create("Invoke Admin-ish", "Invoquer admin-like") },
            { "DllButton", Tuple.Create("Run Event", "Exécuter événement") },
            { "ClipboardButton", Tuple.Create("Try Secret", "Tester secret") },
            { "MailButton", Tuple.Create("Test Role Combo", "Tester combo rôles") },

            // 11..15 (new)
            { "RoleTamperLabel", Tuple.Create("Role/Principal Spoofing", "Usurpation de rôle/principal") },
            { "RoleTamperDesc",  Tuple.Create("Set Thread.CurrentPrincipal with user-supplied role.", "Fixe Thread.CurrentPrincipal avec un rôle fourni.") },
            { "RoleTamperButton", Tuple.Create("Set Role", "Définir le rôle") },

            { "AuthnOnlyLabel", Tuple.Create("AuthN-as-AuthZ", "Confusion AuthN/AuthZ") },
            { "AuthnOnlyDesc",  Tuple.Create("Treat any authenticated identity as admin.", "Traiter tout utilisateur authentifié comme admin.") },
            { "AuthnOnlyButton", Tuple.Create("Check Admin (AuthN)", "Vérifier Admin (AuthN)") },

            { "TenantLabel", Tuple.Create("Tenant Isolation Bypass", "Contournement d’isolement de tenant") },
            { "TenantDesc",  Tuple.Create("Read another tenant's resource with tenantId/resource.", "Lecture d’une ressource d’un autre tenant via tenantId/ressource.") },
            { "TenantButton", Tuple.Create("Read Tenant Resource", "Lire ressource tenant") },

            { "ConfigFlagLabel", Tuple.Create("Config Flag Override", "Drapeau de config non fiable") },
            { "ConfigFlagDesc",  Tuple.Create("Local 'isAdmin=true' grants admin.", "Un 'isAdmin=true' local octroie admin.") },
            { "ConfigFlagButton", Tuple.Create("Apply Config", "Appliquer config") },

            { "CasePathLabel", Tuple.Create("Path Prefix Policy Bypass", "Contournement de politique par préfixe") },
            { "CasePathDesc",  Tuple.Create("StartsWith on case-insensitive FS allows sibling paths.", "StartsWith sur FS insensible à la casse autorise des chemins voisins.") },
            { "CasePathButton", Tuple.Create("Operate Path", "Opérer sur chemin") },
        };

        public DA05AccessControlWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage(_lang);
            SetPlaceholders();
        }

        private void LanguageSelector_Changed(object sender, SelectionChangedEventArgs e)
        {
            _lang = (LanguageSelector.SelectedIndex == 1) ? "fr" : "en";
            SetLanguage(_lang);
        }

        private string GetLabel(string key, string lang) => (lang == "fr") ? labels[key].Item2 : labels[key].Item1;

        private void SetLanguage(string lang)
        {
            Title = GetLabel("Title", lang);
            TitleText.Text = GetLabel("Title", lang);
            IntroText.Text = GetLabel("Intro", lang);

            // Existing 1..10
            BolaLabel.Text = GetLabel("HttpLabel", lang);
            BolaDesc.Text = GetLabel("HttpDesc", lang);

            FuncAuthLabel.Text = GetLabel("TcpLabel", lang);
            FuncAuthDesc.Text = GetLabel("TcpDesc", lang);

            PrivilegeEscalationLabel.Text = GetLabel("UdpLabel", lang);
            PrivilegeEscalationDesc.Text = GetLabel("UdpDesc", lang);

            HorizontalEscalationLabel.Text = GetLabel("WebSocketLabel", lang);
            HorizontalEscalationDesc.Text = GetLabel("WebSocketDesc", lang);

            ForcedBrowsingLabel.Text = GetLabel("PipeLabel", lang);
            ForcedBrowsingDesc.Text = GetLabel("PipeDesc", lang);

            AuthBypassLabel.Text = GetLabel("FileDropLabel", lang);
            AuthBypassDesc.Text = GetLabel("FileDropDesc", lang);

            AdminFuncLabel.Text = GetLabel("CmdLabel", lang);
            AdminFuncDesc.Text = GetLabel("CmdDesc", lang);

            EventHandlerLabel.Text = GetLabel("DllLabel", lang);
            EventHandlerDesc.Text = GetLabel("DllDesc", lang);

            ObscurityLabel.Text = GetLabel("ClipboardLabel", lang);
            ObscurityDesc.Text = GetLabel("ClipboardDesc", lang);

            RoleConfusionLabel.Text = GetLabel("MailLabel", lang);
            RoleConfusionDesc.Text = GetLabel("MailDesc", lang);

            BolaTestButton.Content = GetLabel("HttpButton", lang);
            FuncAuthTestButton.Content = GetLabel("TcpButton", lang);
            PrivilegeEscalationTestButton.Content = GetLabel("UdpButton", lang);
            HorizontalEscalationTestButton.Content = GetLabel("WebSocketButton", lang);
            ForcedBrowsingTestButton.Content = GetLabel("PipeButton", lang);
            AuthBypassTestButton.Content = GetLabel("FileDropButton", lang);
            AdminFuncTestButton.Content = GetLabel("CmdButton", lang);
            EventHandlerTestButton.Content = GetLabel("DllButton", lang);
            ClipboardTestButton.Content = GetLabel("ClipboardButton", lang);
            RoleConfusionTestButton.Content = GetLabel("MailButton", lang);

            // New 11..15
            RoleTamperLabel.Text = GetLabel("RoleTamperLabel", lang);
            RoleTamperDesc.Text = GetLabel("RoleTamperDesc", lang);
            RoleTamperTestButton.Content = GetLabel("RoleTamperButton", lang);

            AuthnOnlyLabel.Text = GetLabel("AuthnOnlyLabel", lang);
            AuthnOnlyDesc.Text = GetLabel("AuthnOnlyDesc", lang);
            AuthnOnlyTestButton.Content = GetLabel("AuthnOnlyButton", lang);

            TenantLabel.Text = GetLabel("TenantLabel", lang);
            TenantDesc.Text = GetLabel("TenantDesc", lang);
            TenantTestButton.Content = GetLabel("TenantButton", lang);

            ConfigFlagLabel.Text = GetLabel("ConfigFlagLabel", lang);
            ConfigFlagDesc.Text = GetLabel("ConfigFlagDesc", lang);
            ConfigFlagTestButton.Content = GetLabel("ConfigFlagButton", lang);

            CasePathLabel.Text = GetLabel("CasePathLabel", lang);
            CasePathDesc.Text = GetLabel("CasePathDesc", lang);
            CasePathTestButton.Content = GetLabel("CasePathButton", lang);
        }

        private void SetPlaceholders()
        {
            TrySet("BolaObjectIdInput", @"C:\Users\Alice\private.txt");
            TrySet("FuncAuthInput", "Alice");
            TrySet("PrivilegeEscalationInput", "calc.exe");
            TrySet("HorizontalEscalationInput", "Bob");
            TrySet("ForcedInput", "HiddenAdmin");
            TrySet("AuthBypassInput", "DangerDeleteAll");
            TrySet("AdminFuncInput", "DangerDeleteAll");
            TrySet("ObscurityInput", "opensecret");
            TrySet("RoleConfusionInput", "manager,admin");

            // New
            TrySet("RoleTamperInput", "Admin");
            TrySet("TenantIdInput", "tenantB");
            TrySet("TenantResourceInput", "invoices");
            TrySet("ConfigFlagPathInput", @"C:\PublicShare\app.cfg");
            TrySet("CasePathInput", @"C:\Secure\AdminBackup\notes.txt");
        }

        private void TrySet(string name, string value)
        {
            var tb = FindName(name) as TextBox;
            if (tb != null) tb.Text = value;
        }

        // ===================== Handlers =====================

        private void BolaTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.BrokenObjectLevelAuthorization(BolaObjectIdInput.Text);

        private void FuncAuthTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.InsecureDirectObjectReference(FuncAuthInput.Text);

        private void PrivilegeEscalationTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.VerticalPrivilegeEscalation(PrivilegeEscalationInput.Text);

        private void HorizontalEscalationTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.HorizontalPrivilegeEscalation(HorizontalEscalationInput.Text);

        private void ForcedBrowsingTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.ForcedBrowsing(ForcedInput.Text);

        private void AuthBypassTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.MissingFunctionLevelAccessControl(AuthBypassInput.Text);

        private void AdminFuncTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.MissingFunctionLevelAccessControl(AdminFuncInput.Text);

        private void EventHandlerTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.UnprotectedEventHandler();

        private void ClipboardTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.SecurityThroughObscurity(ObscurityInput.Text);

        private void RoleConfusionTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.RoleConfusion(RoleConfusionInput.Text);

        // New 11..15
        private void RoleTamperTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.RoleTampering(RoleTamperInput.Text);

        private void AuthnOnlyTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.AuthenticatedIsAdmin();

        private void TenantTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.MultiTenantBypass(TenantIdInput.Text, TenantResourceInput.Text);

        private void ConfigFlagTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.ConfigFlagOverride(ConfigFlagPathInput.Text);

        private void CasePathTestButton_Click(object sender, RoutedEventArgs e)
            => AccessControlVuln.CaseInsensitivePathPolicy(CasePathInput.Text);
    }
}
