using NetFrmk_Desktop_InsecureApp.Vulnerabilities;
using System;
using System.Collections.Generic;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp
{
    public partial class DA05AccessControlWindow : Window
    {
        private readonly Dictionary<string, Tuple<string, string>> labels = new Dictionary<string, Tuple<string, string>>
        {
            { "Title", Tuple.Create("DA05 – Insufficient Authorization / Access Control", "DA05 – Autorisation insuffisante / Contrôle d'accès") },
            { "Intro", Tuple.Create("This module demonstrates common authorization weaknesses in desktop apps.", "Ce module démontre les failles courantes d'autorisation dans les applications desktop.") },

            { "HttpLabel", Tuple.Create("Broken Object Level Authorization (BOLA)", "Broken Object Level Authorization (BOLA)") },
            { "HttpDesc", Tuple.Create("Access unauthorized user data by manipulating object IDs.", "Accès non autorisé à des données utilisateurs en manipulant les IDs.") },

            { "TcpLabel", Tuple.Create("Broken Function Level Authorization", "Contrôle fonctionnel insuffisant") },
            { "TcpDesc", Tuple.Create("Invoke protected functions without authorization.", "Appeler des fonctions protégées sans autorisation.") },

            { "UdpLabel", Tuple.Create("Privilege Escalation - Vertical", "Escalade de privilèges - verticale") },
            { "UdpDesc", Tuple.Create("Gain admin privileges by exploiting flawed role checks.", "Obtention illégitime de privilèges admin.") },

            { "WebSocketLabel", Tuple.Create("Privilege Escalation - Horizontal", "Escalade de privilèges - horizontale") },
            { "WebSocketDesc", Tuple.Create("Access other users' data with the same role.", "Accès aux données d'autres utilisateurs du même rôle.") },

            { "PipeLabel", Tuple.Create("Forced Browsing / URL Tampering", "Navigation forcée / manipulation d'URL") },
            { "PipeDesc", Tuple.Create("Access restricted resources by guessing URLs or paths.", "Accès à des ressources restreintes par devinette d'URL ou chemin.") },

            { "FileDropLabel", Tuple.Create("Authorization Bypass via Parameter/State Manipulation", "Contournement d'autorisation par manipulation de paramètres ou état.") },
            { "FileDropDesc", Tuple.Create("Bypass auth by tampering with session parameters or cookies.", "Contournement par manipulation de paramètres ou cookies.") },

            { "CmdLabel", Tuple.Create("Unprotected Admin or Sensitive Functionality", "Fonctions admin non protégées") },
            { "CmdDesc", Tuple.Create("Admin functions accessible without proper authentication.", "Fonctions admin accessibles sans authentification.") },

            { "DllLabel", Tuple.Create("Missing Authorization on Event Handlers or IPC", "Autorisation manquante sur gestionnaires d'événements ou IPC") },
            { "DllDesc", Tuple.Create("Events or IPC calls executed without checking permissions.", "Evènements ou appels IPC sans vérification des permissions.") },

            { "ClipboardLabel", Tuple.Create("Access Control via Security Through Obscurity", "Contrôle d'accès par obscurcissement") },
            { "ClipboardDesc", Tuple.Create("Authorization based on secret or hidden object names.", "Autorisation basée sur des noms d'objets cachés ou secrets.") },

            { "MailLabel", Tuple.Create("Role Confusion or Misconfiguration", "Confusion ou mauvaise configuration des rôles") },
            { "MailDesc", Tuple.Create("Incorrect role assignments leading to excessive privileges.", "Attribution incorrecte des rôles avec privilèges excessifs.") },

            // Buttons
            { "HttpButton", Tuple.Create("Test BOLA", "Tester BOLA") },
            { "TcpButton", Tuple.Create("Test Function Auth", "Tester contrôle fonctionnel") },
            { "UdpButton", Tuple.Create("Test Privilege Escalation", "Tester escalade privilèges") },
            { "WebSocketButton", Tuple.Create("Test Horizontal Escalation", "Tester escalade horizontale") },
            { "PipeButton", Tuple.Create("Test Forced Browsing", "Tester navigation forcée") },
            { "FileDropButton", Tuple.Create("Test Auth Bypass", "Tester contournement auth") },
            { "CmdButton", Tuple.Create("Test Admin Access", "Tester accès admin") },
            { "DllButton", Tuple.Create("Test Event Auth", "Tester gestion événements") },
            { "ClipboardButton", Tuple.Create("Test Obscurity", "Tester obscurcissement") },
            { "MailButton", Tuple.Create("Test Role Confusion", "Tester confusion rôles") },
        };

        private string _lang = "en";
        public DA05AccessControlWindow()
        {
            InitializeComponent();
            LanguageSelector.SelectedIndex = 0;
            SetLanguage(_lang);
        }

        private void LanguageSelector_Changed(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            // Attention : ComboBox.SelectedIndex == 0 => EN, == 1 => FR
            if (LanguageSelector.SelectedIndex == 1) _lang = "fr";
            else _lang = "en";
            SetLanguage(_lang);
        }

        private string GetLabel(string key, string lang)
        {
            return lang == "fr" ? labels[key].Item2 : labels[key].Item1;
        }

        private void SetLanguage(string lang)
        {
            _lang = lang;
            Title = GetLabel("Title", lang);
            TitleText.Text = GetLabel("Title",lang);
            IntroText.Text = GetLabel("Intro",lang);

            BolaLabel.Text = GetLabel("HttpLabel",lang);
            BolaDesc.Text = GetLabel("HttpDesc",lang);

            FuncAuthLabel.Text = GetLabel("TcpLabel",lang);
            FuncAuthDesc.Text = GetLabel("TcpDesc",lang);

            PrivilegeEscalationLabel.Text = GetLabel("UdpLabel",lang);
            PrivilegeEscalationDesc.Text = GetLabel("UdpDesc",lang);

            HorizontalEscalationLabel.Text = GetLabel("WebSocketLabel",lang);
            HorizontalEscalationDesc.Text = GetLabel("WebSocketDesc",lang);

            ForcedBrowsingLabel.Text = GetLabel("PipeLabel",lang);
            ForcedBrowsingDesc.Text = GetLabel("PipeDesc",lang);

            AuthBypassLabel.Text = GetLabel("FileDropLabel",lang);
            AuthBypassDesc.Text = GetLabel("FileDropDesc",lang);

            AdminFuncLabel.Text = GetLabel("CmdLabel",lang);
            AdminFuncDesc.Text = GetLabel("CmdDesc",lang);

            EventHandlerLabel.Text = GetLabel("DllLabel",lang);
            EventHandlerDesc.Text = GetLabel("DllDesc",lang);

            ObscurityLabel.Text = GetLabel("ClipboardLabel",lang);
            ObscurityDesc.Text = GetLabel("ClipboardDesc",lang);

            RoleConfusionLabel.Text = GetLabel("MailLabel",lang);
            RoleConfusionDesc.Text = GetLabel("MailDesc",lang);

            BolaTestButton.Content = GetLabel("HttpButton",lang);
            FuncAuthTestButton.Content = GetLabel("TcpButton",lang);
            PrivilegeEscalationTestButton.Content = GetLabel("UdpButton",lang);
            HorizontalEscalationTestButton.Content = GetLabel("WebSocketButton",lang);
            ForcedBrowsingTestButton.Content = GetLabel("PipeButton",lang);
            AuthBypassTestButton.Content = GetLabel("FileDropButton",lang);
            AdminFuncTestButton.Content = GetLabel("CmdButton",lang);
            EventHandlerTestButton.Content = GetLabel("DllButton",lang);
            ClipboardTestButton.Content = GetLabel("ClipboardButton",lang);
            RoleConfusionTestButton.Content = GetLabel("MailButton",lang);
        }

        // Handlers : tous les noms sont alignés avec le code vulnérable
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
    }
}
