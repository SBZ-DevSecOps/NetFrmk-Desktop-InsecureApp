using System.Security.Principal;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            MessageBox.Show(IsAdmin().ToString(),"Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        bool IsAdmin()
        {
            var wp = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            return wp.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private void BtnDA01_Click(object sender, RoutedEventArgs e)
            => new DA01InjectionsWindow().Show();

        private void BtnDA02_Click(object sender, RoutedEventArgs e)
            => new DA02AuthWindow().Show();

        private void BtnDA03_Click(object sender, RoutedEventArgs e)
            => new DA03DataExposureWindow().Show();

        private void BtnDA04_Click(object sender, RoutedEventArgs e)
            => new DA04CommWindow().Show();

        private void BtnDA05_Click(object sender, RoutedEventArgs e)
            => new DA05AccessControlWindow().Show();

        private void BtnDA06_Click(object sender, RoutedEventArgs e)
            => new DA06ResourceWindow().Show();

        private void BtnDA07_Click(object sender, RoutedEventArgs e)
            => new DA07UnsafeApiWindow().Show();

        private void BtnDA08_Click(object sender, RoutedEventArgs e)
            => new DA08MisconfigWindow().Show();

        private void BtnDA09_Click(object sender, RoutedEventArgs e)
            => new DA09ErrorHandlingWindow().Show();

        private void BtnDA10_Click(object sender, RoutedEventArgs e)
            => new DA10LoggingWindow().Show();
    }
}
