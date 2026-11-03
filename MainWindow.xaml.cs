using System.IO;
using System.Windows;
using Microsoft.Win32;

namespace FolderLock;

public partial class MainWindow : Window
{
    public MainWindow() { InitializeComponent(); RefreshHidden(); }

    void BrowseFolder_Click(object s, RoutedEventArgs e)
    {
        var d = new OpenFolderDialog();
        if (d.ShowDialog() == true) FolderBox.Text = d.FolderName;
    }

    void BrowseVault_Click(object s, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Filter = "FolderLock vault (*.flock)|*.flock" };
        if (d.ShowDialog() == true) VaultBox.Text = d.FileName;
    }

    void SetBusy(bool b)
    {
        Busy.Visibility = b ? Visibility.Visible : Visibility.Hidden;
        LockBtn.IsEnabled = UnlockBtn.IsEnabled = !b;
    }

    void Log(string m) => Dispatcher.Invoke(() => Status.Text = m);

    async void Lock_Click(object s, RoutedEventArgs e)
    {
        var folder = FolderBox.Text.Trim().TrimEnd('\\');
        var pw = LockPw.Password;
        if (!Directory.Exists(folder)) { Log("Choose a valid folder."); return; }
        if (pw.Length < 10) { Log("Password must be at least 10 characters."); return; }
        if (pw != LockPw2.Password) { Log("Passwords do not match."); return; }
        var vault = folder + ".flock";

        var ok = MessageBox.Show($"This encrypts '{folder}' into '{vault}' and then DELETES the original folder.\n\n" +
            "If you forget the password, your data cannot be recovered. Continue?",
            "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (ok != MessageBoxResult.Yes) return;

        SetBusy(true);
        try
        {
            await Task.Run(() => Vault.Lock(folder, vault, pw, Log));
            LockPw.Clear(); LockPw2.Clear(); FolderBox.Clear();
            if (HideAfterLock.IsChecked == true) { Hider.Hide(vault); RefreshHidden(); Log("Locked and vault hidden: " + vault); }
        }
        catch (Exception ex) { Log("Failed: " + ex.Message + " (original folder untouched)"); }
        finally { SetBusy(false); }
    }

    async void Unlock_Click(object s, RoutedEventArgs e)
    {
        var vault = VaultBox.Text.Trim();
        if (!File.Exists(vault)) { Log("Choose a valid vault file."); return; }
        var dest = Path.Combine(Path.GetDirectoryName(vault)!, Path.GetFileNameWithoutExtension(vault));
        if (Directory.Exists(dest)) { Log("Folder already exists: " + dest); return; }
        var pw = UnlockPw.Password;
        bool del = DeleteVault.IsChecked == true;

        SetBusy(true);
        try
        {
            await Task.Run(() =>
            {
                try { Vault.Extract(vault, pw, dest, Log); }
                catch { if (Directory.Exists(dest)) Directory.Delete(dest, true); throw; }
                if (del) { File.Delete(vault); Hider.Unhide(vault); }
            });
            UnlockPw.Clear(); RefreshHidden();
            Log("Unlocked to " + dest);
        }
        catch (Exception ex) { Log("Failed: " + ex.Message); }
        finally { SetBusy(false); }
    }

    // ---------- Hide / Unhide ----------
    void RefreshHidden() => HiddenList.ItemsSource = Hider.Load();

    void HideBrowseFolder_Click(object s, RoutedEventArgs e)
    {
        var d = new OpenFolderDialog();
        if (d.ShowDialog() == true) HideBox.Text = d.FolderName;
    }

    void HideBrowseFile_Click(object s, RoutedEventArgs e)
    {
        var d = new OpenFileDialog();
        if (d.ShowDialog() == true) HideBox.Text = d.FileName;
    }

    void Hide_Click(object s, RoutedEventArgs e)
    {
        try { Hider.Hide(HideBox.Text.Trim()); HideBox.Clear(); RefreshHidden(); Log("Hidden."); }
        catch (Exception ex) { Log("Failed: " + ex.Message); }
    }

    void Unhide_Click(object s, RoutedEventArgs e)
    {
        if (HiddenList.SelectedItem is not string p) { Log("Select an item to unhide."); return; }
        try { Hider.Unhide(p); RefreshHidden(); Log("Unhidden: " + p); }
        catch (Exception ex) { Log("Failed: " + ex.Message); }
    }
}
