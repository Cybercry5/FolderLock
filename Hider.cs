namespace FolderLock;

/// Hides files/folders using the Hidden + System attributes and remembers them
/// in %AppData%\FolderLock\hidden.txt so they can be found and unhidden later.
public static class Hider
{
    static readonly string Dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FolderLock");
    static readonly string StorePath = Path.Combine(Dir, "hidden.txt");
    const FileAttributes HS = FileAttributes.Hidden | FileAttributes.System;

    public static List<string> Load()
    {
        try { return File.Exists(StorePath) ? File.ReadAllLines(StorePath).Where(l => l.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList() : new(); }
        catch { return new(); }
    }

    static void Save(IEnumerable<string> items)
    {
        Directory.CreateDirectory(Dir);
        File.WriteAllLines(StorePath, items);
    }

    static string Norm(string p) => Path.GetFullPath(p).TrimEnd('\\');

    public static void Hide(string path)
    {
        path = Norm(path);
        if (!File.Exists(path) && !Directory.Exists(path)) throw new FileNotFoundException("Path not found.", path);
        File.SetAttributes(path, File.GetAttributes(path) | HS);
        var list = Load();
        if (!list.Contains(path, StringComparer.OrdinalIgnoreCase)) list.Add(path);
        Save(list);
    }

    public static void Unhide(string path)
    {
        path = Norm(path);
        if (File.Exists(path) || Directory.Exists(path))
        {
            var a = File.GetAttributes(path) & ~HS;
            File.SetAttributes(path, a == 0 ? FileAttributes.Normal : a);
        }
        Save(Load().Where(p => !p.Equals(path, StringComparison.OrdinalIgnoreCase)));
    }
}
