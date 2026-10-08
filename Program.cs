using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

internal record Entry(string Path, string Hash, long Size);
internal record Snapshot(int Format, string Id, DateTime CreatedUtc, List<Entry> Files, int SkippedLinks);
internal static class Program
{
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    static string store = "";
    static string Objects => System.IO.Path.Combine(store, "objects");
    static string Manifests => System.IO.Path.Combine(store, "snapshots");
    static void Print(object value) => Console.WriteLine(JsonSerializer.Serialize(value, Json));
    static bool Inside(string path, string parent)
    {
        var rel = System.IO.Path.GetRelativePath(parent, path);
        return rel == "." || (!System.IO.Path.IsPathRooted(rel) && rel != ".." && !rel.StartsWith(".." + System.IO.Path.DirectorySeparatorChar));
    }
    static void NoLinks(string path)
    {
        for (DirectoryInfo? d = new(System.IO.Path.GetFullPath(path)); d != null; d = d.Parent)
            if (d.Exists && d.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new IOException("Symbolic link in destination path");
    }
    static Snapshot Load(string id)
    {
        if (!Regex.IsMatch(id, @"^[0-9]{8}T[0-9]{9}Z-[a-f0-9]{8}$")) throw new ArgumentException("Invalid snapshot id");
        var snap = JsonSerializer.Deserialize<Snapshot>(File.ReadAllText(System.IO.Path.Combine(Manifests, id + ".json"))) ?? throw new IOException("Empty manifest");
        if (snap.Format != 1 || snap.Id != id || snap.Files == null) throw new IOException("Unsupported manifest");
        var paths = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var entry in snap.Files)
        {
            if (string.IsNullOrEmpty(entry.Path) || entry.Path.Contains('\\') || entry.Path.Contains(':') || entry.Path.StartsWith('/') || entry.Path.Split('/').Any(p => p is "" or "." or "..") || !paths.Add(entry.Path)) throw new IOException("Unsafe or duplicate manifest path");
            if (entry.Hash == null || entry.Hash.Length != 64 || !Regex.IsMatch(entry.Hash, "^[a-f0-9]{64}$") || entry.Size < 0) throw new IOException("Invalid object metadata");
        }
        return snap;
    }
    static string ObjectPath(string hash) => System.IO.Path.Combine(Objects, hash + ".blob");
    static async Task VerifyObject(Entry entry)
    {
        string path = ObjectPath(entry.Hash);
        if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint)) throw new IOException("Symbolic link object");
        using var file = File.OpenRead(path);
        if (file.Length != entry.Size) throw new IOException("Size mismatch: " + entry.Path);
        string hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(file));
        if (hash != entry.Hash) throw new IOException("Hash mismatch: " + entry.Path);
    }
    static async Task Verify(Snapshot snap)
    {
        foreach (var group in snap.Files.GroupBy(e => e.Hash))
        {
            if (group.Any(e => e.Size != group.First().Size)) throw new IOException("Inconsistent object sizes");
            await VerifyObject(group.First());
        }
    }
    static IEnumerable<string> Walk(string dir, Action skip)
    {
        foreach (string path in Directory.EnumerateFileSystemEntries(dir))
        {
            var attributes = File.GetAttributes(path);
            if (attributes.HasFlag(FileAttributes.ReparsePoint)) { skip(); continue; }
            if (attributes.HasFlag(FileAttributes.Directory)) { foreach (var child in Walk(path, skip)) yield return child; }
            else yield return path;
        }
    }
    static async Task Take(string source, int workers)
    {
        source = System.IO.Path.GetFullPath(source);
        if (!Directory.Exists(source)) throw new DirectoryNotFoundException(source);
        NoLinks(source); NoLinks(store); NoLinks(Objects); NoLinks(Manifests);
        if (Inside(store, source) || Inside(source, store)) throw new ArgumentException("Source and store must not contain each other");
        Directory.CreateDirectory(Objects); Directory.CreateDirectory(Manifests);
        using var gate = new FileStream(System.IO.Path.Combine(store, ".lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        int skipped = 0; var files = Walk(source, () => skipped++).ToList();
        var entries = new ConcurrentBag<Entry>();
        await Parallel.ForEachAsync(files, new ParallelOptions { MaxDegreeOfParallelism = workers }, async (path, cancel) =>
        {
            string temp = System.IO.Path.Combine(Objects, Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                var before = new FileInfo(path); long size = before.Length; var stamp = before.LastWriteTimeUtc;
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                await using (var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, true))
                await using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, true))
                {
                    byte[] buffer = new byte[65536]; int n; long copied = 0;
                    while ((n = await input.ReadAsync(buffer, cancel)) > 0) { hash.AppendData(buffer, 0, n); await output.WriteAsync(buffer.AsMemory(0, n), cancel); copied += n; }
                    await output.FlushAsync(cancel);
                    if (copied != size) throw new IOException("File changed: " + path);
                }
                var after = new FileInfo(path);
                if (after.Length != size || after.LastWriteTimeUtc != stamp) throw new IOException("File changed: " + path);
                string digest = Convert.ToHexStringLower(hash.GetHashAndReset());
                string relative = System.IO.Path.GetRelativePath(source, path).Replace(System.IO.Path.DirectorySeparatorChar, '/');
                if (relative.Contains('\\') || relative.Contains(':')) throw new IOException("Unsupported filename: " + relative);
                var entry = new Entry(relative, digest, size);
                try { File.Move(temp, ObjectPath(digest)); }
                catch (IOException) when (File.Exists(ObjectPath(digest))) { await VerifyObject(entry); File.Delete(temp); }
                entries.Add(entry);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        });
        string id = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmssfff'Z'") + "-" + Guid.NewGuid().ToString("N")[..8];
        var snap = new Snapshot(1, id, DateTime.UtcNow, entries.OrderBy(e => e.Path, StringComparer.Ordinal).ToList(), skipped);
        string manifest = System.IO.Path.Combine(Manifests, id + ".json"); string staging = manifest + ".tmp";
        await File.WriteAllTextAsync(staging, JsonSerializer.Serialize(snap, Json)); File.Move(staging, manifest);
        Print(new { id, files = snap.Files.Count, bytes = snap.Files.Sum(e => e.Size), skippedLinks = skipped });
    }
    static async Task Restore(Snapshot snap, string target, bool apply)
    {
        target = System.IO.Path.GetFullPath(target); NoLinks(target); NoLinks(store); NoLinks(Objects); NoLinks(Manifests);
        if (Inside(target, store) || Inside(store, target)) throw new ArgumentException("Destination and store must not contain each other");
        if (File.Exists(target) || (Directory.Exists(target) && Directory.EnumerateFileSystemEntries(target).Any())) throw new IOException("Destination must be absent or empty");
        await Verify(snap);
        if (apply)
        {
            Directory.CreateDirectory(target);
            foreach (var entry in snap.Files)
            {
                string path = System.IO.Path.GetFullPath(System.IO.Path.Combine(target, entry.Path.Replace('/', System.IO.Path.DirectorySeparatorChar)));
                if (!Inside(path, target)) throw new IOException("Unsafe destination");
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!); NoLinks(System.IO.Path.GetDirectoryName(path)!);
                // Recheck each object after preflight. Never overwrite a destination file.
                await VerifyObject(entry);
                using var input = File.OpenRead(ObjectPath(entry.Hash)); using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                await input.CopyToAsync(output);
            }
        }
        Print(new { snapshot = snap.Id, target, apply, files = snap.Files.Count, bytes = snap.Files.Sum(e => e.Size) });
    }
    public static async Task<int> Main(string[] raw)
    {
        try
        {
            var args = raw.ToList(); store = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".vaulttrail");
            int si = args.IndexOf("--store"); if (si >= 0) { if (si + 1 >= args.Count) throw new ArgumentException("Missing store"); store = args[si + 1]; args.RemoveRange(si, 2); }
            store = System.IO.Path.GetFullPath(store);
            if (args.Count == 0) { Console.WriteLine("VaultTrail [--store DIR] snapshot|list|diff|verify|restore ..."); return 0; }
            switch (args[0])
            {
                case "snapshot":
                    int workers = 4;
                    if (args.Count == 4 && args[2] == "--workers") workers = int.Parse(args[3]);
                    else if (args.Count != 2) throw new ArgumentException("snapshot SOURCE [--workers 1..16]");
                    if (workers < 1 || workers > 16) throw new ArgumentException("Workers must be 1..16");
                    await Take(args[1], workers); break;
                case "list":
                    if (args.Count != 1) throw new ArgumentException("list takes no arguments");
                    Print(Directory.Exists(Manifests) ? Directory.GetFiles(Manifests, "*.json").Order().Select(p => Load(System.IO.Path.GetFileNameWithoutExtension(p))).Select(s => new { s.Id, s.CreatedUtc, files = s.Files.Count, bytes = s.Files.Sum(e => e.Size) }).ToArray() : []); break;
                case "verify":
                    if (args.Count != 2) throw new ArgumentException("verify SNAPSHOT_ID");
                    var verified = Load(args[1]); NoLinks(store); NoLinks(Objects); NoLinks(Manifests); await Verify(verified); Print(new { id = verified.Id, ok = true, files = verified.Files.Count }); break;
                case "diff":
                    if (args.Count != 3) throw new ArgumentException("diff SNAPSHOT_A SNAPSHOT_B");
                    var a = Load(args[1]).Files.ToDictionary(e => e.Path); var b = Load(args[2]).Files.ToDictionary(e => e.Path);
                    Print(new { added = b.Keys.Except(a.Keys).Order().ToArray(), removed = a.Keys.Except(b.Keys).Order().ToArray(), changed = a.Keys.Intersect(b.Keys).Where(p => a[p].Hash != b[p].Hash).Order().ToArray() }); break;
                case "restore":
                    if (args.Count != 3 && !(args.Count == 4 && args[3] == "--apply")) throw new ArgumentException("restore SNAPSHOT_ID DESTINATION [--apply]");
                    await Restore(Load(args[1]), args[2], args.Count == 4); break;
                default: throw new ArgumentException("Unknown command");
            }
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e.Message); return 1; }
    }
}
