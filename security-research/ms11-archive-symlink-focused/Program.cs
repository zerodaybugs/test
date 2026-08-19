using System.Formats.Tar;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

record Row(string Format, string Case, int Repetition, bool Compressed, bool Completed,
    string? ExceptionType, bool OutsideWrite, string? OutsideContent, bool ControlOk);

static class Program
{
    const int Repetitions = 20;

    public static int Main(string[] args)
    {
        var label = args.ElementAtOrDefault(0) ?? "local";
        var output = Path.GetFullPath(args.ElementAtOrDefault(1) ?? "RESULT.json");
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var root = Path.Combine(Path.GetTempPath(), "ms11-tar-symlink-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var rows = new List<Row>();
        try
        {
            foreach (var format in new[] { TarEntryFormat.Pax, TarEntryFormat.Gnu, TarEntryFormat.Ustar })
            {
                foreach (var compressed in new[] { false, true })
                {
                    for (var i = 1; i <= Repetitions; i++)
                    {
                        rows.Add(Run(root, format, "relative-directory-symlink", i, compressed));
                        rows.Add(Run(root, format, "absolute-directory-symlink", i, compressed));
                        rows.Add(Run(root, format, "relative-file-symlink-overwrite", i, compressed));
                        rows.Add(Run(root, format, "relative-symlink-chain", i, compressed));
                        rows.Add(Run(root, format, "relative-hardlink", i, compressed));
                        rows.Add(Run(root, format, "inside-directory-symlink-control", i, compressed));
                        rows.Add(Run(root, format, "regular-control", i, compressed));
                    }
                }
            }

            var attackRows = rows.Where(r => !r.Case.EndsWith("control", StringComparison.Ordinal)).ToArray();
            var controlRows = rows.Where(r => r.Case.EndsWith("control", StringComparison.Ordinal)).ToArray();
            var positiveGroups = attackRows.GroupBy(r => new { r.Format, r.Case, r.Compressed })
                .Select(g => new
                {
                    g.Key.Format,
                    g.Key.Case,
                    g.Key.Compressed,
                    outsideWrites = g.Count(r => r.OutsideWrite),
                    total = g.Count(),
                    deterministic = g.All(r => r.OutsideWrite),
                }).Where(g => g.outsideWrites > 0).ToArray();
            var controlsPass = controlRows.All(r => r.ControlOk && !r.OutsideWrite);
            var deterministicCandidate = positiveGroups.Any(g => g.deterministic) && controlsPass;
            var assembly = typeof(TarFile).Assembly;
            var location = assembly.Location;
            var result = new
            {
                schema = "ms11_tar_archive_controlled_symlink_escape/v2",
                generatedUtc = DateTimeOffset.UtcNow,
                label,
                framework = RuntimeInformation.FrameworkDescription,
                runtimeIdentifier = RuntimeInformation.RuntimeIdentifier,
                os = RuntimeInformation.OSDescription,
                assembly = new
                {
                    name = assembly.GetName().Name,
                    version = assembly.GetName().Version?.ToString(),
                    informationalVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
                    sha256 = File.Exists(location) ? Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(location))).ToLowerInvariant() : null,
                },
                repetitions = Repetitions,
                rows,
                positiveGroups,
                controlsPass,
                deterministicCandidate,
                verdict = deterministicCandidate
                    ? "DIRECT_ARCHIVE_CONTROLLED_OUTSIDE_WRITE_CANDIDATE"
                    : controlsPass ? "NO_DIRECT_ARCHIVE_CONTROLLED_OUTSIDE_WRITE" : "CONTROL_FAILURE",
                submissionReady = false,
            };
            File.WriteAllText(output, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"VERDICT={result.verdict}");
            Console.WriteLine($"POSITIVE_GROUPS={positiveGroups.Length}");
            Console.WriteLine($"CONTROLS_PASS={controlsPass}");
            return 0;
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    static Row Run(string root, TarEntryFormat format, string caseName, int repetition, bool compressed)
    {
        var caseRoot = Path.Combine(root, $"{format}-{caseName}-{compressed}-{repetition}-{Guid.NewGuid():N}");
        var dest = Path.Combine(caseRoot, "dest");
        var outsideDir = Path.Combine(caseRoot, "outside");
        var outsideFile = Path.Combine(outsideDir, "pwn.txt");
        Directory.CreateDirectory(dest);
        Directory.CreateDirectory(outsideDir);
        var tarPath = Path.Combine(caseRoot, compressed ? "payload.tar.gz" : "payload.tar");
        Directory.CreateDirectory(caseRoot);

        try
        {
            using var fs = File.Create(tarPath);
            using Stream target = compressed ? new GZipStream(fs, CompressionLevel.NoCompression, leaveOpen: false) : fs;
            using var writer = new TarWriter(target, format, leaveOpen: false);
            switch (caseName)
            {
                case "relative-directory-symlink":
                    writer.WriteEntry(Link(format, TarEntryType.SymbolicLink, "link", "../outside"));
                    writer.WriteEntry(Regular(format, "link/pwn.txt", "REL-DIR"));
                    break;
                case "absolute-directory-symlink":
                    writer.WriteEntry(Link(format, TarEntryType.SymbolicLink, "link", outsideDir));
                    writer.WriteEntry(Regular(format, "link/pwn.txt", "ABS-DIR"));
                    break;
                case "relative-file-symlink-overwrite":
                    writer.WriteEntry(Link(format, TarEntryType.SymbolicLink, "file.txt", "../outside/pwn.txt"));
                    writer.WriteEntry(Regular(format, "file.txt", "REL-FILE"));
                    break;
                case "relative-symlink-chain":
                    writer.WriteEntry(Link(format, TarEntryType.SymbolicLink, "a", "b"));
                    writer.WriteEntry(Link(format, TarEntryType.SymbolicLink, "b", "../outside"));
                    writer.WriteEntry(Regular(format, "a/pwn.txt", "CHAIN"));
                    break;
                case "relative-hardlink":
                    File.WriteAllText(outsideFile, "ORIGINAL");
                    writer.WriteEntry(Link(format, TarEntryType.HardLink, "hard", "../outside/pwn.txt"));
                    writer.WriteEntry(Regular(format, "hard", "HARD"));
                    break;
                case "inside-directory-symlink-control":
                    Directory.CreateDirectory(Path.Combine(dest, "inside"));
                    writer.WriteEntry(Link(format, TarEntryType.SymbolicLink, "link", "inside"));
                    writer.WriteEntry(Regular(format, "link/control.txt", "INSIDE-CONTROL"));
                    break;
                case "regular-control":
                    writer.WriteEntry(Regular(format, "safe/control.txt", "REGULAR-CONTROL"));
                    break;
                default:
                    throw new InvalidOperationException(caseName);
            }
        }
        catch (Exception ex)
        {
            return new(format.ToString(), caseName, repetition, compressed, false, ex.GetType().FullName,
                false, File.Exists(outsideFile) ? SafeRead(outsideFile) : null, false);
        }

        bool completed = false;
        Exception? error = null;
        try
        {
            TarFile.ExtractToDirectory(tarPath, dest, overwriteFiles: true);
            completed = true;
        }
        catch (Exception ex)
        {
            error = ex;
        }

        var outsideContent = File.Exists(outsideFile) ? SafeRead(outsideFile) : null;
        var outsideWrite = outsideContent is not null && outsideContent != "ORIGINAL";
        bool controlOk = caseName switch
        {
            "regular-control" => completed && File.ReadAllText(Path.Combine(dest, "safe", "control.txt")) == "REGULAR-CONTROL",
            "inside-directory-symlink-control" => completed && File.ReadAllText(Path.Combine(dest, "inside", "control.txt")) == "INSIDE-CONTROL",
            _ => true,
        };
        return new(format.ToString(), caseName, repetition, compressed, completed, error?.GetType().FullName,
            outsideWrite, outsideContent, controlOk);
    }

    static TarEntry Regular(TarEntryFormat format, string name, string value)
    {
        var entry = Create(format, TarEntryType.RegularFile, name);
        entry.DataStream = new MemoryStream(Encoding.UTF8.GetBytes(value), writable: false);
        return entry;
    }

    static TarEntry Link(TarEntryFormat format, TarEntryType type, string name, string target)
    {
        var entry = Create(format, type, name);
        entry.LinkName = target;
        return entry;
    }

    static TarEntry Create(TarEntryFormat format, TarEntryType type, string name) => format switch
    {
        TarEntryFormat.Pax => new PaxTarEntry(type, name),
        TarEntryFormat.Gnu => new GnuTarEntry(type, name),
        TarEntryFormat.Ustar => new UstarTarEntry(type, name),
        _ => throw new NotSupportedException(format.ToString()),
    };

    static string SafeRead(string path)
    {
        try { return File.ReadAllText(path); }
        catch (Exception ex) { return "<read-error:" + ex.GetType().Name + ">"; }
    }
}
