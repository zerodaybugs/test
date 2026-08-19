using System.Formats.Tar;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

record Row(
    string Family,
    string Name,
    bool OperationCompleted,
    string? ExceptionType,
    string? ExceptionMessage,
    bool OutsideCreated,
    string? OutsideContent,
    bool DestinationCreated,
    string? DestinationContent,
    bool ExpectedSafe,
    bool Passed);

static class Program
{
    public static int Main(string[] args)
    {
        var label = args.Length > 0 ? args[0] : "local";
        var output = args.Length > 1 ? Path.GetFullPath(args[1]) : Path.GetFullPath("RESULT.json");
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);

        var root = Path.Combine(Path.GetTempPath(), "ms11-archive-boundary-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var rows = new List<Row>();

        try
        {
            rows.Add(RunTarNormal(root));
            rows.Add(RunTarDotDot(root));
            rows.Add(RunTarAbsolute(root));
            rows.Add(RunTarBackslashDotDot(root));
            rows.Add(RunTarArchiveSymlinkDirectory(root));
            rows.Add(RunTarPreexistingSymlinkDirectory(root));
            rows.Add(RunTarPreexistingSymlinkFile(root));
            rows.Add(RunTarArchiveHardLink(root));

            rows.Add(RunZipNormal(root));
            rows.Add(RunZipDotDot(root));
            rows.Add(RunZipAbsolute(root));
            rows.Add(RunZipBackslashDotDot(root));
            rows.Add(RunZipPreexistingSymlinkDirectory(root));
            rows.Add(RunZipPreexistingSymlinkFile(root));

            var outsideWrites = rows.Where(r => r.ExpectedSafe && r.OutsideCreated).ToList();
            var controlPass = rows.Where(r => !r.ExpectedSafe).All(r => r.Passed);
            var safeRowsPass = rows.Where(r => r.ExpectedSafe).All(r => r.Passed);
            var result = new
            {
                schema = "ms11_archive_extraction_boundary/v2",
                generatedUtc = DateTimeOffset.UtcNow,
                label,
                framework = RuntimeInformation.FrameworkDescription,
                runtimeIdentifier = RuntimeInformation.RuntimeIdentifier,
                os = RuntimeInformation.OSDescription,
                processArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
                tarAssembly = AssemblyInfo(typeof(TarFile).Assembly),
                zipAssembly = AssemblyInfo(typeof(ZipFile).Assembly),
                rows,
                counts = new
                {
                    total = rows.Count,
                    passed = rows.Count(r => r.Passed),
                    failed = rows.Count(r => !r.Passed),
                    outsideWrites = outsideWrites.Count,
                },
                controlPass,
                safeRowsPass,
                rawCandidate = outsideWrites.Count > 0 && controlPass,
                candidateRows = outsideWrites.Select(r => r.Name).ToArray(),
                verdict = outsideWrites.Count > 0 && controlPass
                    ? "RAW_OUTSIDE_WRITE_CANDIDATE_REQUIRES_SCOPE_AND_DESIGN_REVIEW"
                    : safeRowsPass && controlPass
                        ? "NO_ARCHIVE_BOUNDARY_ESCAPE_OBSERVED"
                        : "HARNESS_OR_CONTROL_FAILURE",
                submissionReady = false,
            };
            File.WriteAllText(output, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    static object AssemblyInfo(Assembly assembly)
    {
        var location = assembly.Location;
        return new
        {
            name = assembly.GetName().Name,
            version = assembly.GetName().Version?.ToString(),
            informationalVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
            location,
            sha256 = File.Exists(location) ? Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(location))).ToLowerInvariant() : null,
        };
    }

    static Row RunTarNormal(string root)
        => RunTarRegular(root, "tar-normal", "safe/file.txt", outsideRelative: "outside-normal.txt", expectedSafe: false);

    static Row RunTarDotDot(string root)
        => RunTarRegular(root, "tar-dotdot", "../outside.txt", outsideRelative: "outside.txt", expectedSafe: true);

    static Row RunTarAbsolute(string root)
    {
        var caseRoot = CaseRoot(root, "tar-absolute");
        var outside = Path.Combine(caseRoot, "outside-absolute.txt");
        return RunTar(caseRoot, "tar-absolute", outside, "absolute/file.txt", expectedSafe: true, writer =>
        {
            WriteTarRegular(writer, outside.Replace('\\', '/'), "PWN-TAR-ABS");
        });
    }

    static Row RunTarBackslashDotDot(string root)
        => RunTarRegular(root, "tar-backslash-dotdot", "..\\outside-backslash.txt", outsideRelative: "outside-backslash.txt", expectedSafe: true);

    static Row RunTarArchiveSymlinkDirectory(string root)
    {
        var caseRoot = CaseRoot(root, "tar-archive-symlink-dir");
        var outsideDir = Path.Combine(caseRoot, "outside");
        Directory.CreateDirectory(outsideDir);
        var outside = Path.Combine(outsideDir, "pwn.txt");
        return RunTar(caseRoot, "tar-archive-symlink-dir", outside, "link/pwn.txt", expectedSafe: true, writer =>
        {
            var symlink = new PaxTarEntry(TarEntryType.SymbolicLink, "link") { LinkName = outsideDir };
            writer.WriteEntry(symlink);
            WriteTarRegular(writer, "link/pwn.txt", "PWN-TAR-ARCHIVE-SYMLINK-DIR");
        });
    }

    static Row RunTarPreexistingSymlinkDirectory(string root)
    {
        var caseRoot = CaseRoot(root, "tar-preexisting-symlink-dir");
        var dest = Path.Combine(caseRoot, "dest");
        var outsideDir = Path.Combine(caseRoot, "outside");
        Directory.CreateDirectory(dest);
        Directory.CreateDirectory(outsideDir);
        Directory.CreateSymbolicLink(Path.Combine(dest, "link"), outsideDir);
        var outside = Path.Combine(outsideDir, "pwn.txt");
        return RunTar(caseRoot, "tar-preexisting-symlink-dir", outside, "link/pwn.txt", expectedSafe: true, writer =>
        {
            WriteTarRegular(writer, "link/pwn.txt", "PWN-TAR-PREEXISTING-SYMLINK-DIR");
        }, precreatedDestination: dest);
    }

    static Row RunTarPreexistingSymlinkFile(string root)
    {
        var caseRoot = CaseRoot(root, "tar-preexisting-symlink-file");
        var dest = Path.Combine(caseRoot, "dest");
        Directory.CreateDirectory(dest);
        var outside = Path.Combine(caseRoot, "outside-file.txt");
        File.WriteAllText(outside, "ORIGINAL");
        File.CreateSymbolicLink(Path.Combine(dest, "file.txt"), outside);
        return RunTar(caseRoot, "tar-preexisting-symlink-file", outside, "file.txt", expectedSafe: true, writer =>
        {
            WriteTarRegular(writer, "file.txt", "PWN-TAR-PREEXISTING-SYMLINK-FILE");
        }, precreatedDestination: dest, outsideExistenceMeansWrite: false, originalOutsideContent: "ORIGINAL");
    }

    static Row RunTarArchiveHardLink(string root)
    {
        var caseRoot = CaseRoot(root, "tar-archive-hardlink");
        var outside = Path.Combine(caseRoot, "outside-hardlink-target.txt");
        File.WriteAllText(outside, "ORIGINAL");
        return RunTar(caseRoot, "tar-archive-hardlink", outside, "hard", expectedSafe: true, writer =>
        {
            var hard = new PaxTarEntry(TarEntryType.HardLink, "hard") { LinkName = outside };
            writer.WriteEntry(hard);
        }, outsideExistenceMeansWrite: false, originalOutsideContent: "ORIGINAL");
    }

    static Row RunTarRegular(string root, string name, string entryName, string outsideRelative, bool expectedSafe)
    {
        var caseRoot = CaseRoot(root, name);
        var outside = Path.Combine(caseRoot, outsideRelative);
        var destinationRelative = entryName.Replace("..", "dotdot").Replace('\\', '/');
        return RunTar(caseRoot, name, outside, destinationRelative, expectedSafe, writer =>
        {
            WriteTarRegular(writer, entryName, "PWN-" + name.ToUpperInvariant());
        });
    }

    static Row RunTar(
        string caseRoot,
        string name,
        string outside,
        string destinationRelative,
        bool expectedSafe,
        Action<TarWriter> write,
        string? precreatedDestination = null,
        bool outsideExistenceMeansWrite = true,
        string? originalOutsideContent = null)
    {
        var tarPath = Path.Combine(caseRoot, "payload.tar");
        var dest = precreatedDestination ?? Path.Combine(caseRoot, "dest");
        Directory.CreateDirectory(dest);
        using (var fs = File.Create(tarPath))
        using (var writer = new TarWriter(fs, TarEntryFormat.Pax, leaveOpen: false))
        {
            write(writer);
        }

        bool completed = false;
        Exception? exception = null;
        try
        {
            TarFile.ExtractToDirectory(tarPath, dest, overwriteFiles: true);
            completed = true;
        }
        catch (Exception ex)
        {
            exception = ex;
        }

        var outsideCreated = File.Exists(outside) && (outsideExistenceMeansWrite || File.ReadAllText(outside) != originalOutsideContent);
        var outsideContent = File.Exists(outside) ? SafeRead(outside) : null;
        var destinationPath = Path.Combine(dest, destinationRelative.Replace('/', Path.DirectorySeparatorChar));
        var destinationCreated = File.Exists(destinationPath);
        var destinationContent = destinationCreated ? SafeRead(destinationPath) : null;
        var passed = expectedSafe ? !outsideCreated : completed && destinationCreated;
        return new("tar", name, completed, exception?.GetType().FullName, exception?.Message, outsideCreated, outsideContent, destinationCreated, destinationContent, expectedSafe, passed);
    }

    static void WriteTarRegular(TarWriter writer, string name, string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        var entry = new PaxTarEntry(TarEntryType.RegularFile, name)
        {
            DataStream = new MemoryStream(bytes, writable: false),
        };
        writer.WriteEntry(entry);
    }

    static Row RunZipNormal(string root)
        => RunZipRegular(root, "zip-normal", "safe/file.txt", "outside-normal.txt", expectedSafe: false);

    static Row RunZipDotDot(string root)
        => RunZipRegular(root, "zip-dotdot", "../outside.txt", "outside.txt", expectedSafe: true);

    static Row RunZipAbsolute(string root)
    {
        var caseRoot = CaseRoot(root, "zip-absolute");
        var outside = Path.Combine(caseRoot, "outside-absolute.txt");
        return RunZip(caseRoot, "zip-absolute", outside, "absolute/file.txt", expectedSafe: true, archive =>
        {
            WriteZipRegular(archive, outside.Replace('\\', '/'), "PWN-ZIP-ABS");
        });
    }

    static Row RunZipBackslashDotDot(string root)
        => RunZipRegular(root, "zip-backslash-dotdot", "..\\outside-backslash.txt", "outside-backslash.txt", expectedSafe: true);

    static Row RunZipPreexistingSymlinkDirectory(string root)
    {
        var caseRoot = CaseRoot(root, "zip-preexisting-symlink-dir");
        var dest = Path.Combine(caseRoot, "dest");
        var outsideDir = Path.Combine(caseRoot, "outside");
        Directory.CreateDirectory(dest);
        Directory.CreateDirectory(outsideDir);
        Directory.CreateSymbolicLink(Path.Combine(dest, "link"), outsideDir);
        var outside = Path.Combine(outsideDir, "pwn.txt");
        return RunZip(caseRoot, "zip-preexisting-symlink-dir", outside, "link/pwn.txt", expectedSafe: true, archive =>
        {
            WriteZipRegular(archive, "link/pwn.txt", "PWN-ZIP-PREEXISTING-SYMLINK-DIR");
        }, precreatedDestination: dest);
    }

    static Row RunZipPreexistingSymlinkFile(string root)
    {
        var caseRoot = CaseRoot(root, "zip-preexisting-symlink-file");
        var dest = Path.Combine(caseRoot, "dest");
        Directory.CreateDirectory(dest);
        var outside = Path.Combine(caseRoot, "outside-file.txt");
        File.WriteAllText(outside, "ORIGINAL");
        File.CreateSymbolicLink(Path.Combine(dest, "file.txt"), outside);
        return RunZip(caseRoot, "zip-preexisting-symlink-file", outside, "file.txt", expectedSafe: true, archive =>
        {
            WriteZipRegular(archive, "file.txt", "PWN-ZIP-PREEXISTING-SYMLINK-FILE");
        }, precreatedDestination: dest, outsideExistenceMeansWrite: false, originalOutsideContent: "ORIGINAL");
    }

    static Row RunZipRegular(string root, string name, string entryName, string outsideRelative, bool expectedSafe)
    {
        var caseRoot = CaseRoot(root, name);
        var outside = Path.Combine(caseRoot, outsideRelative);
        var destinationRelative = entryName.Replace("..", "dotdot").Replace('\\', '/');
        return RunZip(caseRoot, name, outside, destinationRelative, expectedSafe, archive =>
        {
            WriteZipRegular(archive, entryName, "PWN-" + name.ToUpperInvariant());
        });
    }

    static Row RunZip(
        string caseRoot,
        string name,
        string outside,
        string destinationRelative,
        bool expectedSafe,
        Action<ZipArchive> write,
        string? precreatedDestination = null,
        bool outsideExistenceMeansWrite = true,
        string? originalOutsideContent = null)
    {
        var zipPath = Path.Combine(caseRoot, "payload.zip");
        var dest = precreatedDestination ?? Path.Combine(caseRoot, "dest");
        Directory.CreateDirectory(dest);
        using (var fs = File.Create(zipPath))
        using (var archive = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false))
        {
            write(archive);
        }

        bool completed = false;
        Exception? exception = null;
        try
        {
            ZipFile.ExtractToDirectory(zipPath, dest, overwriteFiles: true);
            completed = true;
        }
        catch (Exception ex)
        {
            exception = ex;
        }

        var outsideCreated = File.Exists(outside) && (outsideExistenceMeansWrite || File.ReadAllText(outside) != originalOutsideContent);
        var outsideContent = File.Exists(outside) ? SafeRead(outside) : null;
        var destinationPath = Path.Combine(dest, destinationRelative.Replace('/', Path.DirectorySeparatorChar));
        var destinationCreated = File.Exists(destinationPath);
        var destinationContent = destinationCreated ? SafeRead(destinationPath) : null;
        var passed = expectedSafe ? !outsideCreated : completed && destinationCreated;
        return new("zip", name, completed, exception?.GetType().FullName, exception?.Message, outsideCreated, outsideContent, destinationCreated, destinationContent, expectedSafe, passed);
    }

    static void WriteZipRegular(ZipArchive archive, string name, string content)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
        writer.Write(content);
    }

    static string CaseRoot(string root, string name)
    {
        var path = Path.Combine(root, name);
        Directory.CreateDirectory(path);
        return path;
    }

    static string? SafeRead(string path)
    {
        try { return File.ReadAllText(path); }
        catch (Exception ex) { return "<read-error:" + ex.GetType().Name + ">"; }
    }
}
