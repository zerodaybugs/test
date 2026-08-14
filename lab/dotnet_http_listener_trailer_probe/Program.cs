using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

string artifactDirectory = Path.GetFullPath(
    Environment.GetEnvironmentVariable("ARTIFACT_DIR") ??
    Path.Combine(Directory.GetCurrentDirectory(), "artifacts"));
Directory.CreateDirectory(artifactDirectory);

var report = new ProbeReport
{
    StartedUtc = DateTimeOffset.UtcNow,
    FrameworkDescription = RuntimeInformation.FrameworkDescription,
    EnvironmentVersion = Environment.Version.ToString(),
    OperatingSystem = RuntimeInformation.OSDescription,
    RuntimeIdentifier = RuntimeInformation.RuntimeIdentifier,
    ProcessArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
};

try
{
    ScenarioSpec[] specifications =
    [
        new("late-cookie-trailer", InitialCookie: false, TrailerCookie: true, ReadCookiesBeforeBody: false),
        new("early-cookie-cache-control", InitialCookie: false, TrailerCookie: true, ReadCookiesBeforeBody: true),
        new("no-cookie-control", InitialCookie: false, TrailerCookie: false, ReadCookiesBeforeBody: false),
        new("initial-cookie-control", InitialCookie: true, TrailerCookie: false, ReadCookiesBeforeBody: true),
    ];

    foreach (ScenarioSpec specification in specifications)
    {
        report.Scenarios.Add(await RunScenarioAsync(specification));
    }

    Validate(report.Scenarios);
    report.Verdict = "PASS";
}
catch (Exception exception)
{
    report.Verdict = "FAIL";
    report.Error = exception.ToString();
    Environment.ExitCode = 1;
}
finally
{
    report.FinishedUtc = DateTimeOffset.UtcNow;
    string json = JsonSerializer.Serialize(report, new JsonSerializerOptions
    {
        WriteIndented = true,
    });

    string resultPath = Path.Combine(artifactDirectory, "result.json");
    await File.WriteAllTextAsync(resultPath, json + Environment.NewLine, Encoding.UTF8);
    Console.WriteLine(json);
    Console.WriteLine($"PROBE_RESULT={report.Verdict}");
}

static async Task<ScenarioResult> RunScenarioAsync(ScenarioSpec specification)
{
    int port = GetFreePort();
    string prefix = $"http://127.0.0.1:{port}/";
    string rawRequest = BuildRawRequest(port, specification);

    using var listener = new HttpListener();
    listener.Prefixes.Add(prefix);
    listener.Start();

    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    Task<HttpListenerContext> contextTask = listener.GetContextAsync();
    Task<string> clientTask = SendRawRequestAsync(port, rawRequest, timeout.Token);

    HttpListenerContext context = await contextTask.WaitAsync(timeout.Token);
    HttpListenerRequest request = context.Request;

    string? cookieHeaderBeforeBody = request.Headers["Cookie"];
    string? cookieBeforeBody = null;
    if (specification.ReadCookiesBeforeBody)
    {
        cookieBeforeBody = request.Cookies["probe"]?.Value;
    }

    using var bodyBuffer = new MemoryStream();
    await request.InputStream.CopyToAsync(bodyBuffer, timeout.Token);
    string body = Encoding.ASCII.GetString(bodyBuffer.ToArray());

    string? cookieHeaderAfterBody = request.Headers["Cookie"];
    string? cookieAfterBody = request.Cookies["probe"]?.Value;

    var responseDocument = new
    {
        specification.Name,
        cookieHeaderBeforeBody,
        cookieBeforeBody,
        cookieHeaderAfterBody,
        cookieAfterBody,
        body,
    };
    byte[] responsePayload = JsonSerializer.SerializeToUtf8Bytes(responseDocument);
    context.Response.StatusCode = (int)HttpStatusCode.OK;
    context.Response.ContentType = "application/json";
    context.Response.ContentLength64 = responsePayload.Length;
    context.Response.KeepAlive = false;
    await context.Response.OutputStream.WriteAsync(responsePayload, timeout.Token);
    context.Response.Close();

    string rawResponse = await clientTask.WaitAsync(timeout.Token);
    listener.Stop();

    return new ScenarioResult
    {
        Name = specification.Name,
        InitialCookieSent = specification.InitialCookie,
        TrailerCookieSent = specification.TrailerCookie,
        CookiesReadBeforeBody = specification.ReadCookiesBeforeBody,
        CookieHeaderBeforeBody = cookieHeaderBeforeBody,
        CookieBeforeBody = cookieBeforeBody,
        CookieHeaderAfterBody = cookieHeaderAfterBody,
        CookieAfterBody = cookieAfterBody,
        Body = body,
        ResponseStatusLine = rawResponse.Split(["\r\n"], 2, StringSplitOptions.None)[0],
    };
}

static string BuildRawRequest(int port, ScenarioSpec specification)
{
    var headerLines = new List<string>
    {
        "POST /probe HTTP/1.1",
        $"Host: 127.0.0.1:{port}",
        "Transfer-Encoding: chunked",
        "Connection: close",
    };

    if (specification.InitialCookie)
    {
        headerLines.Add("Cookie: probe=initial");
    }

    if (specification.TrailerCookie)
    {
        headerLines.Add("Trailer: Cookie");
    }

    string trailerBlock = specification.TrailerCookie
        ? "0\r\nCookie: probe=trailer\r\n\r\n"
        : "0\r\n\r\n";

    return string.Join("\r\n", headerLines) +
        "\r\n\r\n" +
        "4\r\ndata\r\n" +
        trailerBlock;
}

static async Task<string> SendRawRequestAsync(int port, string rawRequest, CancellationToken cancellationToken)
{
    using var client = new TcpClient();
    await client.ConnectAsync(IPAddress.Loopback, port, cancellationToken);
    using NetworkStream stream = client.GetStream();

    byte[] requestBytes = Encoding.ASCII.GetBytes(rawRequest);
    await stream.WriteAsync(requestBytes, cancellationToken);
    await stream.FlushAsync(cancellationToken);

    using var responseBuffer = new MemoryStream();
    byte[] buffer = new byte[4096];
    while (true)
    {
        int bytesRead = await stream.ReadAsync(buffer, cancellationToken);
        if (bytesRead == 0)
        {
            break;
        }
        await responseBuffer.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
    }

    return Encoding.ASCII.GetString(responseBuffer.ToArray());
}

static int GetFreePort()
{
    var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    int port = ((IPEndPoint)listener.LocalEndpoint).Port;
    listener.Stop();
    return port;
}

static void Validate(IReadOnlyList<ScenarioResult> scenarios)
{
    ScenarioResult late = Find(scenarios, "late-cookie-trailer");
    Require(late.CookieHeaderBeforeBody is null, "Late-trailer scenario unexpectedly had an initial Cookie header.");
    Require(late.CookieHeaderAfterBody == "probe=trailer", "Late-trailer Cookie was not merged into request headers after body consumption.");
    Require(late.CookieAfterBody == "trailer", "Lazy Request.Cookies did not materialize the trailer Cookie.");
    Require(late.Body == "data", "Late-trailer body mismatch.");

    ScenarioResult early = Find(scenarios, "early-cookie-cache-control");
    Require(early.CookieHeaderBeforeBody is null, "Early-cache scenario unexpectedly had an initial Cookie header.");
    Require(early.CookieBeforeBody is null, "Early-cache scenario unexpectedly materialized a Cookie before body consumption.");
    Require(early.CookieHeaderAfterBody == "probe=trailer", "Early-cache scenario did not expose the trailer Cookie in request headers.");
    Require(early.CookieAfterBody is null, "Early Request.Cookies cache unexpectedly changed after the trailer was parsed.");
    Require(early.Body == "data", "Early-cache body mismatch.");

    ScenarioResult none = Find(scenarios, "no-cookie-control");
    Require(none.CookieHeaderBeforeBody is null, "No-cookie control unexpectedly had a Cookie header before body consumption.");
    Require(none.CookieHeaderAfterBody is null, "No-cookie control unexpectedly had a Cookie header after body consumption.");
    Require(none.CookieAfterBody is null, "No-cookie control unexpectedly materialized a Cookie.");
    Require(none.Body == "data", "No-cookie control body mismatch.");

    ScenarioResult initial = Find(scenarios, "initial-cookie-control");
    Require(initial.CookieHeaderBeforeBody == "probe=initial", "Initial-cookie control did not expose the initial Cookie header.");
    Require(initial.CookieBeforeBody == "initial", "Initial-cookie control did not materialize the initial Cookie.");
    Require(initial.CookieHeaderAfterBody == "probe=initial", "Initial-cookie control changed after body consumption.");
    Require(initial.CookieAfterBody == "initial", "Initial-cookie control Cookie changed after body consumption.");
    Require(initial.Body == "data", "Initial-cookie control body mismatch.");

    foreach (ScenarioResult scenario in scenarios)
    {
        Require(scenario.ResponseStatusLine.Contains(" 200 ", StringComparison.Ordinal), $"Unexpected response for {scenario.Name}: {scenario.ResponseStatusLine}");
    }
}

static ScenarioResult Find(IReadOnlyList<ScenarioResult> scenarios, string name) =>
    scenarios.Single(scenario => string.Equals(scenario.Name, name, StringComparison.Ordinal));

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

internal sealed record ScenarioSpec(
    string Name,
    bool InitialCookie,
    bool TrailerCookie,
    bool ReadCookiesBeforeBody);

internal sealed class ScenarioResult
{
    public required string Name { get; init; }
    public bool InitialCookieSent { get; init; }
    public bool TrailerCookieSent { get; init; }
    public bool CookiesReadBeforeBody { get; init; }
    public string? CookieHeaderBeforeBody { get; init; }
    public string? CookieBeforeBody { get; init; }
    public string? CookieHeaderAfterBody { get; init; }
    public string? CookieAfterBody { get; init; }
    public required string Body { get; init; }
    public required string ResponseStatusLine { get; init; }
}

internal sealed class ProbeReport
{
    public DateTimeOffset StartedUtc { get; init; }
    public DateTimeOffset FinishedUtc { get; set; }
    public required string FrameworkDescription { get; init; }
    public required string EnvironmentVersion { get; init; }
    public required string OperatingSystem { get; init; }
    public required string RuntimeIdentifier { get; init; }
    public required string ProcessArchitecture { get; init; }
    public List<ScenarioResult> Scenarios { get; } = [];
    public string Verdict { get; set; } = "INCOMPLETE";
    public string? Error { get; set; }
}
