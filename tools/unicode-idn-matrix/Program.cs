using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;

var idn = new IdnMapping
{
    AllowUnassigned = false,
    UseStd3AsciiRules = true,
};

var allEquivalents = new List<object>();
var divergent = new List<object>();

for (char ascii = 'a'; ascii <= 'z'; ascii++)
{
    string expected = ascii.ToString();
    string baselineLabel = $"a{ascii}b";
    string baselineAscii = idn.GetAscii(baselineLabel).ToLowerInvariant();

    for (int codePoint = 0; codePoint <= 0xFFFF; codePoint++)
    {
        if (codePoint is >= 0xD800 and <= 0xDFFF)
        {
            continue;
        }

        char candidateChar = (char)codePoint;
        string candidate = candidateChar.ToString();
        if (candidate == expected || !string.Equals(expected, candidate, StringComparison.OrdinalIgnoreCase))
        {
            continue;
        }

        string candidateLabel = $"a{candidate}b";
        string? asciiLabel = null;
        string? idnError = null;
        try
        {
            asciiLabel = idn.GetAscii(candidateLabel).ToLowerInvariant();
        }
        catch (Exception ex)
        {
            idnError = ex.GetType().FullName + ": " + ex.Message;
        }

        string uriHost = "";
        string uriDnsSafeHost = "";
        string uriIdnHost = "";
        string? uriError = null;
        try
        {
            var uri = new Uri($"https://vault.{candidateLabel}.example/");
            uriHost = uri.Host;
            uriDnsSafeHost = uri.DnsSafeHost;
            uriIdnHost = uri.IdnHost;
        }
        catch (Exception ex)
        {
            uriError = ex.GetType().FullName + ": " + ex.Message;
        }

        bool suffixAccepted = $"vault.{candidateLabel}.example".EndsWith(
            $".{baselineLabel}.example",
            StringComparison.OrdinalIgnoreCase);

        var row = new
        {
            ascii = expected,
            codePoint = $"U+{codePoint:X4}",
            utf16 = $"\\u{codePoint:X4}",
            unicode = candidate,
            category = CharUnicodeInfo.GetUnicodeCategory(candidateChar).ToString(),
            ordinalIgnoreCaseEqual = true,
            baselineLabel,
            candidateLabel,
            baselineAscii,
            candidateAscii = asciiLabel,
            idnError,
            suffixAccepted,
            uriHost,
            uriDnsSafeHost,
            uriIdnHost,
            uriError,
            idnDistinct = asciiLabel is not null && !string.Equals(baselineAscii, asciiLabel, StringComparison.Ordinal),
        };

        allEquivalents.Add(row);
        if (asciiLabel is not null && !string.Equals(baselineAscii, asciiLabel, StringComparison.Ordinal))
        {
            divergent.Add(row);
        }
    }
}

bool dotlessIEqualsAsciiI = string.Equals("i", "\u0131", StringComparison.OrdinalIgnoreCase);
bool dottedCapitalIEqualsAsciiI = string.Equals("i", "\u0130", StringComparison.OrdinalIgnoreCase);

var result = new
{
    generatedUtc = DateTimeOffset.UtcNow,
    runtime = RuntimeInformation.FrameworkDescription,
    os = RuntimeInformation.OSDescription,
    processArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
    globalizationInvariant = AppContext.TryGetSwitch("System.Globalization.Invariant", out bool invariant) && invariant,
    idnSettings = new { idn.AllowUnassigned, idn.UseStd3AsciiRules },
    sanity = new
    {
        dotlessIEqualsAsciiI,
        dottedCapitalIEqualsAsciiI,
        asciiCaseEquals = string.Equals("i", "I", StringComparison.OrdinalIgnoreCase),
    },
    counts = new
    {
        nonAsciiBmpOrdinalIgnoreCaseEquivalentsToAsciiLetters = allEquivalents.Count,
        idnDistinctEquivalents = divergent.Count,
    },
    verdict = divergent.Count == 0
        ? "NO_ASCII_LETTER_TO_IDN_DISTINCT_ORDINALIGNORECASE_PAIR_IN_BMP"
        : "IDN_DISTINCT_ORDINALIGNORECASE_PAIRS_FOUND",
    divergent,
    allEquivalents,
};

var options = new JsonSerializerOptions { WriteIndented = true };
string output = JsonSerializer.Serialize(result, options) + Environment.NewLine;
File.WriteAllText("unicode-idn-matrix.json", output);
Console.Write(output);

if (dotlessIEqualsAsciiI || !string.Equals("i", "I", StringComparison.OrdinalIgnoreCase))
{
    Console.Error.WriteLine("Runtime sanity check failed.");
    return 2;
}

return 0;
