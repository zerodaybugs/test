from pathlib import Path

path = Path("Program.cs")
source = path.read_text(encoding="utf-8")

source = source.replace(
    "using Microsoft.Extensions.DependencyInjection;\n",
    "using Microsoft.Extensions.DependencyInjection;\nusing Microsoft.Extensions.Options;\n",
    1,
)

endpoint_marker = '        app.MapPost("/http/mfa-install/{key}", (string key, CapabilityStore store, HttpContext context) =>\n'
expired_endpoint = '''        app.MapGet("/ticket/mfa-expired/{user}", (IOptionsMonitor<CookieAuthenticationOptions> options, string user) =>
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var properties = new AuthenticationProperties
            {
                IssuedUtc = now.AddMinutes(-20),
                ExpiresUtc = now.AddMinutes(-10),
                IsPersistent = false,
            };
            var ticket = new AuthenticationTicket(Principal(MfaScheme, user, "mfa-expired"), properties, MfaScheme);
            string protectedTicket = options.Get(MfaScheme).TicketDataFormat.Protect(ticket);
            return Results.Json(new TicketValue(protectedTicket));
        }).AllowAnonymous();

'''
if endpoint_marker not in source:
    raise SystemExit("HTTP endpoint insertion point missing")
source = source.replace(endpoint_marker, expired_endpoint + endpoint_marker, 1)

source = source.replace(
    '        Directory.CreateDirectory("evidence");\n',
    '        string evidenceDirectory = Path.GetFullPath(Environment.GetEnvironmentVariable("EVIDENCE_DIR") ?? "evidence");\n'
    '        Directory.CreateDirectory(evidenceDirectory);\n',
    1,
)
source = source.replace(
    '"evidence/RESULT.json"',
    'Path.Combine(evidenceDirectory, "RESULT.json")',
    1,
)
source = source.replace(
    '"evidence/VERDICT.env"',
    'Path.Combine(evidenceDirectory, "VERDICT.env")',
    1,
)

return_marker = '''        return output;
    }

    private static ClaimsPrincipal'''
extra_controls = '''        // A normal HTTP endpoint must also fail closed for an unregistered scheme.
        string httpMissingKey = $"http-missing-{transport}-{iteration}-{Guid.NewGuid():N}";
        using (var client = CreateClient(baseCookies))
        {
            int status;
            try
            {
                status = (int)(await client.PostAsync(new Uri(baseUri, $"/http/missing-install/{httpMissingKey}"), null)).StatusCode;
            }
            catch
            {
                status = 599;
            }
            using var freshProof = CreateClient(new CookieContainer());
            int proof = (int)(await freshProof.GetAsync(new Uri(baseUri, $"/proof/{httpMissingKey}"))).StatusCode;
            output.Add(new ControlRow(transport.ToString(), iteration, "http_missing_scheme_fail_closed",
                status is not (>= 200 and < 300) && proof == 403, $"status={status};proof={proof}"));
        }

        // With both cookies, the actual connection principal must be the MFA user.
        string bothKey = $"both-{transport}-{iteration}-{Guid.NewGuid():N}";
        var bothCookies = new CookieContainer();
        using (var client = CreateClient(bothCookies))
        {
            (await client.PostAsync(new Uri(baseUri, $"/login/base/base-both-{iteration}"), null)).EnsureSuccessStatusCode();
            (await client.PostAsync(new Uri(baseUri, $"/login/mfa/mfa-both-{iteration}"), null)).EnsureSuccessStatusCode();
        }
        await using (HubConnection both = BuildConnection(baseUri, "/method-hub", bothCookies, transport))
        {
            await both.StartAsync();
            IdentitySnapshot identity = await both.InvokeAsync<IdentitySnapshot>("IdentitySnapshot");
            InstallSnapshot install = await both.InvokeAsync<InstallSnapshot>("InstallAdminApiKey", bothKey);
            output.Add(new ControlRow(transport.ToString(), iteration, "both_cookies_select_mfa_identity",
                identity.AuthenticationType == MfaScheme && identity.Name == $"mfa-both-{iteration}" &&
                install.AuthenticationType == MfaScheme && install.Name == $"mfa-both-{iteration}",
                $"identity={identity.AuthenticationType}:{identity.Name};install={install.AuthenticationType}:{install.Name}"));
        }

        // A valid MFA cookie for a different user must not merge with the base identity.
        string differentUserKey = $"different-{transport}-{iteration}-{Guid.NewGuid():N}";
        var differentCookies = new CookieContainer();
        using (var client = CreateClient(differentCookies))
        {
            (await client.PostAsync(new Uri(baseUri, $"/login/base/base-owner-{iteration}"), null)).EnsureSuccessStatusCode();
            (await client.PostAsync(new Uri(baseUri, $"/login/mfa/mfa-other-{iteration}"), null)).EnsureSuccessStatusCode();
        }
        await using (HubConnection different = BuildConnection(baseUri, "/method-hub", differentCookies, transport))
        {
            await different.StartAsync();
            InstallSnapshot install = await different.InvokeAsync<InstallSnapshot>("InstallAdminApiKey", differentUserKey);
            output.Add(new ControlRow(transport.ToString(), iteration, "different_user_mfa_identity_not_mixed",
                install.AuthenticationType == MfaScheme && install.Name == $"mfa-other-{iteration}",
                $"auth={install.AuthenticationType};name={install.Name}"));
        }

        // An internally expired MFA ticket that is still presented must not fall back to BaseCookie.
        string expiredKey = $"expired-{transport}-{iteration}-{Guid.NewGuid():N}";
        var expiredCookies = new CookieContainer();
        using (var client = CreateClient(expiredCookies))
        {
            (await client.PostAsync(new Uri(baseUri, $"/login/base/base-expired-{iteration}"), null)).EnsureSuccessStatusCode();
            TicketValue ticket = (await client.GetFromJsonAsync<TicketValue>(new Uri(baseUri, $"/ticket/mfa-expired/mfa-expired-{iteration}")))!;
            expiredCookies.Add(baseUri, new Cookie(MfaCookieName, ticket.Value, "/") { Secure = true });
        }
        bool expiredDenied = false;
        await using (HubConnection expired = BuildConnection(baseUri, "/method-hub", expiredCookies, transport))
        {
            try
            {
                await expired.StartAsync();
                await expired.InvokeAsync<InstallSnapshot>("InstallAdminApiKey", expiredKey);
            }
            catch
            {
                expiredDenied = true;
            }
        }
        using (var freshProof = CreateClient(new CookieContainer()))
        {
            int proof = (int)(await freshProof.GetAsync(new Uri(baseUri, $"/proof/{expiredKey}"))).StatusCode;
            output.Add(new ControlRow(transport.ToString(), iteration, "expired_mfa_no_base_fallback",
                expiredDenied && proof == 403, $"denied={expiredDenied};proof={proof}"));
        }

'''
if return_marker not in source:
    raise SystemExit("RunControls return marker missing")
source = source.replace(return_marker, extra_controls + return_marker, 1)

record = "public sealed record InstallSnapshot(bool Installed, string? AuthenticationType, string? Name);\n"
if record not in source:
    raise SystemExit("record insertion point missing")
source = source.replace(record, record + "public sealed record TicketValue(string Value);\n", 1)

required = [
    "http_missing_scheme_fail_closed",
    "both_cookies_select_mfa_identity",
    "different_user_mfa_identity_not_mixed",
    "expired_mfa_no_base_fallback",
]
for marker in required:
    if marker not in source:
        raise SystemExit(f"missing patched marker: {marker}")

path.write_text(source, encoding="utf-8")
