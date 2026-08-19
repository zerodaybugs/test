# MS11 recent security-adjacent source scan

This is static triage only. It is not a vulnerability report.

| Score | Date | Repository | Commit | Subject |
|---:|---|---|---|---|
| 70 | 2026-07-02 | `dotnet/aspnetcore` | `fa8126f62f64` | Fix typos in code. (#67428) |
| 56 | 2026-05-14 | `dotnet/aspnetcore` | `fde609409304` | Include scheme in certificate cache for Authentication middleware (#66673) |
| 55 | 2026-07-30 | `dotnet/aspnetcore` | `eb04e4399c96` | Device Bound Session Credentials (DBSC) for cookie authentication (prototype) (#67388) |
| 54 | 2026-08-04 | `dotnet/runtime` | `953021c788d6` | Fix SslAuthenticationOptions incorrectly disposing unowned IntermediateCertificates (#131758) |
| 46 | 2026-08-17 | `dotnet/aspnetcore` | `47b2e02e0282` | Avoid ignoring authorization failure reasons (#68572) (#68576) |
| 46 | 2026-08-17 | `dotnet/aspnetcore` | `d1310d9a8821` | Avoid ignoring authorization failure reasons (#68572) |
| 46 | 2026-08-13 | `dotnet/aspnetcore` | `704fddddc31f` | Use TLS channel binding in Negotiate authentication (#68317) |
| 46 | 2026-08-04 | `dotnet/runtime` | `5d00cb4d8681` | Enforce required Negotiate mutual authentication (#131588) |
| 46 | 2026-07-31 | `dotnet/aspnetcore` | `9f99606fb477` | Harden SocialSample FailureMessage rendering and add READMEs into samples (#67995) |
| 46 | 2026-07-22 | `dotnet/aspnetcore` | `51a14e4ed387` | Unhandled-security-metadata guard misses AuthorizationPolicy and IAuthorizationRequirementData (#67742) |
| 46 | 2026-07-17 | `dotnet/aspnetcore` | `face016de004` | Support AuthorizationPolicy and IAuthorizationRequirementData metadata everywhere (#67765) |
| 46 | 2026-06-29 | `dotnet/runtime` | `185a5f29abca` | Use managed NTLM on RHEL 8 to fix NegotiateAuthentication test failures (#129468) |
| 46 | 2026-06-09 | `dotnet/runtime` | `3654fe464c77` | Fix NegotiateAuthentication to surface TargetUnknown status for unknown SPNs (#126623) |
| 45 | 2026-07-21 | `dotnet/aspnetcore` | `15bdfbf8551c` | Clear cached session key in cookie auth handler sign-out (#67049) |
| 45 | 2026-07-21 | `dotnet/aspnetcore` | `326d5668a631` | SignalR .NET client: make auth refresh work behind a redirecting server (Azure SignalR) (#67612) |
| 45 | 2026-06-23 | `dotnet/aspnetcore` | `7c9c01bc83da` | Reject ASCII control characters in cookie auth return URLs (#66876) |
| 45 | 2026-04-28 | `dotnet/aspnetcore` | `d827882b5341` | fix: escape LDAP filter values per RFC 4515 (#66436) |
| 44 | 2026-08-17 | `dotnet/aspnetcore` | `d201668e63ed` | Harden SignalR authentication refresh (#68459) (#68593) |
| 44 | 2026-08-17 | `dotnet/aspnetcore` | `af049eb8f38b` | Harden SignalR authentication refresh (#68459) |
| 44 | 2026-08-05 | `dotnet/aspnetcore` | `3ba28b7c0fdd` | [Blazor] Propagate SignalR authentication refresh to server circuits |
| 44 | 2026-07-27 | `dotnet/aspnetcore` | `1259668fb4d3` | [test-quarantine] Quarantine HubConnectionTests authentication refresh tests (#68020) |
| 44 | 2026-07-09 | `dotnet/aspnetcore` | `87ef375cf093` | Suppress by-design CodeQL alerts (#67713) |
| 44 | 2026-07-09 | `dotnet/aspnetcore` | `bd8b9db931ca` | Suppress false-positive CodeQL alerts (#67710) |
| 42 | 2026-08-19 | `dotnet/aspnetcore` | `e6847b7e2c9a` | Align authentication-state revalidation semantics |
| 42 | 2026-06-24 | `dotnet/aspnetcore` | `8835dfcb307b` | Add SignalR Auth Refresh support to server and .NET client (#67111) |
| 42 | 2026-05-12 | `dotnet/aspnetcore` | `31fc9ba8e566` | Cache uncached AppContext.TryGetSwitch calls (#66513) |
| 40 | 2026-07-30 | `dotnet/aspnetcore` | `747d2cdb5840` | Add SignalR TypeScript auth refresh (#67964) |
| 40 | 2026-05-13 | `NuGet/NuGet.Client` | `7b398f907874` | Enable nullable for NuGet.Protocol HttpSource types (#7370) |
| 39 | 2026-07-03 | `AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet` | `3fbc3cf74148` | Port ML-DSA (FIPS 204) post-quantum signature support to dev (#3532) |
| 38 | 2026-07-23 | `dotnet/runtime` | `06bd751859b6` | Add low-level TLS state machine API (TlsContext / TlsSession) (#130366) |
| 38 | 2026-07-15 | `dotnet/aspnetcore` | `1abace74da84` | Cherry-pick internal commits (release/9.0) (#67805) |
| 38 | 2026-06-18 | `dotnet/runtime` | `4796c4f23612` | Port System.Net.Security to OpenBSD (#129479) |
| 37 | 2026-07-16 | `dotnet/aspnetcore` | `e4f3314bc703` | Treat QUERY as a safe HTTP method for antiforgery and CSRF protection (#67839) |
| 36 | 2026-08-18 | `dotnet/aspnetcore` | `6ce0ffbfe087` | Remove misleading debug log message from AuthenticationService.ts (#68626) |
| 36 | 2026-08-14 | `dotnet/runtime` | `48fa6effffe3` | Compile UpdateOptions_ServerCertificateContextProvided test on desktop only (#132277) |
| 36 | 2026-07-20 | `dotnet/aspnetcore` | `fc4e6e0915a5` | Update AngleSharp to latest (#67898) |
| 36 | 2026-07-14 | `dotnet/aspnetcore` | `564927ca5012` | Fix API for CacheView (#67776) |
| 36 | 2026-07-10 | `dotnet/aspnetcore` | `d1866a23152c` | CacheBoundary support for Blazor (#65772) |
| 36 | 2026-07-09 | `dotnet/aspnetcore` | `1ae00e66adf5` | Add TLS channel binding token access to `ITlsConnectionFeature` (#67436) |
| 36 | 2026-06-24 | `dotnet/aspnetcore` | `b11209eb90a7` | Add BL0013 analyzer: detect missing `AuthenticationStateChanged` subscription (#67383) |
| 36 | 2026-05-27 | `NuGet/NuGet.Client` | `ef16870f13ce` | Enable nullable for NuGet.Protocol repository abstractions (#7406) |
| 36 | 2026-04-23 | `dotnet/aspnetcore` | `52144dbb388b` | Fix XML doc validation warnings (#66339) |
| 34 | 2026-08-07 | `dotnet/aspnetcore` | `97251a568d0b` | Use HubConnection for authentication refresh test |
| 34 | 2026-07-24 | `dotnet/runtime` | `8642df88eefc` | Fall back to NTLM in managed SPNEGO when Kerberos credentials are missing on Unix (#131195) |
| 34 | 2026-07-23 | `dotnet/runtime` | `3e64752d437b` | Implement channel binding support on Unix (#130758) |
| 34 | 2026-07-22 | `dotnet/runtime` | `97e5cfb1cb0a` | Throw PNSE for Extended Protection on unsupported platforms (#131144) |
| 34 | 2026-06-17 | `dotnet/runtime` | `26243ad3bf71` | Move DSA tests into System.Security.Cryptography (#129320) |
| 31 | 2026-06-24 | `dotnet/aspnetcore` | `23dc2a5de035` | Use SearchValues/ContainsAny/span helpers in more places (#67018) |
| 30 | 2026-08-05 | `dotnet/aspnetcore` | `20ee2cb074fb` | Address review feedback on authentication refresh tests |
| 30 | 2026-06-18 | `dotnet/aspnetcore` | `d54f274f8335` | [breaking] Defer antiforgery/CSRF rejection to form consumers via `IAntiforgeryValidationFeature` (#67082) |
| 28 | 2026-05-19 | `dotnet/aspnetcore` | `b24ff65cc65b` | [Blazor] Replace Blazor WebAssembly DevServer with Gateway in templates (#66729) |
| 27 | 2026-07-07 | `dotnet/aspnetcore` | `b126e4ffb9b8` | Improve Blazor async form validation (#67323) |
| 26 | 2026-08-13 | `dotnet/runtime` | `811225a48270` | Replace SHA-1/RSA-1024 test data with SHA-256/RSA-2048 equivalents (#131783) |
| 26 | 2026-07-13 | `dotnet/runtime` | `5ad8ae4df419` | Improve Certificate Policy tests |
| 26 | 2026-06-10 | `dotnet/runtime` | `9e2858a585c3` | Don't throw in NegotiateClientCertificateAsync if Post-Handshake auth wasn't enabled. (#128942) |
| 25 | 2026-07-16 | `dotnet/runtime` | `dfd3a95b5c70` | Normalize GetNameInfo under malformed SANs |
| 25 | 2026-04-22 | `NuGet/NuGet.Client` | `df6c51a37522` | Local tests don't run netfx signing tests needing admin access (#7303) |
| 24 | 2026-07-23 | `dotnet/runtime` | `ab7ed79da4bd` | Make AiaCompletionHasLimits handle Windows variance |
| 24 | 2026-07-08 | `AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet` | `c58a45119909` | add missing lines to strong name bypass registry file (#3537) |
| 24 | 2026-06-11 | `dotnet/runtime` | `d6db5692f704` | Generate TLS alerts on certificate validation failure on macOS (#128316) |
| 24 | 2026-06-08 | `NuGet/NuGet.Client` | `4fa4e6966179` | Enable nullable for NuGet.Protocol plugin messages, logging, and contracts (#7434) |
| 24 | 2026-06-01 | `dotnet/aspnetcore` | `d8cd74d22828` | [main] Source code updates from dotnet/dotnet (#66933) |
| 24 | 2026-05-19 | `NuGet/NuGet.Client` | `1bd3bcce3e4d` | Enable nullability for NuGet.Protocol PackagesFolder types (#7396) |
| 22 | 2026-08-04 | `dotnet/runtime` | `53aec40da3b3` | Enable out-of-process tests for CoreCLR browser WASM (#131110) |
| 22 | 2026-07-29 | `dotnet/aspnetcore` | `5997c34364c4` | Use ReadOnlyDictionary/ReadOnlyCollection for ValidateContext.ValidationErrors backing collections (#67822) |
| 22 | 2026-07-08 | `dotnet/aspnetcore` | `76452386cc5b` | Switch ValidateContext.ValidationErrors to `IReadOnlyList<string>` instead of `IEnumerable<string>` (#67659) |
| 22 | 2026-06-26 | `dotnet/aspnetcore` | `9481547ed4e7` | Add synchronous Validate method in Microsoft.Extensions.Validation (#67427) |
| 22 | 2026-06-19 | `dotnet/aspnetcore` | `afca1bd277d4` | [main] Source code updates from dotnet/dotnet (#67309) |
| 21 | 2026-08-13 | `dotnet/runtime` | `a3a0683d3fa4` | Unify sync/async Options validation contract (#131197) |
| 21 | 2026-07-15 | `NuGet/NuGet.Client` | `abefa380052f` | [dev] Source code updates from dotnet/dotnet (#7564) |
| 20 | 2026-08-14 | `dotnet/aspnetcore` | `07d11eb57133` | [Experimental] DirectTls transport implementation (#67912) |
| 20 | 2026-07-21 | `dotnet/aspnetcore` | `1037569ddd05` | Improve antiforgery error message for unauthenticated requests with authenticated tokens (#67942) |
| 20 | 2026-07-20 | `dotnet/runtime` | `f7dfaf6882e0` | Add System.Security.Cryptography Copilot instructions (#131006) |
| 20 | 2026-07-16 | `AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet` | `bb897f7c9664` | Add JsonWebToken header-replacement path to avoid re-parsing payload (#3552) |
| 20 | 2026-07-15 | `dotnet/runtime` | `883277ee4090` | Apply a number of mitigations to System.Security.Cryptography.Xml (#130705) |
| 20 | 2026-06-12 | `dotnet/runtime` | `f5645e2af5f5` | Convert corehost hostmisc trace and fx_ver to C (#128420) |
| 19 | 2026-07-21 | `dotnet/aspnetcore` | `93148da620b4` | Fix CollapseLeadingSlashes bypass via bare leading backslash (#67928) |
| 19 | 2026-06-15 | `dotnet/aspnetcore` | `ac7fe7db41a8` | Reduce algorithmic complexity for parsing If-Match and If-None-Match. (#66796) |
| 19 | 2026-04-08 | `microsoft/reverse-proxy` | `d54bfadfc5ae` | [main] Update dependencies from dotnet/arcade (#3001) |
| 18 | 2026-08-19 | `dotnet/aspnetcore` | `b128b9a6c7bd` | Use fully qualified names, including `global::`, in OpenAPI XML generator output (#67972) |
| 18 | 2026-08-17 | `NuGet/NuGet.Client` | `ecf4a3d86d03` | Replace per-restore static state resets with a single build-scoped event (#7630) |
| 18 | 2026-08-12 | `dotnet/runtime` | `49cb411b6854` | Fix SslStream client certificate credential caching (#132079) |
| 18 | 2026-07-29 | `AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet` | `4aea30f2599b` | Configure SHR path comparison (#3569) |
| 18 | 2026-07-28 | `dotnet/runtime` | `35ccab4a8601` | [Wasm Ryujit]: implement runtime-async codegen for R2R Wasm (#131167) |
| 18 | 2026-07-27 | `AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet` | `ee975e7a951d` | Add IgnoreCaseWhenValidatingAudience flag to audience validation (#3558) |
| 18 | 2026-07-10 | `dotnet/runtime` | `66cc35cbd334` | Use hint-safe pointer authentication stripping in NativeAOT (#130474) |
| 18 | 2026-07-08 | `AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet` | `01273779903b` | Make Signed HTTP Request `p` claim (path) comparison case-sensitive (RFC 3986 section 3.3) (#3539) |
| 18 | 2026-05-12 | `AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet` | `d0bdcea5c5cc` | adjust error message (#3482) |
| 18 | 2026-04-24 | `AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet` | `3565e761ea68` | L2 cache bypass (#3444) |
| 18 | 2026-04-21 | `AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet` | `f9b491f2c493` | Add DPoP (RFC 9449) proof creation and server-side validation (#3443) |
| 17 | 2026-08-12 | `dotnet/aspnetcore` | `f508645b0749` | Message key conventions for validation localization (#68202) |
| 17 | 2026-07-24 | `dotnet/aspnetcore` | `74de72982f35` | Streamline localization in Microsoft.Extensions.Validation (#67987) |
| 17 | 2026-07-24 | `dotnet/aspnetcore` | `342686d1567e` |  Handle passing a Func expression to Map* in ValidationsGenerator and RDG (#67821) |
| 17 | 2026-07-23 | `dotnet/aspnetcore` | `0ae3b028b124` | Move the abstract `Validatable*Info` from Microsoft.Extensions.Validation to be source-generated (#67956) |
| 17 | 2026-07-21 | `dotnet/aspnetcore` | `24a934e43839` | Remove DataAnnotations' ValidationContext from MEV public API (#67549) |
| 17 | 2026-07-16 | `dotnet/aspnetcore` | `6a0d7ae4deff` | Improve Blazor SSR client-side form validation (#67324) |
| 17 | 2026-07-15 | `dotnet/runtime` | `a238e237c5f3` | Fix zip unix permissions (#130304) |
| 17 | 2026-07-12 | `dotnet/aspnetcore` | `f82669acc283` | Fix array type unwrapping in validation source generator (#67743) |
| 17 | 2026-06-30 | `dotnet/aspnetcore` | `cda719fc919c` | Fix ambiguous hidden-property lookup in validation (#67455) |
| 17 | 2026-06-26 | `dotnet/aspnetcore` | `b761cb6291fc` | Fix passkey login broken by SSR client-side validation (#67258) |
| 17 | 2026-06-25 | `dotnet/aspnetcore` | `4c23531802c5` | ValidationsGenerator: Allow validating internal types (#67399) |
| 17 | 2026-06-24 | `dotnet/aspnetcore` | `0563bffcb76c` | Collapse scheme-relative leading slashes in Rewrite middleware redirect/rewrite targets (#66961) |
| 17 | 2026-06-23 | `dotnet/aspnetcore` | `b5462785ad52` | Implement async validation support for Microsoft.Extensions.Validation (#66487) |
| 17 | 2026-06-22 | `dotnet/aspnetcore` | `579a90524dbc` | Use globalized type names in validations gen (#67363) |
| 17 | 2026-05-18 | `dotnet/aspnetcore` | `c4728002789d` | Add localization support to Microsoft.Extensions.Validation (#66646) |
| 17 | 2026-05-14 | `dotnet/aspnetcore` | `a751caa6d543` | Add JS library for client-side validation in Blazor SSR (#66420) |
| 17 | 2026-05-14 | `dotnet/aspnetcore` | `aab7c9491e9f` | Close connection after processing CL+TE (#66671) |
| 17 | 2026-04-16 | `NuGet/NuGet.Client` | `1f130f612623` | Improve nupkg validation in NuGet.Protocol (#7284) |
| 16 | 2026-08-14 | `dotnet/runtime` | `0df564ff20ef` | [OptionsValidator] source generator: emit ValidateAsync() for IAsyncValidateOptions<T> (#130263) |
| 16 | 2026-08-07 | `dotnet/runtime` | `183c9545c2eb` | Improve TlsSession error diagnostics (#131943) |
| 16 | 2026-08-04 | `dotnet/runtime` | `2dd5330804f9` | Accept moving write buffers for socket-bound TLS sessions (#131759) |
| 16 | 2026-07-30 | `dotnet/runtime` | `db6e4f98f325` | Ship hosting layer error codes as a public header (#131617) |
| 16 | 2026-07-24 | `dotnet/runtime` | `911ee587428f` | Remove large-memory CopyTo and parser overflow tests (#131280) |
| 16 | 2026-07-23 | `dotnet/runtime` | `b96436e0baf6` | Require ML-DSA keys match the signature algorithm OID in SignedCms |
| 16 | 2026-07-20 | `dotnet/aspnetcore` | `58c56325e2e4` | Add IEndpointMetadataProvider to UnauthorizedHttpResult (#65611) |
| 16 | 2026-07-17 | `dotnet/runtime` | `3522269feadf` | Align CoseKey async verification with synchronous validation |
| 16 | 2026-07-16 | `dotnet/runtime` | `5453829b04a3` | Skip null elements in [ValidateEnumeratedItems] validation (#130720) |
| 16 | 2026-07-15 | `AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet` | `43a457b066ad` | Add claims dictionary preallocation (#3542) |
| 16 | 2026-07-12 | `dotnet/runtime` | `f98c7ad70646` | Use no-op MD Importer for DIA-backed stacktraces (#129866) |
| 16 | 2026-07-10 | `dotnet/aspnetcore` | `cf607f360f64` | HttpHeaders: reject Content-Length with leading `+` or `-` sign (#67635) |
