from pathlib import Path

p = Path("src/SignalR/server/Core/src/Internal/DefaultHubDispatcher.cs")
s = p.read_text()
old = """            var authorizeAttributes = methodInfo.GetCustomAttributes<AuthorizeAttribute>(inherit: true);
            _methods[methodName] = new HubMethodDescriptor(executor, serviceProviderIsService, authorizeAttributes);
"""
new = """            var authorizeAttributes = methodInfo.GetCustomAttributes<AuthorizeAttribute>(inherit: true).ToArray();

            foreach (var authorizeAttribute in authorizeAttributes)
            {
                if (!string.IsNullOrWhiteSpace(authorizeAttribute.AuthenticationSchemes))
                {
                    throw new NotSupportedException(
                        $"Hub method '{hubName}.{methodName}' specifies {nameof(AuthorizeAttribute.AuthenticationSchemes)} " +
                        $"('{authorizeAttribute.AuthenticationSchemes}'). SignalR establishes the connection principal when the " +
                        "connection is created and cannot re-run named authentication handlers for individual hub method invocations. " +
                        "Move scheme-specific authorization to the hub endpoint or hub class.");
                }
            }

            _methods[methodName] = new HubMethodDescriptor(executor, serviceProviderIsService, authorizeAttributes);
"""
if old not in s:
    raise SystemExit("patch point missing")
p.write_text(s.replace(old, new, 1))
