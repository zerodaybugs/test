using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Microsoft.AspNetCore.SignalR.Tests;

public class HubMethodAuthenticationSchemesTests
{
    [Fact]
    public void MethodLevelAuthenticationSchemesFailFast()
    {
        using ServiceProvider provider = BuildProvider();
        NotSupportedException exception = Assert.Throws<NotSupportedException>(
            () => provider.GetRequiredService<HubConnectionHandler<MethodSchemeHub>>());
        Assert.Contains(nameof(AuthorizeAttribute.AuthenticationSchemes), exception.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(MethodSchemeHub.Restricted), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingMethodLevelAuthenticationSchemeAlsoFailsFast()
    {
        using ServiceProvider provider = BuildProvider();
        NotSupportedException exception = Assert.Throws<NotSupportedException>(
            () => provider.GetRequiredService<HubConnectionHandler<MissingSchemeHub>>());
        Assert.Contains("Nonexistent", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ClassLevelAuthenticationSchemesRemainSupported()
    {
        using ServiceProvider provider = BuildProvider();
        Assert.NotNull(provider.GetRequiredService<HubConnectionHandler<ClassSchemeHub>>());
    }

    [Fact]
    public void PlainMethodAuthorizationRemainsSupported()
    {
        using ServiceProvider provider = BuildProvider();
        Assert.NotNull(provider.GetRequiredService<HubConnectionHandler<PlainMethodHub>>());
    }

    private static ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization();
        services.AddSignalR();
        return services.BuildServiceProvider();
    }

    private sealed class MethodSchemeHub : Hub
    {
        [Authorize(AuthenticationSchemes = "MfaCookie")]
        public void Restricted() { }
    }

    private sealed class MissingSchemeHub : Hub
    {
        [Authorize(AuthenticationSchemes = "Nonexistent")]
        public void Missing() { }
    }

    [Authorize(AuthenticationSchemes = "MfaCookie")]
    private sealed class ClassSchemeHub : Hub
    {
        public void Ping() { }
    }

    private sealed class PlainMethodHub : Hub
    {
        [Authorize]
        public void Restricted() { }
    }
}
