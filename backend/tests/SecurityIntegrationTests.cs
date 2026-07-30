using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

public sealed class SecurityIntegrationTests
{
    [Fact]
    public async Task Anonymous_CanReadHealth_ButCannotReadManagementApis()
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/health", CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/hosts", CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/v1/agents/ingest", SampleIngest("WEB-01"), CancellationToken)).StatusCode);
    }

    [Fact]
    public async Task Viewer_CanReadAssets_ButCannotModifyThem()
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        var adminToken = await LoginAsync(client, ApiFactory.AdminUser, ApiFactory.AdminPassword);
        await CreateUserAsync(client, adminToken, "viewer1", "Viewer-Test-2026!", "Viewer");
        var viewerToken = await LoginAsync(client, "viewer1", "Viewer-Test-2026!");
        Authorize(client, viewerToken);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/hosts", CancellationToken)).StatusCode);
        var response = await client.PostAsJsonAsync("/api/hosts", new { name = "TEST-01", ip = "10.9.0.1", room = "测试机房", service = "测试" }, CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        Authorize(client, adminToken);
        var disable = await client.PutAsJsonAsync("/api/users/viewer1", new { role = "Viewer", enabled = false, password = (string?)null }, CancellationToken);
        Assert.Equal(HttpStatusCode.OK, disable.StatusCode);
        Authorize(client, viewerToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/hosts", CancellationToken)).StatusCode);
    }

    [Fact]
    public async Task Operator_CanAcknowledgeIncident_ButCannotModifyAssets()
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        var adminToken = await LoginAsync(client, ApiFactory.AdminUser, ApiFactory.AdminPassword);
        await CreateUserAsync(client, adminToken, "operator1", "Operator-Test-2026!", "Operator");
        var operatorToken = await LoginAsync(client, "operator1", "Operator-Test-2026!");
        Authorize(client, operatorToken);

        var incidents = await client.GetFromJsonAsync<JsonElement>("/api/incidents", CancellationToken);
        var incidentId = incidents.EnumerateArray().First().GetProperty("id").GetGuid();
        var acknowledge = await client.PostAsJsonAsync($"/api/incidents/{incidentId}/acknowledge", new { note = "集成测试确认" }, CancellationToken);
        Assert.Equal(HttpStatusCode.OK, acknowledge.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.DeleteAsync("/api/hosts/WEB-01", CancellationToken)).StatusCode);
    }

    [Fact]
    public async Task Admin_CanManageAssets_AndAgentKeyIsRequiredAndHostBound()
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        var adminToken = await LoginAsync(client, ApiFactory.AdminUser, ApiFactory.AdminPassword);
        Authorize(client, adminToken);

        var create = await client.PostAsJsonAsync("/api/hosts", new { name = "TEST-AGENT", ip = "10.9.0.2", room = "测试机房", service = "测试" }, CancellationToken);
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var rotate = await client.PostAsync("/api/hosts/TEST-AGENT/agent-key", null, CancellationToken);
        Assert.Equal(HttpStatusCode.OK, rotate.StatusCode);
        var keyPayload = await rotate.Content.ReadFromJsonAsync<JsonElement>(CancellationToken);
        var key = keyPayload.GetProperty("agentKey").GetString();
        Assert.False(string.IsNullOrWhiteSpace(key));

        client.DefaultRequestHeaders.Authorization = null;
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/v1/agents/ingest", SampleIngest("TEST-AGENT"), CancellationToken)).StatusCode);

        client.DefaultRequestHeaders.Add("X-Agent-Name", "TEST-AGENT");
        client.DefaultRequestHeaders.Add("X-Agent-Key", key);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/api/v1/agents/ingest", SampleIngest("WEB-01"), CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/api/v1/agents/ingest", SampleIngest("TEST-AGENT"), CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsJsonAsync("/api/v1/agents/ingest", SampleIngest("TEST-AGENT"), CancellationToken)).StatusCode);
    }

    private static object SampleIngest(string hostName) => new
    {
        hostName,
        sequence = 1,
        collectedAt = DateTimeOffset.UtcNow,
        cpu = 20,
        memory = 30,
        disk = 40,
        latency = 5
    };

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        client.DefaultRequestHeaders.Authorization = null;
        var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password }, CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var payload = await response.Content.ReadFromJsonAsync<JsonElement>(CancellationToken);
        return payload.GetProperty("accessToken").GetString()!;
    }

    private static async Task CreateUserAsync(HttpClient client, string adminToken, string username, string password, string role)
    {
        Authorize(client, adminToken);
        var response = await client.PostAsJsonAsync("/api/users", new { username, password, role }, CancellationToken);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    private static void Authorize(HttpClient client, string token) =>
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;
}

sealed class ApiFactory : WebApplicationFactory<Program>, IAsyncDisposable
{
    public const string AdminUser = "integration-admin";
    public const string AdminPassword = "Integration-Admin-2026!";
    private readonly string _databasePath = Path.Combine(Path.GetTempPath(), $"monitoring-tests-{Guid.NewGuid():N}.db");
    private readonly string _keysPath = Path.Combine(Path.GetTempPath(), $"monitoring-keys-{Guid.NewGuid():N}");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Monitoring"] = $"Data Source={_databasePath};Pooling=False",
            ["Authentication:DataProtectionKeysPath"] = _keysPath,
            ["DevelopmentAuth:Enabled"] = "true",
            ["DevelopmentAuth:Username"] = AdminUser,
            ["DevelopmentAuth:Password"] = AdminPassword
        }));
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<MonitoringDbContext>();
            services.RemoveAll<DbContextOptions<MonitoringDbContext>>();
            services.AddDbContext<MonitoringDbContext>(options => options.UseSqlite($"Data Source={_databasePath};Pooling=False"));
        });
    }

    public new async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        if (File.Exists(_databasePath)) File.Delete(_databasePath);
        if (Directory.Exists(_keysPath)) Directory.Delete(_keysPath, true);
    }
}
