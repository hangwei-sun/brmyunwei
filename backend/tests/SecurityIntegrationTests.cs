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

    [Fact]
    public async Task Admin_CanManageNetworkProbes_AndProbeStateDeduplicatesAndRecoversIncident()
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        var adminToken = await LoginAsync(client, ApiFactory.AdminUser, ApiFactory.AdminPassword);
        Authorize(client, adminToken);
        var createHost = await client.PostAsJsonAsync("/api/hosts", new { name = "TEST-PROBE", ip = "10.9.0.3", room = "测试机房", service = "测试" }, CancellationToken);
        Assert.Equal(HttpStatusCode.Created, createHost.StatusCode);

        var createProbe = await client.PostAsJsonAsync("/api/hosts/TEST-PROBE/probes", new
        {
            name = "业务端口",
            type = "tcp",
            target = "10.9.0.3",
            port = 443,
            expectedStatus = (int?)null,
            enabled = true,
            intervalSeconds = 30,
            timeoutMilliseconds = 1000,
            failureThreshold = 2,
            recoveryThreshold = 2
        }, CancellationToken);
        Assert.Equal(HttpStatusCode.Created, createProbe.StatusCode);
        var probePayload = await createProbe.Content.ReadFromJsonAsync<JsonElement>(CancellationToken);
        var probeId = probePayload.GetProperty("id").GetInt32();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/probes", CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsJsonAsync("/api/hosts/TEST-PROBE/probes", new
        {
            name = "重复业务端口",
            type = "tcp",
            target = "10.9.0.3",
            port = 443,
            expectedStatus = (int?)null,
            enabled = true,
            intervalSeconds = 30,
            timeoutMilliseconds = 1000,
            failureThreshold = 2,
            recoveryThreshold = 2
        }, CancellationToken)).StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
        var probe = await db.ProbeDefinitions.Include(item => item.Host).SingleAsync(item => item.Id == probeId, CancellationToken);
        var now = DateTimeOffset.UtcNow;
        Assert.Equal(ProbeTransition.None, ProbeStateMachine.Apply(probe, ProbeRunResult.Failure("connect failed"), now));
        var opened = ProbeStateMachine.Apply(probe, ProbeRunResult.Failure("connect failed"), now.AddSeconds(30));
        Assert.Equal(ProbeTransition.Opened, opened);
        await ProbeIncidentService.ApplyTransitionAsync(db, probe, opened, now.AddSeconds(30), CancellationToken);
        await db.SaveChangesAsync(CancellationToken);
        Assert.Single(await db.Incidents.Where(item => item.Fingerprint == probe.Fingerprint && item.ResolvedAt == null).ToListAsync(CancellationToken));

        Assert.Equal(ProbeTransition.None, ProbeStateMachine.Apply(probe, ProbeRunResult.Success(), now.AddSeconds(60)));
        var recovered = ProbeStateMachine.Apply(probe, ProbeRunResult.Success(), now.AddSeconds(90));
        Assert.Equal(ProbeTransition.Recovered, recovered);
        await ProbeIncidentService.ApplyTransitionAsync(db, probe, recovered, now.AddSeconds(90), CancellationToken);
        await db.SaveChangesAsync(CancellationToken);
        Assert.Single(await db.Incidents.Where(item => item.Fingerprint == probe.Fingerprint && item.ResolvedAt != null).ToListAsync(CancellationToken));
    }

    [Fact]
    public async Task AgentTelemetry_PersistsExtendedStatus_AndCreatesRecoverableIncidents()
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        var adminToken = await LoginAsync(client, ApiFactory.AdminUser, ApiFactory.AdminPassword);
        Authorize(client, adminToken);
        var create = await client.PostAsJsonAsync("/api/hosts", new { name = "TEST-TELEMETRY", ip = "10.9.0.4", room = "测试机房", service = "测试", group = "灰度组" }, CancellationToken);
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var rotate = await client.PostAsync("/api/hosts/TEST-TELEMETRY/agent-key", null, CancellationToken);
        var key = (await rotate.Content.ReadFromJsonAsync<JsonElement>(CancellationToken)).GetProperty("agentKey").GetString();
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("X-Agent-Name", "TEST-TELEMETRY");
        client.DefaultRequestHeaders.Add("X-Agent-Key", key);

        var oldBoot = DateTimeOffset.UtcNow.AddDays(-10);
        Assert.Equal(HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/api/v1/agents/ingest", ExtendedIngest(1, 20, oldBoot, "Running"), CancellationToken)).StatusCode);
        var newBoot = DateTimeOffset.UtcNow.AddMinutes(-3);
        for (var sequence = 2; sequence <= 6; sequence++)
            Assert.Equal(HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/api/v1/agents/ingest", ExtendedIngest(sequence, 95, newBoot, "Stopped"), CancellationToken)).StatusCode);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
            var host = await db.Hosts.SingleAsync(item => item.Name == "TEST-TELEMETRY", CancellationToken);
            Assert.Equal("灰度组", host.Group);
            Assert.Equal("1.0.0", host.AgentVersion);
            Assert.Equal(2048, host.NetworkBytesPerSecond);
            Assert.Equal("Stopped", (await db.HostServiceStatuses.SingleAsync(item => item.HostId == host.Id && item.Name == "Spooler", CancellationToken)).Status);
            Assert.Contains(await db.Incidents.Where(item => item.HostId == host.Id && item.ResolvedAt == null).ToListAsync(CancellationToken), item => item.Fingerprint.StartsWith("agent:reboot:"));
            Assert.Contains(await db.Incidents.Where(item => item.HostId == host.Id && item.ResolvedAt == null).ToListAsync(CancellationToken), item => item.Fingerprint == "service:SPOOLER");
            Assert.Contains(await db.Incidents.Where(item => item.HostId == host.Id && item.ResolvedAt == null).ToListAsync(CancellationToken), item => item.Fingerprint.StartsWith("metric:"));
        }

        Assert.Equal(HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/api/v1/agents/ingest", ExtendedIngest(7, 20, newBoot, "Running"), CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/api/v1/agents/ingest", ExtendedIngest(8, 20, newBoot, "Running"), CancellationToken)).StatusCode);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
            var hostId = await db.Hosts.Where(item => item.Name == "TEST-TELEMETRY").Select(item => item.Id).SingleAsync(CancellationToken);
            Assert.DoesNotContain(await db.Incidents.Where(item => item.HostId == hostId && item.ResolvedAt == null).ToListAsync(CancellationToken), item => item.Fingerprint == "service:SPOOLER" || item.Fingerprint.StartsWith("metric:"));
        }
    }

    [Fact]
    public async Task Admin_CanManageCompleteNotificationPolicyContract_AndPlannerDeduplicates()
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        var adminToken = await LoginAsync(client, ApiFactory.AdminUser, ApiFactory.AdminPassword);
        Authorize(client, adminToken);
        var create = await client.PostAsJsonAsync("/api/notification-policies", new
        {
            name = "灰度严重告警",
            serverGroup = "生产服务器组",
            severity = "严重",
            contactGroup = "灰度值班组",
            enabled = true,
            repeatMinutes = 20
        }, CancellationToken);
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var policyId = (await create.Content.ReadFromJsonAsync<JsonElement>(CancellationToken)).GetProperty("id").GetInt32();

        var invalid = await client.PutAsJsonAsync($"/api/notification-policies/{policyId}", new
        {
            name = "灰度严重告警",
            serverGroup = "生产服务器组",
            severity = "严重",
            contactGroup = "灰度值班组",
            enabled = true,
            repeatMinutes = 1
        }, CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
            await NotificationPlanner.EnsureStatesAsync(db, DateTimeOffset.UtcNow, CancellationToken);
            var firstCount = await db.NotificationDeliveryStates.CountAsync(CancellationToken);
            Assert.True(firstCount > 0);
            await NotificationPlanner.EnsureStatesAsync(db, DateTimeOffset.UtcNow.AddSeconds(1), CancellationToken);
            Assert.Equal(firstCount, await db.NotificationDeliveryStates.CountAsync(CancellationToken));
        }

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/notification-policies/{policyId}", CancellationToken)).StatusCode);
    }

    private static object ExtendedIngest(long sequence, double cpu, DateTimeOffset bootTime, string serviceStatus) => new
    {
        hostName = "TEST-TELEMETRY",
        sequence,
        collectedAt = DateTimeOffset.UtcNow,
        cpu,
        memory = 30,
        disk = 40,
        latency = 5,
        networkBytesPerSecond = 2048,
        bootTime,
        agentVersion = "1.0.0",
        services = new[] { new { name = "Spooler", status = serviceStatus } }
    };

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
            ["DevelopmentAuth:Password"] = AdminPassword,
            ["ProbeWorker:Enabled"] = "false",
            ["AgentHealth:Enabled"] = "false",
            ["NotificationWorker:Enabled"] = "false"
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
