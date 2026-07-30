using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class AgentEnrollmentTests
{
    [Fact]
    public async Task EnrollmentToken_IsSingleUse_AndInvalidatesLegacyKey()
    {
        using var issuerKey = RSA.Create(2048);
        var issuerRequest = new CertificateRequest($"CN=Agent Enrollment Test {Guid.NewGuid():N}", issuerKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        issuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var issuer = issuerRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        const string issuerPassword = "test-only-issuer-password";
        using var persistedIssuer = X509CertificateLoader.LoadPkcs12(issuer.Export(X509ContentType.Pfx, issuerPassword), issuerPassword,
            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(persistedIssuer);

        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var dbOptions = new DbContextOptionsBuilder<MonitoringDbContext>().UseSqlite(connection).Options;
        await using var db = new MonitoringDbContext(dbOptions);
        try
        {
            await db.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            await SecuritySchema.EnsureAsync(db);
            var host = new Host { Name = "MTLS-TEST", Ip = "10.9.0.5", Room = "测试", Service = "测试", Status = "未知", LastHeartbeatAt = DateTimeOffset.UtcNow };
            db.Hosts.Add(host);
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
            const string legacyKey = "legacy-agent-key-abcdefghijklmnopqrstuvwxyz";
            db.AgentCredentials.Add(new AgentCredential { HostId = host.Id, KeyHash = AgentKeyAuthenticationHandler.Hash(legacyKey), RotatedAt = DateTimeOffset.UtcNow });
            const string enrollmentToken = "one-time-enrollment-token-abcdefghijklmnopqrstuvwxyz";
            db.AgentEnrollmentTokens.Add(new AgentEnrollmentToken { HostId = host.Id, TokenHash = AgentEnrollmentService.HashToken(enrollmentToken), CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10) });
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);

            using var agentKey = RSA.Create(2048);
            var csr = new CertificateRequest("CN=MTLS-TEST", agentKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequestPem();
            var service = new AgentEnrollmentService(Options.Create(new AgentEnrollmentOptions
            {
                Enabled = true,
                IssuerCertificateSubject = persistedIssuer.GetNameInfo(X509NameType.SimpleName, false),
                IssuerCertificateSha256 = Convert.ToHexString(SHA256.HashData(persistedIssuer.RawData)),
                IssuerStoreLocation = StoreLocation.CurrentUser,
                IssuerStoreName = StoreName.My,
                CertificateDays = 7
            }), db);

            await Assert.ThrowsAsync<CryptographicException>(() => service.EnrollAsync(new AgentEnrollmentRequest(host.Name, new string('!', 128)), enrollmentToken, TestContext.Current.CancellationToken));
            var enrolled = await service.EnrollAsync(new AgentEnrollmentRequest(host.Name, csr), enrollmentToken, TestContext.Current.CancellationToken);
            Assert.NotNull(enrolled);
            Assert.Equal(64, enrolled.CertificateSha256.Length);
            var credential = await db.AgentCredentials.SingleAsync(TestContext.Current.CancellationToken);
            Assert.Equal(enrolled.CertificateSha256, credential.CertificateSha256);
            Assert.True(credential.RequireCertificate);
            Assert.NotEqual(AgentKeyAuthenticationHandler.Hash(legacyKey), credential.KeyHash);
            Assert.Null(await service.EnrollAsync(new AgentEnrollmentRequest(host.Name, csr), enrollmentToken, TestContext.Current.CancellationToken));

            const string rotationToken = "one-time-rotation-token-abcdefghijklmnopqrstuvwxyz";
            await db.AgentEnrollmentTokens.Where(item => item.HostId == host.Id).ExecuteUpdateAsync(updates => updates
                .SetProperty(item => item.TokenHash, AgentEnrollmentService.HashToken(rotationToken))
                .SetProperty(item => item.UsedAt, (DateTimeOffset?)null)
                .SetProperty(item => item.ExpiresAt, DateTimeOffset.UtcNow.AddMinutes(10)), TestContext.Current.CancellationToken);
            using var rotatedKey = RSA.Create(2048);
            var rotatedCsr = new CertificateRequest("CN=MTLS-TEST", rotatedKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequestPem();
            var rotated = await service.EnrollAsync(new AgentEnrollmentRequest(host.Name, rotatedCsr), rotationToken, TestContext.Current.CancellationToken);
            Assert.NotNull(rotated);
            await db.Entry(credential).ReloadAsync(TestContext.Current.CancellationToken);
            Assert.Equal(enrolled.CertificateSha256, credential.PreviousCertificateSha256);
            Assert.True(credential.PreviousCertificateValidUntil > DateTimeOffset.UtcNow);
            Assert.Equal(rotated.CertificateSha256, credential.CertificateSha256);
        }
        finally
        {
            store.Remove(persistedIssuer);
        }
    }
}
