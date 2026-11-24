export interface CodeArtifact {
  id: string;
  title: string;
  titleAr: string;
  filename: string;
  category: 'ASP.NET Core 8' | 'Oracle Read-Only SQL' | 'C# Collector' | 'DBA Approval DDL' | 'IIS Deployment';
  summary: string;
  summaryAr: string;
  code: string;
}

export const ENTERPRISE_ARTIFACTS: CodeArtifact[] = [
  {
    id: 'oracle-readonly',
    title: 'Oracle Read-Only Monitoring Queries (ODP.NET Safe)',
    titleAr: 'استعلامات مراقبة Oracle للقراءة فقط (بدون تعديل)',
    filename: 'sql/01_oracle_readonly_monitoring.sql',
    category: 'Oracle Read-Only SQL',
    summary:
      'Strictly SELECT-only queries against V$INSTANCE, V$SESSION, DBA_TABLESPACE_USAGE_METRICS, and V$SQL. Requires only SELECT_CATALOG_ROLE / CREATE SESSION.',
    summaryAr:
      'استعلامات SELECT فقط لقراءة الحالة والجلسات ومساحات الجداول والاستعلامات الطويلة بدون أي صلاحيات تعديل.',
    code: `-- ============================================================================
-- MedLabs IT Infrastructure Intelligence — Read-Only Oracle Monitoring Queries
-- Prerequisite: DBA grants CREATE SESSION + SELECT on required V$/DBA_ views.
-- NEVER execute ALTER SYSTEM, KILL SESSION, or DDL from monitoring collectors.
-- ============================================================================

-- 1. Database Instance Status & Availability Check
SELECT INSTANCE_NAME, HOST_NAME, VERSION, STATUS, DATABASE_STATUS,
       ROUND((SYSDATE - STARTUP_TIME) * 24, 2) AS UPTIME_HOURS
FROM V$INSTANCE;

-- 2. Active & Blocking Sessions Summary
SELECT COUNT(*) AS TOTAL_SESSIONS,
       SUM(CASE WHEN STATUS = 'ACTIVE' AND TYPE = 'USER' THEN 1 ELSE 0 END) AS ACTIVE_USER_SESSIONS,
       SUM(CASE WHEN BLOCKING_SESSION IS NOT NULL THEN 1 ELSE 0 END) AS BLOCKED_SESSIONS
FROM V$SESSION
WHERE TYPE = 'USER';

-- 3. Tablespace Utilization (%)
SELECT TABLESPACE_NAME,
       ROUND(USED_SPACE * 8192 / 1024 / 1024 / 1024, 2) AS USED_GB,
       ROUND(TABLESPACE_SIZE * 8192 / 1024 / 1024 / 1024, 2) AS MAX_GB,
       ROUND(USED_PERCENT, 2) AS USED_PCT
FROM DBA_TABLESPACE_USAGE_METRICS
ORDER BY USED_PERCENT DESC;

-- 4. Long-Running Active Queries (> 30 seconds)
SELECT s.SID, s.SERIAL#, s.USERNAME, s.MODULE, s.EVENT AS WAIT_EVENT,
       s.LAST_CALL_ET AS ELAPSED_SECONDS, s.SQL_ID
FROM V$SESSION s
WHERE s.STATUS = 'ACTIVE'
  AND s.TYPE = 'USER'
  AND s.LAST_CALL_ET > 30
ORDER BY s.LAST_CALL_ET DESC;`,
  },
  {
    id: 'oracle-ddl-approval',
    title: 'DBA-Approval Monitoring Schema Proposal (Optional)',
    titleAr: 'مقترح جداول المراقبة في Oracle (يُنفذ فقط بعد موافقة DBA)',
    filename: 'sql/02_dba_approval_schema_proposal.sql',
    category: 'DBA Approval DDL',
    summary:
      'Dedicated MEDLABS_MON schema proposal for historical telemetry, alert thresholds, incidents, and audit logs. Submit to MedLabs DBA for review prior to creation.',
    summaryAr:
      'تصميم الجداول التاريخية والتنبيهات وسجل التدقيق في Oracle لتقديمها لمسؤول قواعد البيانات للموافقة قبل الإنشاء.',
    code: `-- Submit to MedLabs Oracle DBA for review & approval before execution.
-- Target Schema: MEDLABS_MON (separate tablespace MEDLABS_MON_DATA)

CREATE TABLE MEDLABS_MON.MON_SERVER_METRICS (
  METRIC_ID       NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  HOSTNAME        VARCHAR2(128) NOT NULL,
  CPU_PCT         NUMBER(5,2)   NOT NULL,
  RAM_PCT         NUMBER(5,2)   NOT NULL,
  DISK_PCT        NUMBER(5,2)   NOT NULL,
  UPTIME_HOURS    NUMBER(10,2)  NOT NULL,
  COLLECTED_AT    TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL
);

CREATE INDEX MEDLABS_MON.IDX_SRV_HOST_TIME
  ON MEDLABS_MON.MON_SERVER_METRICS (HOSTNAME, COLLECTED_AT);

CREATE TABLE MEDLABS_MON.MON_INCIDENTS (
  INCIDENT_ID     VARCHAR2(32)  PRIMARY KEY,
  SEVERITY        VARCHAR2(20)  NOT NULL,
  STATUS          VARCHAR2(20)  NOT NULL,
  MODULE_NAME     VARCHAR2(40)  NOT NULL,
  ASSET_NAME      VARCHAR2(128) NOT NULL,
  SUMMARY         VARCHAR2(400) NOT NULL,
  ASSIGNED_TO     VARCHAR2(100),
  RESOLUTION_NOTE VARCHAR2(2000),
  DOWNTIME_MIN    NUMBER(10,2)  DEFAULT 0,
  CREATED_AT      TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
  RESOLVED_AT     TIMESTAMP WITH TIME ZONE
);

CREATE TABLE MEDLABS_MON.MON_AUDIT_LOG (
  AUDIT_ID        NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ACTOR_USERNAME  VARCHAR2(100) NOT NULL,
  ACTOR_ROLE      VARCHAR2(40)  NOT NULL,
  ACTION_NAME     VARCHAR2(120) NOT NULL,
  TARGET_RESOURCE VARCHAR2(200) NOT NULL,
  OUTCOME         VARCHAR2(20)  NOT NULL,
  EVENT_TIME      TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL
);`,
  },
  {
    id: 'dotnet-oracle-repo',
    title: 'ASP.NET Core 8 ODP.NET Repository (Read-Only)',
    titleAr: 'كود ASP.NET Core 8 للاتصال بقاعدة Oracle عبر ODP.NET',
    filename: 'backend/Repositories/OracleMonitoringRepository.cs',
    category: 'ASP.NET Core 8',
    summary:
      'Uses Oracle.ManagedDataAccess.Core (ODP.NET) with IConfiguration / environment variables—zero hardcoded credentials and strict command timeouts.',
    summaryAr:
      'مستودع بيانات يعتمد على ODP.NET لقراءة مؤشرات Oracle بأمان عبر متغيرات البيئة دون أي كلمات مرور مكتوبة في الكود.',
    code: `using Oracle.ManagedDataAccess.Client;
using Microsoft.Extensions.Configuration;

namespace MedLabs.Infrastructure.Api.Repositories;

public sealed class OracleMonitoringRepository
{
    private readonly string _connectionString;

    public OracleMonitoringRepository(IConfiguration configuration)
    {
        // Read exclusively from environment variable or Windows DPAPI / IIS protected config
        _connectionString = configuration.GetConnectionString("MedLabsOracleReadOnly")
            ?? Environment.GetEnvironmentVariable("ORACLE_CONNECTION_STRING")
            ?? throw new InvalidOperationException("Oracle connection string is not configured.");
    }

    public async Task<OracleHealthSnapshot> GetHealthSnapshotAsync(CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await using var conn = new OracleConnection(_connectionString);
        await conn.OpenAsync(ct);

        await using var cmd = conn.CreateCommand();
        cmd.CommandTimeout = 10; // Prevent excessive load on production DB
        cmd.CommandText = @"
            SELECT
                (SELECT STATUS FROM V$INSTANCE) AS DB_STATUS,
                (SELECT COUNT(*) FROM V$SESSION WHERE TYPE = 'USER' AND STATUS = 'ACTIVE') AS ACTIVE_SESS,
                (SELECT COUNT(*) FROM V$SESSION WHERE BLOCKING_SESSION IS NOT NULL) AS BLOCKED_SESS
            FROM DUAL";

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        await reader.ReadAsync(ct);
        sw.Stop();

        return new OracleHealthSnapshot(
            Status: reader.GetString(0),
            ActiveSessions: reader.GetInt32(1),
            BlockingSessions: reader.GetInt32(2),
            ResponseTimeMs: Math.Round(sw.Elapsed.TotalMilliseconds, 1),
            MeasuredAtUtc: DateTimeOffset.UtcNow
        );
    }
}

public record OracleHealthSnapshot(
    string Status,
    int ActiveSessions,
    int BlockingSessions,
    double ResponseTimeMs,
    DateTimeOffset MeasuredAtUtc);`,
  },
  {
    id: 'dotnet-program',
    title: 'ASP.NET Core 8 Security, JWT RBAC & Audit Setup',
    titleAr: 'إعداد الأمان والصلاحيات RBAC في ASP.NET Core 8',
    filename: 'backend/Program.cs',
    category: 'ASP.NET Core 8',
    summary:
      'Configures HTTPS enforcement, JWT role-based policies (Administrator, IT Manager, IT Engineer, Read-only Viewer), and ODP.NET health services.',
    summaryAr:
      'تهيئة HTTPS والمصادقة المعتمدة على الأدوار RBAC وسياسات الحماية في بوابة Web API.',
    code: `using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var jwtKey = Environment.GetEnvironmentVariable("MEDLABS_JWT_SIGNING_KEY")
    ?? throw new InvalidOperationException("Missing MEDLABS_JWT_SIGNING_KEY environment variable.");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "MedLabs.Infrastructure.Api",
            ValidAudience = "MedLabs.Infrastructure.Portal",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanManageUsers", p => p.RequireRole("Administrator"));
    options.AddPolicy("CanEditThresholds", p => p.RequireRole("Administrator", "IT Manager"));
    options.AddPolicy("CanTriageIncidents", p => p.RequireRole("Administrator", "IT Manager", "IT Engineer"));
    options.AddPolicy("CanViewDashboards", p => p.RequireRole("Administrator", "IT Manager", "IT Engineer", "Read-only Viewer"));
});

builder.Services.AddControllers();
var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();`,
  },
  {
    id: 'csharp-collector',
    title: 'Centralized Agentless Windows WMI/CIM Collector Reference',
    titleAr: 'مرجع السحب المركزي لويندوز عبر WMI/CIM (بدون وكيل)',
    filename: 'central-engine/WindowsWmiPoller.ps1',
    category: 'C# Collector',
    summary:
      'Runs exclusively on the central monitoring server using native New-CimSession (Wsman/DCOM) and Windows Integrated or encrypted read-only credentials—zero software installed on monitored servers.',
    summaryAr:
      'يعمل مركزياً على خادم المراقبة فقط عبر WMI/CIM/WinRM دون تثبيت أي برنامج أو خدمة على الخوادم المراقبة.',
    code: `# Executed ONLY on the central monitoring server (zero files or agents placed on target servers)
# Prerequisite on target Windows servers: Native WinRM (5985/5986) or WMI/DCOM (135) + Performance Monitor Users role.

$opt = New-CimSessionOption -Protocol Wsman
$session = New-CimSession -ComputerName $TargetHost -SessionOption $opt -OperationTimeoutSec 8
try {
    $os   = Get-CimInstance Win32_OperatingSystem -CimSession $session -Property Caption,TotalVisibleMemorySize,FreePhysicalMemory,LastBootUpTime
    $cpu  = Get-CimInstance Win32_Processor -CimSession $session -Property LoadPercentage
    $disk = Get-CimInstance Win32_LogicalDisk -CimSession $session -Filter "DriveType=3" -Property DeviceID,Size,FreeSpace
    $svc  = Get-CimInstance Win32_Service -CimSession $session -Property Name,DisplayName,State,StartMode
} finally {
    if ($session) { Remove-CimSession $session }
}`,
  },
  {
    id: 'iis-webconfig',
    title: 'IIS Deployment Configuration & HTTPS Security Headers',
    titleAr: 'ملف نشر التطبيق على خادم Windows Server / IIS',
    filename: 'deploy/web.config',
    category: 'IIS Deployment',
    summary:
      'Production IIS AspNetCoreModuleV2 configuration for hosting the ASP.NET Core 8 API alongside the built React Vite bundle.',
    summaryAr:
      'إعدادات IIS الرسمية لاستضافة واجهة React وخدمة ASP.NET Core 8 مع تفعيل التوجيه وترويسات الأمان.',
    code: `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
    </handlers>
    <aspNetCore processPath="dotnet"
                arguments=".\\MedLabs.Infrastructure.Api.dll"
                stdoutLogEnabled="true"
                stdoutLogFile=".\\logs\\stdout"
                hostingModel="inprocess" />
    <httpProtocol>
      <customHeaders>
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="X-Frame-Options" value="SAMEORIGIN" />
        <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>`,
  },
];
