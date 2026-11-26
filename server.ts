import { formatMedLabsTimestamp } from './src/engine/time.ts';
import crypto from 'crypto';
import dotenv from 'dotenv';
import express, { NextFunction, Request, Response } from 'express';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { CredentialVault } from './src/engine/credentialVault.ts';
import { collectApiEndpoint, collectIisSite, testIisSiteConnection } from './src/engine/iisCollector.ts';
import { CentralMonitoringEngine } from './src/engine/monitoringEngine.ts';
import { collectNetworkDevice, testNetworkConnection } from './src/engine/networkCollector.ts';
import { collectPrintTarget } from './src/engine/printingCollector.ts';
import { isValidTargetHost } from './src/engine/networkHelpers.ts';
import { collectOracleDatabase, testOracleConnection } from './src/engine/oracleCollector.ts';
import { loadPersistedState, schedulePersistState } from './src/engine/persistenceStore.ts';
import { collectWindowsServer, detectProcessWindowsIdentity, testWindowsConnection } from './src/engine/windowsCollector.ts';
import {
  HISTORICAL_REPORTS,
  INITIAL_ALERTS,
  INITIAL_API_ENDPOINTS,
  INITIAL_APP_POOLS,
  INITIAL_AUDIT_LOGS,
  INITIAL_BACKUP_JOBS,
  INITIAL_COLLECTORS,
  INITIAL_IIS_SITES,
  INITIAL_NETWORK_DEVICES,
  INITIAL_ORACLE_DATABASES,
  INITIAL_THRESHOLDS,
  INITIAL_USERS,
  INITIAL_WINDOWS_SERVERS,
} from './src/data/medlabsData.ts';
import type {
  AlertRecord,
  AlertSeverity,
  ApiEndpointCheck,
  AuditLogEntry,
  CredentialKind,
  IisSite,
  IncidentStatus,
  NetworkDevice,
  OracleDatabaseMetric,
  PrintMonitorTarget,
  TimelineSample,
  UserAccount,
  UserRole,
  WindowsServer,
} from './src/types/infrastructure.ts';

dotenv.config();

const PORT = Number(process.env.PORT) || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

interface CredentialRecord {
  userId: string;
  username: string;
  salt: string;
  hash: string;
}

function hashPassword(password: string, existingSalt?: string): { salt: string; hash: string } {
  const salt = existingSalt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash: derived };
}

function verifyPassword(password: string, salt: string, expectedHash: string): boolean {
  const derived = crypto.scryptSync(password, salt, 64);
  const expectedBuf = Buffer.from(expectedHash, 'hex');
  if (derived.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(derived, expectedBuf);
}

interface SessionPayload {
  userId: string;
  username: string;
  fullName: string;
  role: UserRole;
  exp: number;
}

function signToken(payload: SessionPayload): string {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

function verifyToken(token: string): SessionPayload | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encoded, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as SessionPayload;
    if (!parsed.exp || parsed.exp < Date.now()) return null;
    return parsed;
  } catch {
    return null;
  }
}

const vault = new CredentialVault(process.env.MEDLABS_VAULT_KEY);

const persisted = loadPersistedState();
const state = {
  servers: persisted?.servers ?? structuredClone(INITIAL_WINDOWS_SERVERS),
  oracleDatabases: persisted?.oracleDatabases ?? structuredClone(INITIAL_ORACLE_DATABASES),
  iisSites: persisted?.iisSites ?? structuredClone(INITIAL_IIS_SITES),
  appPools: persisted?.appPools ?? structuredClone(INITIAL_APP_POOLS),
  apiEndpoints: persisted?.apiEndpoints ?? structuredClone(INITIAL_API_ENDPOINTS),
  networkDevices: persisted?.networkDevices ?? structuredClone(INITIAL_NETWORK_DEVICES),
  backups: persisted?.backups ?? structuredClone(INITIAL_BACKUP_JOBS),
  thresholds: persisted?.thresholds ?? structuredClone(INITIAL_THRESHOLDS),
  alerts: persisted?.alerts ?? structuredClone(INITIAL_ALERTS),
  collectors: persisted?.collectors?.length ? persisted.collectors : structuredClone(INITIAL_COLLECTORS),
  reports: persisted?.reports ?? structuredClone(HISTORICAL_REPORTS),
  printTargets: persisted?.printTargets ?? ([] as PrintMonitorTarget[]),
  reportExecutions: persisted?.reportExecutions ?? [],
  timeline: persisted?.timeline ?? ([] as TimelineSample[]),
  users: structuredClone(INITIAL_USERS) as UserAccount[],
  auditLogs: persisted?.auditLogs ?? (structuredClone(INITIAL_AUDIT_LOGS) as AuditLogEntry[]),
};

if (persisted?.credentials) {
  vault.loadSerializedRecords(persisted.credentials);
}

function persistNow() {
  schedulePersistState(() => ({
    servers: state.servers,
    oracleDatabases: state.oracleDatabases,
    iisSites: state.iisSites,
    appPools: state.appPools,
    apiEndpoints: state.apiEndpoints,
    networkDevices: state.networkDevices,
    backups: state.backups,
    thresholds: state.thresholds,
    alerts: state.alerts,
    collectors: state.collectors,
    reports: state.reports,
    printTargets: state.printTargets,
    reportExecutions: state.reportExecutions,
    timeline: state.timeline,
    auditLogs: state.auditLogs,
    credentials: vault.exportSerializedRecords(),
  }));
}

const engine = new CentralMonitoringEngine(state, vault, persistNow);

const credentials = new Map<string, CredentialRecord>();
const envAdminPasscode = process.env.MEDLABS_ADMIN_PASSCODE?.trim() || '';
let adminClaimed = false;

if (envAdminPasscode.length > 0) {
  const { salt, hash } = hashPassword(envAdminPasscode);
  credentials.set('admin.medlabs', {
    userId: 'USR-01',
    username: 'admin.medlabs',
    salt,
    hash,
  });
  adminClaimed = true;
}

function nowTimestamp(): string {
  return formatMedLabsTimestamp();
}

function appendAudit(
  actor: string,
  role: string,
  action: string,
  target: string,
  outcome: 'Success' | 'Denied',
  details: string
) {
  state.auditLogs.unshift({
    id: `AUD-${Math.floor(100 + Math.random() * 9000)}`,
    timestamp: nowTimestamp(),
    actor,
    role,
    action,
    target,
    outcome,
    details,
  });
  if (state.auditLogs.length > 250) {
    state.auditLogs.length = 250;
  }
  persistNow();
}

interface AuthedRequest extends Request {
  sessionUser?: SessionPayload;
}

function attachSession(req: AuthedRequest, _res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    const verified = verifyToken(token);
    if (verified) {
      req.sessionUser = verified;
    }
  }
  next();
}

function requireRole(allowedRoles: UserRole[]) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    const user = req.sessionUser;
    if (!user) {
      appendAudit('anonymous', 'None', 'UNAUTHORIZED_ACCESS', req.path, 'Denied', 'Missing or expired session token.');
      res.status(401).json({ error: 'Authentication required. Please sign in.' });
      return;
    }
    if (!allowedRoles.includes(user.role)) {
      appendAudit(
        user.username,
        user.role,
        'RBAC_FORBIDDEN',
        req.path,
        'Denied',
        `Role ${user.role} lacks permission (${allowedRoles.join(', ')} required).`
      );
      res.status(403).json({
        error: `Access denied for role "${user.role}". Required: ${allowedRoles.join(' or ')}.`,
      });
      return;
    }
    next();
  };
}

function nextPrefixedId(items: { id: string }[], prefix: string): string {
  const re = new RegExp(`^${prefix}-(\\d+)$`, 'i');
  const nextIdx =
    items.reduce((max, item) => {
      const m = re.exec(item.id);
      return m ? Math.max(max, Number(m[1])) : max;
    }, 0) + 1;
  return `${prefix}-${String(nextIdx).padStart(2, '0')}`;
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(attachSession);

  // ==================== AUTH ROUTES ====================
  app.get('/api/auth/status', (req: AuthedRequest, res: Response) => {
    res.json({
      adminClaimed,
      envManagedAdmin: envAdminPasscode.length > 0,
      user: req.sessionUser ?? null,
    });
  });

  app.post('/api/auth/claim-admin', (req: AuthedRequest, res: Response) => {
    if (adminClaimed || envAdminPasscode.length > 0) {
      res.status(409).json({ error: 'Initial administrator password has already been claimed.' });
      return;
    }
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (password.length < 8 || password.length > 128) {
      res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
      return;
    }

    const adminUser = state.users.find((u) => u.role === 'Administrator');
    if (!adminUser) {
      res.status(500).json({ error: 'Administrator account missing.' });
      return;
    }

    const { salt, hash } = hashPassword(password);
    credentials.set(adminUser.username, {
      userId: adminUser.id,
      username: adminUser.username,
      salt,
      hash,
    });
    adminClaimed = true;
    adminUser.lastLogin = nowTimestamp();

    const token = signToken({
      userId: adminUser.id,
      username: adminUser.username,
      fullName: adminUser.fullName,
      role: adminUser.role,
      exp: Date.now() + 8 * 60 * 60 * 1000,
    });

    appendAudit(
      adminUser.username,
      adminUser.role,
      'ADMIN_BOOTSTRAP_CLAIM',
      adminUser.username,
      'Success',
      'Initial Administrator credentials hashed with scrypt and claimed.'
    );

    res.json({
      token,
      user: {
        userId: adminUser.id,
        username: adminUser.username,
        fullName: adminUser.fullName,
        role: adminUser.role,
      },
    });
  });

  app.post('/api/auth/login', (req: AuthedRequest, res: Response) => {
    const username = typeof req.body?.username === 'string' ? req.body.username.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!username || !password) {
      res.status(400).json({ error: 'Username and password are required.' });
      return;
    }

    const user = state.users.find((u) => u.username.toLowerCase() === username);
    const cred = credentials.get(username);

    if (!user || !user.active || !cred || !verifyPassword(password, cred.salt, cred.hash)) {
      appendAudit(username || 'unknown', 'Unknown', 'AUTH_LOGIN_FAILED', username, 'Denied', 'Invalid credentials or inactive account.');
      res.status(401).json({ error: 'Invalid username or password.' });
      return;
    }

    user.lastLogin = nowTimestamp();
    const token = signToken({
      userId: user.id,
      username: user.username,
      fullName: user.fullName,
      role: user.role,
      exp: Date.now() + 8 * 60 * 60 * 1000,
    });

    appendAudit(user.username, user.role, 'AUTH_LOGIN', user.username, 'Success', 'Authenticated session started.');

    res.json({
      token,
      user: {
        userId: user.id,
        username: user.username,
        fullName: user.fullName,
        role: user.role,
      },
    });
  });

  // ==================== CENTRAL SNAPSHOT (NEVER EXPOSES CREDENTIAL SECRETS) ====================
  app.get('/api/infrastructure/snapshot', async (req: AuthedRequest, res: Response) => {
    const includeSecurity = req.sessionUser && ['Administrator', 'IT Manager'].includes(req.sessionUser.role);
    const canManageTargets =
      req.sessionUser && ['Administrator', 'IT Manager', 'IT Engineer'].includes(req.sessionUser.role);

    res.json({
      servers: state.servers,
      oracleDatabases: state.oracleDatabases,
      iisSites: state.iisSites,
      appPools: state.appPools,
      apiEndpoints: state.apiEndpoints,
      networkDevices: state.networkDevices,
      backups: state.backups,
      thresholds: state.thresholds,
      alerts: state.alerts,
      collectors: state.collectors,
      reports: state.reports,
      printTargets: state.printTargets,
      reportExecutions: state.reportExecutions,
      timeline: state.timeline,
      credentials: canManageTargets ? vault.listSummaries() : [],
      vaultPersistent: vault.isPersistentKeyConfigured(),
      processIdentity: canManageTargets ? await detectProcessWindowsIdentity(false) : null,
      users: includeSecurity ? state.users : state.users.map((u) => ({ ...u, email: 'restricted@medlabs.jo' })),
      auditLogs: includeSecurity ? state.auditLogs : [],
    });
  });

  app.get('/api/infrastructure/timeline', (req: AuthedRequest, res: Response) => {
    const requestedDate = typeof req.query?.date === 'string' ? req.query.date.trim().slice(0, 10) : '';
    const availableDates = Array.from(new Set(state.timeline.map((t) => t.date))).sort();
    const samples = requestedDate
      ? state.timeline.filter((t) => t.date === requestedDate)
      : state.timeline;
    res.json({
      date: requestedDate || null,
      availableDates,
      samples,
    });
  });

  app.get(
    '/api/servers/process-identity',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (_req: AuthedRequest, res: Response) => {
      const identity = await detectProcessWindowsIdentity(true);
      res.json(identity);
    }
  );

  // ==================== ENCRYPTED CREDENTIAL VAULT ROUTES ====================
  app.post(
    '/api/credentials',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const validKinds: CredentialKind[] = ['windows', 'oracle', 'snmpv2c', 'snmpv3', 'http'];
      const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 80) : '';
      const kind = validKinds.includes(req.body?.kind) ? (req.body.kind as CredentialKind) : null;
      if (!name || !kind) {
        res.status(400).json({ error: 'Valid credential profile name and type are required.' });
        return;
      }

      const username = typeof req.body?.username === 'string' ? req.body.username.trim().slice(0, 80) : undefined;
      const password = typeof req.body?.password === 'string' ? req.body.password.slice(0, 256) : undefined;
      const domain = typeof req.body?.domain === 'string' ? req.body.domain.trim().slice(0, 80) : undefined;
      const community = typeof req.body?.community === 'string' ? req.body.community.trim().slice(0, 64) : undefined;
      const useIntegratedAuth = Boolean(req.body?.useIntegratedAuth);
      const snmpSecurityLevel = ['noAuthNoPriv', 'authNoPriv', 'authPriv'].includes(req.body?.snmpSecurityLevel)
        ? req.body.snmpSecurityLevel
        : 'authPriv';
      const snmpAuthProtocol = ['MD5', 'SHA', 'SHA256'].includes(req.body?.snmpAuthProtocol)
        ? req.body.snmpAuthProtocol
        : 'SHA';
      const snmpPrivProtocol = ['DES', 'AES'].includes(req.body?.snmpPrivProtocol)
        ? req.body.snmpPrivProtocol
        : 'AES';
      const snmpPrivPassword =
        typeof req.body?.snmpPrivPassword === 'string' ? req.body.snmpPrivPassword.slice(0, 256) : undefined;

      if (kind === 'oracle' && (!username || !password)) {
        res.status(400).json({ error: 'Oracle read-only username and password are required.' });
        return;
      }
      if (kind === 'windows' && !useIntegratedAuth && (!username || !password)) {
        res.status(400).json({ error: 'Windows username/password or Integrated Auth is required.' });
        return;
      }
      if (kind === 'snmpv2c' && !community) {
        res.status(400).json({ error: 'SNMPv2c read-only community string is required.' });
        return;
      }
      if (kind === 'snmpv3' && !username) {
        res.status(400).json({ error: 'SNMPv3 USM username is required.' });
        return;
      }

      const effectivePassword = kind === 'windows' && useIntegratedAuth ? undefined : password;

      const summary = vault.saveCredential({
        name,
        kind,
        payload: {
          kind,
          username,
          password: effectivePassword,
          domain,
          useIntegratedAuth,
          community,
          snmpSecurityLevel,
          snmpAuthProtocol,
          snmpPrivProtocol,
          snmpPrivPassword,
        },
      });
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'CREDENTIAL_VAULT_SAVED',
        `${summary.id} (${summary.name})`,
        'Success',
        `Encrypted AES-256-GCM ${summary.kind} read-only profile stored.`
      );
      res.status(201).json(summary);
    }
  );

  app.delete(
    '/api/credentials/:id',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const deleted = vault.deleteCredential(req.params.id);
      if (!deleted) {
        res.status(404).json({ error: 'Credential profile not found.' });
        return;
      }
      for (const s of state.servers) if (s.credentialId === req.params.id) s.credentialId = undefined;
      for (const d of state.oracleDatabases) if (d.credentialId === req.params.id) d.credentialId = undefined;
      for (const n of state.networkDevices) if (n.credentialId === req.params.id) n.credentialId = undefined;
      for (const i of state.iisSites) if (i.credentialId === req.params.id) i.credentialId = undefined;
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'CREDENTIAL_VAULT_DELETED',
        req.params.id,
        'Success',
        'Removed encrypted credential profile.'
      );
      res.json({ deleted: req.params.id });
    }
  );

  // ==================== INCIDENTS & THRESHOLDS ====================
  app.post(
    '/api/incidents',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const validSeverities: AlertSeverity[] = ['Critical', 'High', 'Medium', 'Low', 'Information'];
      const validModules = ['Windows Server', 'Oracle DB', 'IIS & App', 'Network', 'Backup'] as const;

      const severity = validSeverities.includes(req.body?.severity) ? req.body.severity : 'Medium';
      const module = validModules.includes(req.body?.module) ? req.body.module : 'Windows Server';
      const assetName = typeof req.body?.assetName === 'string' ? req.body.assetName.trim().slice(0, 120) : '';
      const title = typeof req.body?.title === 'string' ? req.body.title.trim().slice(0, 200) : '';
      const description = typeof req.body?.description === 'string' ? req.body.description.trim().slice(0, 1000) : '';

      if (!assetName || !title) {
        res.status(400).json({ error: 'Asset name and incident summary are required.' });
        return;
      }

      const created: AlertRecord = {
        id: `INC-${Math.floor(4020 + Math.random() * 900)}`,
        timestamp: nowTimestamp(),
        severity,
        status: 'Open',
        module,
        assetId: assetName,
        assetName,
        title,
        titleAr: title,
        description: description || 'Logged manually by IT Operations.',
        descriptionAr: description || 'ØªÙ… ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¨Ù„Ø§Øº ÙŠØ¯ÙˆÙŠØ§Ù‹ Ø¨ÙˆØ§Ø³Ø·Ø© ÙØ±ÙŠÙ‚ Ø¹Ù…Ù„ÙŠØ§Øª ØªÙƒÙ†ÙˆÙ„ÙˆØ¬ÙŠØ§ Ø§Ù„Ù…Ø¹Ù„ÙˆÙ…Ø§Øª.',
        acknowledgedBy: null,
        assignedTo: typeof req.body?.assignedTo === 'string' ? req.body.assignedTo.trim().slice(0, 80) : null,
        resolutionNotes: '',
        downtimeMinutes: Number(req.body?.downtimeMinutes) >= 0 ? Number(req.body.downtimeMinutes) : 0,
        notifiedChannels: ['NOC Dashboard'],
      };

      state.alerts.unshift(created);
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'INCIDENT_CREATED',
        `${created.id} (${created.assetName})`,
        'Success',
        `Severity: ${created.severity}`
      );
      res.status(201).json(created);
    }
  );

  app.patch(
    '/api/incidents/:id',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const incident = state.alerts.find((a) => a.id === req.params.id);
      if (!incident) {
        res.status(404).json({ error: 'Incident not found.' });
        return;
      }

      const validStatuses: IncidentStatus[] = ['Open', 'Acknowledged', 'In Progress', 'Resolved'];
      if (typeof req.body?.status === 'string' && validStatuses.includes(req.body.status as IncidentStatus)) {
        incident.status = req.body.status as IncidentStatus;
        if (incident.status === 'Acknowledged' && !incident.acknowledgedBy) {
          incident.acknowledgedBy = req.sessionUser!.fullName;
        }
      }
      if (req.body?.acknowledge === true) {
        incident.acknowledgedBy = req.sessionUser!.fullName;
        if (incident.status === 'Open') incident.status = 'Acknowledged';
      }
      if (typeof req.body?.assignedTo === 'string') {
        incident.assignedTo = req.body.assignedTo.trim().slice(0, 80) || null;
      }
      if (typeof req.body?.resolutionNotes === 'string') {
        incident.resolutionNotes = req.body.resolutionNotes.trim().slice(0, 1000);
      }
      if (typeof req.body?.downtimeMinutes === 'number' && req.body.downtimeMinutes >= 0) {
        incident.downtimeMinutes = Math.round(req.body.downtimeMinutes);
      }

      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'INCIDENT_UPDATED',
        incident.id,
        'Success',
        `Status=${incident.status}, Assigned=${incident.assignedTo ?? 'Unassigned'}`
      );
      res.json(incident);
    }
  );

  app.patch(
    '/api/thresholds/:id',
    requireRole(['Administrator', 'IT Manager']),
    (req: AuthedRequest, res: Response) => {
      const threshold = state.thresholds.find((t) => t.id === req.params.id);
      if (!threshold) {
        res.status(404).json({ error: 'Threshold rule not found.' });
        return;
      }

      const warn = Number(req.body?.warningValue);
      const crit = Number(req.body?.criticalValue);
      if (!Number.isFinite(warn) || !Number.isFinite(crit) || warn <= 0 || crit <= warn) {
        res.status(400).json({ error: 'Warning threshold must be positive and strictly lower than critical threshold.' });
        return;
      }

      threshold.warningValue = warn;
      threshold.criticalValue = crit;
      threshold.updatedBy = req.sessionUser!.fullName;
      threshold.updatedAt = nowTimestamp();

      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'THRESHOLD_UPDATED',
        threshold.metricKey,
        'Success',
        `Warn=${warn}${threshold.unit}, Critical=${crit}${threshold.unit}`
      );
      res.json(threshold);
    }
  );

  // ==================== CENTRAL COLLECTOR SCHEDULER ROUTES ====================
  app.patch(
    '/api/collectors/:id',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const col = state.collectors.find((c) => c.id === req.params.id);
      if (!col) {
        res.status(404).json({ error: 'Collector not found.' });
        return;
      }

      let scheduleChanged = false;
      if (typeof req.body?.scheduleSeconds === 'number') {
        const sec = Math.round(req.body.scheduleSeconds);
        if (sec < 15 || sec > 86400) {
          res.status(400).json({ error: 'Schedule interval must be between 15s and 86400s.' });
          return;
        }
        col.scheduleSeconds = sec;
        scheduleChanged = true;
      }
      if (typeof req.body?.timeoutMs === 'number') {
        col.timeoutMs = Math.max(1000, Math.min(30000, Math.round(req.body.timeoutMs)));
      }
      if (typeof req.body?.retryCount === 'number') {
        col.retryCount = Math.max(0, Math.min(5, Math.round(req.body.retryCount)));
      }
      if (typeof req.body?.enabled === 'boolean') {
        col.enabled = req.body.enabled;
        col.status = col.enabled ? 'Healthy' : 'Paused';
        scheduleChanged = true;
      }
      if (scheduleChanged) {
        engine.rescheduleAll();
      }
      if (req.body?.runNow === true) {
        await engine.runCollector(col.id);
      } else {
        persistNow();
      }

      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'COLLECTOR_CONFIG_UPDATED',
        col.id,
        'Success',
        `Enabled=${col.enabled}, Interval=${col.scheduleSeconds}s, Timeout=${col.timeoutMs || 8000}ms`
      );
      res.json(col);
    }
  );

  // ==================== WINDOWS SERVERS (AGENTLESS WMI/CIM/SNMP) ====================
  app.post(
    '/api/servers',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const hostname = typeof req.body?.hostname === 'string' ? req.body.hostname.trim().slice(0, 64) : '';
      const ipAddress = typeof req.body?.ipAddress === 'string' ? req.body.ipAddress.trim().slice(0, 45) : '';
      const site = typeof req.body?.site === 'string' ? req.body.site.trim().slice(0, 80) : 'MedLabs Central';
      const role = typeof req.body?.role === 'string' ? req.body.role.trim().slice(0, 80) : 'Windows Server';
      const osVersion = typeof req.body?.osVersion === 'string' ? req.body.osVersion.trim().slice(0, 80) : 'Windows Server';
      const snmpCommunity = typeof req.body?.snmpCommunity === 'string' ? req.body.snmpCommunity.trim().slice(0, 64) : '';
      const credentialId = typeof req.body?.credentialId === 'string' ? req.body.credentialId.trim() : undefined;
      const authMode = ['integrated', 'credential', 'snmp-only'].includes(req.body?.authMode)
        ? req.body.authMode
        : credentialId
          ? 'credential'
          : 'integrated';

      if (!hostname || !ipAddress || !isValidTargetHost(ipAddress)) {
        res.status(400).json({ error: 'Valid hostname and IP address are required.' });
        return;
      }
      if (state.servers.some((s) => s.hostname.toLowerCase() === hostname.toLowerCase())) {
        res.status(409).json({ error: `Server ${hostname} is already registered.` });
        return;
      }

      const created: WindowsServer = {
        id: nextPrefixedId(state.servers, 'SRV'),
        hostname,
        role,
        roleAr: role,
        site,
        ipAddress,
        osVersion,
        status: 'Online',
        cpuPct: 0,
        ramPct: 0,
        ramTotalGb: 0,
        diskTotalGb: 0,
        diskAvailableGb: 0,
        diskPct: 0,
        uptimeHours: 0,
        lastCheck: 'Probing...',
        snmpCommunity: snmpCommunity || undefined,
        credentialId: credentialId || undefined,
        authMode,
        services: [],
        history: [],
      };

      state.servers.unshift(created);
      await collectWindowsServer(created, vault);
      engine.evaluateServerMetrics(created);
      persistNow();

      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'SERVER_REGISTERED',
        `${created.hostname} (${created.ipAddress})`,
        'Success',
        `Site=${created.site}, Status=${created.integrity?.collectionStatus || created.status}`
      );
      res.status(201).json(created);
    }
  );

  app.post(
    '/api/servers/poll-all',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      await engine.runCollector('COL-WIN');
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'SERVERS_LIVE_PROBE',
        `${state.servers.length} servers`,
        'Success',
        'Executed centralized agentless WMI/CIM/SNMP sweep across all Windows servers.'
      );
      res.json({ probed: state.servers.length, servers: state.servers });
    }
  );

  app.post(
    '/api/servers/poll-host',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const hostname = os.hostname();
      let srv = state.servers.find((s) => s.hostname.toLowerCase() === hostname.toLowerCase());
      if (!srv) {
        srv = {
          id: nextPrefixedId(state.servers, 'SRV'),
          hostname,
          role: 'Central Monitoring Server',
          roleAr: 'Ø®Ø§Ø¯Ù… Ø§Ù„Ù…Ø±Ø§Ù‚Ø¨Ø© Ø§Ù„Ù…Ø±ÙƒØ²ÙŠ',
          site: 'Local Hosting Server',
          ipAddress: '127.0.0.1',
          osVersion: `${os.type()} ${os.release()}`,
          status: 'Online',
          cpuPct: 0,
          ramPct: 0,
          ramTotalGb: 0,
          diskTotalGb: 0,
          diskAvailableGb: 0,
          diskPct: 0,
          uptimeHours: 0,
          lastCheck: nowTimestamp(),
          services: [],
          history: [],
        };
        state.servers.unshift(srv);
      }

      await collectWindowsServer(srv, vault);
      engine.evaluateServerMetrics(srv);
      persistNow();

      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'HOST_LIVE_POLL',
        srv.hostname,
        'Success',
        `CPU=${srv.cpuPct}%, RAM=${srv.ramPct}%, Disk=${srv.diskPct}%`
      );
      res.json(srv);
    }
  );

  app.post(
    '/api/servers/:id/test',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const srv = state.servers.find((s) => s.id === req.params.id);
      if (!srv) {
        res.status(404).json({ error: 'Server not found.' });
        return;
      }
      const result = await testWindowsConnection(srv, vault);
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'SERVER_CONNECTION_TEST',
        `${srv.hostname} (${srv.ipAddress})`,
        result.ok ? 'Success' : 'Denied',
        `${result.status}: ${result.details.slice(0, 120)}`
      );
      res.json(result);
    }
  );

  app.patch(
    '/api/servers/:id',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const srv = state.servers.find((s) => s.id === req.params.id);
      if (!srv) {
        res.status(404).json({ error: 'Server not found.' });
        return;
      }

      const hostname =
        typeof req.body?.hostname === 'string' ? req.body.hostname.trim().slice(0, 64) : srv.hostname;
      const ipAddress =
        typeof req.body?.ipAddress === 'string' ? req.body.ipAddress.trim().slice(0, 45) : srv.ipAddress;
      const site =
        typeof req.body?.site === 'string' ? req.body.site.trim().slice(0, 80) : srv.site;
      const role =
        typeof req.body?.role === 'string' ? req.body.role.trim().slice(0, 80) : srv.role;
      const snmpCommunity =
        typeof req.body?.snmpCommunity === 'string'
          ? req.body.snmpCommunity.trim().slice(0, 64)
          : srv.snmpCommunity || '';

      if (!hostname || !ipAddress || !site || !role || !isValidTargetHost(ipAddress)) {
        res.status(400).json({ error: 'Valid hostname, IP address, site, and role are required.' });
        return;
      }
      if (state.servers.some((s) => s.id !== srv.id && s.hostname.toLowerCase() === hostname.toLowerCase())) {
        res.status(409).json({ error: `Server ${hostname} is already registered.` });
        return;
      }

      srv.hostname = hostname;
      srv.ipAddress = ipAddress;
      srv.site = site;
      srv.role = role;
      srv.roleAr = role;
      srv.snmpCommunity = snmpCommunity || undefined;
      if (typeof req.body?.credentialId === 'string') {
        srv.credentialId = req.body.credentialId.trim() || undefined;
      }
      if (['integrated', 'credential', 'snmp-only'].includes(req.body?.authMode)) {
        srv.authMode = req.body.authMode;
      }

      await collectWindowsServer(srv, vault);
      engine.evaluateServerMetrics(srv);
      persistNow();

      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'SERVER_UPDATED',
        `${srv.hostname} (${srv.ipAddress})`,
        'Success',
        `Site=${srv.site}, Status=${srv.integrity?.collectionStatus || srv.status}`
      );
      res.json(srv);
    }
  );

  app.delete(
    '/api/servers/:id',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const idx = state.servers.findIndex((s) => s.id === req.params.id);
      if (idx === -1) {
        res.status(404).json({ error: 'Server not found.' });
        return;
      }
      const [removed] = state.servers.splice(idx, 1);
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'SERVER_DELETED',
        `${removed.hostname} (${removed.ipAddress})`,
        'Success',
        'Removed from monitored inventory'
      );
      res.json({ deleted: removed.id });
    }
  );

  app.patch(
    '/api/oracle/:id',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const db = state.oracleDatabases.find((d) => d.id === req.params.id);
      if (!db) {
        res.status(404).json({ error: 'Oracle target not found.' });
        return;
      }

      const body = req.body || {};
      const host = typeof body.host === 'string' ? body.host.trim().slice(0, 80) : db.host;
      const serviceName = typeof body.serviceName === 'string'
        ? body.serviceName.trim().slice(0, 64)
        : db.serviceName;
      const port = Number(body.port) || db.port || 1521;

      if (!host || !serviceName || !isValidTargetHost(host) || port < 1 || port > 65535) {
        res.status(400).json({ error: 'Valid Oracle host, port, and Service Name are required.' });
        return;
      }

      Object.assign(db, {
        host,
        serviceName,
        port,
        connectionType: body.connectionType === 'tns' ? 'tns' : 'direct',
        tnsAlias: body.tnsAlias,
        tnsAdminDir: body.tnsAdminDir,
        protocol: body.protocol === 'TCPS' ? 'TCPS' : 'TCP',
        walletDir: body.walletDir,
        role: body.role === 'Read-Only Standby' ? 'Read-Only Standby' : 'Primary',
        credentialId: body.credentialId,
        connectTimeoutMs: Number(body.connectTimeoutMs) || 8000,
        queryTimeoutMs: Number(body.queryTimeoutMs) || 8000,
        collectRmanBackups: body.collectRmanBackups === true,
        ociConfig: body.ociConfig,
        linuxConfig: body.linuxConfig,
        schedules: body.schedules,
      });

      const resCollect = await collectOracleDatabase(db, vault);
      if (resCollect.rmanBackups.length > 0) {
        state.backups.splice(0, state.backups.length, ...resCollect.rmanBackups);
      }

      persistNow();

      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'ORACLE_TARGET_UPDATED',
        `${host}:${port}/${serviceName}`,
        'Success',
        'Updated Oracle, OCI, and Linux configuration and re-polled.'
      );

      res.json(db);
    }
  );
  // ==================== ORACLE DATABASE ROUTES (THIN SELECT-ONLY) ====================
  app.post(
    '/api/oracle',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const host = typeof req.body?.host === 'string' ? req.body.host.trim().slice(0, 80) : '';
      const serviceName = typeof req.body?.serviceName === 'string' ? req.body.serviceName.trim().slice(0, 64) : '';
      const port = Number(req.body?.port) || 1521;
      const role = req.body?.role === 'Read-Only Standby' ? 'Read-Only Standby' : 'Primary';
      const credentialId = typeof req.body?.credentialId === 'string' ? req.body.credentialId.trim() : undefined;

      if (!host || !serviceName || !isValidTargetHost(host) || port < 1 || port > 65535) {
        res.status(400).json({ error: 'Valid Oracle host, port, and Service Name are required.' });
        return;
      }

      const created: OracleDatabaseMetric = {
        id: nextPrefixedId(state.oracleDatabases, 'ORA'),
        serviceName,
        host,
        port,
        credentialId: credentialId || undefined,
        role,
        status: 'Offline',
        availabilityPct: 0,
        responseTimeMs: 0,
        activeSessions: 0,
        totalSessions: 0,
        blockingSessions: 0,
        connectionFailures24h: 0,
        cpuUsagePct: 0,
        sgaUsedPct: 0,
        pgaUsedMb: 0,
        dbSizeGb: 0,
        lastCheck: 'Probing...',
        tablespaces: [],
        longRunningQueries: [],
        topWaitEvents: [],
        responseHistory: [],
      };

      state.oracleDatabases.unshift(created);
      const resCollect = await collectOracleDatabase(created, vault);
      if (resCollect.rmanBackups.length > 0) {
        state.backups.splice(0, state.backups.length, ...resCollect.rmanBackups);
      }
      persistNow();

      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'ORACLE_TARGET_REGISTERED',
        `${host}:${port}/${serviceName}`,
        'Success',
        `Status=${created.integrity?.collectionStatus || created.status}`
      );
      res.status(201).json(created);
    }
  );

  app.post(
    '/api/oracle/:id/test',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const db = state.oracleDatabases.find((d) => d.id === req.params.id);
      if (!db) {
        res.status(404).json({ error: 'Oracle target not found.' });
        return;
      }
      const result = await testOracleConnection(db, vault);
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'ORACLE_CONNECTION_TEST',
        `${db.host}:${db.port || 1521}/${db.serviceName}`,
        result.ok ? 'Success' : 'Denied',
        `${result.status}: ${result.details.slice(0, 120)}`
      );
      res.json(result);
    }
  );

  app.post(
    '/api/oracle/poll-all',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      await engine.runCollector('COL-ORA');
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'ORACLE_POLL_ALL',
        `${state.oracleDatabases.length} databases`,
        'Success',
        'Executed centralized read-only SELECT sweep across registered Oracle targets.'
      );
      res.json({ polled: state.oracleDatabases.length });
    }
  );

  app.delete(
    '/api/oracle/:id',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const idx = state.oracleDatabases.findIndex((d) => d.id === req.params.id);
      if (idx === -1) {
        res.status(404).json({ error: 'Oracle target not found.' });
        return;
      }
      const [removed] = state.oracleDatabases.splice(idx, 1);
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'ORACLE_TARGET_DELETED',
        `${removed.host}/${removed.serviceName}`,
        'Success',
        'Removed Oracle database target.'
      );
      res.json({ deleted: removed.id });
    }
  );

  // ==================== NETWORK DEVICES (ICMP / TCP / SNMPv2c / SNMPv3) ====================
  app.post(
    '/api/network',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 80) : '';
      const ipAddress = typeof req.body?.ipAddress === 'string' ? req.body.ipAddress.trim().slice(0, 64) : '';
      const site = typeof req.body?.site === 'string' ? req.body.site.trim().slice(0, 80) : 'MedLabs Central';
      const validTypes: NetworkDevice['type'][] = ['Core Firewall', 'L3 Switch', 'SD-WAN Gateway', 'Branch Router'];
      const type = validTypes.includes(req.body?.type) ? req.body.type : 'L3 Switch';
      const credentialId = typeof req.body?.credentialId === 'string' ? req.body.credentialId.trim() : undefined;
      const tcpPorts = Array.isArray(req.body?.tcpPorts)
        ? req.body.tcpPorts.map(Number).filter((p: number) => Number.isInteger(p) && p >= 1 && p <= 65535)
        : [22, 80, 443];

      if (!name || !ipAddress || !isValidTargetHost(ipAddress)) {
        res.status(400).json({ error: 'Valid device name and IP/hostname are required.' });
        return;
      }

      const created: NetworkDevice = {
        id: nextPrefixedId(state.networkDevices, 'NET'),
        name,
        type,
        site,
        ipAddress,
        snmpEnabled: Boolean(credentialId),
        snmpVersion: credentialId ? 'v2c' : 'none',
        credentialId: credentialId || undefined,
        tcpPorts,
        openPorts: [],
        status: 'Online',
        latencyMs: 0,
        packetLossPct: 0,
        uptimePct30d: 100,
        lastCheck: 'Probing...',
        interfaces: [],
        latencyHistory: [],
      };

      state.networkDevices.unshift(created);
      await collectNetworkDevice(created, vault);
      persistNow();

      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'NETWORK_DEVICE_ADDED',
        `${name} (${ipAddress})`,
        'Success',
        `Status=${created.integrity?.collectionStatus || created.status}`
      );
      res.status(201).json(created);
    }
  );

  app.post(
    '/api/network/:id/test',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const dev = state.networkDevices.find((d) => d.id === req.params.id);
      if (!dev) {
        res.status(404).json({ error: 'Network device not found.' });
        return;
      }
      const result = await testNetworkConnection(dev, vault);
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'NETWORK_CONNECTION_TEST',
        `${dev.name} (${dev.ipAddress})`,
        result.ok ? 'Success' : 'Denied',
        `${result.status}: ${result.details.slice(0, 120)}`
      );
      res.json(result);
    }
  );

  app.post(
    '/api/network/poll-all',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      await engine.runCollector('COL-NET');
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'NETWORK_POLL_ALL',
        `${state.networkDevices.length} devices`,
        'Success',
        'Executed ICMP, TCP, and SNMPv2c/v3 IF-MIB sweep.'
      );
      res.json({ polled: state.networkDevices.length });
    }
  );

  app.delete(
    '/api/network/:id',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const idx = state.networkDevices.findIndex((d) => d.id === req.params.id);
      if (idx === -1) {
        res.status(404).json({ error: 'Network device not found.' });
        return;
      }
      const [removed] = state.networkDevices.splice(idx, 1);
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'NETWORK_DEVICE_DELETED',
        `${removed.name} (${removed.ipAddress})`,
        'Success',
        'Removed network target.'
      );
      res.json({ deleted: removed.id });
    }
  );

  // ==================== PRINTING & REPORT MONITORING ====================
  app.post(
    '/api/printing/printers',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 100) : '';
      const hostOrIp = typeof req.body?.hostOrIp === 'string' ? req.body.hostOrIp.trim().slice(0, 253) : '';
      const site = typeof req.body?.site === 'string' ? req.body.site.trim().slice(0, 100) : 'MedLabs Central';
      const protocols: PrintMonitorTarget['protocol'][] = ['RAW-9100', 'IPP-631', 'LPD-515', 'Windows-Spooler'];
      const protocol = protocols.includes(req.body?.protocol) ? req.body.protocol : null;
      const port = Number(req.body?.port);
      const spoolerHost = typeof req.body?.spoolerHost === 'string'
        ? req.body.spoolerHost.trim().slice(0, 253)
        : '';

      if (!name || !hostOrIp || !isValidTargetHost(hostOrIp) || !protocol ||
          !Number.isInteger(port) || port < 1 || port > 65535 ||
          (spoolerHost && !isValidTargetHost(spoolerHost))) {
        res.status(400).json({ error: 'Valid printer name, host, protocol and port are required.' });
        return;
      }

      const created: PrintMonitorTarget = {
        id: nextPrefixedId(state.printTargets, 'PRN'),
        name,
        site: site || 'MedLabs Central',
        hostOrIp,
        protocol,
        port,
        spoolerHost: spoolerHost || undefined,
        status: 'Offline',
        responseTimeMs: null,
        queueDepth: null,
        failedJobs24h: null,
        printerStateLabel: 'Not tested',
        lastCheck: 'Not tested',
        tested: false,
      };

      // Registration only stores configuration. It does not probe the printer.
      state.printTargets.unshift(created);
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'PRINT_TARGET_ADDED',
        `${name} (${hostOrIp}:${port})`,
        'Success',
        'Printer registered without running a connection test.'
      );
      res.status(201).json(created);
    }
  );

  app.post(
    '/api/printing/printers/:id/test',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const printer = state.printTargets.find((p) => p.id === req.params.id);
      if (!printer) {
        res.status(404).json({ error: 'Printer target not found.' });
        return;
      }

      const outcome = await collectPrintTarget(printer, vault);
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'PRINT_TARGET_TEST',
        `${printer.name} (${printer.hostOrIp}:${printer.port})`,
        outcome.ok ? 'Success' : 'Denied',
        `${outcome.integrity.collectionStatus}: ${outcome.integrity.errorDetail || outcome.integrity.dataSource}`
      );
      res.json({
        ok: outcome.ok,
        status: outcome.integrity.collectionStatus,
        dataSource: outcome.integrity.dataSource,
        latencyMs: printer.responseTimeMs,
        measuredAt: outcome.integrity.measuredAt,
        details: outcome.ok
          ? `Printer ${printer.name} reachable in ${printer.responseTimeMs} ms${printer.queueDepth !== null ? ` · Queue=${printer.queueDepth}` : ''}.`
          : outcome.integrity.errorDetail || 'Printer unreachable.',
        prerequisiteHint: outcome.integrity.prerequisiteHint,
      });
    }
  );

  app.post(
    '/api/printing/poll-all',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      let tested = 0;
      let reachable = 0;
      for (const printer of state.printTargets) {
        const outcome = await collectPrintTarget(printer, vault);
        tested += 1;
        if (outcome.ok) reachable += 1;
      }
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'PRINT_TARGETS_POLL_ALL',
        `${tested} printers`,
        'Success',
        `Manual sweep completed. Reachable=${reachable}; Unreachable=${tested - reachable}.`
      );
      res.json({ polled: tested, reachable });
    }
  );

  app.delete(
    '/api/printing/printers/:id',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const idx = state.printTargets.findIndex((p) => p.id === req.params.id);
      if (idx === -1) {
        res.status(404).json({ error: 'Printer target not found.' });
        return;
      }
      const [removed] = state.printTargets.splice(idx, 1);
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'PRINT_TARGET_DELETED',
        `${removed.name} (${removed.hostOrIp})`,
        'Success',
        'Removed printer monitoring target.'
      );
      res.json({ deleted: removed.id });
    }
  );

  // ==================== IIS SITES & HTTP/HTTPS ENDPOINTS ====================
  app.post(
    '/api/iis/sites',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 80) : '';
      const url = typeof req.body?.url === 'string' ? req.body.url.trim().slice(0, 240) : '';
      const serverHostname =
        typeof req.body?.serverHostname === 'string' ? req.body.serverHostname.trim().slice(0, 80) : '';
      const appPoolName =
        typeof req.body?.appPoolName === 'string' ? req.body.appPoolName.trim().slice(0, 80) : 'DefaultAppPool';
      const credentialId = typeof req.body?.credentialId === 'string' ? req.body.credentialId.trim() : undefined;

      let validUrl = false;
      try {
        const parsed = new URL(url);
        validUrl = parsed.protocol === 'http:' || parsed.protocol === 'https:';
      } catch {
        validUrl = false;
      }

      if (!name || !validUrl) {
        res.status(400).json({ error: 'Valid site name and http:// or https:// URL are required.' });
        return;
      }

      const created: IisSite = {
        id: nextPrefixedId(state.iisSites, 'IIS'),
        name,
        serverHostname: serverHostname || new URL(url).hostname,
        url,
        appPoolName,
        credentialId: credentialId || undefined,
        httpStatus: 0,
        responseTimeMs: 0,
        availabilityPct: 100,
        httpErrors1h: 0,
        sslDaysRemaining: null,
        status: 'Online',
        lastCheck: 'Probing...',
      };

      state.iisSites.unshift(created);
      const resSite = await collectIisSite(created, vault);
      if (resSite.discoveredPools.length > 0) {
        state.appPools.splice(0, state.appPools.length, ...resSite.discoveredPools);
      }
      persistNow();

      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'IIS_SITE_REGISTERED',
        `${created.name} (${created.url})`,
        'Success',
        `HTTP=${created.httpStatus}, RTT=${created.responseTimeMs}ms`
      );
      res.status(201).json(created);
    }
  );

  app.post(
    '/api/iis/sites/:id/test',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const site = state.iisSites.find((s) => s.id === req.params.id);
      if (!site) {
        res.status(404).json({ error: 'IIS site target not found.' });
        return;
      }
      const result = await testIisSiteConnection(site, vault);
      res.json(result);
    }
  );

  app.delete(
    '/api/iis/sites/:id',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const idx = state.iisSites.findIndex((s) => s.id === req.params.id);
      if (idx === -1) {
        res.status(404).json({ error: 'IIS site not found.' });
        return;
      }
      const [removed] = state.iisSites.splice(idx, 1);
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'IIS_SITE_DELETED',
        removed.name,
        'Success',
        'Removed IIS site target.'
      );
      res.json({ deleted: removed.id });
    }
  );

  app.post(
    '/api/iis/endpoints',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 80) : '';
      const url = typeof req.body?.url === 'string' ? req.body.url.trim().slice(0, 240) : '';
      const method = req.body?.method === 'POST' ? 'POST' : 'GET';

      let validUrl = false;
      try {
        const parsed = new URL(url);
        validUrl = parsed.protocol === 'http:' || parsed.protocol === 'https:';
      } catch {
        validUrl = false;
      }
      if (!name || !validUrl) {
        res.status(400).json({ error: 'Valid endpoint name and http(s) URL are required.' });
        return;
      }

      const created: ApiEndpointCheck = {
        id: nextPrefixedId(state.apiEndpoints, 'API'),
        name,
        method,
        url,
        httpStatus: 0,
        responseTimeMs: 0,
        status: 'Online',
        lastCheck: 'Probing...',
      };
      state.apiEndpoints.unshift(created);
      await collectApiEndpoint(created);
      persistNow();
      res.status(201).json(created);
    }
  );

  app.delete(
    '/api/iis/endpoints/:id',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const idx = state.apiEndpoints.findIndex((a) => a.id === req.params.id);
      if (idx === -1) {
        res.status(404).json({ error: 'Endpoint not found.' });
        return;
      }
      const [removed] = state.apiEndpoints.splice(idx, 1);
      persistNow();
      res.json({ deleted: removed.id });
    }
  );

  app.post(
    '/api/iis/poll-all',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (_req: AuthedRequest, res: Response) => {
      await engine.runCollector('COL-IIS');
      res.json({ polled: state.iisSites.length + state.apiEndpoints.length });
    }
  );

  // ==================== USER MANAGEMENT (ADMINISTRATOR ONLY) ====================
  app.post(
    '/api/users',
    requireRole(['Administrator']),
    (req: AuthedRequest, res: Response) => {
      const validRoles: UserRole[] = ['Administrator', 'IT Manager', 'IT Engineer', 'Read-only Viewer'];
      const username = typeof req.body?.username === 'string' ? req.body.username.trim().toLowerCase() : '';
      const fullName = typeof req.body?.fullName === 'string' ? req.body.fullName.trim().slice(0, 80) : '';
      const email = typeof req.body?.email === 'string' ? req.body.email.trim().slice(0, 120) : '';
      const role = validRoles.includes(req.body?.role) ? (req.body.role as UserRole) : 'Read-only Viewer';
      const password = typeof req.body?.password === 'string' ? req.body.password : '';

      if (!username || !fullName || !email || password.length < 8) {
        res.status(400).json({ error: 'Username, fullName, email, and an 8+ char password are required.' });
        return;
      }
      if (state.users.some((u) => u.username.toLowerCase() === username)) {
        res.status(409).json({ error: 'Username already exists.' });
        return;
      }

      const newUser: UserAccount = {
        id: `USR-${Math.floor(10 + Math.random() * 90)}`,
        username,
        fullName,
        email,
        role,
        active: true,
        lastLogin: 'Never',
      };

      const { salt, hash } = hashPassword(password);
      credentials.set(username, { userId: newUser.id, username, salt, hash });
      state.users.push(newUser);

      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'USER_CREATED',
        `${newUser.username} (${newUser.role})`,
        'Success',
        'Account created with scrypt-hashed password.'
      );
      res.status(201).json(newUser);
    }
  );

  app.patch(
    '/api/users/:id',
    requireRole(['Administrator']),
    (req: AuthedRequest, res: Response) => {
      const targetUser = state.users.find((u) => u.id === req.params.id);
      if (!targetUser) {
        res.status(404).json({ error: 'User not found.' });
        return;
      }

      const validRoles: UserRole[] = ['Administrator', 'IT Manager', 'IT Engineer', 'Read-only Viewer'];
      if (typeof req.body?.role === 'string' && validRoles.includes(req.body.role as UserRole)) {
        targetUser.role = req.body.role as UserRole;
      }
      if (typeof req.body?.active === 'boolean') {
        targetUser.active = req.body.active;
      }

      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'USER_UPDATED',
        targetUser.username,
        'Success',
        `Role=${targetUser.role}, Active=${targetUser.active}`
      );
      res.json(targetUser);
    }
  );

  // Mount Vite middleware in development or static dist/ in production
  const isProd = process.env.NODE_ENV === 'production' && fs.existsSync(path.resolve('dist'));
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve('dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', async () => {
    console.log(`MedLabs IT Infrastructure Intelligence (Agentless Central Engine) running on http://0.0.0.0:${PORT}`);
    const procId = await detectProcessWindowsIdentity(true);
    console.log(
      `Central Process Security Context: ${procId.identityName} | Platform=${procId.platform} | DomainJoined=${procId.partOfDomain} | Auth=${procId.authenticationType} | KerberosTGT=${procId.kerberosTgtAvailable}${procId.doubleHopRisk ? ` | DoubleHopRisk=${procId.doubleHopReason}` : ''}`
    );
  });

  // Start independent centralized collectors & scheduler
  engine.start();
}

startServer();

