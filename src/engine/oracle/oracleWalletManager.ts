import fs from 'fs';
import os from 'os';
import path from 'path';
import type { TnsAliasInfo } from '../../types/infrastructure.ts';
import type { TnsDiscoverySnapshot } from './oracleTypes.ts';

function isSafeExistingDirectory(candidate: string): boolean {
  if (!candidate || candidate.includes('\0')) return false;
  try {
    const resolved = path.resolve(candidate);
    if (!fs.existsSync(resolved)) return false;
    return fs.statSync(resolved).isDirectory();
  } catch {
    return false;
  }
}

export function resolveCandidateTnsDirectories(customDir?: string): {
  searched: string[];
  existing: string[];
  tnsAdminEnv?: string;
  oracleHomeEnv?: string;
} {
  const tnsAdminEnv = process.env.TNS_ADMIN?.trim() || undefined;
  const oracleHomeEnv = process.env.ORACLE_HOME?.trim() || undefined;
  const rawCandidates: string[] = [];

  if (customDir?.trim()) rawCandidates.push(customDir.trim());
  if (tnsAdminEnv) rawCandidates.push(tnsAdminEnv);
  if (oracleHomeEnv) rawCandidates.push(path.join(oracleHomeEnv, 'network', 'admin'));

  if (os.platform() === 'win32') {
    rawCandidates.push(
      'C:\\Oracle\\network\\admin',
      'C:\\app\\oracle\\product\\19c\\dbhome_1\\network\\admin',
      'C:\\oracle\\instantclient\\network\\admin',
      'C:\\instantclient\\network\\admin'
    );
  } else {
    rawCandidates.push(
      '/etc/oracle',
      '/usr/lib/oracle/21/client64/lib/network/admin',
      '/usr/lib/oracle/19.3/client64/lib/network/admin',
      '/opt/oracle/network/admin'
    );
  }

  const searched = Array.from(new Set(rawCandidates.map((d) => path.resolve(d))));
  const existing = searched.filter((d) => isSafeExistingDirectory(d));
  return { searched, existing, tnsAdminEnv, oracleHomeEnv };
}

/**
 * Strictly READ-ONLY parser for existing Oracle tnsnames.ora files.
 * Extracts top-level alias names and primary HOST/PORT/SERVICE_NAME/PROTOCOL metadata
 * without ever writing, modifying, or overwriting tnsnames.ora.
 */
export function parseTnsNamesContent(content: string, sourceFile: string): TnsAliasInfo[] {
  const results: TnsAliasInfo[] = [];
  const cleaned = content
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*$/, ''))
    .join('\n');

  let i = 0;
  const len = cleaned.length;

  while (i < len) {
    // Skip whitespace
    while (i < len && /\s/.test(cleaned[i])) i += 1;
    if (i >= len) break;

    // Look for ALIAS = ( ... )
    const eqIdx = cleaned.indexOf('=', i);
    if (eqIdx === -1) break;

    const lhs = cleaned.slice(i, eqIdx).trim();
    let j = eqIdx + 1;
    while (j < len && /\s/.test(cleaned[j])) j += 1;

    if (cleaned[j] !== '(') {
      i = eqIdx + 1;
      continue;
    }

    let depth = 0;
    const startBlock = j;
    while (j < len) {
      if (cleaned[j] === '(') depth += 1;
      else if (cleaned[j] === ')') {
        depth -= 1;
        if (depth === 0) {
          j += 1;
          break;
        }
      }
      j += 1;
    }

    const block = cleaned.slice(startBlock, j);
    i = j;

    if (!lhs || /\s|\(|\)/.test(lhs)) continue;
    // Handle comma-separated aliases like ALIAS1,ALIAS2 = (...)
    const aliasNames = lhs
      .split(',')
      .map((a) => a.trim())
      .filter((a) => /^[A-Za-z0-9._-]+$/.test(a));
    if (aliasNames.length === 0) continue;

    const hostMatch = /\bHOST\s*=\s*([^)\s]+)/i.exec(block);
    const portMatch = /\bPORT\s*=\s*(\d{1,5})/i.exec(block);
    const svcMatch = /\b(?:SERVICE_NAME|SID)\s*=\s*([^)\s]+)/i.exec(block);
    const protoMatch = /\bPROTOCOL\s*=\s*(TCPS|TCP)/i.exec(block);

    for (const alias of aliasNames) {
      results.push({
        alias,
        host: hostMatch?.[1],
        port: portMatch ? Number(portMatch[1]) : undefined,
        serviceName: svcMatch?.[1],
        protocol: protoMatch?.[1]?.toUpperCase() === 'TCPS' ? 'TCPS' : 'TCP',
        sourceFile,
      });
    }
  }

  return results;
}

export function inspectOracleWalletDir(walletDir?: string): {
  valid: boolean;
  resolvedPath?: string;
  hasAutoLoginSso: boolean;
  hasPkcs12Wallet: boolean;
  hasSqlnetOra: boolean;
  hasTnsnamesOra: boolean;
  error?: string;
} {
  if (!walletDir || !walletDir.trim()) {
    return {
      valid: false,
      hasAutoLoginSso: false,
      hasPkcs12Wallet: false,
      hasSqlnetOra: false,
      hasTnsnamesOra: false,
    };
  }
  const candidate = walletDir.trim();
  if (candidate.includes('\0') || candidate.length > 260) {
    return {
      valid: false,
      hasAutoLoginSso: false,
      hasPkcs12Wallet: false,
      hasSqlnetOra: false,
      hasTnsnamesOra: false,
      error: 'Invalid Oracle Wallet directory path.',
    };
  }
  const resolved = path.resolve(candidate);
  if (!isSafeExistingDirectory(resolved)) {
    return {
      valid: false,
      resolvedPath: resolved,
      hasAutoLoginSso: false,
      hasPkcs12Wallet: false,
      hasSqlnetOra: false,
      hasTnsnamesOra: false,
      error: `Oracle Wallet directory does not exist on the central monitoring server: ${resolved}`,
    };
  }
  const hasAutoLoginSso = fs.existsSync(path.join(resolved, 'cwallet.sso'));
  const hasPkcs12Wallet = fs.existsSync(path.join(resolved, 'ewallet.p12'));
  const hasSqlnetOra = fs.existsSync(path.join(resolved, 'sqlnet.ora'));
  const hasTnsnamesOra = fs.existsSync(path.join(resolved, 'tnsnames.ora'));
  return {
    valid: true,
    resolvedPath: resolved,
    hasAutoLoginSso,
    hasPkcs12Wallet,
    hasSqlnetOra,
    hasTnsnamesOra,
  };
}

export function discoverOracleTnsAndWallets(params?: {
  customTnsDir?: string;
  oracledbThinSupported?: boolean;
  oracledbThickInitialized?: boolean;
}): TnsDiscoverySnapshot {
  const dirs = resolveCandidateTnsDirectories(params?.customTnsDir);
  const aliases: TnsAliasInfo[] = [];
  const seenAliases = new Set<string>();
  const walletDirectoriesDetected: string[] = [];

  for (const dir of dirs.existing) {
    const tnsPath = path.join(dir, 'tnsnames.ora');
    if (fs.existsSync(tnsPath)) {
      try {
        const content = fs.readFileSync(tnsPath, 'utf8');
        const parsed = parseTnsNamesContent(content, tnsPath);
        for (const item of parsed) {
          if (!seenAliases.has(item.alias.toLowerCase())) {
            seenAliases.add(item.alias.toLowerCase());
            aliases.push(item);
          }
        }
      } catch {
        // Read error is non-fatal
      }
    }
    if (fs.existsSync(path.join(dir, 'cwallet.sso')) || fs.existsSync(path.join(dir, 'ewallet.p12'))) {
      walletDirectoriesDetected.push(dir);
    }
  }

  return {
    tnsAdminEnv: dirs.tnsAdminEnv,
    oracleHomeEnv: dirs.oracleHomeEnv,
    searchedDirectories: dirs.searched,
    existingDirectories: dirs.existing,
    aliases,
    walletDirectoriesDetected,
    oracledbThinSupported: params?.oracledbThinSupported ?? true,
    oracledbThickInitialized: params?.oracledbThickInitialized ?? false,
    checkedAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
  };
}
