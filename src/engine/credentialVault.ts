import crypto from 'crypto';
import type { CloudProviderId, CredentialKind, CredentialProfileSummary } from '../types/infrastructure.ts';

export interface DecryptedCredentialPayload {
  kind: CredentialKind;
  username?: string;
  password?: string;
  domain?: string;
  useIntegratedAuth?: boolean;
  privateKey?: string;
  passphrase?: string;
  cloudProvider?: CloudProviderId;
  cloudApiToken?: string;
  cloudBaseUrl?: string;
  ociUserOcid?: string;
  ociTenancyOcid?: string;
  ociFingerprint?: string;
  ociRegion?: string;
  ociProxyUrl?: string;
  ociAuthType?: 'api-key' | 'instance-principal' | 'resource-principal' | 'proxy-url';
  walletPassword?: string;
  community?: string;
  snmpSecurityLevel?: 'noAuthNoPriv' | 'authNoPriv' | 'authPriv';
  snmpAuthProtocol?: 'MD5' | 'SHA' | 'SHA256';
  snmpPrivProtocol?: 'DES' | 'AES';
  snmpPrivPassword?: string;
}

export interface EncryptedCredentialRecord {
  id: string;
  name: string;
  kind: CredentialKind;
  encryptedAt: string;
  // Public non-secret metadata (secrets are strictly inside ciphertext)
  username?: string;
  domain?: string;
  useIntegratedAuth?: boolean;
  hasPrivateKey?: boolean;
  cloudProvider?: CloudProviderId;
  cloudBaseUrl?: string;
  ociUserOcid?: string;
  ociTenancyOcid?: string;
  ociFingerprint?: string;
  ociRegion?: string;
  ociProxyUrl?: string;
  ociAuthType?: 'api-key' | 'instance-principal' | 'resource-principal' | 'proxy-url';
  snmpSecurityLevel?: 'noAuthNoPriv' | 'authNoPriv' | 'authPriv';
  snmpAuthProtocol?: 'MD5' | 'SHA' | 'SHA256';
  snmpPrivProtocol?: 'DES' | 'AES';
  // AES-256-GCM ciphertext bundle
  iv: string;
  tag: string;
  ciphertext: string;
}

export function maskSensitiveText(input: string): string {
  if (!input) return '';
  return input
    .replace(
      /(password|passwd|passphrase|wallet[_-]?password|pass|token|secret|authorization|bearer|api[_-]?key|signature)\s*[:=]\s*"?[^"\s,;]+"?/gi,
      '$1=[REDACTED]'
    )
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, '[PRIVATE_KEY_REDACTED]');
}

export class CredentialVault {
  private readonly key: Buffer;
  private readonly persistentKeyConfigured: boolean;
  private readonly records = new Map<string, EncryptedCredentialRecord>();

  constructor(masterSecret?: string) {
    const trimmed = masterSecret?.trim() || '';
    this.persistentKeyConfigured = trimmed.length > 0;
    const rawMaterial = this.persistentKeyConfigured ? trimmed : crypto.randomBytes(32).toString('hex');
    this.key = crypto.scryptSync(rawMaterial, 'medlabs-agentless-vault-v1', 32);
  }

  isPersistentKeyConfigured(): boolean {
    return this.persistentKeyConfigured;
  }

  loadSerializedRecords(items: EncryptedCredentialRecord[]): void {
    this.records.clear();
    for (const item of items) {
      if (item && typeof item.id === 'string' && typeof item.ciphertext === 'string') {
        this.records.set(item.id, item);
      }
    }
  }

  exportSerializedRecords(): EncryptedCredentialRecord[] {
    return Array.from(this.records.values());
  }

  private toSummary(r: EncryptedCredentialRecord): CredentialProfileSummary {
    return {
      id: r.id,
      name: r.name,
      kind: r.kind,
      username: r.username,
      domain: r.domain,
      useIntegratedAuth: r.useIntegratedAuth,
      hasPrivateKey: r.hasPrivateKey,
      cloudProvider: r.cloudProvider,
      cloudBaseUrl: r.cloudBaseUrl,
      ociUserOcid: r.ociUserOcid,
      ociTenancyOcid: r.ociTenancyOcid,
      ociFingerprint: r.ociFingerprint,
      ociRegion: r.ociRegion,
      ociProxyUrl: r.ociProxyUrl,
      ociAuthType: r.ociAuthType,
      snmpSecurityLevel: r.snmpSecurityLevel,
      snmpAuthProtocol: r.snmpAuthProtocol,
      snmpPrivProtocol: r.snmpPrivProtocol,
      encryptedAt: r.encryptedAt,
    };
  }

  listSummaries(): CredentialProfileSummary[] {
    return Array.from(this.records.values()).map((r) => this.toSummary(r));
  }

  saveCredential(
    input: {
      id?: string;
      name: string;
      kind: CredentialKind;
      payload: DecryptedCredentialPayload;
    }
  ): CredentialProfileSummary {
    const nextIdx =
      Array.from(this.records.keys()).reduce((max, id) => {
        const m = /^CRED-(\d+)$/i.exec(id);
        return m ? Math.max(max, Number(m[1])) : max;
      }, 0) + 1;

    const id = input.id && this.records.has(input.id) ? input.id : `CRED-${String(nextIdx).padStart(2, '0')}`;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    const jsonBytes = Buffer.from(JSON.stringify(input.payload), 'utf8');
    const encrypted = Buffer.concat([cipher.update(jsonBytes), cipher.final()]);
    const tag = cipher.getAuthTag();
    const encryptedAt = new Date().toISOString().replace('T', ' ').slice(0, 19);

    const record: EncryptedCredentialRecord = {
      id,
      name: input.name.trim().slice(0, 80),
      kind: input.kind,
      encryptedAt,
      username: input.payload.username ? input.payload.username.slice(0, 80) : undefined,
      domain: input.payload.domain ? input.payload.domain.slice(0, 80) : undefined,
      useIntegratedAuth: Boolean(input.payload.useIntegratedAuth),
      hasPrivateKey: Boolean(input.payload.privateKey && input.payload.privateKey.trim().length > 0),
      cloudProvider: input.payload.cloudProvider,
      cloudBaseUrl: input.payload.cloudBaseUrl ? input.payload.cloudBaseUrl.slice(0, 180) : undefined,
      ociUserOcid: input.payload.ociUserOcid ? input.payload.ociUserOcid.slice(0, 120) : undefined,
      ociTenancyOcid: input.payload.ociTenancyOcid ? input.payload.ociTenancyOcid.slice(0, 120) : undefined,
      ociFingerprint: input.payload.ociFingerprint ? input.payload.ociFingerprint.slice(0, 96) : undefined,
      ociRegion: input.payload.ociRegion ? input.payload.ociRegion.slice(0, 48) : undefined,
      ociProxyUrl: input.payload.ociProxyUrl ? input.payload.ociProxyUrl.slice(0, 180) : undefined,
      ociAuthType: input.payload.ociAuthType,
      snmpSecurityLevel: input.payload.snmpSecurityLevel,
      snmpAuthProtocol: input.payload.snmpAuthProtocol,
      snmpPrivProtocol: input.payload.snmpPrivProtocol,
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: encrypted.toString('base64'),
    };

    this.records.set(id, record);
    return this.toSummary(record);
  }

  getDecrypted(id?: string | null): { ok: true; payload: DecryptedCredentialPayload } | { ok: false; error: string } {
    if (!id) {
      return { ok: false, error: 'No credential profile attached.' };
    }
    const rec = this.records.get(id);
    if (!rec) {
      return { ok: false, error: `Credential profile ${id} not found.` };
    }
    try {
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        this.key,
        Buffer.from(rec.iv, 'base64')
      );
      decipher.setAuthTag(Buffer.from(rec.tag, 'base64'));
      const plain = Buffer.concat([
        decipher.update(Buffer.from(rec.ciphertext, 'base64')),
        decipher.final(),
      ]).toString('utf8');
      return { ok: true, payload: JSON.parse(plain) as DecryptedCredentialPayload };
    } catch {
      return {
        ok: false,
        error:
          'Stored credential could not be decrypted. Set persistent MEDLABS_VAULT_KEY in .env or re-save the credential profile.',
      };
    }
  }

  deleteCredential(id: string): boolean {
    return this.records.delete(id);
  }
}
