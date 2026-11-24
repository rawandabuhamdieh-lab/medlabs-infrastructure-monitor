import crypto from 'crypto';
import dgram from 'dgram';
import type { CollectionStatus, NetworkInterfaceStat } from './types/infrastructure.ts';

export interface SnmpServerMetrics {
  sysName?: string;
  osVersion?: string;
  uptimeHours?: number;
  cpuPct: number;
  ramPct: number;
  ramTotalGb: number;
  diskTotalGb: number;
  diskAvailableGb: number;
  diskPct: number;
}

export interface SnmpV3AuthConfig {
  version: 'v3';
  username: string;
  securityLevel: 'noAuthNoPriv' | 'authNoPriv' | 'authPriv';
  authProtocol?: 'MD5' | 'SHA' | 'SHA256';
  authPassword?: string;
  privProtocol?: 'DES' | 'AES';
  privPassword?: string;
}

export type SnmpTargetAuth =
  | { version: 'v2c'; community: string }
  | SnmpV3AuthConfig;

export interface SnmpNetworkResult {
  ok: boolean;
  status: CollectionStatus;
  sysName?: string;
  sysDescr?: string;
  uptimeHours?: number;
  interfaces: NetworkInterfaceStat[];
  errorDetail?: string;
}

interface SnmpVarBind {
  oid: string;
  tag: number;
  value: string | number | null;
}

function encodeLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function wrapTlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

function encodeInteger(val: number): Buffer {
  let n = Math.trunc(val);
  if (n === 0) return wrapTlv(0x02, Buffer.from([0]));
  const bytes: number[] = [];
  if (n > 0) {
    while (n > 0) {
      bytes.unshift(n & 0xff);
      n = Math.floor(n / 256);
    }
    if ((bytes[0] & 0x80) !== 0) bytes.unshift(0x00);
  } else {
    let comp = Math.abs(n) - 1;
    while (comp > 0 || bytes.length === 0) {
      bytes.unshift((~comp) & 0xff);
      comp = Math.floor(comp / 256);
    }
    if ((bytes[0] & 0x80) === 0) bytes.unshift(0xff);
  }
  return wrapTlv(0x02, Buffer.from(bytes));
}

function encodeOctetBytes(buf: Buffer): Buffer {
  return wrapTlv(0x04, buf);
}

function encodeOctetString(str: string): Buffer {
  return wrapTlv(0x04, Buffer.from(str, 'utf8'));
}

function encodeOid(oid: string): Buffer {
  const parts = oid.split('.').map((p) => Number(p));
  if (parts.length < 2 || parts.some((p) => !Number.isFinite(p) || p < 0)) {
    throw new Error(`Invalid OID: ${oid}`);
  }
  const out: number[] = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    if (v === 0) {
      out.push(0);
      continue;
    }
    const enc: number[] = [];
    while (v > 0) {
      enc.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    }
    for (let j = 0; j < enc.length - 1; j++) {
      enc[j] |= 0x80;
    }
    out.push(...enc);
  }
  return wrapTlv(0x06, Buffer.from(out));
}

export function buildSnmpPacket(
  pduTag: 0xa0 | 0xa1,
  community: string,
  requestId: number,
  oids: string[]
): Buffer {
  const varBindList = wrapTlv(
    0x30,
    Buffer.concat(
      oids.map((oid) => wrapTlv(0x30, Buffer.concat([encodeOid(oid), Buffer.from([0x05, 0x00])])))
    )
  );
  const pdu = wrapTlv(
    pduTag,
    Buffer.concat([
      encodeInteger(requestId),
      encodeInteger(0),
      encodeInteger(0),
      varBindList,
    ])
  );
  return wrapTlv(
    0x30,
    Buffer.concat([encodeInteger(1), encodeOctetString(community), pdu])
  );
}

function readLength(buf: Buffer, pos: number): { len: number; nextPos: number } {
  const first = buf[pos];
  if (first === undefined) throw new Error('Truncated ASN.1 length');
  if ((first & 0x80) === 0) {
    return { len: first, nextPos: pos + 1 };
  }
  const count = first & 0x7f;
  if (count === 0 || pos + 1 + count > buf.length) {
    throw new Error('Invalid ASN.1 length');
  }
  let len = 0;
  for (let i = 0; i < count; i++) {
    len = len * 256 + buf[pos + 1 + i];
  }
  return { len, nextPos: pos + 1 + count };
}

function readTlv(buf: Buffer, pos: number): { tag: number; value: Buffer; nextPos: number } {
  if (pos >= buf.length) throw new Error('Truncated ASN.1 TLV');
  const tag = buf[pos];
  const { len, nextPos } = readLength(buf, pos + 1);
  if (nextPos + len > buf.length) throw new Error('ASN.1 value exceeds buffer');
  return { tag, value: buf.subarray(nextPos, nextPos + len), nextPos: nextPos + len };
}

function decodeOid(buf: Buffer): string {
  if (buf.length === 0) return '';
  const first = buf[0];
  const arcs: number[] =
    first >= 80 ? [2, first - 80] : [Math.floor(first / 40), first % 40];
  let acc = 0;
  for (let i = 1; i < buf.length; i++) {
    const b = buf[i];
    acc = acc * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      arcs.push(acc);
      acc = 0;
    }
  }
  return arcs.join('.');
}

function decodeSignedInt(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const negative = (buf[0] & 0x80) !== 0;
  let val = 0;
  for (const b of buf) {
    val = val * 256 + (negative ? (~b & 0xff) : b);
  }
  return negative ? -(val + 1) : val;
}

function decodeUnsignedInt(buf: Buffer): number {
  let val = 0;
  for (const b of buf) {
    val = val * 256 + b;
  }
  return val;
}

function parseVarBindList(vbListValue: Buffer): SnmpVarBind[] {
  const varBinds: SnmpVarBind[] = [];
  let vPos = 0;
  while (vPos < vbListValue.length) {
    const item = readTlv(vbListValue, vPos);
    vPos = item.nextPos;
    const oidTlv = readTlv(item.value, 0);
    const valTlv = readTlv(item.value, oidTlv.nextPos);
    const oid = decodeOid(oidTlv.value);

    let decoded: string | number | null = null;
    if (valTlv.tag === 0x02) {
      decoded = decodeSignedInt(valTlv.value);
    } else if (valTlv.tag === 0x41 || valTlv.tag === 0x42 || valTlv.tag === 0x43 || valTlv.tag === 0x46) {
      decoded = decodeUnsignedInt(valTlv.value);
    } else if (valTlv.tag === 0x04) {
      decoded = valTlv.value.toString('utf8');
    } else if (valTlv.tag === 0x06) {
      decoded = decodeOid(valTlv.value);
    } else if (valTlv.tag === 0x05 || valTlv.tag === 0x80 || valTlv.tag === 0x81 || valTlv.tag === 0x82) {
      decoded = null;
    }

    varBinds.push({ oid, tag: valTlv.tag, value: decoded });
  }
  return varBinds;
}

export function parseSnmpResponse(buf: Buffer): {
  requestId: number;
  errorStatus: number;
  varBinds: SnmpVarBind[];
} {
  const outer = readTlv(buf, 0);
  if (outer.tag !== 0x30) throw new Error('Invalid SNMP message');

  const ver = readTlv(outer.value, 0);
  const comm = readTlv(outer.value, ver.nextPos);
  const pdu = readTlv(outer.value, comm.nextPos);

  const reqIdTlv = readTlv(pdu.value, 0);
  const errStatTlv = readTlv(pdu.value, reqIdTlv.nextPos);
  const errIdxTlv = readTlv(pdu.value, errStatTlv.nextPos);
  const vbListTlv = readTlv(pdu.value, errIdxTlv.nextPos);

  return {
    requestId: decodeSignedInt(reqIdTlv.value),
    errorStatus: decodeSignedInt(errStatTlv.value),
    varBinds: parseVarBindList(vbListTlv.value),
  };
}

// ==================== SNMPv3 USM Key Localization & Crypto (RFC 3414 / 3826) ====================
function hashAlgoName(proto: 'MD5' | 'SHA' | 'SHA256'): 'md5' | 'sha1' | 'sha256' {
  if (proto === 'MD5') return 'md5';
  if (proto === 'SHA256') return 'sha256';
  return 'sha1';
}

function passwordToKey(
  password: string,
  engineId: Buffer,
  proto: 'MD5' | 'SHA' | 'SHA256'
): Buffer {
  const alg = hashAlgoName(proto);
  const h = crypto.createHash(alg);
  const pwdBuf = Buffer.from(password, 'utf8');
  let count = 0;
  let idx = 0;
  const block = Buffer.alloc(64);
  while (count < 1_048_576) {
    for (let i = 0; i < 64; i++) {
      block[i] = pwdBuf[idx++ % pwdBuf.length];
    }
    h.update(block);
    count += 64;
  }
  const ku = h.digest();
  return crypto.createHash(alg).update(Buffer.concat([ku, engineId, ku])).digest();
}

function computeSnmpV3Hmac(
  authKey: Buffer,
  packetBytes: Buffer,
  proto: 'MD5' | 'SHA' | 'SHA256'
): Buffer {
  const alg = hashAlgoName(proto);
  const macLen = proto === 'SHA256' ? 24 : 12;
  return crypto.createHmac(alg, authKey).update(packetBytes).digest().subarray(0, macLen);
}

function buildUsmSecurityParams(params: {
  engineId: Buffer;
  engineBoots: number;
  engineTime: number;
  username: string;
  authParams: Buffer;
  privParams: Buffer;
}): Buffer {
  const seq = wrapTlv(
    0x30,
    Buffer.concat([
      encodeOctetBytes(params.engineId),
      encodeInteger(params.engineBoots),
      encodeInteger(params.engineTime),
      encodeOctetString(params.username),
      encodeOctetBytes(params.authParams),
      encodeOctetBytes(params.privParams),
    ])
  );
  return encodeOctetBytes(seq);
}

function encryptAes128Cfb(
  plain: Buffer,
  privKey: Buffer,
  engineBoots: number,
  engineTime: number,
  localSalt: Buffer
): { ciphertext: Buffer; privParams: Buffer } {
  const iv = Buffer.alloc(16);
  iv.writeUInt32BE(engineBoots >>> 0, 0);
  iv.writeUInt32BE(engineTime >>> 0, 4);
  localSalt.copy(iv, 8, 0, 8);
  const cipher = crypto.createCipheriv('aes-128-cfb', privKey.subarray(0, 16), iv);
  return {
    ciphertext: Buffer.concat([cipher.update(plain), cipher.final()]),
    privParams: localSalt,
  };
}

function decryptAes128Cfb(
  ciphertext: Buffer,
  privKey: Buffer,
  engineBoots: number,
  engineTime: number,
  privParams: Buffer
): Buffer {
  const iv = Buffer.alloc(16);
  iv.writeUInt32BE(engineBoots >>> 0, 0);
  iv.writeUInt32BE(engineTime >>> 0, 4);
  privParams.copy(iv, 8, 0, Math.min(8, privParams.length));
  const decipher = crypto.createDecipheriv('aes-128-cfb', privKey.subarray(0, 16), iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function sendUdpRaw(host: string, port: number, packet: Buffer, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    let done = false;
    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        socket.close();
        reject(new Error('SNMP timeout'));
      }
    }, timeoutMs);

    socket.on('error', (err) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        socket.close();
        reject(err);
      }
    });

    socket.on('message', (msg) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        socket.close();
        resolve(msg);
      }
    });

    socket.send(packet, port, host);
  });
}

function buildV3Message(opts: {
  msgId: number;
  flags: number;
  engineId: Buffer;
  engineBoots: number;
  engineTime: number;
  username: string;
  authPlaceholderLen: number;
  privParams: Buffer;
  scopedPduOrEncrypted: Buffer;
}): Buffer {
  const headerData = wrapTlv(
    0x30,
    Buffer.concat([
      encodeInteger(opts.msgId),
      encodeInteger(65507),
      encodeOctetBytes(Buffer.from([opts.flags])),
      encodeInteger(3), // USM security model
    ])
  );
  const secParams = buildUsmSecurityParams({
    engineId: opts.engineId,
    engineBoots: opts.engineBoots,
    engineTime: opts.engineTime,
    username: opts.username,
    authParams: Buffer.alloc(opts.authPlaceholderLen, 0),
    privParams: opts.privParams,
  });
  return wrapTlv(
    0x30,
    Buffer.concat([encodeInteger(3), headerData, secParams, opts.scopedPduOrEncrypted])
  );
}

interface V3SessionContext {
  engineId: Buffer;
  engineBoots: number;
  engineTime: number;
  authKey?: Buffer;
  privKey?: Buffer;
}

function parseV3Packet(buf: Buffer): {
  msgFlags: number;
  engineId: Buffer;
  engineBoots: number;
  engineTime: number;
  username: string;
  privParams: Buffer;
  scopedPayloadTag: number;
  scopedPayloadBytes: Buffer;
} {
  const outer = readTlv(buf, 0);
  const ver = readTlv(outer.value, 0);
  if (decodeSignedInt(ver.value) !== 3) throw new Error('Expected SNMPv3 response');
  const hdr = readTlv(outer.value, ver.nextPos);
  const secOctet = readTlv(outer.value, hdr.nextPos);
  const scoped = readTlv(outer.value, secOctet.nextPos);

  const msgId = readTlv(hdr.value, 0);
  const maxSz = readTlv(hdr.value, msgId.nextPos);
  const flags = readTlv(hdr.value, maxSz.nextPos);
  const msgFlags = flags.value[0] ?? 0;

  const usmSeq = readTlv(secOctet.value, 0);
  const engId = readTlv(usmSeq.value, 0);
  const boots = readTlv(usmSeq.value, engId.nextPos);
  const time = readTlv(usmSeq.value, boots.nextPos);
  const user = readTlv(usmSeq.value, time.nextPos);
  const auth = readTlv(usmSeq.value, user.nextPos);
  const priv = readTlv(usmSeq.value, auth.nextPos);

  return {
    msgFlags,
    engineId: engId.value,
    engineBoots: decodeSignedInt(boots.value),
    engineTime: decodeSignedInt(time.value),
    username: user.value.toString('utf8'),
    privParams: priv.value,
    scopedPayloadTag: scoped.tag,
    scopedPayloadBytes: scoped.value,
  };
}

let reqCounter = Math.floor(1000 + Math.random() * 50000);
function nextReqId(): number {
  reqCounter = (reqCounter + 1) & 0x7fffffff;
  if (reqCounter === 0) reqCounter = 1;
  return reqCounter;
}

async function discoverSnmpV3Engine(
  host: string,
  port: number,
  config: SnmpV3AuthConfig,
  timeoutMs: number
): Promise<V3SessionContext> {
  const scopedPdu = wrapTlv(
    0x30,
    Buffer.concat([
      encodeOctetBytes(Buffer.alloc(0)),
      encodeOctetBytes(Buffer.alloc(0)),
      wrapTlv(
        0xa0,
        Buffer.concat([
          encodeInteger(nextReqId()),
          encodeInteger(0),
          encodeInteger(0),
          wrapTlv(0x30, Buffer.alloc(0)),
        ])
      ),
    ])
  );
  const discoveryPkt = buildV3Message({
    msgId: nextReqId(),
    flags: 0x04, // reportable
    engineId: Buffer.alloc(0),
    engineBoots: 0,
    engineTime: 0,
    username: '',
    authPlaceholderLen: 0,
    privParams: Buffer.alloc(0),
    scopedPduOrEncrypted: scopedPdu,
  });

  const resp = await sendUdpRaw(host, port, discoveryPkt, timeoutMs);
  const parsed = parseV3Packet(resp);
  if (parsed.engineId.length === 0) {
    throw new Error('SNMPv3 engine discovery failed (empty engineID).');
  }

  const ctx: V3SessionContext = {
    engineId: parsed.engineId,
    engineBoots: parsed.engineBoots,
    engineTime: parsed.engineTime,
  };

  if (config.securityLevel !== 'noAuthNoPriv') {
    if (!config.authPassword) {
      throw new Error('SNMPv3 authentication password is missing.');
    }
    const authProto = config.authProtocol || 'SHA';
    ctx.authKey = passwordToKey(config.authPassword, ctx.engineId, authProto);

    if (config.securityLevel === 'authPriv') {
      if (!config.privPassword) {
        throw new Error('SNMPv3 privacy encryption password is missing.');
      }
      ctx.privKey = passwordToKey(config.privPassword, ctx.engineId, authProto);
    }
  }
  return ctx;
}

async function sendSnmpV3Udp(
  host: string,
  port: number,
  config: SnmpV3AuthConfig,
  ctx: V3SessionContext,
  pduTag: 0xa0 | 0xa1,
  oids: string[],
  timeoutMs: number
): Promise<SnmpVarBind[]> {
  const reqId = nextReqId();
  const msgId = nextReqId();
  const varBindList = wrapTlv(
    0x30,
    Buffer.concat(
      oids.map((oid) => wrapTlv(0x30, Buffer.concat([encodeOid(oid), Buffer.from([0x05, 0x00])])))
    )
  );
  const pdu = wrapTlv(
    pduTag,
    Buffer.concat([encodeInteger(reqId), encodeInteger(0), encodeInteger(0), varBindList])
  );
  const scopedPdu = wrapTlv(
    0x30,
    Buffer.concat([encodeOctetBytes(ctx.engineId), encodeOctetBytes(Buffer.alloc(0)), pdu])
  );

  const authProto = config.authProtocol || 'SHA';
  const authLen = config.securityLevel === 'noAuthNoPriv' ? 0 : authProto === 'SHA256' ? 24 : 12;
  let flags = 0x04;
  let privParams: Buffer = Buffer.alloc(0);
  let payloadSection: Buffer = scopedPdu;

  if (config.securityLevel !== 'noAuthNoPriv') flags |= 0x01;
  if (config.securityLevel === 'authPriv') {
    flags |= 0x02;
    if ((config.privProtocol || 'AES') !== 'AES') {
      throw new Error('Only AES-128 privacy is supported for SNMPv3 authPriv in pure Node.js mode.');
    }
    const enc = encryptAes128Cfb(
      scopedPdu,
      ctx.privKey!,
      ctx.engineBoots,
      ctx.engineTime,
      crypto.randomBytes(8)
    );
    privParams = enc.privParams;
    payloadSection = encodeOctetBytes(enc.ciphertext);
  }

  let packet = buildV3Message({
    msgId,
    flags,
    engineId: ctx.engineId,
    engineBoots: ctx.engineBoots,
    engineTime: ctx.engineTime,
    username: config.username,
    authPlaceholderLen: authLen,
    privParams,
    scopedPduOrEncrypted: payloadSection,
  });

  if (config.securityLevel !== 'noAuthNoPriv' && ctx.authKey) {
    const placeholder = Buffer.alloc(authLen, 0);
    const mac = computeSnmpV3Hmac(ctx.authKey, packet, authProto);
    const idx = packet.indexOf(Buffer.concat([Buffer.from([0x04, authLen]), placeholder]));
    if (idx !== -1) {
      mac.copy(packet, idx + 2);
    }
  }

  const rawResp = await sendUdpRaw(host, port, packet, timeoutMs);
  const parsed = parseV3Packet(rawResp);
  let scopedBuf = parsed.scopedPayloadTag === 0x30
    ? wrapTlv(0x30, parsed.scopedPayloadBytes)
    : parsed.scopedPayloadBytes;

  if ((parsed.msgFlags & 0x02) !== 0 && ctx.privKey && parsed.scopedPayloadTag === 0x04) {
    scopedBuf = decryptAes128Cfb(
      parsed.scopedPayloadBytes,
      ctx.privKey,
      parsed.engineBoots,
      parsed.engineTime,
      parsed.privParams
    );
  }

  const scopedSeq = readTlv(scopedBuf, 0);
  const ctxEng = readTlv(scopedSeq.value, 0);
  const ctxName = readTlv(scopedSeq.value, ctxEng.nextPos);
  const respPdu = readTlv(scopedSeq.value, ctxName.nextPos);

  if (respPdu.tag === 0xa8) {
    // Report PDU (e.g. usmStatsUnknownUserNames / usmStatsWrongDigests)
    const rId = readTlv(respPdu.value, 0);
    const errS = readTlv(respPdu.value, rId.nextPos);
    const errI = readTlv(respPdu.value, errS.nextPos);
    const vbl = readTlv(respPdu.value, errI.nextPos);
    const vbs = parseVarBindList(vbl.value);
    const reportOid = vbs[0]?.oid || '';
    if (
      reportOid.startsWith('1.3.6.1.6.3.15.1.1.3') || // unknown user
      reportOid.startsWith('1.3.6.1.6.3.15.1.1.5') || // wrong digest
      reportOid.startsWith('1.3.6.1.6.3.15.1.1.1')    // unsupported sec level
    ) {
      throw new Error(`SNMPv3 Authentication Failed (USM report ${reportOid})`);
    }
    throw new Error(`SNMPv3 USM Report (${reportOid})`);
  }

  const respReqId = readTlv(respPdu.value, 0);
  const errStat = readTlv(respPdu.value, respReqId.nextPos);
  const errIdx = readTlv(respPdu.value, errStat.nextPos);
  const vbList = readTlv(respPdu.value, errIdx.nextPos);
  const errCode = decodeSignedInt(errStat.value);
  if (errCode !== 0) {
    throw new Error(`SNMP errorStatus=${errCode}`);
  }
  return parseVarBindList(vbList.value);
}

function sendSnmpUdp(
  host: string,
  port: number,
  community: string,
  pduTag: 0xa0 | 0xa1,
  oids: string[],
  timeoutMs = 1500
): Promise<SnmpVarBind[]> {
  return new Promise((resolve, reject) => {
    const reqId = nextReqId();
    const packet = buildSnmpPacket(pduTag, community, reqId, oids);
    const socket = dgram.createSocket('udp4');
    let done = false;

    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        socket.close();
        reject(new Error('SNMP timeout'));
      }
    }, timeoutMs);

    socket.on('error', (err) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        socket.close();
        reject(err);
      }
    });

    socket.on('message', (msg) => {
      if (done) return;
      try {
        const parsed = parseSnmpResponse(msg);
        if (parsed.requestId !== reqId) return;
        done = true;
        clearTimeout(timer);
        socket.close();
        if (parsed.errorStatus !== 0) {
          reject(new Error(`SNMP errorStatus=${parsed.errorStatus}`));
          return;
        }
        resolve(parsed.varBinds);
      } catch (err) {
        done = true;
        clearTimeout(timer);
        socket.close();
        reject(err);
      }
    });

    socket.send(packet, port, host);
  });
}

async function snmpGetWithAuth(
  host: string,
  port: number,
  auth: SnmpTargetAuth,
  oids: string[],
  v3Ctx: V3SessionContext | null,
  timeoutMs: number
): Promise<SnmpVarBind[]> {
  if (auth.version === 'v2c') {
    return sendSnmpUdp(host, port, auth.community, 0xa0, oids, timeoutMs);
  }
  return sendSnmpV3Udp(host, port, auth, v3Ctx!, 0xa0, oids, timeoutMs);
}

async function snmpWalkWithAuth(
  host: string,
  port: number,
  auth: SnmpTargetAuth,
  baseOid: string,
  v3Ctx: V3SessionContext | null,
  timeoutMs: number,
  maxVars = 64
): Promise<SnmpVarBind[]> {
  const results: SnmpVarBind[] = [];
  let cursor = baseOid;
  for (let i = 0; i < maxVars; i++) {
    const vbs =
      auth.version === 'v2c'
        ? await sendSnmpUdp(host, port, auth.community, 0xa1, [cursor], timeoutMs)
        : await sendSnmpV3Udp(host, port, auth, v3Ctx!, 0xa1, [cursor], timeoutMs);
    if (vbs.length === 0) break;
    const vb = vbs[0];
    if (vb.tag === 0x82 || vb.oid === cursor || !vb.oid.startsWith(`${baseOid}.`)) {
      break;
    }
    results.push(vb);
    cursor = vb.oid;
  }
  return results;
}

export async function pollSnmpServerMetrics(
  host: string,
  communityOrAuth: string | SnmpTargetAuth,
  port = 161,
  timeoutMs = 1500
): Promise<SnmpServerMetrics | null> {
  const auth: SnmpTargetAuth =
    typeof communityOrAuth === 'string'
      ? { version: 'v2c', community: communityOrAuth }
      : communityOrAuth;

  if (auth.version === 'v2c' && !auth.community.trim()) return null;

  try {
    const v3Ctx =
      auth.version === 'v3' ? await discoverSnmpV3Engine(host, port, auth, timeoutMs) : null;

    const basic = await snmpGetWithAuth(
      host,
      port,
      auth,
      [
        '1.3.6.1.2.1.1.1.0', // sysDescr
        '1.3.6.1.2.1.1.3.0', // sysUpTime
        '1.3.6.1.2.1.1.5.0', // sysName
        '1.3.6.1.2.1.25.1.1.0', // hrSystemUptime
      ],
      v3Ctx,
      timeoutMs
    );

    const sysDescr = typeof basic[0]?.value === 'string' ? basic[0].value : undefined;
    const sysUpTicks = typeof basic[1]?.value === 'number' ? basic[1].value : undefined;
    const sysName = typeof basic[2]?.value === 'string' ? basic[2].value : undefined;
    const hrUpTicks = typeof basic[3]?.value === 'number' ? basic[3].value : undefined;

    const upTicks = hrUpTicks ?? sysUpTicks;
    const uptimeHours = typeof upTicks === 'number' ? Math.round(upTicks / 360_000) : undefined;

    const cpuRows = await snmpWalkWithAuth(
      host,
      port,
      auth,
      '1.3.6.1.2.1.25.3.3.1.2',
      v3Ctx,
      timeoutMs,
      64
    );
    const cpuValues = cpuRows
      .map((r) => (typeof r.value === 'number' ? r.value : null))
      .filter((n): n is number => n !== null && n >= 0 && n <= 100);
    const cpuPct =
      cpuValues.length > 0
        ? Number((cpuValues.reduce((a, b) => a + b, 0) / cpuValues.length).toFixed(1))
        : 0;

    const [stTypes, stUnits, stSizes, stUsed] = await Promise.all([
      snmpWalkWithAuth(host, port, auth, '1.3.6.1.2.1.25.2.3.1.2', v3Ctx, timeoutMs, 64),
      snmpWalkWithAuth(host, port, auth, '1.3.6.1.2.1.25.2.3.1.4', v3Ctx, timeoutMs, 64),
      snmpWalkWithAuth(host, port, auth, '1.3.6.1.2.1.25.2.3.1.5', v3Ctx, timeoutMs, 64),
      snmpWalkWithAuth(host, port, auth, '1.3.6.1.2.1.25.2.3.1.6', v3Ctx, timeoutMs, 64),
    ]);

    const mapByIndex = (rows: SnmpVarBind[]) => {
      const m = new Map<string, string | number | null>();
      for (const r of rows) {
        const idx = r.oid.split('.').pop();
        if (idx) m.set(idx, r.value);
      }
      return m;
    };

    const types = mapByIndex(stTypes);
    const units = mapByIndex(stUnits);
    const sizes = mapByIndex(stSizes);
    const useds = mapByIndex(stUsed);

    let ramTotalBytes = 0;
    let ramUsedBytes = 0;
    let diskTotalBytes = 0;
    let diskUsedBytes = 0;

    for (const [idx, typeOid] of types.entries()) {
      const unit = Number(units.get(idx) ?? 0);
      const size = Number(sizes.get(idx) ?? 0);
      const used = Number(useds.get(idx) ?? 0);
      if (!Number.isFinite(unit) || !Number.isFinite(size) || unit <= 0 || size <= 0) continue;

      const totalB = unit * size;
      const usedB = Math.max(0, Math.min(totalB, unit * used));

      if (typeOid === '1.3.6.1.2.1.25.2.1.2') {
        ramTotalBytes += totalB;
        ramUsedBytes += usedB;
      } else if (typeOid === '1.3.6.1.2.1.25.2.1.4') {
        diskTotalBytes += totalB;
        diskUsedBytes += usedB;
      }
    }

    const ramTotalGb = ramTotalBytes > 0 ? Number((ramTotalBytes / 1024 ** 3).toFixed(1)) : 0;
    const ramPct = ramTotalBytes > 0 ? Number(((ramUsedBytes / ramTotalBytes) * 100).toFixed(1)) : 0;
    const diskTotalGb = diskTotalBytes > 0 ? Math.round(diskTotalBytes / 1024 ** 3) : 0;
    const diskAvailableGb =
      diskTotalBytes > 0 ? Math.max(0, Math.round((diskTotalBytes - diskUsedBytes) / 1024 ** 3)) : 0;
    const diskPct = diskTotalBytes > 0 ? Number(((diskUsedBytes / diskTotalBytes) * 100).toFixed(1)) : 0;

    return {
      sysName,
      osVersion: sysDescr ? sysDescr.slice(0, 80) : undefined,
      uptimeHours,
      cpuPct,
      ramPct,
      ramTotalGb,
      diskTotalGb,
      diskAvailableGb,
      diskPct,
    };
  } catch {
    return null;
  }
}

const prevIfCounters = new Map<string, { ts: number; inOctets: number; outOctets: number }>();

export async function pollNetworkDeviceSnmp(
  host: string,
  auth: SnmpTargetAuth,
  port = 161,
  timeoutMs = 1800
): Promise<SnmpNetworkResult> {
  if (auth.version === 'v2c' && !auth.community.trim()) {
    return {
      ok: false,
      status: 'Not Configured',
      interfaces: [],
      errorDetail: 'SNMPv2c read-only community string is not configured.',
    };
  }

  try {
    const v3Ctx =
      auth.version === 'v3' ? await discoverSnmpV3Engine(host, port, auth, timeoutMs) : null;

    const basic = await snmpGetWithAuth(
      host,
      port,
      auth,
      ['1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.3.0', '1.3.6.1.2.1.1.5.0'],
      v3Ctx,
      timeoutMs
    );

    const sysDescr = typeof basic[0]?.value === 'string' ? basic[0].value : undefined;
    const upTicks = typeof basic[1]?.value === 'number' ? basic[1].value : undefined;
    const sysName = typeof basic[2]?.value === 'string' ? basic[2].value : undefined;
    const uptimeHours = typeof upTicks === 'number' ? Math.round(upTicks / 360_000) : undefined;

    const [descrRows, speedRows, operRows, inOctRows, inErrRows, outOctRows, outErrRows] =
      await Promise.all([
        snmpWalkWithAuth(host, port, auth, '1.3.6.1.2.1.2.2.1.2', v3Ctx, timeoutMs, 32),
        snmpWalkWithAuth(host, port, auth, '1.3.6.1.2.1.2.2.1.5', v3Ctx, timeoutMs, 32),
        snmpWalkWithAuth(host, port, auth, '1.3.6.1.2.1.2.2.1.8', v3Ctx, timeoutMs, 32),
        snmpWalkWithAuth(host, port, auth, '1.3.6.1.2.1.2.2.1.10', v3Ctx, timeoutMs, 32),
        snmpWalkWithAuth(host, port, auth, '1.3.6.1.2.1.2.2.1.14', v3Ctx, timeoutMs, 32),
        snmpWalkWithAuth(host, port, auth, '1.3.6.1.2.1.2.2.1.16', v3Ctx, timeoutMs, 32),
        snmpWalkWithAuth(host, port, auth, '1.3.6.1.2.1.2.2.1.20', v3Ctx, timeoutMs, 32),
      ]);

    const byIdx = (rows: SnmpVarBind[]) => {
      const m = new Map<number, string | number | null>();
      for (const r of rows) {
        const idx = Number(r.oid.split('.').pop());
        if (Number.isInteger(idx)) m.set(idx, r.value);
      }
      return m;
    };

    const descrs = byIdx(descrRows);
    const speeds = byIdx(speedRows);
    const opers = byIdx(operRows);
    const inOcts = byIdx(inOctRows);
    const inErrs = byIdx(inErrRows);
    const outOcts = byIdx(outOctRows);
    const outErrs = byIdx(outErrRows);

    const nowMs = Date.now();
    const interfaces: NetworkInterfaceStat[] = [];

    for (const [idx, rawName] of descrs.entries()) {
      const name = typeof rawName === 'string' && rawName.trim() ? rawName.trim().slice(0, 64) : `if-${idx}`;
      const operNum = Number(opers.get(idx) ?? 2);
      const speedBps = Number(speeds.get(idx) ?? 0);
      const inOctet = Number(inOcts.get(idx) ?? 0);
      const outOctet = Number(outOcts.get(idx) ?? 0);
      const inError = Number(inErrs.get(idx) ?? 0);
      const outError = Number(outErrs.get(idx) ?? 0);

      const cacheKey = `${host}:${idx}`;
      const prev = prevIfCounters.get(cacheKey);
      let rxKbps = 0;
      let txKbps = 0;
      if (prev && nowMs > prev.ts) {
        const dtSec = (nowMs - prev.ts) / 1000;
        const dIn = inOctet >= prev.inOctets ? inOctet - prev.inOctets : 0;
        const dOut = outOctet >= prev.outOctets ? outOctet - prev.outOctets : 0;
        rxKbps = Number(((dIn * 8) / dtSec / 1000).toFixed(1));
        txKbps = Number(((dOut * 8) / dtSec / 1000).toFixed(1));
      }
      prevIfCounters.set(cacheKey, { ts: nowMs, inOctets: inOctet, outOctets: outOctet });

      interfaces.push({
        index: idx,
        name,
        operStatus: operNum === 1 ? 'up' : 'down',
        speedMbps: speedBps > 0 ? Math.round(speedBps / 1_000_000) : 0,
        rxKbps,
        txKbps,
        inErrors: Number.isFinite(inError) ? inError : 0,
        outErrors: Number.isFinite(outError) ? outError : 0,
      });
    }

    return {
      ok: true,
      status: 'Healthy',
      sysName,
      sysDescr,
      uptimeHours,
      interfaces: interfaces.slice(0, 24),
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/Authentication Failed|wrong digest|unknown user/i.test(msg)) {
      return {
        ok: false,
        status: 'Authentication Failed',
        interfaces: [],
        errorDetail: msg,
      };
    }
    if (/timeout/i.test(msg)) {
      return {
        ok: false,
        status: 'Unreachable',
        interfaces: [],
        errorDetail: `SNMP UDP/${port} timed out on ${host}. Verify SNMP service is enabled and UDP port ${port} permits traffic from the central monitoring server.`,
      };
    }
    return {
      ok: false,
      status: 'Unsupported Metric',
      interfaces: [],
      errorDetail: msg,
    };
  }
}
