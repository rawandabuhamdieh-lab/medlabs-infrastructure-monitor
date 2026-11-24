import { execFile } from 'child_process';
import net from 'net';

export interface PingProbeResult {
  alive: boolean;
  avgLatencyMs: number | null;
  minLatencyMs: number | null;
  maxLatencyMs: number | null;
  packetLossPct: number;
  errorDetail?: string;
}

export function isValidTargetHost(target: string): boolean {
  return /^[a-zA-Z0-9.:_-]{1,120}$/.test(target);
}

export function pingHostStats(
  target: string,
  count = 4,
  timeoutMs = 1500
): Promise<PingProbeResult> {
  return new Promise((resolve) => {
    if (!isValidTargetHost(target)) {
      resolve({
        alive: false,
        avgLatencyMs: null,
        minLatencyMs: null,
        maxLatencyMs: null,
        packetLossPct: 100,
        errorDetail: 'Invalid hostname or IP format.',
      });
      return;
    }

    const safeCount = Math.max(1, Math.min(10, Math.round(count)));
    const waitSec = Math.max(1, Math.ceil(timeoutMs / 1000));
    const args =
      process.platform === 'win32'
        ? ['-n', String(safeCount), '-w', String(Math.max(500, timeoutMs)), target]
        : ['-c', String(safeCount), '-W', String(waitSec), target];

    const execTimeout = safeCount * Math.max(1000, timeoutMs) + 3000;
    execFile('ping', args, { timeout: execTimeout }, (err, stdout, stderr) => {
      const output = `${stdout || ''}\n${stderr || ''}`;

      // Parse packet loss (%) across Windows & Linux formats
      let packetLossPct = err ? 100 : 0;
      const lossMatch = /(\d+(?:\.\d+)?)\s*%\s*(?:packet\s*)?loss/i.exec(output);
      if (lossMatch) {
        packetLossPct = Math.max(0, Math.min(100, Number(lossMatch[1])));
      }

      // Windows: Minimum = 0ms, Maximum = 1ms, Average = 0ms
      const winRtt = /Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms/i.exec(output);
      // Linux: rtt min/avg/max/mdev = 0.032/0.041/0.052/0.008 ms
      const nixRtt = /=\s*(\d+(?:\.\d+)?)\/(\d+(?:\.\d+)?)\/(\d+(?:\.\d+)?)\/[\d.]+\s*ms/i.exec(output);

      let minLatencyMs: number | null = null;
      let maxLatencyMs: number | null = null;
      let avgLatencyMs: number | null = null;

      if (winRtt) {
        minLatencyMs = Math.max(1, Math.round(Number(winRtt[1])));
        maxLatencyMs = Math.max(1, Math.round(Number(winRtt[2])));
        avgLatencyMs = Math.max(1, Math.round(Number(winRtt[3])));
      } else if (nixRtt) {
        minLatencyMs = Math.max(1, Math.round(Number(nixRtt[1])));
        avgLatencyMs = Math.max(1, Math.round(Number(nixRtt[2])));
        maxLatencyMs = Math.max(1, Math.round(Number(nixRtt[3])));
      } else {
        const singleMatches = Array.from(output.matchAll(/time[=<]\s*(\d+(?:\.\d+)?)\s*ms/gi)).map((m) =>
          Math.max(1, Math.round(Number(m[1])))
        );
        if (singleMatches.length > 0) {
          minLatencyMs = Math.min(...singleMatches);
          maxLatencyMs = Math.max(...singleMatches);
          avgLatencyMs = Math.round(
            singleMatches.reduce((a, b) => a + b, 0) / singleMatches.length
          );
        }
      }

      const alive = packetLossPct < 100 && avgLatencyMs !== null;
      resolve({
        alive,
        avgLatencyMs,
        minLatencyMs,
        maxLatencyMs,
        packetLossPct,
        errorDetail: alive
          ? undefined
          : err?.message || 'Host unreachable via ICMP Echo Request (all packets timed out or filtered).',
      });
    });
  });
}

export function checkTcpPort(
  host: string,
  port: number,
  timeoutMs = 1000
): Promise<{ open: boolean; latencyMs: number | null }> {
  return new Promise((resolve) => {
    if (!isValidTargetHost(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
      resolve({ open: false, latencyMs: null });
      return;
    }
    const started = Date.now();
    const socket = new net.Socket();
    let settled = false;
    const done = (open: boolean) => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve({ open, latencyMs: open ? Math.max(1, Date.now() - started) : null });
      }
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, host);
  });
}
