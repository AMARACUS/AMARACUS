import net from 'net';

/**
 * Optional per-API-key IP allowlist. A key copied off the server it belongs to is useless from
 * anywhere else (docs/recovery/breach-drill-2026-11.md). Entries are single addresses
 * ("203.0.113.7", "2001:db8::1") or CIDR ranges ("203.0.113.0/24", "2001:db8::/32").
 */
export const MAX_ALLOWED_IPS = 20;

/** "::ffff:203.0.113.7" (IPv4 seen through an IPv6 socket) becomes "203.0.113.7". */
export function normalizeIp(ip: string): string {
  const trimmed = ip.trim();
  const mapped = trimmed.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  return mapped ? mapped[1] : trimmed;
}

function parseEntry(entry: string): { address: string; prefix?: number; family: 'ipv4' | 'ipv6' } | null {
  const [rawAddress, rawPrefix, extra] = entry.trim().split('/');
  if (extra !== undefined || !rawAddress) return null;
  const address = normalizeIp(rawAddress);
  const version = net.isIP(address);
  if (version === 0) return null;
  const family = version === 4 ? 'ipv4' : 'ipv6';
  if (rawPrefix === undefined) return { address, family };
  if (!/^\d{1,3}$/.test(rawPrefix)) return null;
  const prefix = Number(rawPrefix);
  if (prefix > (version === 4 ? 32 : 128)) return null;
  return { address, prefix, family };
}

/**
 * Checks a list from a request body. Returns the cleaned list (null for "any address") or an
 * error message naming the first bad entry.
 */
export function validateAllowedIps(input: unknown): { ok: true; value: string[] | null } | { ok: false; error: string } {
  if (input === undefined || input === null) return { ok: true, value: null };
  if (!Array.isArray(input)) return { ok: false, error: '"allowedIps" must be a list of IP addresses or CIDR ranges.' };
  if (input.length > MAX_ALLOWED_IPS) return { ok: false, error: `"allowedIps" can hold at most ${MAX_ALLOWED_IPS} entries.` };
  const cleaned: string[] = [];
  for (const entry of input) {
    if (typeof entry !== 'string' || !parseEntry(entry)) {
      return { ok: false, error: `"${String(entry)}" is not an IP address or CIDR range (for example 203.0.113.7 or 203.0.113.0/24).` };
    }
    cleaned.push(entry.trim());
  }
  return { ok: true, value: cleaned.length ? Array.from(new Set(cleaned)) : null };
}

/** True when the key has no allowlist, or the client IP is inside one of its entries. */
export function isIpAllowed(clientIp: string | undefined, allowedIps: string[] | null | undefined): boolean {
  if (!allowedIps || allowedIps.length === 0) return true;
  if (!clientIp) return false;
  const ip = normalizeIp(clientIp);
  const version = net.isIP(ip);
  if (version === 0) return false;
  const list = new net.BlockList();
  for (const entry of allowedIps) {
    const parsed = parseEntry(entry);
    if (!parsed) continue;
    if (parsed.prefix === undefined) list.addAddress(parsed.address, parsed.family);
    else list.addSubnet(parsed.address, parsed.prefix, parsed.family);
  }
  return list.check(ip, version === 4 ? 'ipv4' : 'ipv6');
}
