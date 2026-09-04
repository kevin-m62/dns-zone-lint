// A DNS record line looks like: NAME TTL CLASS TYPE RDATA...
// e.g. "mail.example.com. 3600 IN A 192.0.2.1"
// This module turns that text into a typed, validated record, or refuses to.

export type DnsRecord =
  | { name: string; ttl: number; class: "IN"; type: "A"; address: string }
  | { name: string; ttl: number; class: "IN"; type: "AAAA"; address: string }
  | { name: string; ttl: number; class: "IN"; type: "CNAME"; target: string }
  | { name: string; ttl: number; class: "IN"; type: "NS"; target: string }
  | {
      name: string;
      ttl: number;
      class: "IN";
      type: "MX";
      preference: number;
      exchange: string;
    }
  | { name: string; ttl: number; class: "IN"; type: "TXT"; text: string }
  | { name: string; ttl: number; class: "IN"; type: "PTR"; target: string }
  | {
      name: string;
      ttl: number;
      class: "IN";
      type: "SRV";
      priority: number;
      weight: number;
      port: number;
      target: string;
    }
  | {
      name: string;
      ttl: number;
      class: "IN";
      type: "SOA";
      mname: string;
      rname: string;
      serial: number;
      refresh: number;
      retry: number;
      expire: number;
      minimum: number;
    };

export class DnsParseError extends Error {
  constructor(
    public readonly line: number,
    reason: string,
  ) {
    super(`line ${line}: ${reason}`);
    this.name = "DnsParseError";
  }
}

export class AggregateDnsParseError extends Error {
  constructor(public readonly errors: DnsParseError[]) {
    super(`${errors.length} error(s) while parsing zone data`);
    this.name = "AggregateDnsParseError";
  }
}

const MAX_TTL = 2147483647; // RFC 2181 4.3: TTL is a signed 32-bit value
const MAX_U16 = 65535;
const MAX_U32 = 4294967295;

export function parseZone(input: string): DnsRecord[] {
  const records: DnsRecord[] = [];
  const errors: DnsParseError[] = [];

  input.split(/\r\n|\n/).forEach((raw, index) => {
    const line = stripComment(raw).trim();
    if (line.length === 0) return;

    try {
      records.push(parseLine(line, index + 1));
    } catch (err) {
      if (err instanceof DnsParseError) {
        errors.push(err);
      } else {
        throw err;
      }
    }
  });

  if (errors.length > 0) {
    throw new AggregateDnsParseError(errors);
  }
  return records;
}

function parseLine(line: string, lineNumber: number): DnsRecord {
  let tokens: string[];
  try {
    tokens = tokenize(line);
  } catch (err) {
    throw new DnsParseError(
      lineNumber,
      err instanceof Error ? err.message : "malformed line",
    );
  }

  if (tokens.length < 4) {
    throw new DnsParseError(
      lineNumber,
      `expected at least 4 fields (name ttl class type), got ${tokens.length}`,
    );
  }

  const [name, ttlText, cls, type, ...rdata] = tokens as [
    string,
    string,
    string,
    string,
    ...string[],
  ];

  if (!isValidHostname(name)) {
    throw new DnsParseError(lineNumber, `invalid owner name "${name}"`);
  }
  const ttl = parseTtl(ttlText, lineNumber);
  if (cls !== "IN") {
    throw new DnsParseError(
      lineNumber,
      `unsupported class "${cls}", only IN is supported`,
    );
  }

  switch (type) {
    case "A": {
      requireFieldCount(rdata, 1, type, lineNumber);
      const address = rdata[0]!;
      if (!isValidIPv4(address)) {
        throw new DnsParseError(lineNumber, `invalid IPv4 address "${address}"`);
      }
      return { name, ttl, class: "IN", type: "A", address };
    }
    case "AAAA": {
      requireFieldCount(rdata, 1, type, lineNumber);
      const address = rdata[0]!;
      if (!isValidIPv6(address)) {
        throw new DnsParseError(lineNumber, `invalid IPv6 address "${address}"`);
      }
      return { name, ttl, class: "IN", type: "AAAA", address };
    }
    case "CNAME": {
      requireFieldCount(rdata, 1, type, lineNumber);
      const target = rdata[0]!;
      if (!isValidHostname(target)) {
        throw new DnsParseError(lineNumber, `invalid CNAME target "${target}"`);
      }
      return { name, ttl, class: "IN", type: "CNAME", target };
    }
    case "NS": {
      requireFieldCount(rdata, 1, type, lineNumber);
      const target = rdata[0]!;
      if (!isValidHostname(target)) {
        throw new DnsParseError(lineNumber, `invalid NS target "${target}"`);
      }
      return { name, ttl, class: "IN", type: "NS", target };
    }
    case "MX": {
      requireFieldCount(rdata, 2, type, lineNumber);
      const preference = parsePreference(rdata[0]!, lineNumber);
      const exchange = rdata[1]!;
      if (!isValidHostname(exchange)) {
        throw new DnsParseError(lineNumber, `invalid MX exchange "${exchange}"`);
      }
      return { name, ttl, class: "IN", type: "MX", preference, exchange };
    }
    case "TXT": {
      requireFieldCount(rdata, 1, type, lineNumber);
      return { name, ttl, class: "IN", type: "TXT", text: rdata[0]! };
    }
    case "PTR": {
      requireFieldCount(rdata, 1, type, lineNumber);
      const target = rdata[0]!;
      if (!isValidHostname(target)) {
        throw new DnsParseError(lineNumber, `invalid PTR target "${target}"`);
      }
      return { name, ttl, class: "IN", type: "PTR", target };
    }
    case "SRV": {
      requireFieldCount(rdata, 4, type, lineNumber);
      const priority = parseUnsignedInt(rdata[0]!, MAX_U16, "SRV priority", lineNumber);
      const weight = parseUnsignedInt(rdata[1]!, MAX_U16, "SRV weight", lineNumber);
      const port = parseUnsignedInt(rdata[2]!, MAX_U16, "SRV port", lineNumber);
      const target = rdata[3]!;
      if (!isValidHostname(target)) {
        throw new DnsParseError(lineNumber, `invalid SRV target "${target}"`);
      }
      return { name, ttl, class: "IN", type: "SRV", priority, weight, port, target };
    }
    case "SOA": {
      requireFieldCount(rdata, 7, type, lineNumber);
      const mname = rdata[0]!;
      const rname = rdata[1]!;
      if (!isValidHostname(mname)) {
        throw new DnsParseError(lineNumber, `invalid SOA mname "${mname}"`);
      }
      if (!isValidHostname(rname)) {
        throw new DnsParseError(lineNumber, `invalid SOA rname "${rname}"`);
      }
      const serial = parseUnsignedInt(rdata[2]!, MAX_U32, "SOA serial", lineNumber);
      const refresh = parseUnsignedInt(rdata[3]!, MAX_U32, "SOA refresh", lineNumber);
      const retry = parseUnsignedInt(rdata[4]!, MAX_U32, "SOA retry", lineNumber);
      const expire = parseUnsignedInt(rdata[5]!, MAX_U32, "SOA expire", lineNumber);
      const minimum = parseUnsignedInt(rdata[6]!, MAX_U32, "SOA minimum", lineNumber);
      return {
        name,
        ttl,
        class: "IN",
        type: "SOA",
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
      };
    }
    default:
      throw new DnsParseError(lineNumber, `unsupported record type "${type}"`);
  }
}

function requireFieldCount(
  rdata: string[],
  expected: number,
  type: string,
  lineNumber: number,
): void {
  if (rdata.length !== expected) {
    throw new DnsParseError(
      lineNumber,
      `${type} record expects ${expected} rdata field(s), got ${rdata.length}`,
    );
  }
}

function parseTtl(text: string, lineNumber: number): number {
  return parseUnsignedInt(text, MAX_TTL, "TTL", lineNumber);
}

function parsePreference(text: string, lineNumber: number): number {
  return parseUnsignedInt(text, MAX_U16, "MX preference", lineNumber);
}

function parseUnsignedInt(
  text: string,
  max: number,
  label: string,
  lineNumber: number,
): number {
  if (!/^\d+$/.test(text)) {
    throw new DnsParseError(
      lineNumber,
      `invalid ${label} "${text}", expected a non-negative integer`,
    );
  }
  const value = Number(text);
  if (value > max) {
    throw new DnsParseError(
      lineNumber,
      `${label} "${text}" out of range (max ${max})`,
    );
  }
  return value;
}

// Splits on whitespace, but keeps double-quoted spans (used by TXT) intact
// and unescapes \" and \\ within them.
function tokenize(line: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < line.length) {
    while (i < line.length && /\s/.test(line[i]!)) i++;
    if (i >= line.length) break;

    if (line[i] === '"') {
      let j = i + 1;
      let value = "";
      while (j < line.length && line[j] !== '"') {
        if (line[j] === "\\" && j + 1 < line.length) {
          value += line[j + 1];
          j += 2;
        } else {
          value += line[j];
          j += 1;
        }
      }
      if (j >= line.length) {
        throw new Error("unterminated quoted string");
      }
      tokens.push(value);
      i = j + 1;
    } else {
      let j = i;
      while (j < line.length && !/\s/.test(line[j]!)) j++;
      tokens.push(line.slice(i, j));
      i = j;
    }
  }
  return tokens;
}

// Strips a ';' comment, ignoring ';' that appears inside a quoted string.
function stripComment(line: string): string {
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '"' && line[i - 1] !== "\\") {
      inQuotes = !inQuotes;
    } else if (line[i] === ";" && !inQuotes) {
      return line.slice(0, i);
    }
  }
  return line;
}

function isValidHostname(name: string): boolean {
  const bare = name.endsWith(".") ? name.slice(0, -1) : name;
  if (bare.length === 0 || bare.length > 253) return false;
  return bare
    .split(".")
    .every((label) => /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label));
}

function isValidIPv4(address: string): boolean {
  const parts = address.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part[0] === "0") return false;
    return Number(part) <= 255;
  });
}

// Accepts standard colon-hex IPv6 notation with at most one "::" collapse.
// Does not attempt to validate embedded IPv4 tails or zone indices.
function isValidIPv6(address: string): boolean {
  if (address.length === 0) return false;
  const collapseCount = (address.match(/::/g) || []).length;
  if (collapseCount > 1) return false;

  const collapsed = address.includes("::");
  const groups = address
    .split("::")
    .flatMap((section) => (section.length === 0 ? [] : section.split(":")));

  if (!groups.every((group) => /^[0-9a-fA-F]{1,4}$/.test(group))) return false;
  if (collapsed) return groups.length <= 7;
  return groups.length === 8;
}
