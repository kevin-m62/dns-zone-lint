import type { DnsRecord } from "./dns-record.js";

// Renders records back into aligned, zone-file-style text: one record per
// line, columns padded to the widest entry so a batch of records reads
// like a table instead of ragged text.
export function formatZone(records: DnsRecord[]): string {
  if (records.length === 0) return "";

  const nameWidth = widestOf(records, (r) => r.name);
  const ttlWidth = widestOf(records, (r) => String(r.ttl));
  const typeWidth = widestOf(records, (r) => r.type);

  const lines = records.map((record) =>
    [
      record.name.padEnd(nameWidth),
      String(record.ttl).padStart(ttlWidth),
      record.class.padEnd(2),
      record.type.padEnd(typeWidth),
      formatRdata(record),
    ].join(" "),
  );

  return lines.join("\n") + "\n";
}

function widestOf(records: DnsRecord[], select: (r: DnsRecord) => string): number {
  return records.reduce((max, r) => Math.max(max, select(r).length), 0);
}

function formatRdata(record: DnsRecord): string {
  switch (record.type) {
    case "A":
    case "AAAA":
      return record.address;
    case "CNAME":
    case "NS":
      return record.target;
    case "MX":
      return `${record.preference} ${record.exchange}`;
    case "TXT":
      return `"${escapeText(record.text)}"`;
  }
}

function escapeText(text: string): string {
  return text.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}
