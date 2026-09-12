import { test } from "node:test";
import assert from "node:assert/strict";
import type { DnsRecord } from "./dns-record.js";
import { formatZone, formatZoneJson } from "./printer.js";

test("formats no records as an empty string", () => {
  assert.equal(formatZone([]), "");
});

test("pads name, ttl, and type columns to the widest entry in the batch", () => {
  const records: DnsRecord[] = [
    { name: "a.example.com.", ttl: 300, class: "IN", type: "A", address: "192.0.2.1" },
    { name: "www.example.com.", ttl: 3600, class: "IN", type: "CNAME", target: "example.com." },
  ];
  const nameWidth = Math.max(...records.map((r) => r.name.length));
  const ttlWidth = Math.max(...records.map((r) => String(r.ttl).length));
  const typeWidth = Math.max(...records.map((r) => r.type.length));

  const expected = [
    ["a.example.com.".padEnd(nameWidth), "300".padStart(ttlWidth), "IN", "A".padEnd(typeWidth), "192.0.2.1"].join(" "),
    ["www.example.com.".padEnd(nameWidth), "3600".padStart(ttlWidth), "IN", "CNAME".padEnd(typeWidth), "example.com."].join(" "),
    "",
  ];
  assert.deepEqual(formatZone(records).split("\n"), expected);
});

test("formats no records as JSON as an empty array", () => {
  assert.equal(formatZoneJson([]), "[]\n");
});

test("formats records as a pretty-printed JSON array, in order, with a trailing newline", () => {
  const records: DnsRecord[] = [
    { name: "example.com.", ttl: 300, class: "IN", type: "A", address: "192.0.2.1" },
    { name: "example.com.", ttl: 300, class: "IN", type: "MX", preference: 10, exchange: "mail.example.com." },
  ];
  const output = formatZoneJson(records);
  assert.equal(output.endsWith("\n"), true);
  assert.deepEqual(JSON.parse(output), records);
});

test("re-quotes TXT rdata and escapes embedded quotes and backslashes", () => {
  const records: DnsRecord[] = [
    { name: "example.com.", ttl: 300, class: "IN", type: "TXT", text: 'say "hi"\\bye' },
  ];
  assert.equal(
    formatZone(records),
    'example.com. 300 IN TXT "say \\"hi\\"\\\\bye"\n',
  );
});

test("formats SRV and SOA rdata as space-separated fields in field order", () => {
  const srv: DnsRecord = {
    name: "_sip._tcp.example.com.",
    ttl: 3600,
    class: "IN",
    type: "SRV",
    priority: 10,
    weight: 60,
    port: 5060,
    target: "sip.example.com.",
  };
  const soa: DnsRecord = {
    name: "example.com.",
    ttl: 3600,
    class: "IN",
    type: "SOA",
    mname: "ns1.example.com.",
    rname: "hostmaster.example.com.",
    serial: 2026090501,
    refresh: 7200,
    retry: 3600,
    expire: 1209600,
    minimum: 3600,
  };
  const records = [srv, soa];
  const nameWidth = Math.max(...records.map((r) => r.name.length));
  const typeWidth = Math.max(...records.map((r) => r.type.length));

  const expected = [
    [
      srv.name.padEnd(nameWidth),
      "3600",
      "IN",
      "SRV".padEnd(typeWidth),
      "10 60 5060 sip.example.com.",
    ].join(" "),
    [
      soa.name.padEnd(nameWidth),
      "3600",
      "IN",
      "SOA".padEnd(typeWidth),
      "ns1.example.com. hostmaster.example.com. 2026090501 7200 3600 1209600 3600",
    ].join(" "),
    "",
  ];
  assert.deepEqual(formatZone(records).split("\n"), expected);
});
