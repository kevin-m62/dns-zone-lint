import { test } from "node:test";
import assert from "node:assert/strict";
import { AggregateDnsParseError, parseZone } from "./dns-record.js";

// Pulls the single error out of a zone that's expected to fail parsing.
function firstError(zone: string): string {
  try {
    parseZone(zone);
  } catch (err) {
    assert.ok(err instanceof AggregateDnsParseError);
    assert.equal(err.errors.length, 1);
    return err.errors[0]!.message;
  }
  throw new Error("expected parseZone to throw");
}

test("parses one record of each supported type", () => {
  const zone = `
example.com.        3600 IN A     192.0.2.10
example.com.        3600 IN AAAA  2001:db8::1
www.example.com.    3600 IN CNAME example.com.
example.com.        3600 IN NS    ns1.example.com.
example.com.        3600 IN MX    10 mail.example.com.
example.com.        3600 IN TXT   "v=spf1 -all"
10.2.0.192.in-addr.arpa. 3600 IN PTR example.com.
_sip._tcp.example.com. 3600 IN SRV 10 60 5060 sip.example.com.
example.com.        3600 IN SOA   ns1.example.com. hostmaster.example.com. 2026090501 7200 3600 1209600 3600
`;
  const records = parseZone(zone);
  assert.equal(records.length, 9);
  assert.deepEqual(records[0], {
    name: "example.com.",
    ttl: 3600,
    class: "IN",
    type: "A",
    address: "192.0.2.10",
  });
  assert.deepEqual(records[4], {
    name: "example.com.",
    ttl: 3600,
    class: "IN",
    type: "MX",
    preference: 10,
    exchange: "mail.example.com.",
  });
  assert.deepEqual(records[7], {
    name: "_sip._tcp.example.com.",
    ttl: 3600,
    class: "IN",
    type: "SRV",
    priority: 10,
    weight: 60,
    port: 5060,
    target: "sip.example.com.",
  });
});

test("ignores blank lines and comments, including trailing comments", () => {
  const zone = `
; a full-line comment

example.com. 3600 IN A 192.0.2.1 ; trailing comment
`;
  const records = parseZone(zone);
  assert.equal(records.length, 1);
  assert.equal(records[0]!.name, "example.com.");
});

test("keeps a semicolon inside a quoted TXT string instead of treating it as a comment", () => {
  const record = parseZone(`example.com. 3600 IN TXT "a;b"`)[0]!;
  assert.equal(record.type, "TXT");
  if (record.type === "TXT") assert.equal(record.text, "a;b");
});

test("unescapes backslash-escaped quotes and backslashes in TXT strings", () => {
  const record = parseZone(String.raw`example.com. 3600 IN TXT "a\"b\\c"`)[0]!;
  assert.equal(record.type, "TXT");
  if (record.type === "TXT") assert.equal(record.text, 'a"b\\c');
});

test("relative (non-dot-terminated) owner names are accepted", () => {
  const records = parseZone("www 3600 IN A 192.0.2.1");
  assert.equal(records[0]!.name, "www");
});

test("rejects an out-of-range IPv4 octet", () => {
  assert.match(
    firstError("example.com. 3600 IN A 999.0.2.10"),
    /invalid IPv4 address/,
  );
});

test("rejects an IPv4 octet with a leading zero", () => {
  assert.match(
    firstError("example.com. 3600 IN A 192.068.0.1"),
    /invalid IPv4 address/,
  );
});

test("accepts collapsed and full-form IPv6 addresses", () => {
  const records = parseZone(`
example.com. 3600 IN AAAA 2001:0db8:0000:0000:0000:ff00:0042:8329
example.com. 3600 IN AAAA 2001:db8::8a2e:370:7334
example.com. 3600 IN AAAA ::1
example.com. 3600 IN AAAA ::
`);
  assert.equal(records.length, 4);
});

test("rejects an IPv6 address with more than one '::' collapse", () => {
  assert.match(
    firstError("example.com. 3600 IN AAAA 1::2::3"),
    /invalid IPv6 address/,
  );
});

test("rejects an IPv6 address with too many groups", () => {
  assert.match(
    firstError("example.com. 3600 IN AAAA 1:2:3:4:5:6:7:8:9"),
    /invalid IPv6 address/,
  );
});

test("rejects an owner name with an empty label", () => {
  assert.match(
    firstError("example..com. 3600 IN A 192.0.2.1"),
    /invalid owner name/,
  );
});

test("rejects an owner name with a label over 63 characters", () => {
  const label = "a".repeat(64);
  assert.match(
    firstError(`${label}.example.com. 3600 IN A 192.0.2.1`),
    /invalid owner name/,
  );
});

test("rejects a TTL above the RFC 2181 signed 32-bit maximum", () => {
  assert.match(
    firstError("example.com. 2147483648 IN A 192.0.2.1"),
    /invalid TTL|TTL.*out of range/,
  );
});

test("rejects a class other than IN", () => {
  assert.match(
    firstError("example.com. 3600 CH A 192.0.2.1"),
    /unsupported class/,
  );
});

test("rejects an unsupported record type", () => {
  assert.match(
    firstError("example.com. 3600 IN CAA 0 issue example.com."),
    /unsupported record type/,
  );
});

test("rejects a record with too few rdata fields", () => {
  assert.match(
    firstError("example.com. 3600 IN MX mail.example.com."),
    /MX record expects 2 rdata field\(s\), got 1/,
  );
});

test("rejects an unterminated quoted TXT string", () => {
  assert.match(
    firstError('example.com. 3600 IN TXT "unterminated'),
    /unterminated quoted string/,
  );
});

test("collects one error per bad line, with correct line numbers, instead of stopping at the first", () => {
  const zone = `example.com. 3600 IN A 999.0.2.10
www.example.com. 3600 IN A 192.0.2.1
example.com. 3600 IN A 1.2.3.4.5`;
  try {
    parseZone(zone);
    assert.fail("expected parseZone to throw");
  } catch (err) {
    assert.ok(err instanceof AggregateDnsParseError);
    assert.equal(err.errors.length, 2);
    assert.equal(err.errors[0]!.line, 1);
    assert.equal(err.errors[1]!.line, 3);
  }
});
