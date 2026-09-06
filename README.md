# dns-zone-lint

Hand-edited DNS zone files are plain text with no structure enforcement:
a stray tab, a missing quote around a TXT string, or a typo'd record type
will sit there silently until something fails to resolve. This is a small
tool that parses zone-file-style DNS record lines, validates each field
against what the record type actually requires, and reprints the whole
batch in an aligned, consistent format.

It reads from files or from stdin, so it fits into a pipeline as easily as
it runs standalone against a saved zone file.

## Supported records

`A`, `AAAA`, `CNAME`, `NS`, `MX`, `TXT`, `PTR`, `SRV`, `SOA`, class `IN`
only. Anything else is reported as an error rather than silently passed
through.

## Record format

One record per line:

```
NAME TTL CLASS TYPE RDATA...
```

```
example.com.        3600 IN A     192.0.2.10
www.example.com.    3600 IN CNAME example.com.
example.com.        3600 IN MX    10 mail.example.com.
example.com.        3600 IN TXT   "v=spf1 -all"
10.2.0.192.in-addr.arpa. 3600 IN PTR example.com.
_sip._tcp.example.com. 3600 IN SRV 10 60 5060 sip.example.com.
example.com.        3600 IN SOA   ns1.example.com. hostmaster.example.com. 2026090501 7200 3600 1209600 3600
```

`;` starts a comment that runs to the end of the line. Blank lines are
ignored.

## Building and running

There are no dependencies to install. Compile with `tsc` (any recent
TypeScript install, local or via `npx typescript`) and run the result
with Node:

```
tsc
node dist/cli.js zone.txt
```

Reading from a file:

```
node dist/cli.js zone.txt
```

Reading from stdin:

```
cat zone.txt | node dist/cli.js
```

Multiple files are concatenated in the order given before parsing, so
records can be split across files (e.g. one file per record type) and
still be checked and printed together.

## Testing

Tests use Node's built-in test runner, so there's nothing to install:

```
npm test
```

This compiles with `tsc` and then runs everything under `dist` matching
Node's test file conventions (`*.test.js`).

## Output

On success, the reformatted, column-aligned records are written to
stdout. On failure, every line-numbered error is written to stderr and
the process exits with a non-zero status; nothing is written to stdout,
so a broken zone never produces output that looks like it passed.

```
$ echo 'example.com. 3600 IN A 999.0.2.10' | node dist/cli.js
line 1: invalid IPv4 address "999.0.2.10"
```

## Library use

The parser and printer are also usable directly:

```ts
import { parseZone } from "./src/dns-record.js";
import { formatZone } from "./src/printer.js";

const records = parseZone(zoneText); // throws AggregateDnsParseError on bad input
process.stdout.write(formatZone(records));
```

## Status

Early skeleton. See the record types listed above for what's covered so
far — there's no `$ORIGIN`/`$TTL` directive support yet, and only class
`IN` is recognized.
