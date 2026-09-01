import { readFileSync } from "node:fs";
import {
  AggregateDnsParseError,
  DnsParseError,
  parseZone,
} from "./dns-record.js";
import { formatZone } from "./printer.js";

// With no file arguments, read the zone data from stdin (fd 0). This lets
// the tool sit in a pipeline, e.g. `dig +nocmd example.com AXFR | dns-zone-lint`.
function readInput(paths: string[]): string {
  if (paths.length === 0) {
    return readFileSync(0, "utf-8");
  }
  return paths.map((path) => readFileSync(path, "utf-8")).join("\n");
}

function main(): void {
  const paths = process.argv.slice(2);

  let input: string;
  try {
    input = readInput(paths);
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : err}\n`);
    process.exitCode = 1;
    return;
  }

  try {
    const records = parseZone(input);
    process.stdout.write(formatZone(records));
  } catch (err) {
    if (err instanceof AggregateDnsParseError) {
      for (const e of err.errors) process.stderr.write(`${e.message}\n`);
    } else if (err instanceof DnsParseError) {
      process.stderr.write(`${err.message}\n`);
    } else {
      throw err;
    }
    process.exitCode = 1;
  }
}

main();
