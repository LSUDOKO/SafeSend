import { keccak_256 } from "@noble/hashes/sha3";
import { utf8ToBytes } from "@noble/hashes/utils";

import { call } from "./rpc.js";

// Basenames registry on Base mainnet (resolver(bytes32) -> address).
const BASENAMES_REGISTRY = "0xb94704422c2a1e396835a571837aa5ae53285a95";

export function namehash(name: string): string {
  let node: Uint8Array = new Uint8Array(32);
  for (const label of name.split(".").reverse()) {
    const joined = new Uint8Array(64);
    joined.set(node);
    joined.set(keccak_256(utf8ToBytes(label)), 32);
    node = keccak_256(joined);
  }
  return Buffer.from(node).toString("hex");
}

export type NameCheck = { ok: true; name: string } | { ok: false; code: string; message: string };

// Only plain ASCII labels are accepted: a name that renders like a real one but
// uses Cyrillic, Greek, full-width or invisible characters is a spoofing attempt.
export function checkBasename(input: string): NameCheck {
  const name = input.trim().toLowerCase();
  if (!name.endsWith(".base.eth")) {
    return { ok: false, code: "UNSUPPORTED_NAME", message: `${input} is not a Basename. Only names ending in .base.eth resolve on Base; resolve other names to a 0x address with the payee first.` };
  }
  const labels = name.slice(0, -".base.eth".length).split(".");
  if (labels.some((l) => l.length === 0)) return { ok: false, code: "INVALID_NAME", message: `${input} has an empty label.` };
  const nonAscii = [...name].filter((c) => !/[a-z0-9.\-]/.test(c));
  if (nonAscii.length > 0) {
    const shown = nonAscii.map((c) => `"${c}" (U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")})`).join(", ");
    return { ok: false, code: "NAME_SPOOFING", message: `${input} contains characters that only look like normal letters: ${shown}. This is how fake names impersonate real ones; do not pay it.` };
  }
  if (labels.some((l) => l.startsWith("-") || l.endsWith("-"))) return { ok: false, code: "INVALID_NAME", message: `${input} is not a valid Basename.` };
  return { ok: true, name };
}

export async function resolveBasename(name: string): Promise<string | null> {
  const node = namehash(name);
  const resolverWord = await call("eth_call", [{ to: BASENAMES_REGISTRY, data: `0x0178b8bf${node}` }, "latest"]);
  const resolver = `0x${resolverWord.slice(-40)}`;
  if (/^0x0{40}$/.test(resolver)) return null;
  const addrWord = await call("eth_call", [{ to: resolver, data: `0x3b3b57de${node}` }, "latest"]);
  if (addrWord.length < 66) return null;
  const address = `0x${addrWord.slice(-40)}`;
  return /^0x0{40}$/.test(address) ? null : address;
}

export type Resolved = { ok: true; address: string; name: string | null } | { ok: false; code: string; message: string };

export async function resolveRecipient(input: string): Promise<Resolved> {
  const value = input.trim();
  if (/^0x[0-9a-fA-F]{40}$/.test(value)) return { ok: true, address: value, name: null };
  if (/^0x/i.test(value)) return { ok: false, code: "INVALID_ADDRESS", message: `${value} is not a valid address: it must be 0x followed by exactly 40 hex characters (it has ${value.length - 2}).` };
  const check = checkBasename(value);
  if (!check.ok) return check;
  let address: string | null;
  try {
    address = await resolveBasename(check.name);
  } catch (error) {
    return { ok: false, code: "NAME_LOOKUP_FAILED", message: `Could not resolve ${check.name} right now (${(error as Error).message}). Try again or use the 0x address from the payee.` };
  }
  if (!address) return { ok: false, code: "NAME_NOT_FOUND", message: `${check.name} is not registered or has no address set. Check the spelling with the payee.` };
  return { ok: true, address, name: check.name };
}
