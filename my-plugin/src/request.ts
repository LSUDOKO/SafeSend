// Payment-request parsing for invoices and EIP-681 links. Pure, no network.
// EIP-681: ethereum:<target>[@chainId][/function]?params, where a missing
// chain id means Ethereum mainnet and numbers may use exponents (1.5e6).

import { BASE_USDC, formatUsdc, normalize, type Finding } from "./safety.js";

export type ParsedRequest = {
  format: "eip681" | "text";
  recipient: string | null;
  amountAtomic: bigint | null;
  chainId: number | null;
  token: string | null;
  findings: Finding[];
};

const ADDRESS = /0x[0-9a-fA-F]{40}(?![0-9a-fA-F])/g;
const BASENAME = /[^\s,;:<>()"'`]+\.base\.eth\b/gi;

// Exact integer from "1000000", "1e6" or "1.5e6"; null if fractional or malformed.
export function parseEip681Number(raw: string): bigint | null {
  const m = /^([0-9]+)(?:\.([0-9]+))?(?:[eE]\+?([0-9]{1,2}))?$/.exec(raw.trim());
  if (!m) return null;
  const [, whole, fraction = "", exp = "0"] = m;
  const digits = `${whole}${fraction}`;
  const shift = Number(exp) - fraction.length;
  if (shift >= 0) return BigInt(digits) * 10n ** BigInt(shift);
  if (/[1-9]/.test(digits.slice(shift))) return null;
  return BigInt(digits.slice(0, shift) || "0");
}

function usdcFromText(text: string): bigint | null {
  const m = /(?:\$\s*)?\b([0-9]{1,12}(?:,[0-9]{3})*(?:\.[0-9]{1,6})?)\s*(?:USDC|USD)\b|\$\s*([0-9]{1,12}(?:,[0-9]{3})*(?:\.[0-9]{1,6})?)/i.exec(text);
  const value = (m?.[1] ?? m?.[2])?.replace(/,/g, "");
  if (!value) return null;
  const [whole, fraction = ""] = value.split(".");
  return BigInt(whole!) * 1_000_000n + BigInt(fraction.padEnd(6, "0"));
}

function parseUri(uri: string): ParsedRequest {
  const findings: Finding[] = [];
  const add = (severity: Finding["severity"], code: string, message: string) => findings.push({ code, severity, message });
  const m = /^ethereum:(?:pay-)?([^@/?#]+)(?:@([0-9]+))?(?:\/([A-Za-z_][A-Za-z0-9_]*))?(?:\?([^#]*))?$/.exec(uri.trim());
  const result: ParsedRequest = { format: "eip681", recipient: null, amountAtomic: null, chainId: null, token: null, findings };
  if (!m) {
    add("block", "MALFORMED_REQUEST", "The payment link is not a valid EIP-681 URI (ethereum:<address>@<chain>/transfer?address=…&uint256=…).");
    return result;
  }
  const [, target, chain, fn, query = ""] = m;
  const params = new URLSearchParams(query);
  result.chainId = chain === undefined ? 1 : Number(chain);
  if (chain === undefined) {
    add("caution", "NETWORK_UNSPECIFIED", "The link has no chain id, which under EIP-681 means Ethereum mainnet, not Base. Confirm the payee accepts USDC on Base before paying; exchange deposit addresses often do not.");
  } else if (result.chainId !== 8453) {
    add("block", "WRONG_NETWORK", `The link asks for payment on chain ${result.chainId}, not Base (8453). SafeSend pays USDC on Base only; funds sent on the wrong network can be lost.`);
  }
  if (fn === undefined) {
    add("block", "UNSUPPORTED_ASSET", "The link requests native ETH, not USDC. SafeSend only sends USDC; ask the payee for a USDC payment request.");
    result.recipient = target!;
    return result;
  }
  if (fn !== "transfer") {
    add("block", "UNSUPPORTED_FUNCTION", `The link calls ${fn}() instead of a token transfer. Requests that call other contract functions (approve, transferFrom, swaps) can drain funds; do not pay it.`);
    return result;
  }
  result.token = target!;
  if (normalize(target!) !== BASE_USDC) {
    add("block", "UNEXPECTED_TOKEN", `The link asks for a transfer of token ${target}, which is not Base USDC (${BASE_USDC}). Counterfeit-token invoices are a known scam; do not pay it.`);
  }
  const to = params.get("address");
  if (!to) add("block", "MISSING_RECIPIENT", "The link has no recipient address parameter.");
  else result.recipient = to;
  const amount = params.get("uint256") ?? params.get("amount");
  if (amount !== null) {
    const parsed = parseEip681Number(amount);
    if (parsed === null || parsed === 0n) add("block", "INVALID_AMOUNT", `The link's amount "${amount}" is not a positive whole number of USDC units.`);
    else result.amountAtomic = parsed;
  }
  if (params.has("value") && params.get("value") !== "0") {
    add("block", "UNEXPECTED_VALUE", "The link attaches native ETH to a token transfer, which a legitimate USDC invoice never does.");
  }
  return result;
}

export function parsePaymentRequest(request: string): ParsedRequest {
  const text = request.normalize("NFKC");
  const uri = /ethereum:[^\s"'<>]+/i.exec(text)?.[0];
  if (uri) return parseUri(uri);

  const findings: Finding[] = [];
  const addresses = [...new Set([...text.matchAll(ADDRESS)].map((m) => normalize(m[0])))];
  const names = [...new Set([...request.matchAll(BASENAME)].map((m) => m[0].toLowerCase()))];
  const candidates = [...addresses, ...names];
  const result: ParsedRequest = { format: "text", recipient: null, amountAtomic: usdcFromText(text), chainId: null, token: null, findings };
  // 64 hex characters is a transaction hash, not a broken address.
  const odd = [...text.matchAll(/0x([0-9a-fA-F]+)/g)].some((m) => m[1]!.length !== 40 && m[1]!.length !== 64 && m[1]!.length >= 30);
  if (odd) {
    findings.push({ code: "TRUNCATED_OR_PADDED_ADDRESS", severity: "block", message: "The request contains a 0x string that is not exactly 40 hex characters. An address was cut off or altered; ask the payee to resend it." });
  }
  if (candidates.length === 0) {
    findings.push({ code: "MISSING_RECIPIENT", severity: "block", message: "No 0x address or .base.eth name was found in the request." });
  } else if (candidates.length > 1) {
    findings.push({ code: "AMBIGUOUS_RECIPIENT", severity: "block", message: `The request contains ${candidates.length} different payees (${candidates.join(", ")}). Invoices that have been tampered with often add a second address; ask the payee which one is correct.` });
  } else {
    result.recipient = addresses.length === 1 ? [...text.matchAll(ADDRESS)][0]![0] : names[0]!;
  }
  if (/\b(ethereum mainnet|erc-?20 on ethereum|arbitrum|optimism|polygon|solana|bsc|bnb chain|tron|trc-?20)\b/i.test(text) && !/\bbase\b/i.test(text)) {
    findings.push({ code: "NETWORK_MISMATCH", severity: "caution", message: "The request mentions another network but not Base. Confirm the payee accepts USDC on Base." });
  }
  return result;
}

export function amountCheck(requested: bigint | null, expected: bigint | undefined): Finding | null {
  if (expected === undefined || requested === null || requested === expected) return null;
  return { code: "AMOUNT_MISMATCH", severity: "caution", message: `The request asks for ${formatUsdc(requested)} USDC but you expected ${formatUsdc(expected)} USDC.` };
}
