// SafeSend risk engine: pure functions, no network. Detection rules follow
// Tsuchiya et al., "Blockchain Address Poisoning" (arXiv:2501.16681):
// attackers mine addresses whose first and last hex characters match a real
// counterparty, then plant one of three poisoning transfers in the victim's
// history so the lookalike is copied next time:
//   tiny transfer      lookalike -> victim, real stablecoin, 0 < value < $10
//   zero-value         victim -> lookalike via transferFrom(…, 0)
//   counterfeit token  victim -> lookalike in a fake "USDC"-style token
// A "payoff" is the victim later sending real value to the lookalike.
// Duplicate and outlier payment checks follow the agent-payment failure modes
// measured in Agentic Commerce Bench (arXiv:2609.35886).

import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

export const BASE_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

// Canonical Base contracts for tokens that scammers most often counterfeit.
const CANONICAL: Record<string, string[]> = {
  USDC: [BASE_USDC],
  USDBC: ["0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca"],
  USDT: ["0xfde4c96c8593536e31f229ea8f37b2ada2699bb2"],
  DAI: ["0x50c5725949a6f0c72e6c4a641f24049a917db0cb"],
  EURC: ["0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"],
  WETH: ["0x4200000000000000000000000000000000000006"],
};
const CANONICAL_TOKENS = new Set(Object.values(CANONICAL).flat());

// Authentic stablecoins and the atomic value of $10, the paper's tiny-transfer ceiling.
const TINY_CEILING: Record<string, bigint> = {
  [BASE_USDC]: 10_000_000n,
  "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca": 10_000_000n,
  "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2": 10_000_000n,
  "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42": 10_000_000n,
  "0x50c5725949a6f0c72e6c4a641f24049a917db0cb": 10n * 10n ** 18n,
};

export type Severity = "block" | "caution" | "info";
export type Finding = { code: string; severity: Severity; message: string };
export type PoisonKind = "tiny_transfer" | "zero_value" | "counterfeit_token";

export type Transfer = {
  from: string;
  to: string;
  value: string;
  tokenAddress: string;
  tokenSymbol: string;
  tokenDecimals: number;
  tokenFlagged: boolean;
  txHash: string;
  timestamp: string | null;
};

export type AddressInfo = {
  isContract: boolean;
  isScam: boolean;
  isToken: boolean;
  name: string | null;
  ensName: string | null;
  reputation: string | null;
  coinBalanceWei: string | null;
};

export function normalize(address: string): string {
  return address.toLowerCase();
}

export function isAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

export function short(address: string): string {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

// EIP-55 mixed-case checksum.
export function toChecksum(address: string): string {
  const hex = normalize(address).slice(2);
  const hash = bytesToHex(keccak_256(utf8ToBytes(hex)));
  let out = "0x";
  for (let i = 0; i < 40; i += 1) out += parseInt(hash[i]!, 16) >= 8 ? hex[i]!.toUpperCase() : hex[i]!;
  return out;
}

// All-lowercase or all-uppercase input carries no checksum; mixed case must match.
export function checksumStatus(address: string): "valid" | "invalid" | "none" {
  const body = address.slice(2);
  if (body === body.toLowerCase() || body === body.toUpperCase()) return "none";
  return toChecksum(address) === address ? "valid" : "invalid";
}

export type Lookalike = { address: string; matchedPrefix: number; matchedSuffix: number };

// Shared leading/trailing hex characters (after 0x), case-insensitive.
export function similarity(a: string, b: string): { prefix: number; suffix: number } {
  const x = normalize(a).slice(2);
  const y = normalize(b).slice(2);
  let prefix = 0;
  while (prefix < 40 && x[prefix] === y[prefix]) prefix += 1;
  let suffix = 0;
  while (suffix < 40 && x[39 - suffix] === y[39 - suffix]) suffix += 1;
  return { prefix, suffix };
}

// The paper's threshold is prefix >= 3 and suffix >= 4 (wallets abbreviate both
// ends); the mirrored 4/3 case is included because some wallets show 4+3.
// Random collision odds are about 1 in 16^7 per pair.
export function isLookalike(a: string, b: string): Lookalike | null {
  if (normalize(a) === normalize(b)) return null;
  const { prefix, suffix } = similarity(a, b);
  if ((prefix >= 3 && suffix >= 4) || (prefix >= 4 && suffix >= 3)) {
    return { address: normalize(b), matchedPrefix: prefix, matchedSuffix: suffix };
  }
  return null;
}

export function findLookalikes(target: string, candidates: Iterable<string>): Lookalike[] {
  const out: Lookalike[] = [];
  const seen = new Set<string>();
  for (const candidate of candidates) {
    const key = normalize(candidate);
    if (seen.has(key)) continue;
    seen.add(key);
    const match = isLookalike(target, candidate);
    if (match) out.push(match);
  }
  return out.sort((p, q) => (q.matchedPrefix + q.matchedSuffix) - (p.matchedPrefix + p.matchedSuffix));
}

// Cyrillic and Greek letters that render like Latin ones in token symbols ("UЅDC").
const HOMOGLYPHS: Record<string, string> = {
  А: "A", В: "B", С: "C", Е: "E", Н: "H", І: "I", Ј: "J", К: "K", М: "M", О: "O", Р: "P", Ѕ: "S", Т: "T", Х: "X", У: "Y",
  а: "A", с: "C", е: "E", і: "I", ј: "J", о: "O", р: "P", ѕ: "S", х: "X", у: "Y",
  Α: "A", Β: "B", Ε: "E", Ζ: "Z", Η: "H", Ι: "I", Κ: "K", Μ: "M", Ν: "N", Ο: "O", Ρ: "P", Τ: "T", Υ: "Y", Χ: "X",
};

export function canonicalSymbol(symbol: string): string {
  return [...symbol.normalize("NFKC")].map((c) => HOMOGLYPHS[c] ?? c).join("").toUpperCase().replace(/[^A-Z0-9]/g, "");
}

export function isCounterfeitToken(t: Pick<Transfer, "tokenAddress" | "tokenSymbol" | "tokenFlagged">): boolean {
  if (t.tokenFlagged) return true;
  const symbol = canonicalSymbol(t.tokenSymbol);
  for (const [name, addresses] of Object.entries(CANONICAL)) {
    if (symbol === name || (symbol.includes(name) && symbol.length <= name.length + 2)) {
      return !addresses.includes(normalize(t.tokenAddress));
    }
  }
  return false;
}

export function isSystemAddress(address: string): string | null {
  const a = normalize(address);
  if (/^0x0{40}$/.test(a)) return "the zero address; funds sent there are destroyed";
  if (a === "0x000000000000000000000000000000000000dead") return "a burn address; funds sent there are destroyed";
  if (/^0x0{37}[0-9a-f]{3}$/.test(a)) return "a precompile/system address that cannot hold your funds";
  if (/^0x4200000000000000000000000000000000000[0-9a-f]{3}$/.test(a)) return "a Base system (predeploy) contract";
  return null;
}

type Counterparty = {
  address: string;
  payments: number;
  poisonTransfers: number;
  kinds: Set<PoisonKind>;
  txs: Set<string>;
  lastSeen: string | null;
};

export type Payment = { to: string; amountAtomic: bigint; timestamp: string | null };

export type History = {
  counterparties: Map<string, Counterparty>;
  payments: Payment[];
  transfersAnalyzed: number;
};

export function classify(sender: string, t: Transfer): { other: string; outgoing: boolean; kind: PoisonKind | "payment" | "receipt" } | null {
  const me = normalize(sender);
  const from = normalize(t.from);
  const to = normalize(t.to);
  if (from !== me && to !== me) return null;
  const outgoing = from === me;
  const other = outgoing ? to : from;
  const value = /^[0-9]+$/.test(t.value) ? BigInt(t.value) : 0n;
  const token = normalize(t.tokenAddress);
  if (isCounterfeitToken(t)) return { other, outgoing, kind: "counterfeit_token" };
  if (value === 0n) return { other, outgoing, kind: "zero_value" };
  if (!outgoing) {
    const ceiling = TINY_CEILING[token];
    return { other, outgoing, kind: ceiling !== undefined && value < ceiling ? "tiny_transfer" : "receipt" };
  }
  return { other, outgoing, kind: "payment" };
}

export function analyzeHistory(sender: string, transfers: Transfer[]): History {
  const me = normalize(sender);
  const counterparties = new Map<string, Counterparty>();
  const payments: Payment[] = [];
  const seen = new Set<string>();
  let analyzed = 0;
  for (const t of transfers) {
    const key = `${t.txHash}:${normalize(t.from)}:${normalize(t.to)}:${t.value}:${normalize(t.tokenAddress)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const c = classify(sender, t);
    if (!c) continue;
    analyzed += 1;
    if (c.other === me) continue;
    let entry = counterparties.get(c.other);
    if (!entry) {
      entry = { address: c.other, payments: 0, poisonTransfers: 0, kinds: new Set(), txs: new Set(), lastSeen: null };
      counterparties.set(c.other, entry);
    }
    if (t.timestamp && (!entry.lastSeen || t.timestamp > entry.lastSeen)) entry.lastSeen = t.timestamp;
    if (c.kind === "payment") {
      // Real value the user chose to send establishes a payee.
      entry.payments += 1;
      if (normalize(t.tokenAddress) === BASE_USDC) payments.push({ to: c.other, amountAtomic: BigInt(t.value), timestamp: t.timestamp });
    } else if (c.kind !== "receipt") {
      entry.poisonTransfers += 1;
      entry.kinds.add(c.kind);
      entry.txs.add(t.txHash);
    }
  }
  return { counterparties, payments, transfersAnalyzed: analyzed };
}

export type PoisoningAttempt = {
  attacker: string;
  imitates: string;
  matchedPrefix: number;
  matchedSuffix: number;
  plantedTransfers: number;
  kinds: PoisonKind[];
  paidAttacker: boolean;
  lastSeen: string | null;
};

export type Assessment = {
  history: History;
  trusted: Set<string>;
  attempts: PoisoningAttempt[];
  attackers: Map<string, PoisoningAttempt>;
};

// Clean payees (paid, never poisoned) and user-supplied addresses anchor the
// comparison; any poisoned counterparty that imitates one of them is an
// attacker, and a payment to it is a payoff.
export function assess(sender: string, transfers: Transfer[], knownRecipients: string[] = []): Assessment {
  const history = analyzeHistory(sender, transfers);
  const anchors = new Set(knownRecipients.map(normalize));
  for (const c of history.counterparties.values()) if (c.payments > 0 && c.poisonTransfers === 0) anchors.add(c.address);
  const attackers = new Map<string, PoisoningAttempt>();
  for (const c of history.counterparties.values()) {
    if (c.poisonTransfers === 0 || anchors.has(c.address)) continue;
    const match = findLookalikes(c.address, anchors)[0];
    if (!match) continue;
    attackers.set(c.address, {
      attacker: c.address, imitates: match.address, matchedPrefix: match.matchedPrefix, matchedSuffix: match.matchedSuffix,
      plantedTransfers: c.txs.size, kinds: [...c.kinds].sort(), paidAttacker: c.payments > 0, lastSeen: c.lastSeen,
    });
  }
  const trusted = new Set(anchors);
  for (const c of history.counterparties.values()) if (c.payments > 0 && !attackers.has(c.address)) trusted.add(c.address);
  const attempts = [...attackers.values()].sort((a, b) =>
    Number(b.paidAttacker) - Number(a.paidAttacker) || (b.matchedPrefix + b.matchedSuffix) - (a.matchedPrefix + a.matchedSuffix));
  return { history, trusted, attempts, attackers };
}

export function scanPoisoning(sender: string, transfers: Transfer[], knownRecipients: string[] = []) {
  const { attempts, history, trusted } = assess(sender, transfers, knownRecipients);
  return { attempts, history, genuinePayees: trusted.size };
}

export type ScreenInput = {
  sender: string;
  recipient: string;
  amountAtomic?: bigint | undefined;
  knownRecipients?: string[] | undefined;
  recipientInfo: AddressInfo | null;
  senderInfo: AddressInfo | null;
  transfers: Transfer[] | null;
  historyComplete?: boolean;
  historyError?: string | null;
  usdcBalanceAtomic: bigint | null;
  recipientSanctioned?: boolean | null;
  recipientName?: string | null;
  now?: number;
};

export type ScreenResult = {
  verdict: "safe" | "caution" | "block";
  riskScore: number;
  summary: string;
  findings: Finding[];
  recipient: { address: string; checksumAddress: string; isContract: boolean | null; isScam: boolean | null; sanctioned: boolean | null; name: string | null; ensName: string | null };
  knownRecipient: boolean;
  lookalikeOf: string[];
  transfersAnalyzed: number;
  poisoningAttemptsDetected: number;
  usdcBalance: string | null;
};

const WEIGHT: Record<Severity, number> = { block: 80, caution: 25, info: 0 };
const DAY_MS = 86_400_000;

export function formatUsdc(atomic: bigint): string {
  const whole = atomic / 1_000_000n;
  const fraction = (atomic % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

export function screen(input: ScreenInput): ScreenResult {
  const findings: Finding[] = [];
  const add = (severity: Severity, code: string, message: string) => findings.push({ code, severity, message });
  const sender = normalize(input.sender);
  const recipient = normalize(input.recipient);
  const explicit = new Set((input.knownRecipients ?? []).map(normalize));
  const now = input.now ?? Date.now();

  if (checksumStatus(input.recipient) === "invalid") {
    add("block", "BAD_CHECKSUM", `The recipient's mixed-case spelling fails its EIP-55 checksum (expected ${toChecksum(input.recipient)}). A character was mistyped or altered; get the address again from the payee.`);
  }
  for (const k of input.knownRecipients ?? []) {
    if (checksumStatus(k) === "invalid") add("caution", "KNOWN_RECIPIENT_BAD_CHECKSUM", `Trusted address ${k} fails its EIP-55 checksum, so your address book entry may be corrupted.`);
  }
  const system = isSystemAddress(recipient);
  if (system) add("block", "SYSTEM_ADDRESS", `The recipient is ${system}.`);
  if (CANONICAL_TOKENS.has(recipient)) add("block", "TOKEN_CONTRACT", "The recipient is a token contract; tokens sent there are almost always unrecoverable.");
  if (recipient === sender) add("info", "SELF_TRANSFER", "Sender and recipient are the same wallet.");
  if (input.recipientName) {
    add("info", "NAME_RESOLVED", `${input.recipientName} resolved on-chain to ${toChecksum(recipient)}. A name proves who registered it, not who you meant to pay; confirm the spelling with the payee.`);
  }
  if (input.recipientSanctioned === true) {
    add("block", "SANCTIONED", "The recipient is on the OFAC sanctions list (Chainalysis sanctions oracle on Base). Paying it may be illegal.");
  } else if (input.recipientSanctioned == null) {
    add("info", "SANCTIONS_UNCHECKED", "The sanctions oracle could not be reached, so OFAC screening was skipped.");
  }

  let trusted = new Set(explicit);
  let attackers = new Map<string, PoisoningAttempt>();
  let attempts: PoisoningAttempt[] = [];
  let transfersAnalyzed = 0;
  let history: History | null = null;
  if (input.transfers) {
    const a = assess(sender, input.transfers, input.knownRecipients);
    ({ trusted, attackers, attempts, history } = a);
    transfersAnalyzed = a.history.transfersAnalyzed;
    if (input.historyComplete === false) add("info", "HISTORY_PARTIAL", `Checked the most recent ${transfersAnalyzed} transfers; older history was not scanned.`);
  } else {
    add("caution", "HISTORY_UNAVAILABLE", `Could not load the sender's Base transfer history${input.historyError ? ` (${input.historyError})` : ""}, so lookalike checks used only the trusted addresses you supplied.`);
  }

  const attack = attackers.get(recipient);
  if (attack?.paidAttacker) {
    add("block", "PRIOR_PAYOFF", `You have already sent real funds to ${short(recipient)}, but it is a lookalike of ${attack.imitates} that first appeared through poisoning transfers. That earlier payment was probably stolen; do not repeat it.`);
  } else if (attack) {
    add("block", "POISONING_SOURCE", `Recipient ${short(recipient)} reached your history only through ${attack.kinds.join(", ").replace(/_/g, " ")} transfers, the signature of address-poisoning spam.`);
  }

  const knownRecipient = trusted.has(recipient) && !attack;
  // Explicit trusted addresses always win; a history payee that imitates one is suspect.
  const comparison = [...trusted].filter((a) => a !== recipient);
  const lookalikes = explicit.has(recipient) ? [] : findLookalikes(recipient, comparison);
  const explicitLookalike = lookalikes.find((l) => explicit.has(l.address));
  if (lookalikes.length > 0 && (!knownRecipient || explicitLookalike)) {
    const best = explicitLookalike ?? lookalikes[0]!;
    add("block", "LOOKALIKE_OF_KNOWN_PAYEE", `Recipient ${recipient} imitates ${best.address}, an address you ${explicit.has(best.address) ? "marked as trusted" : "have really paid"}. The first ${best.matchedPrefix} and last ${best.matchedSuffix} hex characters match, so when shortened both display as ${short(recipient)}. This is the address-poisoning pattern; confirm the full address with the payee out of band.`);
  } else if (lookalikes.length > 0) {
    add("caution", "SIMILAR_PAYEES", `You have paid both ${short(recipient)} and the very similar ${lookalikes[0]!.address}. One of them may be a lookalike; confirm the full address with the payee.`);
  }

  const info = input.recipientInfo;
  if (info) {
    if (info.isScam || info.reputation === "scam") add("block", "FLAGGED_SCAM", "Blockscout flags the recipient as a scam address.");
    if (info.isToken && !CANONICAL_TOKENS.has(recipient)) {
      add("block", "TOKEN_CONTRACT", `The recipient is a token contract${info.name ? ` (${info.name})` : ""}; tokens sent there are almost always unrecoverable.`);
    } else if (info.isContract && !info.isToken && !system) {
      add("caution", "CONTRACT_RECIPIENT", `The recipient is a smart contract${info.name ? ` (${info.name})` : ""}. Fine for smart wallets and payment contracts, but confirm it can receive and release USDC.`);
    }
  } else {
    add("caution", "RECIPIENT_UNVERIFIED", "Could not load recipient details, so contract and scam checks were skipped.");
  }

  const blocked = findings.some((f) => f.severity === "block");
  if (knownRecipient) {
    add("info", "KNOWN_PAYEE", explicit.has(recipient) ? "The recipient is one of the trusted addresses you supplied." : "You have sent real funds to this exact address before.");
  } else if (!blocked && input.transfers && recipient !== sender) {
    add("caution", "FIRST_TIME_PAYEE", "You have never paid this address before. Double-check it with the payee, or send a small test amount first.");
    if (input.amountAtomic !== undefined && input.amountAtomic >= 500_000_000n) {
      add("caution", "LARGE_FIRST_PAYMENT", `${formatUsdc(input.amountAtomic)} USDC is a large first payment to a new address; send a test transfer first.`);
    }
  }

  if (input.amountAtomic !== undefined && history) {
    const amount = input.amountAtomic;
    const duplicate = history.payments.find((p) => p.to === recipient && p.amountAtomic === amount && p.timestamp && now - Date.parse(p.timestamp) < DAY_MS);
    if (duplicate) {
      add("caution", "POSSIBLE_DUPLICATE", `You already sent exactly ${formatUsdc(amount)} USDC to this address at ${duplicate.timestamp}. If a previous attempt looked like it failed, check it before paying again.`);
    }
    const prior = history.payments.map((p) => p.amountAtomic);
    const largest = prior.reduce((m, v) => (v > m ? v : m), 0n);
    if (prior.length >= 3 && amount >= 100_000_000n && amount > largest * 10n) {
      add("caution", "UNUSUAL_AMOUNT", `${formatUsdc(amount)} USDC is more than 10x your largest recent USDC payment (${formatUsdc(largest)}). Confirm the amount, including decimal places.`);
    }
  }
  if (attempts.length > 0) {
    add("info", "WALLET_TARGETED", `${attempts.length} lookalike address${attempts.length === 1 ? " has" : "es have"} planted fake transfers in this wallet's history. Never copy payees from recent activity.`);
  }

  if (input.amountAtomic !== undefined && input.usdcBalanceAtomic !== null && input.usdcBalanceAtomic < input.amountAtomic) {
    add("block", "INSUFFICIENT_USDC", `Wallet holds ${formatUsdc(input.usdcBalanceAtomic)} USDC on Base, less than the ${formatUsdc(input.amountAtomic)} USDC requested.`);
  }
  if (input.senderInfo?.coinBalanceWei === "0") add("caution", "NO_GAS", "The sending wallet has no ETH on Base for network fees.");

  const order: Record<Severity, number> = { block: 0, caution: 1, info: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  const riskScore = Math.min(100, findings.reduce((sum, f) => sum + WEIGHT[f.severity], 0));
  const verdict = findings.some((f) => f.severity === "block") ? "block" : findings.some((f) => f.severity === "caution") ? "caution" : "safe";
  const top = findings.find((f) => f.severity === verdict) ?? findings[0];
  const summary = verdict === "safe"
    ? `SAFE: ${short(recipient)} is a known payee with no poisoning signals.`
    : `${verdict.toUpperCase()}: ${top?.message ?? "Review the findings."}`;

  return {
    verdict, riskScore, summary, findings,
    recipient: {
      address: input.recipient, checksumAddress: toChecksum(recipient),
      isContract: info?.isContract ?? null, isScam: info ? info.isScam : null, sanctioned: input.recipientSanctioned ?? null,
      name: info?.name ?? null, ensName: input.recipientName ?? info?.ensName ?? null,
    },
    knownRecipient,
    lookalikeOf: lookalikes.map((l) => l.address),
    transfersAnalyzed,
    poisoningAttemptsDetected: attempts.length,
    usdcBalance: input.usdcBalanceAtomic === null ? null : formatUsdc(input.usdcBalanceAtomic),
  };
}

export function renderReport(result: ScreenResult): string {
  const lines = [result.summary, `Risk score: ${result.riskScore}/100 · ${result.transfersAnalyzed} transfers analyzed`];
  for (const f of result.findings) lines.push(`- [${f.severity.toUpperCase()}] ${f.code}: ${f.message}`);
  return lines.join("\n");
}

export function encodeErc20Transfer(recipient: string, amount: bigint): string {
  if (!isAddress(recipient)) throw new Error("Recipient must be a 20-byte hex address.");
  if (amount <= 0n || amount >= 2n ** 256n) throw new Error("Amount must be positive.");
  return `0xa9059cbb${normalize(recipient).slice(2).padStart(64, "0")}${amount.toString(16).padStart(64, "0")}`;
}

// A CAUTION payment needs the code shown alongside its warnings, so an agent
// cannot pre-set a flag and skip them. It binds the exact payment and the
// warnings seen, and stays valid for 10 to 20 minutes.
const CODE_WINDOW_MS = 600_000;

function codeFor(sender: string, recipient: string, amountAtomic: bigint, codes: string[], bucket: number): string {
  const material = [normalize(sender), normalize(recipient), amountAtomic.toString(), [...codes].sort().join(","), bucket].join("|");
  return `SS-${bytesToHex(sha256(utf8ToBytes(material))).slice(0, 8).toUpperCase()}`;
}

export function confirmationCode(sender: string, recipient: string, amountAtomic: bigint, result: ScreenResult, now = Date.now()): string {
  const codes = result.findings.filter((f) => f.severity === "caution").map((f) => f.code);
  return codeFor(sender, recipient, amountAtomic, codes, Math.floor(now / CODE_WINDOW_MS));
}

export function verifyConfirmationCode(code: string, sender: string, recipient: string, amountAtomic: bigint, result: ScreenResult, now = Date.now()): boolean {
  const codes = result.findings.filter((f) => f.severity === "caution").map((f) => f.code);
  const bucket = Math.floor(now / CODE_WINDOW_MS);
  const given = code.trim().toUpperCase();
  return [bucket, bucket - 1].some((b) => codeFor(sender, recipient, amountAtomic, codes, b) === given);
}
