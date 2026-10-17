import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

import { gather, transferHistory } from "./blockscout.js";
import { resolveRecipient } from "./names.js";
import { amountCheck, parsePaymentRequest } from "./request.js";
import { atomicAmount, evmOutputSchema, proposeEvm } from "./paybox.js";
import {
  BASE_USDC, checksumStatus, confirmationCode, encodeErc20Transfer, findLookalikes, formatUsdc, isSystemAddress, normalize,
  renderReport, scanPoisoning, screen, short, toChecksum, verifyConfirmationCode, type ScreenResult,
} from "./safety.js";

const PROTOCOL_VERSION = "2026-07-28";

const address = z.string().trim().regex(/^0x[0-9a-fA-F]{40}$/, "Use a 0x-prefixed 20-byte hex address (42 characters). ENS and Basenames are not accepted; resolve them first.");
const usdcAmount = z.string().trim().regex(/^(0|[1-9][0-9]{0,11})(\.[0-9]{1,6})?$/, "Use a decimal USDC amount with at most 6 decimals and no commas or symbols, e.g. \"12.50\".");
const payee = z.string().trim().min(3).max(255)
  .describe("Recipient as a 0x address or a Basename such as alice.base.eth (resolved on-chain; lookalike-character names are refused).");
const knownRecipients = z.array(address).max(50).optional()
  .describe("Optional trusted payee addresses (an address book, or the address on an invoice the payee sent directly). The recipient is checked for lookalikes against these as well as against the sender's on-chain history.");

const finding = z.object({ code: z.string(), severity: z.enum(["block", "caution", "info"]), message: z.string() }).strict();
const screenOutput = z.object({
  verdict: z.enum(["safe", "caution", "block"]),
  riskScore: z.number().int().min(0).max(100),
  summary: z.string(),
  findings: z.array(finding),
  recipient: z.object({
    address: z.string(),
    checksumAddress: z.string(),
    isContract: z.boolean().nullable(),
    isScam: z.boolean().nullable(),
    sanctioned: z.boolean().nullable(),
    name: z.string().nullable(),
    ensName: z.string().nullable(),
  }).strict(),
  knownRecipient: z.boolean(),
  lookalikeOf: z.array(z.string()),
  transfersAnalyzed: z.number().int().min(0),
  poisoningAttemptsDetected: z.number().int().min(0),
  usdcBalance: z.string().nullable(),
  confirmationCode: z.string().nullable(),
}).strict();


// send_usdc returns either a PayBox proposal or a structured refusal, so agents
// calling through PayBox see why a payment was stopped instead of a bare error.
const PROPOSAL_KEY = "io.paybox/transactionProposal";
const refusalSchema = z.object({
  status: z.enum(["blocked", "needs_confirmation", "invalid"]),
  verdict: z.enum(["block", "caution"]).nullable(),
  summary: z.string(),
  findings: z.array(finding),
  confirmationCode: z.string().nullable(),
  nextStep: z.string(),
}).strict();
const sendOutputSchema = z.object({
  [PROPOSAL_KEY]: evmOutputSchema.shape[PROPOSAL_KEY].optional(),
  refusal: refusalSchema.optional(),
}).strict();
type Refusal = z.infer<typeof refusalSchema>;
const refusePayment = (text: string, refusal: Refusal) => ({ content: [{ type: "text" as const, text }], structuredContent: { refusal } });
const nameFinding = (r: { code: string; message: string }) => [{ code: r.code, severity: "block" as const, message: r.message }];

function createServer() {
  const server = new McpServer(
    { name: "safesend", version: "3.0.0" },
    { supportedProtocolVersions: [PROTOCOL_VERSION] },
  );

  server.registerTool(
    "check_address_lookalike",
    {
      title: "Check address for lookalikes",
      description: "Offline check before trusting an address copied from history, chat or a document: does it imitate a trusted address (same leading and trailing hex characters, different middle, the address-poisoning pattern)? Also validates the EIP-55 checksum and flags burn/system addresses. Needs no network.",
      inputSchema: z.object({
        address,
        trustedAddresses: z.array(address).min(1).max(100).describe("Addresses the user trusts, e.g. an address book or past payees."),
      }).strict(),
      outputSchema: z.object({
        address: z.string(),
        checksumAddress: z.string(),
        verdict: z.enum(["exact_match", "lookalike", "no_match", "invalid"]),
        checksum: z.enum(["valid", "invalid", "none"]),
        matches: z.array(z.object({ address: z.string(), matchedPrefix: z.number().int(), matchedSuffix: z.number().int() }).strict()),
        explanation: z.string(),
      }).strict(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ address: target, trustedAddresses }) => {
      const checksum = checksumStatus(target);
      const system = isSystemAddress(target);
      const exact = trustedAddresses.some((a) => normalize(a) === normalize(target));
      const matches = exact ? [] : findLookalikes(target, trustedAddresses);
      const verdict = checksum === "invalid" || system ? "invalid" : exact ? "exact_match" : matches.length > 0 ? "lookalike" : "no_match";
      const explanation = checksum === "invalid"
        ? `INVALID: ${target} fails its EIP-55 checksum (expected ${toChecksum(target)}). A character was mistyped or altered.`
        : system
          ? `INVALID: ${short(target)} is ${system}.`
          : verdict === "exact_match"
            ? `${short(target)} exactly matches a trusted address.`
            : verdict === "lookalike"
              ? `DANGER: ${short(target)} imitates trusted address ${short(matches[0]!.address)} (first ${matches[0]!.matchedPrefix} and last ${matches[0]!.matchedSuffix} hex characters match, middle differs). Treat it as an address-poisoning attempt and do not send funds.`
              : `${short(target)} does not match or imitate any trusted address; it is simply unknown.`;
      return {
        content: [{ type: "text", text: explanation }],
        structuredContent: { address: target, checksumAddress: toChecksum(target), verdict, checksum, matches, explanation },
      };
    },
  );

  server.registerTool(
    "screen_recipient",
    {
      title: "Screen a Base payment recipient",
      description: "Before paying someone on Base, check the recipient against the sender's real on-chain history and public risk data: lookalikes of past payees, tiny/zero-value/counterfeit-token poisoning, earlier payments to a poisoner, OFAC sanctions (Chainalysis oracle), scam flags, token and system contracts, checksum typos, first-time payees, duplicate or unusually large payments, USDC balance and gas. Returns safe/caution/block with reasons, and a confirmationCode for send_usdc when the verdict is caution. Read-only; never moves funds.",
      inputSchema: z.object({
        sender: address.describe("Public address of the PayBox wallet that would pay."),
        recipient: payee,
        amountUsdc: usdcAmount.optional().describe("Optional USDC amount, to check balance, duplicates and payment size."),
        knownRecipients,
      }).strict(),
      outputSchema: screenOutput,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ sender, recipient: target, amountUsdc, knownRecipients: trusted }) => {
      const resolved = await resolveRecipient(target);
      if (!resolved.ok) {
        const summary = `BLOCK: ${resolved.message}`;
        return {
          content: [{ type: "text", text: `${summary}\n- [BLOCK] ${resolved.code}: ${resolved.message}` }],
          structuredContent: {
            verdict: "block" as const, riskScore: 100, summary, findings: nameFinding(resolved),
            recipient: { address: target, checksumAddress: target, isContract: null, isScam: null, sanctioned: null, name: null, ensName: null },
            knownRecipient: false, lookalikeOf: [], transfersAnalyzed: 0, poisoningAttemptsDetected: 0, usdcBalance: null, confirmationCode: null,
          },
        };
      }
      const recipient = resolved.address;
      const amountAtomic = amountUsdc === undefined ? undefined : BigInt(atomicAmount(amountUsdc, 6));
      const data = await gather(sender, recipient, amountAtomic !== undefined);
      const result = screen({ sender, recipient, amountAtomic, knownRecipients: trusted, recipientName: resolved.name, ...data });
      const code = result.verdict === "caution" && amountAtomic !== undefined && amountAtomic > 0n ? confirmationCode(sender, recipient, amountAtomic, result) : null;
      const text = renderReport(result) + (code ? `\nIf the user confirms after reading these warnings, pass confirmationCode "${code}" to send_usdc.` : "");
      return {
        content: [{ type: "text", text }],
        structuredContent: { ...result, findings: result.findings.map((f) => ({ ...f })), confirmationCode: code },
      };
    },
  );

  server.registerTool(
    "scan_wallet_poisoning",
    {
      title: "Scan a Base wallet for address-poisoning attacks",
      description: "Read-only audit of a Base wallet's recent token-transfer history. Finds attacker addresses that planted tiny, zero-value or counterfeit-token transfers to imitate people this wallet really paid, names the genuine payee each one imitates, and flags any real payment already sent to an attacker. Use it to warn the user which addresses in their activity must never be copied.",
      inputSchema: z.object({
        wallet: address.describe("Public address of the wallet to audit."),
        knownRecipients,
      }).strict(),
      outputSchema: z.object({
        wallet: z.string(),
        status: z.enum(["compromised", "targeted", "clean", "unavailable"]),
        transfersAnalyzed: z.number().int().min(0),
        historyComplete: z.boolean(),
        genuinePayees: z.number().int().min(0),
        attempts: z.array(z.object({
          attacker: z.string(),
          imitates: z.string(),
          matchedPrefix: z.number().int(),
          matchedSuffix: z.number().int(),
          plantedTransfers: z.number().int().min(0),
          kinds: z.array(z.enum(["tiny_transfer", "zero_value", "counterfeit_token"])),
          paidAttacker: z.boolean(),
          lastSeen: z.string().nullable(),
        }).strict()),
        summary: z.string(),
      }).strict(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ wallet, knownRecipients: trusted }) => {
      const { page: history, source, error } = await transferHistory(wallet);
      if (!history) {
        const summary = `Could not load this wallet's Base transfer history (${error}). No conclusion can be drawn; try again shortly.`;
        return {
          content: [{ type: "text", text: summary }],
          structuredContent: { wallet, status: "unavailable" as const, transfersAnalyzed: 0, historyComplete: false, genuinePayees: 0, attempts: [], summary },
        };
      }
      const { attempts, history: h, genuinePayees } = scanPoisoning(wallet, history.transfers, trusted);
      const paid = attempts.filter((a) => a.paidAttacker);
      const status = paid.length > 0 ? "compromised" as const : attempts.length > 0 ? "targeted" as const : "clean" as const;
      const scope = `${history.complete ? "" : "the most recent "}${h.transfersAnalyzed} transfers (via ${source === "alchemy" ? "Alchemy" : "Blockscout"})`;
      const summary = status === "compromised"
        ? `${short(wallet)} has already paid ${paid.length} poisoning address${paid.length === 1 ? "" : "es"}; those funds were likely stolen. ${attempts.length} lookalike attacker${attempts.length === 1 ? "" : "s"} found in ${scope}.`
        : status === "targeted"
          ? `${short(wallet)} is being targeted: ${attempts.length} lookalike address${attempts.length === 1 ? "" : "es"} planted fake transfers in ${scope}. Never copy a payee from recent activity.`
          : `No address-poisoning lookalikes found in ${scope} of ${short(wallet)}.`;
      const lines = [summary, ...attempts.map((a) => `- ${a.paidAttacker ? "[PAID] " : ""}${a.attacker} imitates ${a.imitates} (first ${a.matchedPrefix} / last ${a.matchedSuffix} hex match; ${a.plantedTransfers} planted: ${a.kinds.join(", ").replace(/_/g, " ")})`)];
      return {
        content: [{ type: "text", text: lines.join("\n") }],
        structuredContent: {
          wallet, status, transfersAnalyzed: h.transfersAnalyzed, historyComplete: history.complete, genuinePayees,
          attempts: attempts.map((a) => ({ ...a, kinds: [...a.kinds] })), summary,
        },
      };
    },
  );

  server.registerTool(
    "verify_payment_request",
    {
      title: "Verify an invoice or payment link before paying",
      description: "Check a payment request before paying it: an EIP-681 link (ethereum:0x…@8453/transfer?address=…&uint256=…) or pasted invoice/chat text. Catches counterfeit-token invoices, wrong networks, native-ETH or contract-call links, truncated or multiple conflicting addresses, spoofed Basenames and amount mismatches, then screens the payee exactly like screen_recipient. Returns the ready-to-use send_usdc arguments when the request can be paid. Read-only; never moves funds.",
      inputSchema: z.object({
        sender: address.describe("Public address of the PayBox wallet that would pay."),
        request: z.string().min(1).max(4096).describe("The payment link or the invoice text exactly as received."),
        expectedAmountUsdc: usdcAmount.optional().describe("What the user expects to pay, to catch altered amounts. Required when the request states no amount."),
        knownRecipients,
      }).strict(),
      outputSchema: z.object({
        verdict: z.enum(["safe", "caution", "block"]),
        summary: z.string(),
        request: z.object({
          format: z.enum(["eip681", "text"]),
          recipient: z.string().nullable(),
          recipientName: z.string().nullable(),
          amountUsdc: z.string().nullable(),
          chainId: z.number().int().nullable(),
          token: z.string().nullable(),
        }).strict(),
        findings: z.array(finding),
        screening: screenOutput.nullable(),
        sendUsdcArguments: z.object({
          sender: z.string(), recipient: z.string(), amountUsdc: z.string(), confirmationCode: z.string().optional(),
        }).strict().nullable(),
      }).strict(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ sender, request, expectedAmountUsdc, knownRecipients: trusted }) => {
      const parsed = parsePaymentRequest(request);
      const findings = [...parsed.findings];
      const expected = expectedAmountUsdc === undefined ? undefined : BigInt(atomicAmount(expectedAmountUsdc, 6));
      const mismatch = amountCheck(parsed.amountAtomic, expected);
      if (mismatch) findings.push(mismatch);
      if (parsed.amountAtomic !== null && parsed.amountAtomic >= 10n ** 18n) {
        findings.push({ code: "ABSURD_AMOUNT", severity: "block", message: "The requested amount is larger than any real USDC payment; the decimals are almost certainly wrong (USDC uses 6 decimals)." });
      }
      const amountAtomic = parsed.amountAtomic ?? expected ?? null;
      if (amountAtomic === null) findings.push({ code: "AMOUNT_UNKNOWN", severity: "caution", message: "The request states no amount; ask the payee or pass expectedAmountUsdc." });

      let recipient: string | null = null;
      let recipientName: string | null = null;
      if (parsed.recipient) {
        const resolved = await resolveRecipient(parsed.recipient);
        if (resolved.ok) ({ address: recipient, name: recipientName } = resolved);
        else findings.push({ code: resolved.code, severity: "block", message: resolved.message });
      }
      let screening: (ScreenResult & { confirmationCode: string | null }) | null = null;
      if (recipient && !findings.some((f) => f.severity === "block")) {
        const data = await gather(sender, recipient, amountAtomic !== null);
        const result = screen({ sender, recipient, amountAtomic: amountAtomic ?? undefined, knownRecipients: trusted, recipientName, ...data });
        screening = { ...result, findings: result.findings.map((f) => ({ ...f })), confirmationCode: null };
      }
      const all = [...findings, ...(screening?.findings ?? [])];
      const verdict = all.some((f) => f.severity === "block") ? "block" as const : all.some((f) => f.severity === "caution") ? "caution" as const : "safe" as const;
      let sendUsdcArguments: { sender: string; recipient: string; amountUsdc: string; confirmationCode?: string } | null = null;
      if (verdict !== "block" && recipient && amountAtomic !== null && screening) {
        // The code covers the payee warnings; request-level warnings are shown here.
        const code = screening.verdict === "caution" ? confirmationCode(sender, recipient, amountAtomic, screening) : null;
        screening.confirmationCode = code;
        sendUsdcArguments = { sender, recipient, amountUsdc: formatUsdc(amountAtomic), ...(code ? { confirmationCode: code } : {}) };
      }
      const top = all.find((f) => f.severity === verdict);
      const summary = verdict === "safe"
        ? `SAFE: the request pays ${formatUsdc(amountAtomic!)} USDC on Base to known payee ${short(recipient!)}.`
        : `${verdict.toUpperCase()}: ${top?.message ?? "Review the findings."}`;
      const lines = [summary, ...findings.map((f) => `- [${f.severity.toUpperCase()}] ${f.code}: ${f.message}`)];
      if (screening) lines.push(...renderReport(screening).split("\n").filter((l) => l !== summary));
      if (sendUsdcArguments) lines.push(verdict === "caution"
        ? `Show every warning to the user. Only if they confirm, call send_usdc with ${JSON.stringify(sendUsdcArguments)}.`
        : `Ready: call send_usdc with ${JSON.stringify(sendUsdcArguments)}.`);
      return {
        content: [{ type: "text", text: lines.join("\n") }],
        structuredContent: {
          verdict, summary,
          request: { format: parsed.format, recipient, recipientName, amountUsdc: amountAtomic === null ? null : formatUsdc(amountAtomic), chainId: parsed.chainId, token: parsed.token },
          findings, screening, sendUsdcArguments,
        },
      };
    },
  );

  server.registerTool(
    "send_usdc",
    {
      title: "Send USDC on Base (SafeSend)",
      description: "Pay USDC on Base with address-poisoning, sanctions and mistake protection. Screens the recipient first (same checks as screen_recipient). BLOCK verdicts are refused and cannot be overridden. CAUTION verdicts are refused with the warnings and a confirmationCode; show the warnings to the user and, only if they confirm, call again with that confirmationCode. SAFE returns an unsigned USDC transfer proposal that PayBox simulates and the user approves; nothing is signed by this plugin. Pass the selected PayBox wallet's public address as sender.",
      inputSchema: z.object({
        sender: address.describe("Public address of the PayBox wallet that will sign; must be the wallet selected for this request."),
        recipient: payee.describe("Address or Basename to pay. Prefer one the payee gave you directly, never one copied from transaction history."),
        amountUsdc: usdcAmount.describe("USDC amount as a decimal string, e.g. \"25\" or \"0.50\"."),
        knownRecipients,
        confirmationCode: z.string().trim().max(32).optional().describe("Code returned with CAUTION warnings. Pass it only after the user has read those warnings and explicitly confirmed. Cannot override a BLOCK."),
      }).strict(),
      outputSchema: sendOutputSchema,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ sender, recipient: target, amountUsdc, knownRecipients: trusted, confirmationCode: code }) => {
      const amountAtomic = BigInt(atomicAmount(amountUsdc, 6));
      if (amountAtomic === 0n) return refusePayment("Amount must be greater than zero.", { status: "invalid", verdict: null, summary: "Amount must be greater than zero.", findings: [], confirmationCode: null, nextStep: "Ask the user for a positive USDC amount." });
      const resolved = await resolveRecipient(target);
      if (!resolved.ok) return refusePayment(`SafeSend refused this payment.\nBLOCK: ${resolved.code}: ${resolved.message}\nNo transaction was proposed.`,
        { status: "blocked", verdict: "block", summary: `BLOCK: ${resolved.message}`, findings: nameFinding(resolved), confirmationCode: null, nextStep: "Do not pay. Get the correct address directly from the payee." });
      const recipient = resolved.address;
      if (normalize(sender) === normalize(recipient)) return refusePayment("Sender and recipient are the same wallet; there is nothing to send.", { status: "invalid", verdict: null, summary: "Sender and recipient are the same wallet.", findings: [], confirmationCode: null, nextStep: "Ask the user who they want to pay." });
      const data = await gather(sender, recipient, true);
      const result: ScreenResult = screen({ sender, recipient, amountAtomic, knownRecipients: trusted, recipientName: resolved.name, ...data });
      const report = renderReport(result);
      if (result.verdict === "block") {
        return refusePayment(`SafeSend refused this payment.\n${report}\nNo transaction was proposed. Get the correct address directly from the payee.`,
          { status: "blocked", verdict: "block", summary: result.summary, findings: result.findings.map((f) => ({ ...f })), confirmationCode: null, nextStep: "Do not pay. Show the findings to the user; a BLOCK cannot be overridden." });
      }
      if (result.verdict === "caution") {
        if (!code) {
          const fresh = confirmationCode(sender, recipient, amountAtomic, result);
          return refusePayment(`SafeSend needs confirmation.\n${report}\nShow these warnings to the user. If they confirm, call send_usdc again with the same arguments and confirmationCode "${fresh}".`,
            { status: "needs_confirmation", verdict: "caution", summary: result.summary, findings: result.findings.map((f) => ({ ...f })), confirmationCode: fresh, nextStep: "Show every warning to the user. Only if they confirm, call send_usdc again with the same arguments plus this confirmationCode." });
        }
        if (!verifyConfirmationCode(code, sender, recipient, amountAtomic, result)) {
          const fresh = confirmationCode(sender, recipient, amountAtomic, result);
          return refusePayment(`That confirmation code does not match this payment or its current warnings (it may have expired or the details changed).\n${report}\nShow these warnings to the user again. If they confirm, use confirmationCode "${fresh}".`,
            { status: "needs_confirmation", verdict: "caution", summary: "The confirmation code is expired or does not match this payment.", findings: result.findings.map((f) => ({ ...f })), confirmationCode: fresh, nextStep: "Show the warnings to the user again and use the new confirmationCode only if they confirm." });
        }
      }
      const to = toChecksum(BASE_USDC);
      const proposal = proposeEvm({ chain: "eip155:8453", to, value: "0", data: encodeErc20Transfer(recipient, amountAtomic) });
      return {
        ...proposal,
        content: [
          { type: "text" as const, text: `SafeSend screened ${short(recipient)}: ${result.verdict.toUpperCase()} (risk ${result.riskScore}/100). Proposed a transfer of ${formatUsdc(amountAtomic)} USDC on Base to ${toChecksum(recipient)}${resolved.name ? ` (${resolved.name})` : ""}.\n${report}` },
          ...proposal.content,
        ],
      };
    },
  );

  return server;
}

serveStdio(createServer, { legacy: "reject" });
