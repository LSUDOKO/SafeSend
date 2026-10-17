import assert from "node:assert/strict";
import { test } from "node:test";

import {
  canonicalSymbol, checksumStatus, confirmationCode, encodeErc20Transfer, findLookalikes, isCounterfeitToken, isSystemAddress,
  scanPoisoning, screen, toChecksum, verifyConfirmationCode, type AddressInfo, type ScreenInput, type Transfer,
} from "../src/safety.js";

const me = "0x1234567890abcdef1234567890abcdef12345678";
const friend = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
const fake = "0xd8da6bf20000000000000000000000000aa96045";
const fake2 = "0xd8dab00000000000000000000000000000a96045";
const stranger = "0x1111111111111111111111111111111111111111";
const USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const FAKE_TOKEN = "0x9999999999999999999999999999999999999999";
const NOW = Date.parse("2026-10-17T12:00:00Z");
const base = { tokenDecimals: 6, tokenFlagged: false, timestamp: "2026-10-17T10:00:00Z" };
const tx = (from: string, to: string, value: string, extra: Partial<Transfer> = {}): Transfer =>
  ({ ...base, from, to, value, tokenAddress: USDC, tokenSymbol: "USDC", txHash: `0x${Math.random().toString(16).slice(2)}`, ...extra });

const history: Transfer[] = [
  tx(me, friend, "5000000", { timestamp: "2026-10-01T10:00:00Z" }),
  tx(me, fake, "0"),                                                          // zero-value transferFrom
  tx(fake, me, "5000000", { tokenAddress: FAKE_TOKEN }),                      // counterfeit USDC
  tx(fake2, me, "1000"),                                                      // tiny real-USDC dust
];
const wallet: AddressInfo = { isContract: false, isScam: false, isToken: false, name: null, ensName: null, reputation: "ok", coinBalanceWei: "1" };
const run = (recipient: string, extra: Partial<ScreenInput> = {}) =>
  screen({
    sender: me, recipient, amountAtomic: 1_000_000n, recipientInfo: wallet, senderInfo: wallet, transfers: history,
    historyComplete: true, usdcBalanceAtomic: 100_000_000n, recipientSanctioned: false, now: NOW, ...extra,
  });
const codes = (r: ReturnType<typeof run>) => r.findings.map((f) => f.code);

test("lookalike of a real payee is blocked", () => {
  const r = run(fake);
  assert.equal(r.verdict, "block");
  assert.ok(codes(r).includes("LOOKALIKE_OF_KNOWN_PAYEE"));
  assert.ok(codes(r).includes("POISONING_SOURCE"));
});

test("tiny-transfer dust from a lookalike is detected", () => {
  const r = run(fake2);
  assert.equal(r.verdict, "block");
  const { attempts } = scanPoisoning(me, history);
  assert.ok(attempts.some((a) => a.attacker === fake2 && a.kinds.includes("tiny_transfer")));
});

test("known payee is safe", () => {
  const r = run(friend);
  assert.equal(r.verdict, "safe");
  assert.equal(r.knownRecipient, true);
});

test("prior payment to a poisoner is a payoff", () => {
  const paid = [...history, tx(me, fake, "2000000")];
  const r = run(fake, { transfers: paid });
  assert.equal(r.verdict, "block");
  assert.ok(codes(r).includes("PRIOR_PAYOFF"));
  const { attempts } = scanPoisoning(me, paid);
  assert.equal(attempts.find((a) => a.attacker === fake)?.paidAttacker, true);
});

test("explicit trusted address beats a lookalike already paid", () => {
  const clean = [tx(me, fake, "2000000")];
  const r = run(fake, { transfers: clean, knownRecipients: [friend] });
  assert.equal(r.verdict, "block");
  assert.ok(codes(r).includes("LOOKALIKE_OF_KNOWN_PAYEE"));
});

test("two genuine similar payees only need confirmation", () => {
  const twins = [tx(me, friend, "1000000"), tx(me, fake, "1000000")];
  const r = run(fake, { transfers: twins });
  assert.equal(r.verdict, "caution");
  assert.ok(codes(r).includes("SIMILAR_PAYEES"));
});

test("first-time payee needs confirmation; large first payment flagged", () => {
  const r = run(stranger, { amountAtomic: 600_000_000n, usdcBalanceAtomic: 1_000_000_000n });
  assert.equal(r.verdict, "caution");
  assert.ok(codes(r).includes("FIRST_TIME_PAYEE"));
  assert.ok(codes(r).includes("LARGE_FIRST_PAYMENT"));
});

test("sanctioned recipient is blocked", () => {
  assert.ok(codes(run(friend, { recipientSanctioned: true })).includes("SANCTIONED"));
  assert.equal(run(friend, { recipientSanctioned: true }).verdict, "block");
});

test("token, burn and system addresses are blocked offline", () => {
  for (const a of [USDC, "0x0000000000000000000000000000000000000000", "0x000000000000000000000000000000000000dEaD", "0x4200000000000000000000000000000000000016", "0x0000000000000000000000000000000000000001"]) {
    assert.equal(run(a, { recipientInfo: null, transfers: null }).verdict, "block", a);
  }
  assert.equal(isSystemAddress(friend), null);
});

test("bad EIP-55 checksum is blocked; lowercase is accepted", () => {
  assert.equal(checksumStatus(friend), "valid");
  assert.equal(checksumStatus(friend.toLowerCase()), "none");
  const typo = friend.replace("dA6BF", "Da6BF");
  assert.equal(checksumStatus(typo), "invalid");
  assert.ok(codes(run(typo)).includes("BAD_CHECKSUM"));
  assert.equal(toChecksum(friend.toLowerCase()), friend);
});

test("duplicate payment within 24h needs confirmation", () => {
  const recent = [tx(me, friend, "1000000", { timestamp: "2026-10-17T11:30:00Z" })];
  const r = run(friend, { transfers: recent });
  assert.equal(r.verdict, "caution");
  assert.ok(codes(r).includes("POSSIBLE_DUPLICATE"));
});

test("amount far above usual spending needs confirmation", () => {
  const usual = [1, 2, 3].map((i) => tx(me, friend, "10000000", { timestamp: `2026-09-0${i}T10:00:00Z` }));
  const r = run(friend, { transfers: usual, amountAtomic: 500_000_000n, usdcBalanceAtomic: 1_000_000_000n });
  assert.ok(codes(r).includes("UNUSUAL_AMOUNT"));
});

test("insufficient balance and missing gas", () => {
  assert.ok(codes(run(friend, { usdcBalanceAtomic: 1n })).includes("INSUFFICIENT_USDC"));
  assert.ok(codes(run(friend, { senderInfo: { ...wallet, coinBalanceWei: "0" } })).includes("NO_GAS"));
});

test("history outage degrades to caution, never safe", () => {
  const r = run(friend, { transfers: null });
  assert.equal(r.verdict, "caution");
  assert.ok(codes(r).includes("HISTORY_UNAVAILABLE"));
  assert.equal(run(friend, { transfers: null, knownRecipients: [friend] }).knownRecipient, true);
});

test("counterfeit symbols, including homoglyphs, are detected", () => {
  assert.equal(canonicalSymbol("UЅDC"), "USDC");
  assert.equal(isCounterfeitToken({ tokenAddress: FAKE_TOKEN, tokenSymbol: "UЅDC", tokenFlagged: false }), true);
  assert.equal(isCounterfeitToken({ tokenAddress: FAKE_TOKEN, tokenSymbol: "USDC.e", tokenFlagged: false }), true);
  assert.equal(isCounterfeitToken({ tokenAddress: USDC, tokenSymbol: "USDC", tokenFlagged: false }), false);
  assert.equal(isCounterfeitToken({ tokenAddress: FAKE_TOKEN, tokenSymbol: "AERO", tokenFlagged: false }), false);
});

test("lookalike threshold follows the paper (prefix 3 / suffix 4)", () => {
  assert.equal(findLookalikes("0xd8d0000000000000000000000000000000006045", [friend]).length, 1);
  assert.equal(findLookalikes("0xd8d0000000000000000000000000000000000045", [friend]).length, 0);
  assert.deepEqual(findLookalikes(stranger, [friend]), []);
});

test("confirmation code binds payment and warnings", () => {
  const r = run(stranger);
  const code = confirmationCode(me, stranger, 1_000_000n, r, NOW);
  assert.match(code, /^SS-[0-9A-F]{8}$/);
  assert.equal(verifyConfirmationCode(code, me, stranger, 1_000_000n, r, NOW + 60_000), true);
  assert.equal(verifyConfirmationCode(code, me, stranger, 2_000_000n, r, NOW), false);
  assert.equal(verifyConfirmationCode(code, me, stranger, 1_000_000n, r, NOW + 1_300_000), false);
  assert.equal(verifyConfirmationCode("SS-00000000", me, stranger, 1_000_000n, r, NOW), false);
});

test("ERC-20 transfer calldata", () => {
  assert.equal(encodeErc20Transfer(friend, 1_250_000n),
    "0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa9604500000000000000000000000000000000000000000000000000000000001312d0");
  assert.throws(() => encodeErc20Transfer(friend, 0n));
});
