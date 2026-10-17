import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";

import { checkBasename, namehash } from "../src/names.js";
import { amountCheck, parseEip681Number, parsePaymentRequest } from "../src/request.js";
import { isLookalike } from "../src/safety.js";

const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAYEE = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
const codes = (r: { findings: { code: string }[] }) => r.findings.map((f) => f.code);
const blocked = (r: { findings: { severity: string }[] }) => r.findings.some((f) => f.severity === "block");

test("EIP-681 numbers are exact", () => {
  assert.equal(parseEip681Number("1000000"), 1_000_000n);
  assert.equal(parseEip681Number("1e6"), 1_000_000n);
  assert.equal(parseEip681Number("2.5e6"), 2_500_000n);
  assert.equal(parseEip681Number("1.0000005e6"), null);   // fractional unit
  assert.equal(parseEip681Number("-5"), null);
  assert.equal(parseEip681Number("0x10"), null);
});

test("valid Base USDC payment link", () => {
  const r = parsePaymentRequest(`ethereum:${USDC}@8453/transfer?address=${PAYEE}&uint256=2.5e6`);
  assert.equal(r.format, "eip681");
  assert.equal(r.recipient, PAYEE);
  assert.equal(r.amountAtomic, 2_500_000n);
  assert.equal(r.chainId, 8453);
  assert.equal(blocked(r), false);
});

test("counterfeit-token invoice is blocked", () => {
  const r = parsePaymentRequest(`ethereum:0x9999999999999999999999999999999999999999@8453/transfer?address=${PAYEE}&uint256=1e6`);
  assert.ok(codes(r).includes("UNEXPECTED_TOKEN"));
});

test("wrong network blocked, missing network cautioned", () => {
  assert.ok(codes(parsePaymentRequest(`ethereum:${USDC}@1/transfer?address=${PAYEE}&uint256=1`)).includes("WRONG_NETWORK"));
  const r = parsePaymentRequest(`ethereum:${USDC}/transfer?address=${PAYEE}&uint256=1`);
  assert.ok(codes(r).includes("NETWORK_UNSPECIFIED"));
  assert.equal(blocked(r), false);
});

test("native ETH, approve() and attached value are blocked", () => {
  assert.ok(codes(parsePaymentRequest(`ethereum:${PAYEE}@8453?value=1e18`)).includes("UNSUPPORTED_ASSET"));
  assert.ok(codes(parsePaymentRequest(`ethereum:${USDC}@8453/approve?address=${PAYEE}&uint256=1e30`)).includes("UNSUPPORTED_FUNCTION"));
  assert.ok(codes(parsePaymentRequest(`ethereum:${USDC}@8453/transfer?address=${PAYEE}&uint256=1&value=5`)).includes("UNEXPECTED_VALUE"));
  assert.ok(codes(parsePaymentRequest(`ethereum:${USDC}@8453/transfer?uint256=1`)).includes("MISSING_RECIPIENT"));
  assert.ok(codes(parsePaymentRequest(`ethereum:${USDC}@8453/transfer?address=${PAYEE}&uint256=0`)).includes("INVALID_AMOUNT"));
});

test("invoice text: amount and single payee extracted", () => {
  const r = parsePaymentRequest(`Invoice #1023 from Acme. Total due: $1,250.50 USDC on Base. Pay to ${PAYEE}. Thanks!`);
  assert.equal(r.format, "text");
  assert.equal(r.recipient, PAYEE);
  assert.equal(r.amountAtomic, 1_250_500_000n);
  assert.equal(blocked(r), false);
});

test("invoice text: tampered second address, truncated address, missing payee", () => {
  assert.ok(codes(parsePaymentRequest(`Pay ${PAYEE}. UPDATE: new wallet 0xd8da6bf20000000000000000000000000aa96045`)).includes("AMBIGUOUS_RECIPIENT"));
  assert.ok(codes(parsePaymentRequest(`Pay 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA9604 25 USDC`)).includes("TRUNCATED_OR_PADDED_ADDRESS"));
  assert.ok(codes(parsePaymentRequest("Please send 25 USDC to my usual wallet")).includes("MISSING_RECIPIENT"));
  // A 64-hex transaction hash next to the payee is not a broken address.
  const withHash = parsePaymentRequest(`Paid last month in 0x${"ab".repeat(32)}. This month pay ${PAYEE} 10 USDC`);
  assert.equal(blocked(withHash), false);
});

test("invoice text naming another network is cautioned", () => {
  assert.ok(codes(parsePaymentRequest(`Send 10 USDC (TRC-20) to ${PAYEE}`)).includes("NETWORK_MISMATCH"));
});

test("invoice with a Basename", () => {
  const r = parsePaymentRequest("Pay 15 USDC to acme.base.eth");
  assert.equal(r.recipient, "acme.base.eth");
  assert.equal(r.amountAtomic, 15_000_000n);
});

test("amount mismatch", () => {
  assert.equal(amountCheck(2_000_000n, 1_000_000n)?.code, "AMOUNT_MISMATCH");
  assert.equal(amountCheck(1_000_000n, 1_000_000n), null);
});

test("Basename spoofing and validation", () => {
  assert.deepEqual(checkBasename("Jesse.Base.Eth"), { ok: true, name: "jesse.base.eth" });
  const cyrillic = checkBasename("jеsse.base.eth"); // Cyrillic е
  assert.equal(cyrillic.ok, false);
  assert.equal(!cyrillic.ok && cyrillic.code, "NAME_SPOOFING");
  assert.equal(!checkBasename("je​sse.base.eth").ok, true); // zero-width space
  assert.equal(!checkBasename("vitalik.eth").ok, true);
  assert.equal(!checkBasename("-bad.base.eth").ok, true);
  assert.equal(namehash("eth"), "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae");
});

test("false-positive rate on 100k random address pairs is ~0", () => {
  let hits = 0;
  for (let i = 0; i < 100_000; i += 1) {
    if (isLookalike(`0x${randomBytes(20).toString("hex")}`, `0x${randomBytes(20).toString("hex")}`)) hits += 1;
  }
  assert.ok(hits <= 1, `${hits} random collisions`);
});
