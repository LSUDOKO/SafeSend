import assert from "node:assert/strict";
import { test } from "node:test";

import { alchemyHistory } from "../src/alchemy.js";
import { scanPoisoning } from "../src/safety.js";

const me = "0x1234567890abcdef1234567890abcdef12345678";
const friend = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
const fake = "0xd8da6bf20000000000000000000000000aa96045";
const USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

const transfer = (from: string, to: string, hex: string, hash: string) => ({
  blockNum: "0x1", uniqueId: `${hash}:log:0`, hash, from, to, value: 0, asset: "USDC", category: "erc20",
  rawContract: { value: hex, address: USDC, decimal: "0x6" }, metadata: { blockTimestamp: "2026-10-17T10:00:00.000Z" },
});

test("Alchemy transfers map to the risk engine and expose zero-value poisoning", async () => {
  const bodies: unknown[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (_url: unknown, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    bodies.push(body);
    const filter = body.params[0];
    const transfers = filter.fromAddress
      ? [transfer(me, friend, "0x4c4b40", "0xa"), transfer(me, fake, "0x0", "0xb")]
      : [];
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { transfers } }), { status: 200 });
  }) as typeof fetch;
  try {
    const { transfers, complete } = await alchemyHistory(me);
    assert.equal(complete, true);
    assert.equal(transfers.length, 2);
    assert.equal(transfers[0]!.value, "5000000");
    assert.equal(transfers[1]!.value, "0");
    assert.equal((bodies[0] as { params: { excludeZeroValue: boolean }[] }).params[0]!.excludeZeroValue, false);
    const { attempts } = scanPoisoning(me, transfers);
    assert.equal(attempts[0]?.attacker, fake);
  } finally {
    globalThis.fetch = original;
  }
});

test("missing Alchemy key is reported clearly", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response("Must be authenticated!", { status: 401 })) as typeof fetch;
  try {
    await assert.rejects(alchemyHistory(me), /no API key configured/);
  } finally {
    globalThis.fetch = original;
  }
});
