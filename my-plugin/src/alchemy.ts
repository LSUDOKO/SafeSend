import type { Transfer } from "./safety.js";

// Alchemy Base mainnet, used for transfer history when Blockscout is
// unreachable. In the PayBox portal add this exact network host and a brokered
// secret for it: header "Authorization", value "Bearer <ALCHEMY_API_KEY>".
// The plugin never sees the key.
export const ALCHEMY_HOST = "base-mainnet.g.alchemy.com";
const URL = `https://${ALCHEMY_HOST}/v2`;
const TIMEOUT_MS = 4_000;
const MAX_COUNT = "0x3e8"; // 1,000 transfers per direction

type Json = Record<string, unknown>;
const obj = (v: unknown): Json => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Json) : {});
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

async function assetTransfers(filter: { fromAddress?: string; toAddress?: string }): Promise<{ transfers: Transfer[]; complete: boolean }> {
  const response = await fetch(URL, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "alchemy_getAssetTransfers",
      // excludeZeroValue defaults to true, which would hide zero-value poisoning.
      params: [{ fromBlock: "0x0", toBlock: "latest", category: ["erc20"], withMetadata: true, excludeZeroValue: false, maxCount: MAX_COUNT, order: "desc", ...filter }],
    }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
    redirect: "error",
  });
  if (response.status === 401 || response.status === 403) throw new Error(`no API key configured (HTTP ${response.status})`);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const body = obj(await response.json());
  if (body.error) throw new Error(str(obj(body.error).message) ?? "RPC error");
  const result = obj(body.result);
  const items = Array.isArray(result.transfers) ? result.transfers : [];
  const transfers: Transfer[] = [];
  for (const item of items) {
    const t = obj(item);
    const raw = obj(t.rawContract);
    const from = str(t.from);
    const to = str(t.to);
    const tokenAddress = str(raw.address);
    if (!from || !to || !tokenAddress) continue;
    const hexValue = str(raw.value);
    let value = "0";
    try { value = hexValue && /^0x[0-9a-fA-F]*$/.test(hexValue) ? BigInt(hexValue === "0x" ? 0 : hexValue).toString() : "0"; } catch { value = "0"; }
    const decimals = str(raw.decimal);
    transfers.push({
      from, to, value, tokenAddress,
      tokenSymbol: str(t.asset) ?? "",
      tokenDecimals: decimals ? Number(BigInt(decimals)) : 0,
      tokenFlagged: false,
      txHash: str(t.hash) ?? "",
      timestamp: str(obj(t.metadata).blockTimestamp),
    });
  }
  return { transfers, complete: !result.pageKey };
}

export async function alchemyHistory(address: string): Promise<{ transfers: Transfer[]; complete: boolean }> {
  const [outgoing, incoming] = await Promise.all([assetTransfers({ fromAddress: address }), assetTransfers({ toAddress: address })]);
  return { transfers: [...outgoing.transfers, ...incoming.transfers], complete: outgoing.complete && incoming.complete };
}
