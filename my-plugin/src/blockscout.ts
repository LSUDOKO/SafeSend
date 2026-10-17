import { alchemyHistory } from "./alchemy.js";
import { addressInfoRpc, isSanctioned, usdcBalanceRpc } from "./rpc.js";
import { BASE_USDC, normalize, type AddressInfo, type Transfer } from "./safety.js";

// Public Blockscout explorer for Base mainnet. Configure this exact host in the
// PayBox portal under network access. No API key is required.
export const BLOCKSCOUT_HOST = "base.blockscout.com";
const API = `https://${BLOCKSCOUT_HOST}/api/v2`;
const TIMEOUT_MS = 4_000;
// Hosted calls must finish in 10 s; stop paging history well before that.
const HISTORY_BUDGET_MS = 6_000;
const MAX_PAGES = 4;

type Json = Record<string, unknown>;

async function getJson(path: string, timeoutMs = TIMEOUT_MS): Promise<unknown> {
  const response = await fetch(`${API}${path}`, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(Math.max(500, timeoutMs)),
    redirect: "error",
  });
  if (!response.ok) throw new Error(`Blockscout returned HTTP ${response.status}`);
  return response.json();
}

function obj(value: unknown): Json {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Json) : {};
}

function str(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

export async function addressInfo(address: string): Promise<AddressInfo> {
  const data = obj(await getJson(`/addresses/${address}`));
  // EIP-7702 delegated EOAs report is_contract but are still user wallets.
  return {
    isContract: data.is_contract === true && data.proxy_type !== "eip7702",
    isScam: data.is_scam === true,
    isToken: data.token !== null && data.token !== undefined,
    name: str(data.name),
    ensName: str(data.ens_domain_name),
    reputation: str(data.reputation),
    coinBalanceWei: str(data.coin_balance),
  };
}

function toTransfer(item: unknown): Transfer | null {
  const t = obj(item);
  const token = obj(t.token);
  const total = obj(t.total);
  const from = str(obj(t.from).hash);
  const to = str(obj(t.to).hash);
  const tokenAddress = str(token.address_hash) ?? str(token.address);
  if (!from || !to || !tokenAddress) return null;
  return {
    from, to,
    value: /^[0-9]+$/.test(str(total.value) ?? "") ? (total.value as string) : "0",
    tokenAddress,
    tokenSymbol: str(token.symbol) ?? "",
    tokenDecimals: Number(str(token.decimals) ?? "0") || 0,
    tokenFlagged: token.reputation === "scam",
    txHash: str(t.transaction_hash) ?? "",
    timestamp: str(t.timestamp),
  };
}

export type Page = { transfers: Transfer[]; complete: boolean };

// Newest first; follows next_page_params until the budget or page cap runs out.
export async function tokenTransfers(address: string, direction: "from" | "to" | undefined, deadline: number): Promise<Page> {
  const transfers: Transfer[] = [];
  let next: Json | null = {};
  for (let page = 0; next && page < MAX_PAGES; page += 1) {
    const remaining = deadline - Date.now();
    if (page > 0 && remaining < 1_500) break;
    const query = new URLSearchParams({ type: "ERC-20" });
    if (direction) query.set("filter", direction);
    for (const [k, v] of Object.entries(next)) if (v !== null && v !== undefined) query.set(k, String(v));
    const data = obj(await getJson(`/addresses/${address}/token-transfers?${query}`, Math.min(TIMEOUT_MS, remaining)));
    const items = Array.isArray(data.items) ? data.items : [];
    transfers.push(...items.map(toTransfer).filter((t): t is Transfer => t !== null));
    next = data.next_page_params && typeof data.next_page_params === "object" ? obj(data.next_page_params) : null;
  }
  return { transfers, complete: next === null };
}

export async function usdcBalance(address: string): Promise<bigint> {
  const data = await getJson(`/addresses/${address}/token-balances`);
  if (!Array.isArray(data)) throw new Error("Unexpected token balance response");
  for (const entry of data) {
    const e = obj(entry);
    if (normalize(str(obj(e.token).address_hash) ?? str(obj(e.token).address) ?? "") === BASE_USDC && /^[0-9]+$/.test(str(e.value) ?? "")) {
      return BigInt(e.value as string);
    }
  }
  return 0n;
}

const settle = async <T>(p: Promise<T>): Promise<T | null> => {
  try { return await p; } catch (error) {
    process.stderr.write(`lookup failed: ${(error as Error).message}\n`);
    return null;
  }
};

// Outgoing and full history are fetched separately so payees survive even when
// spam floods the combined feed.
async function blockscoutHistory(address: string): Promise<Page> {
  const deadline = Date.now() + HISTORY_BUDGET_MS;
  const [all, outgoing] = await Promise.allSettled([
    tokenTransfers(address, undefined, deadline),
    tokenTransfers(address, "from", deadline),
  ]);
  if (all.status === "rejected" && outgoing.status === "rejected") throw all.reason;
  const ok = (r: PromiseSettledResult<Page>) => (r.status === "fulfilled" ? r.value : null);
  return {
    transfers: [...(ok(outgoing)?.transfers ?? []), ...(ok(all)?.transfers ?? [])],
    complete: (ok(all)?.complete ?? false) && (ok(outgoing)?.complete ?? false),
  };
}

export type HistoryResult = { page: Page | null; source: "blockscout" | "alchemy" | null; error: string | null };

// Blockscout and Alchemy run in parallel; Blockscout wins when both answer
// because it also carries scam reputation for tokens.
export async function transferHistory(address: string): Promise<HistoryResult> {
  const [bs, al] = await Promise.allSettled([blockscoutHistory(address), alchemyHistory(address)]);
  if (bs.status === "fulfilled") return { page: bs.value, source: "blockscout", error: null };
  if (al.status === "fulfilled") return { page: al.value, source: "alchemy", error: null };
  const reason = (r: PromiseRejectedResult) => (r.reason instanceof Error ? r.reason.message : String(r.reason));
  const error = `Blockscout: ${reason(bs)}; Alchemy: ${reason(al)}`;
  process.stderr.write(`history unavailable: ${error}\n`);
  return { page: null, source: null, error };
}

// Run every lookup in parallel; a failed lookup becomes null so the risk engine
// can report what it could not verify instead of failing the whole call.
// Blockscout first; the public Base RPC covers address and balance facts if it fails.
export async function gather(sender: string, recipient: string, needBalance: boolean) {
  const withFallback = <T>(primary: () => Promise<T>, fallback: () => Promise<T>) =>
    settle(primary().catch((error: Error) => {
      process.stderr.write(`blockscout failed, using Base RPC: ${error.message}\n`);
      return fallback();
    }));
  const [recipientInfo, senderInfo, history, balance, sanctioned] = await Promise.all([
    withFallback(() => addressInfo(recipient), () => addressInfoRpc(recipient)),
    needBalance ? withFallback(() => addressInfo(sender), () => addressInfoRpc(sender)) : Promise.resolve(null),
    transferHistory(sender),
    needBalance ? withFallback(() => usdcBalance(sender), () => usdcBalanceRpc(sender)) : Promise.resolve(null),
    settle(isSanctioned(recipient)),
  ]);
  return {
    recipientInfo, senderInfo, usdcBalanceAtomic: balance, recipientSanctioned: sanctioned,
    transfers: history.page?.transfers ?? null, historyComplete: history.page?.complete ?? false, historyError: history.error,
  };
}
