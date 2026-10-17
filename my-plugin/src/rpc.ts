import { BASE_USDC, type AddressInfo } from "./safety.js";

// Public Base mainnet JSON-RPC, used when Blockscout is unreachable. Configure
// this exact host in the PayBox portal under network access. No API key.
export const RPC_HOST = "mainnet.base.org";
const RPC_URL = `https://${RPC_HOST}`;
const TIMEOUT_MS = 4_000;

export async function call(method: string, params: unknown[]): Promise<string> {
  const response = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
    redirect: "error",
  });
  if (!response.ok) throw new Error(`Base RPC returned HTTP ${response.status}`);
  const body = (await response.json()) as { result?: unknown; error?: { message?: string } };
  if (typeof body.result !== "string") throw new Error(`Base RPC error: ${body.error?.message ?? "no result"}`);
  return body.result;
}

const word = (address: string) => address.toLowerCase().slice(2).padStart(64, "0");

// ERC-20 symbol() returns ABI-encoded string; enough to tell a token contract apart.
async function looksLikeToken(address: string): Promise<boolean> {
  try {
    const result = await call("eth_call", [{ to: address, data: "0x95d89b41" }, "latest"]);
    return result.length >= 2 + 64 * 2;
  } catch {
    return false;
  }
}

export async function addressInfoRpc(address: string): Promise<AddressInfo> {
  const [code, balance] = await Promise.all([call("eth_getCode", [address, "latest"]), call("eth_getBalance", [address, "latest"])]);
  // EIP-7702 delegated EOAs carry 0xef0100 + target; they are still user wallets.
  const isContract = code !== "0x" && !code.toLowerCase().startsWith("0xef0100");
  const isToken = isContract && (address.toLowerCase() === BASE_USDC || (await looksLikeToken(address)));
  return {
    isContract, isScam: false, isToken, name: null, ensName: null, reputation: null,
    coinBalanceWei: BigInt(balance).toString(),
  };
}

export async function usdcBalanceRpc(address: string): Promise<bigint> {
  return BigInt(await call("eth_call", [{ to: BASE_USDC, data: `0x70a08231${word(address)}` }, "latest"]));
}

// Chainalysis sanctions oracle deployed on Base; isSanctioned(address) -> bool.
export const SANCTIONS_ORACLE = "0x3a91a31cb3dc49b4db9ce721f50a9d076c8d739b";

export async function isSanctioned(address: string): Promise<boolean> {
  return BigInt(await call("eth_call", [{ to: SANCTIONS_ORACLE, data: `0xdf592f7d${word(address)}` }, "latest"])) === 1n;
}
