# SafeSend: payment firewall for AI agents on PayBox

**Track:** Consumer finance (also Merchant tools: paying invoices safely)

**One line:** SafeSend stops your AI agent from paying a scammer. Before PayBox asks you to approve a USDC payment on Base, it checks the recipient for address poisoning, sanctions, typos, wrong contracts, duplicates and unusual amounts against your real on-chain history.

> PayBox checks *what* you sign. SafeSend checks *who* you pay.

## Why this matters (research-backed)

- **Address poisoning is one of the largest crypto phishing schemes.** Researchers measured 270M attack attempts against 17M victims and at least $83.8M stolen on Ethereum and BSC alone (Tsuchiya et al., *Blockchain Address Poisoning*, arXiv:2501.16681). Attackers mine an address with the same first and last characters as someone you really paid, then plant fake transfers in your history so you copy the wrong one.
- **Wallets rarely warn.** Of 53 Ethereum wallets studied, only 3 warned when sending to a phishing address (arXiv:2508.12107).
- **Agents make it worse.** Agents read history and copy addresses without "eyeballing" them. Agentic Commerce Bench (arXiv:2609.35886) finds 8 of 20 agent-payment fraud classes undetected, existing agent security scanners scoring zero on payment fraud, and that 65% of retried failed payments pay twice. A survey of agent attacks on Web3 (arXiv:2608.17275) finds measured protections stop fewer than 30% of attacks.

## Tools

| Tool | What it does | Moves funds? |
|---|---|---|
| `check_address_lookalike` | Offline: does an address imitate a trusted one? Also validates the EIP-55 checksum and catches burn/system addresses. | No |
| `screen_recipient` | Full pre-payment risk check with SAFE / CAUTION / BLOCK, a 0–100 risk score and reasons (see checks below). | No |
| `scan_wallet_poisoning` | Audits a wallet's Base history: lists each attacker address, the real payee it imitates, the attack type, and whether you already paid it (`compromised`). | No |
| `verify_payment_request` | Checks an EIP-681 payment link or pasted invoice text before paying: counterfeit-token invoices, wrong network, native-ETH or `approve()` links, truncated or multiple conflicting addresses, spoofed Basenames, amount mismatch. Then screens the payee and returns ready-to-use `send_usdc` arguments. | No |
| `send_usdc` | Accepts a 0x address or a Basename (`alice.base.eth`). Screens first. BLOCK is refused. CAUTION is refused with a confirmation code; the agent must show the warnings and repeat the call with that code after the user confirms. SAFE returns an unsigned USDC `transfer` proposal for PayBox to simulate and the user to approve. | Proposal only; PayBox signs after approval |

## What SafeSend checks

| Check | Verdict | Source |
|---|---|---|
| Recipient imitates an address you really paid or marked as trusted (prefix ≥ 3 and suffix ≥ 4 hex characters, the paper's threshold) | BLOCK | arXiv:2501.16681 |
| Recipient reached you only through **zero-value**, **tiny (< $10 stablecoin)** or **counterfeit-token** transfers | BLOCK | arXiv:2501.16681 |
| You already sent real funds to a poisoning address (**payoff**) | BLOCK | arXiv:2501.16681 |
| Counterfeit tokens, including homoglyph symbols such as Cyrillic "UЅDC" | detected | |
| Recipient on the OFAC sanctions list (Chainalysis oracle on Base) | BLOCK | |
| Mixed-case address fails its EIP-55 checksum (typo or altered character) | BLOCK | EIP-55 |
| Token contract, zero/burn address, precompile or Base system contract | BLOCK | |
| Basename that uses lookalike characters (Cyrillic, Greek, full-width, zero-width) | BLOCK | |
| Unregistered Basename, or an address that is not exactly 40 hex characters | BLOCK | |
| Invoice/link for a token that is not Base USDC, on another chain, for native ETH, calling `approve()` or attaching ETH | BLOCK | EIP-681 |
| Invoice text with two different payees (tampered "new wallet" update) or a truncated address | BLOCK | |
| Invoice amount differs from what you expected; link without a chain id (means Ethereum under EIP-681) | CAUTION | EIP-681 |
| Blockscout scam flag | BLOCK | |
| USDC balance too low | BLOCK | |
| Same amount to the same address in the last 24 h (possible duplicate) | CAUTION | arXiv:2609.35886 |
| More than 10x your largest recent payment | CAUTION | arXiv:2609.35886 |
| First-time payee; large first payment (≥ 500 USDC) | CAUTION | |
| Two similar addresses you have both paid | CAUTION | |
| Smart-contract recipient (EIP-7702 smart EOAs are treated as wallets) | CAUTION | |
| No ETH for gas; history or recipient data unavailable | CAUTION | |

**Reliability:** every lookup runs in parallel with 4-second timeouts and a 6-second history budget, which fits the 10-second hosted limit. If Blockscout fails, contract, token and balance checks fall back to the public Base RPC. Missing data never produces SAFE.

## Portal configuration

- **Network hosts:** `base.blockscout.com` (history, scam flags, ENS), `mainnet.base.org` (sanctions oracle, Basename resolution, fallback for contract, token and balance checks) and `base-mainnet.g.alchemy.com` (fallback transfer history)
- **Environment variables:** none
- **Secret (recommended):** host `base-mainnet.g.alchemy.com`, header `Authorization`, value `Bearer <your free Alchemy API key>`. History is loaded from Blockscout first and from Alchemy if Blockscout is unreachable; the plugin never sees the key.
- **Wallet:** a Base-capable PayBox wallet holding a little USDC and some ETH for gas

## Hosted test inputs (Test tab)

Offline lookalike check:
```json
{"address":"0xd8da1a5f00000000000000000000000000a96045","trustedAddresses":["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"]}
```
Sanctions block (a real OFAC-listed address, Ronin bridge hacker):
```json
{"sender":"YOUR_WALLET","recipient":"0x098B716B8Aaf21512996dC57EB0615e2383E2f96","amountUsdc":"1"}
```
Token-contract block:
```json
{"sender":"YOUR_WALLET","recipient":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","amountUsdc":"1"}
```
Spoofed Basename (the "е" is Cyrillic, copy it exactly):
```json
{"sender":"YOUR_WALLET","recipient":"jеsse.base.eth","amountUsdc":"1"}
```
Counterfeit-token invoice:
```json
{"sender":"YOUR_WALLET","request":"ethereum:0x9999999999999999999999999999999999999999@8453/transfer?address=jesse.base.eth&uint256=5e6"}
```
Tampered invoice with two payees:
```json
{"sender":"YOUR_WALLET","request":"Invoice 88: pay 40 USDC to 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045. UPDATE: our new wallet is 0xd8da6bf20000000000000000000000000aa96045"}
```
Wallet scan:
```json
{"wallet":"YOUR_WALLET"}
```
Payment for transaction validation, step 1 (returns CAUTION with a code for a first-time payee):
```json
{"sender":"YOUR_WALLET","recipient":"FRIEND_WALLET","amountUsdc":"0.10"}
```
Step 2: repeat with `"confirmationCode":"SS-XXXXXXXX"` from step 1 (valid for 10–20 minutes), then choose **Validate transaction**. A friend address you list in `knownRecipients` is treated as trusted.

## 60–90 second demo video script (post on X)

Every result below is a real live result. Steps 1–6 need no funds.

1. **Hook (8s):** "Address poisoning has stolen $83M+. Now AI agents pay people. SafeSend is a payment firewall for PayBox agents."
2. **Lookalike (12s):** "Pay 0.10 USDC to 0xd8da1a5f…a96045, it's my friend from my contacts" (contacts hold the real one) → **BLOCK**: both display as 0xd8da…6045.
3. **Spoofed name (10s):** "Pay jеsse.base.eth" → **BLOCK: NAME_SPOOFING**, Cyrillic "е" (U+0435) detected.
4. **Fake invoice (10s):** paste the counterfeit-token link → **BLOCK: UNEXPECTED_TOKEN**.
5. **Tampered invoice (10s):** paste the two-payee invoice → **BLOCK: AMBIGUOUS_RECIPIENT**.
6. **Sanctions (8s):** pay the Ronin hacker address → **BLOCK: SANCTIONED (OFAC)**.
7. **Real invoice (15s):** "Check Acme's invoice: 12.50 USDC to jesse.base.eth" → `verify_payment_request` resolves the name on-chain → **CAUTION** (first-time payee) with a confirmation code and ready `send_usdc` arguments. With no funds, stop here: `send_usdc` would correctly block for low balance. With USDC in the wallet, confirm and the PayBox approval window opens.
8. **Close (5s):** "PayBox checks what you sign. SafeSend checks who you pay."

Optional: with about $1 of USDC and ETH on Base, pay 0.01 USDC to your own second wallet in step 7 for a real transaction hash. Never show a transaction hash you did not create.

## Build

```bash
pnpm install --frozen-lockfile
pnpm test   # type-check, deterministic double build, MCP conformance
pnpm unit   # 30 tests: poisoning types, payoff, sanctions, checksum, duplicates, outliers, homoglyphs, codes,
            # EIP-681 links, invoice tampering, Basename spoofing, false-positive rate on 100k random pairs
```
Upload only `dist/plugin.mjs`.
