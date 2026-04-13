# Security Incident Analysis: Solv Protocol BRO Double Minting

---

## Overview

| Field | Details |
|------|------|
| **Date** | 2026-03-05 15:09:35 UTC |
| **Network** | Ethereum Mainnet (chainId 1) |
| **Block** | 24,592,074 |
| **TX** | [`0x44e637c7d85190d376a52d89ca75f2d208089bb02b7c4708ad2aaae3a97a958d`](https://etherscan.io/tx/0x44e637c7d85190d376a52d89ca75f2d208089bb02b7c4708ad2aaae3a97a958d) |
| **Attacker EOA** | [`0xA407fE273DB74184898CB56D2cb685615e1C0D6e`](https://etherscan.io/address/0xA407fE273DB74184898CB56D2cb685615e1C0D6e) |
| **Attack Contract** | [`0xb32D389901f963E7C87168724fBDCC3A9DB20dc9`](https://etherscan.io/address/0xb32D389901f963E7C87168724fBDCC3A9DB20dc9) (deployed in this TX) |
| **Protocol** | Solv Protocol -- BitcoinReserveOffering (BRO-SOLV-20MAY2026) |
| **Affected Token** | BRO-SOLV-20MAY2026 [`0x014e6f6ba7a9f4c9a51a0aa3189b5c0a21006869`](https://etherscan.io/token/0x014e6f6ba7a9f4c9a51a0aa3189b5c0a21006869) |
| **Net Profit** | **~1,211 WETH (approx. $3.03M – $3.63M USD)** |

---

## Attack Summary

The attacker exploited a **cross-function reentrancy** vulnerability in Solv Protocol's `BitcoinReserveOffering (BRO)` contract to execute a **Double Minting** attack.

During the process of burning BRO tokens and receiving SolvBTC ERC3525 positions in return, callbacks were triggered in duplicate between **two BRO instances** sharing the same beacon (`UpgradeableBeacon`), causing the amount of BRO minted to **double** with each cycle. Starting from 135.36 BRO, the attacker repeated 22 cycles and ultimately obtained approximately **568 million BRO**, then swapped it through a DEX for **~1,211 WETH**.

---

## Protocol Architecture

### Solv Protocol BitcoinReserveOffering (BRO) Architecture

```
UpgradeableBeacon (0x031c97)
  │
  ├── Implementation: BitcoinReserveOffering (0x15F7c1)
  │
  ├── Instance A: BRO ERC20 Token (0x014e6f)   ← BRO-SOLV-20MAY2026
  │     - wrappedSftAddress = SolvBTC ERC3525
  │     - exchangeRate-based minting/burning
  │
  └── Instance B: Conversion Contract (0x6aa78a)   ← Another BRO instance
        - Same implementation, same beacon
        - Handles BRO burn ↔ SolvBTC exchange
```

### Related Contracts

| Role | Address | Description |
|------|------|------|
| BRO ERC20 Token | [`0x014e6f6ba7a9f4c9a51a0aa3189b5c0a21006869`](https://etherscan.io/address/0x014e6f6ba7a9f4c9a51a0aa3189b5c0a21006869) | BRO-SOLV-20MAY2026 main token |
| BRO Conversion Contract | [`0x6aa78a9b245cc56377b21401b517ec8c03a40f03`](https://etherscan.io/address/0x6aa78a9b245cc56377b21401b517ec8c03a40f03) | BRO burn/mint exchange instance |
| BitcoinReserveOffering Implementation | [`0x15F7c1Ac69f0C102e4f390e45306BD917f21cFCf`](https://etherscan.io/address/0x15F7c1Ac69f0C102e4f390e45306BD917f21cFCf) | Beacon proxy implementation (Blockscout verified source) |
| UpgradeableBeacon | [`0x031c97141721d8ceeb74f96684e4e712fcd6fefd`](https://etherscan.io/address/0x031c97141721d8ceeb74f96684e4e712fcd6fefd) | Beacon contract |
| SolvBTC ERC3525 | [`0x982d50f8557d57b748733a3fc3d55aef40c46756`](https://etherscan.io/address/0x982d50f8557d57b748733a3fc3d55aef40c46756) | Underlying SFT position |
| SolvBTC ERC20 (liquid) | [`0x7a56e1c57c7475ccf742a1832b028f0456652f97`](https://etherscan.io/address/0x7a56e1c57c7475ccf742a1832b028f0456652f97) | Liquid SolvBTC |
| BRO/SolvBTC DEX Pool | [`0xfb2dc2428b6c2fb149a3e6d658fdf979cc0afef9`](https://etherscan.io/address/0xfb2dc2428b6c2fb149a3e6d658fdf979cc0afef9) | BRO sell pool |
| SolvBTC/WBTC Pool (GOEFS) | [`0x5738df8073ad05d0c0fcf60e358033268ebf16cc`](https://etherscan.io/address/0x5738df8073ad05d0c0fcf60e358033268ebf16cc) | SolvBTC -> WBTC swap |
| UniV3 WBTC/WETH Pool | [`0x4585fe77225b41b697c938b018e2ac67ac5a20c0`](https://etherscan.io/address/0x4585fe77225b41b697c938b018e2ac67ac5a20c0) | WBTC -> WETH final swap |
| WBTC | [`0x2260fac5e5542a773aa44fbcfedf7c193bc2c599`](https://etherscan.io/address/0x2260fac5e5542a773aa44fbcfedf7c193bc2c599) | Wrapped Bitcoin |
| WETH | [`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`](https://etherscan.io/address/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2) | Wrapped Ether |

---

## Attack Flow

### Full Attack Diagram

```
Attacker EOA (0xA407fE27)
  │
  ├─[1] Deploy attack contract (0xb32D3899)
  │      Constructor args: loops=22, amount=135.364 BRO
  │
  └─[2] Execute double minting loop (22 cycles)
         │
         │  ┌──────────────────────── 1 Cycle ────────────────────────┐
         │  │                                                          │
         │  │  AttackContract                                          │
         │  │       │                                                  │
         │  │       ├─[a] Transfer BRO → Conversion(0x6aa7)  X BRO deposit │
         │  │       │                                                  │
         │  │  Conversion(0x6aa7)                                      │
         │  │       │                                                  │
         │  │       ├─[b] Burn BRO (Transfer → 0x0)          X BRO burn    │
         │  │       │                                                  │
         │  │       ├─[c] Exchange #1 on SolvBTC (0 amount)            │
         │  │       │     SolvBTC: BRO(0x014e)→0x6aa7, 0              │
         │  │       │     SolvBTC: 0x6aa7→BRO(0x014e), 0              │
         │  │       │                                                  │
         │  │       ├─[d] Exchange #2 on SolvBTC (0 amount) ← Bug!    │
         │  │       │     This exchange double-triggers the callback   │
         │  │       │                                                  │
         │  │  BRO Token(0x014e)                                       │
         │  │       │                                                  │
         │  │       ├─[e] _mint #1: 0x0 → 0x6aa7,         X BRO mint  │
         │  │       │     (onERC721Received path)                      │
         │  │       │                                                  │
         │  │       ├─[f] _mint #2: 0x0 → 0x6aa7,         X BRO mint  │
         │  │       │     (onERC3525Received path) ← Double mint!     │
         │  │       │                                                  │
         │  │       └─[g] Transfer: 0x6aa7 → 0x0,         2X BRO burn │
         │  │             (next cycle input = 2x)                      │
         │  │                                                          │
         │  └──────────────────────────────────────────────────────────┘
         │
         │  After 22 cycles:
         │
         ├─[3] Withdraw all BRO: 0x6aa7 → AttackContract    567,758,816.72 BRO
         │
         ├─[4] Profit realization
         │      │
         │      ├─[4a] Sell BRO: 165,592,064.42 BRO → DEX Pool(0xfb2d)
         │      │      → Receive 38.047 SolvBTC ERC20
         │      │
         │      ├─[4b] SolvBTC → GOEFS(0x5738) → ~38 WBTC swap
         │      │
         │      ├─[4c] WBTC → UniV3(0x4585) → 1,211.054 WETH swap
         │      │
         │      └─[4d] WETH → ETH withdrawal (unwrap)
         │
         └─[5] Return remaining BRO: 402,166,752.30 BRO → Attacker EOA
```

### 22-Cycle Doubling Progression

| Cycle | BRO at Cycle Start | BRO After Doubling |
|--------|---------------|--------------|
| Start | 135.36 | -- |
| 1 | 135.36 | 270.73 |
| 2 | 270.73 | 541.46 |
| 3 | 541.46 | 1,082.91 |
| 4 | 1,082.91 | 2,165.83 |
| 5 | 2,165.83 | 4,331.66 |
| 10 | 138,612.99 | 277,225.98 |
| 15 | 4,435,615.80 | 8,871,231.60 |
| 20 | 141,939,704.18 | 283,879,408.36 |
| 21 | 283,879,408.36 | 567,758,816.72 |
| **22 (end)** | **567,758,816.72** | **Withdrawn to AttackContract** |

---

## Vulnerable Code Analysis

BitcoinReserveOffering.sol (`0x15F7c1Ac69f0C102e4f390e45306BD917f21cFCf`) -- Blockscout source verified.

### Vulnerable Function 1: `onERC721Received`

```solidity
function onERC721Received(
    address, address from_, uint256 sftId_, bytes calldata
) external virtual override onlyWrappedSft returns (bytes4) {
    require(wrappedSftSlot == IERC3525(wrappedSftAddress).slotOf(sftId_));
    require(address(this) == IERC3525(wrappedSftAddress).ownerOf(sftId_));

    if (from_ == address(this)) {
        return IERC721Receiver.onERC721Received.selector;
    }

    uint256 sftValue = IERC3525(wrappedSftAddress).balanceOf(sftId_);

    if (holdingValueSftId == 0) {
        holdingValueSftId = sftId_;
    } else {
        // [BUG] doTransfer performs a SolvBTC ERC3525 value transfer,
        //       during which onERC3525Received callback can be recursively invoked
        ERC3525TransferHelper.doTransfer(
            wrappedSftAddress, sftId_, holdingValueSftId, sftValue
        );
        _holdingEmptySftIds.push(sftId_);
    }

    uint256 value = sftValue * exchangeRate / (10 ** decimals());
    _mint(from_, value);  // ← Mint #1 (onERC721Received path)

    return IERC721Receiver.onERC721Received.selector;
}
```

**Issue:** The `doTransfer` call performs a SolvBTC ERC3525 value transfer, which triggers `onERC3525Received` on the receiving contract. That function also executes `_mint(from_, value)`, causing **two mints for the same deposit**.

### Vulnerable Function 2: `onERC3525Received`

```solidity
function onERC3525Received(
    address, uint256 fromSftId_, uint256 sftId_, uint256 sftValue_, bytes calldata
) external virtual override onlyWrappedSft returns (bytes4) {
    address fromSftOwner = IERC3525(wrappedSftAddress).ownerOf(fromSftId_);

    // [BUG] This check only filters out itself (address(this)).
    //       If another BRO instance (0x6aa7) is the fromSftOwner, it passes through!
    if (fromSftOwner == address(this)) {
        return IERC3525Receiver.onERC3525Received.selector;
    }

    // [BUG] This mint executes again as a duplicate in callbacks routed through
    //       the second instance (0x6aa7)
    uint256 value = sftValue_ * exchangeRate / (10 ** decimals());
    _mint(fromSftOwner, value);  // ← Mint #2 (Double mint!)

    return IERC3525Receiver.onERC3525Received.selector;
}
```

**Issue:** The `fromSftOwner == address(this)` check only skips transfers sent by **itself**. When a **different BRO instance** sharing the same beacon (e.g., `0x6aa7`) is the `fromSftOwner`, it passes the check and `_mint` executes.

### Root Vulnerability Summary

| Vulnerability | Description |
|--------|------|
| **Cross-function reentrancy** | `doTransfer` inside `onERC721Received` triggers `onERC3525Received` as a callback, and both functions call `_mint` |
| **Incomplete sender validation** | `fromSftOwner == address(this)` only filters out the contract itself; other instances sharing the same beacon are not validated |
| **Separate nonReentrant guards** | `burn` and `mint` each have their own `nonReentrant` guard, which fails to prevent cross-function reentrancy |

---

## Event Log Analysis

### Double Minting Loop — 1 Cycle (Log Pattern)

Each cycle repeats the following event sequence:

| Log Offset | Contract | Event | Details |
|------------|---------|--------|------|
| N | BRO (`0x014e`) | `Transfer` | AttackContract -> `0x6aa7`, X BRO (deposit) |
| N+1 | BRO (`0x014e`) | `Transfer` | `0x6aa7` -> `0x0`, X BRO (burn) |
| N+2 | SolvBTC (`0x982d`) | `Exchange` | 0 amount (exchange #1) |
| N+3 | SolvBTC (`0x982d`) | `Transfer` | BRO -> `0x6aa7`, 0 (return 0) |
| N+4 | SolvBTC (`0x982d`) | `Transfer` | `0x6aa7` -> BRO, 0 (re-deposit 0) |
| N+5 | SolvBTC (`0x982d`) | `Exchange` | 0 amount (exchange #2 = bug trigger) |
| N+6 | BRO (`0x014e`) | `Transfer` | `0x0` -> `0x6aa7`, X BRO (**Mint #1**) |
| N+7 | BRO (`0x014e`) | `Transfer` | `0x0` -> `0x6aa7`, X BRO (**Mint #2 = Double!**) |
| N+8 | BRO (`0x014e`) | `Transfer` | `0x6aa7` -> `0x0`, 2X BRO (burn for next cycle) |

### Profit Realization Logs (Final Stage)

| Log Index | Event | Details |
|------------|--------|------|
| 270 | BRO Transfer | `0x6aa7` -> AttackContract, **567,758,816.72 BRO** (full withdrawal) |
| 272 | BRO Transfer | AttackContract -> Pool(`0xfb2d`), **165,592,064.42 BRO** (sell) |
| 273 | SolvBTC Transfer | Pool -> AttackContract, **38.047 SolvBTC** ERC20 |
| 277 | SolvBTC Transfer | AttackContract -> GOEFS(`0x5738`), **38.047 SolvBTC** |
| 278 | GOEFS Swap | SolvBTC -> **~38 WBTC** |
| 279 | WETH Transfer | UniV3(`0x4585`) -> AttackContract, **1,211.054 WETH** |
| 282 | Withdrawal | WETH -> ETH (unwrap) |
| 283 | BRO Transfer | AttackContract -> Attacker EOA, **402,166,752.30 BRO** (remaining returned) |

---

## On-Chain Verification

### Supply Changes

| Item | Block 24,592,073 (pre-attack) | Block 24,592,075 (post-attack) | Change |
|------|------------------------|------------------------|------|
| BRO `totalSupply` | 419,973,588.848 BRO | 987,732,270.206 BRO | **+567,758,681.358 BRO** |
| Attacker BRO balance | 135.364 BRO | 402,166,752.304 BRO | **+402,166,616.940 BRO** |

### Verification Summary

- The total supply increase (`+567,758,681.358 BRO`) matches the BRO generated across 22 doubling cycles
- The attacker sold **165,592,064.42 BRO** out of total BRO obtained, converting it to WETH
- The remaining **402,166,752.30 BRO** remains in the attacker's EOA

---

## Impact

### Direct Losses

| Item | Details |
|------|------|
| Illegitimately minted BRO | ~567,758,681 BRO |
| Attacker net profit | **~1,211 WETH (approx. $3.03M – $3.63M USD)** |
| BRO total supply inflation | **+135%** (419M -> 987M) |
| Attacker remaining BRO | 402,166,752 BRO (available for further sale) |

### Systemic Impact

- BRO token **total supply inflated by 135%** — existing BRO holders suffer severe dilution
- If the attacker sells the remaining ~402M BRO, **DEX liquidity pool exhaustion** is possible
- **All BRO instances** sharing the same beacon are exposed to the same vulnerability
- Other Solv Protocol products using the same pattern may also be affected

---

## Remediation

### Option 1: Beacon Instance Whitelist

```solidity
// BitcoinReserveOffering -- fixed onERC3525Received
mapping(address => bool) public trustedInstances;

function onERC3525Received(
    address, uint256 fromSftId_, uint256 sftId_, uint256 sftValue_, bytes calldata
) external virtual override onlyWrappedSft returns (bytes4) {
    address fromSftOwner = IERC3525(wrappedSftAddress).ownerOf(fromSftId_);

    // [FIX] Skip self + other trusted BRO instances
    if (fromSftOwner == address(this) || trustedInstances[fromSftOwner]) {
        return IERC3525Receiver.onERC3525Received.selector;
    }

    uint256 value = sftValue_ * exchangeRate / (10 ** decimals());
    _mint(fromSftOwner, value);
    return IERC3525Receiver.onERC3525Received.selector;
}
```

### Option 2: Global ReentrancyGuard

```solidity
// BitcoinReserveOffering -- cross-function reentrancy prevention
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// [FIX] Apply the same nonReentrant guard to all state-changing functions
function onERC721Received(...) external nonReentrant ... {
    // ... existing logic
}

function onERC3525Received(...) external nonReentrant ... {
    // ... existing logic
}
```

### Option 3: Mint Deduplication Flag

```solidity
// BitcoinReserveOffering -- duplicate mint prevention
mapping(uint256 => bool) private _mintedForSft;

function onERC721Received(...) external ... {
    // ...
    require(!_mintedForSft[sftId_], "already minted for this SFT");
    _mintedForSft[sftId_] = true;
    _mint(from_, value);
    // ...
}

function onERC3525Received(...) external ... {
    // ...
    // [FIX] Block duplicate minting for SFTs already minted via onERC721Received
    if (_mintedForSft[sftId_]) {
        return IERC3525Receiver.onERC3525Received.selector;
    }
    _mint(fromSftOwner, value);
    // ...
}
```

---

## Timeline

| Time (UTC) | Event |
|-----------|------|
| 2026-03-05 15:09:35 | Attack TX executed — attack contract deployed + 22-cycle double minting + profit realization (single TX) |
| 2026-03-05 15:09:35 | Block 24,592,074 mined — BRO totalSupply increased from 419M to 987M |
| 2026-03-05 15:09:35 | Attacker withdraws 1,211.054 WETH and unwraps to ETH |

---

## References

- **Etherscan TX**: https://etherscan.io/tx/0x44e637c7d85190d376a52d89ca75f2d208089bb02b7c4708ad2aaae3a97a958d
- **Phalcon Explorer**: https://app.blocksec.com/phalcon/explorer/tx/eth/0x44e637c7d85190d376a52d89ca75f2d208089bb02b7c4708ad2aaae3a97a958d
- **Attacker EOA**: https://etherscan.io/address/0xA407fE273DB74184898CB56D2cb685615e1C0D6e
- **Attack Contract**: https://etherscan.io/address/0xb32D389901f963E7C87168724fBDCC3A9DB20dc9
- **BRO Token**: https://etherscan.io/token/0x014e6f6ba7a9f4c9a51a0aa3189b5c0a21006869
- **Conversion Contract**: https://etherscan.io/address/0x6aa78a9b245cc56377b21401b517ec8c03a40f03
- **BitcoinReserveOffering Implementation**: https://etherscan.io/address/0x15F7c1Ac69f0C102e4f390e45306BD917f21cFCf
- **UpgradeableBeacon**: https://etherscan.io/address/0x031c97141721d8ceeb74f96684e4e712fcd6fefd
- **SolvBTC ERC3525**: https://etherscan.io/address/0x982d50f8557d57b748733a3fc3d55aef40c46756

---

## Lessons Learned

1. **Interactions between instances sharing the same beacon/proxy must always be considered.**
   In the `UpgradeableBeacon` pattern, when multiple instances share the same implementation, `address(this)`-based checks only identify the contract itself. Callback paths from other instances under the same beacon must be validated separately.

2. **Cross-function reentrancy in ERC3525/ERC721 callback functions requires careful attention.**
   When both `onERC721Received` and `onERC3525Received` call `_mint`, and one callback can trigger the other, double minting occurs for the same deposit. The possibility of mutual invocation between callback functions must be explicitly analyzed.

3. **`nonReentrant` guards must be applied globally.**
   Applying separate `nonReentrant` guards to `burn` and `mint` individually does not prevent cross-function reentrancy. OpenZeppelin's `ReentrancyGuard` must be used with a shared mutex across all related state-changing functions.

4. **Bounds on exponential amplification are necessary.**
   Starting from just 135 BRO in initial capital, 568 million BRO could be generated in only 22 loop iterations. Double minting vulnerabilities amplify damage exponentially through loop repetition, so the possibility of duplicate execution in minting logic must be treated as the highest priority for verification.

5. **ERC3525 Semi-Fungible Token integrations require additional security review.**
   ERC3525 is a standard combining properties of ERC721 and ERC20, exposing two distinct callback paths: `onERC721Received` and `onERC3525Received`. When both paths affect the same state (minting), the possibility of double execution due to inter-callback interaction must be thoroughly reviewed.