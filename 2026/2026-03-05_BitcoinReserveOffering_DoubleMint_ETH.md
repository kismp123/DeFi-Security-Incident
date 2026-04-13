# BitcoinReserveOffering (BRO) — Double Minting Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2026-03-05 |
| **Protocol** | BitcoinReserveOffering (BRO / SolvProtocol) |
| **Chain** | Ethereum |
| **Loss** | ~$2,700,000 |
| **Attack Tx** | [0x44e6...958d](https://etherscan.io/tx/0x44e637c7d85190d376a52d89ca75f2d208089bb02b7c4708ad2aaae3a97a958d) |
| **Root Cause** | ERC-3525/ERC-721 Double Callback Minting (Business Logic Flaw) |

---

## 1. Vulnerability Overview

Solv Protocol's `BitcoinReserveOffering(BRO)` contract wraps an ERC-3525 Semi-Fungible Token (SFT) to issue BRO ERC-20 tokens. When receiving a SolvBTC SFT deposit, this contract mints tokens via two distinct callback paths.

- `onERC721Received`: Called when an entire SFT is transferred via the ERC-721 interface
- `onERC3525Received`: Called when only the value (quantity) of an SFT is transferred via the ERC-3525 interface

The issue is that when `onERC721Received` internally calls `ERC3525TransferHelper.doTransfer`, that call in turn triggers the `onERC3525Received` callback again. Since both callbacks execute `_mint`, **BRO tokens are minted twice for the same SFT deposit**.

The attacker repeated this double-minting cycle 22 times, exponentially amplifying an initial 135.36 BRO into approximately **568 million BRO**, which was then sold through a DEX. The total loss amounted to **~1,211 WETH ($2.7M–$3.6M)**.

### Protocol Structure

```
UpgradeableBeacon (0x031c97)
  |
  +-- Implementation: BitcoinReserveOffering (0x15F7c1)
  |
  +-- Instance A: BRO ERC20 Token (0x014e6f)   <- BRO-SOLV-20MAY2026
  |     wrappedSftAddress = SolvBTC ERC3525
  |     exchangeRate-based minting/burning
  |
  +-- Instance B: Conversion Contract (0x6aa78a)   <- Second instance exploited in attack
        Same implementation, same beacon
        Handles BRO burn <-> SolvBTC exchange
```

---

## 2. Vulnerable Code Analysis

### Vulnerable Function 1: `onERC721Received` (❌ Vulnerable)

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
        // ❌ BUG: doTransfer internally transfers SolvBTC ERC3525 value,
        //         which re-triggers the onERC3525Received callback on the
        //         receiving BRO instance A
        ERC3525TransferHelper.doTransfer(
            wrappedSftAddress, sftId_, holdingValueSftId, sftValue
        );
        _holdingEmptySftIds.push(sftId_);
    }

    uint256 value = sftValue * exchangeRate / (10 ** decimals());
    _mint(from_, value);  // ❌ Mint #1 - onERC721Received path
    return IERC721Receiver.onERC721Received.selector;
}
```

**Issue:** As `doTransfer` consolidates the SolvBTC ERC3525 value into `holdingValueSftId`, the contract's `onERC3525Received` is invoked as a callback. The `_mint` in `onERC3525Received` fires either before or immediately after the `_mint` in `onERC721Received`, resulting in **double issuance for the same deposit**.

---

### Vulnerable Function 2: `onERC3525Received` (❌ Vulnerable)

```solidity
function onERC3525Received(
    address, uint256 fromSftId_, uint256 sftId_, uint256 sftValue_, bytes calldata
) external virtual override onlyWrappedSft returns (bytes4) {
    address fromSftOwner = IERC3525(wrappedSftAddress).ownerOf(fromSftId_);

    // ❌ BUG: Only filters address(this) — a sibling instance under the same
    //         beacon (0x6aa7) passes through unchecked
    if (fromSftOwner == address(this)) {
        return IERC3525Receiver.onERC3525Received.selector;
    }

    uint256 value = sftValue_ * exchangeRate / (10 ** decimals());
    _mint(fromSftOwner, value);  // ❌ Mint #2 - double mint occurs here!
    return IERC3525Receiver.onERC3525Received.selector;
}
```

**Issue:** The `fromSftOwner == address(this)` check only skips transfers originating from **itself**. When a **different BRO instance** (0x6aa78a) sharing the same `UpgradeableBeacon` becomes the `fromSftOwner`, it is not filtered out, allowing `_mint` to execute a second time.

---

### Fixed Code: `onERC3525Received` (✅ Fixed)

```solidity
// Option A: Whitelist of trusted instances
mapping(address => bool) public trustedInstances;

function onERC3525Received(
    address, uint256 fromSftId_, uint256 sftId_, uint256 sftValue_, bytes calldata
) external virtual override onlyWrappedSft returns (bytes4) {
    address fromSftOwner = IERC3525(wrappedSftAddress).ownerOf(fromSftId_);

    // ✅ FIX: Skip self + trusted instances under the same beacon
    if (fromSftOwner == address(this) || trustedInstances[fromSftOwner]) {
        return IERC3525Receiver.onERC3525Received.selector;
    }

    uint256 value = sftValue_ * exchangeRate / (10 ** decimals());
    _mint(fromSftOwner, value);
    return IERC3525Receiver.onERC3525Received.selector;
}
```

```solidity
// Option B: Cross-function reentrancy guard (shared global mutex)
uint256 private _mintLock;  // 0 = unlocked

modifier mintNonReentrant() {
    require(_mintLock == 0, "BRO: reentrant mint");
    _mintLock = 1;
    _;
    _mintLock = 0;
}

// ✅ FIX: Both callbacks share the same mutex
function onERC721Received(...) external mintNonReentrant ... { ... }
function onERC3525Received(...) external mintNonReentrant ... { ... }
```

---

## 3. Attack Flow

```
Attacker EOA (0xA407fE27)
  |
  +--[1] Deploy attack contract (0xb32D3899)
  |       loops=22, amount=135.364 BRO
  |
  +--[2] Execute 22-cycle double-minting loop
          |
          |  +----------- 1 Cycle (repeating unit) -----------+
          |  |                                                 |
          |  |  AttackContract                                 |
          |  |    |                                            |
          |  |    +--[a] Transfer BRO -> Conversion (0x6aa7)  |  Deposit X BRO
          |  |                                                 |
          |  |  Conversion (0x6aa7) [Instance B]              |
          |  |    |                                            |
          |  |    +--[b] Burn BRO (burn -> 0x0)               |  Burn X BRO
          |  |    |                                            |
          |  |    +--[c] SolvBTC Exchange #1 (0 amount)        |  Internal position settlement
          |  |    |                                            |
          |  |    +--[d] SolvBTC Exchange #2                   |  <-- Bug triggered
          |  |           |                                     |
          |  |  BRO Token (0x014e) [Instance A]               |
          |  |           |                                     |
          |  |           +--[e] onERC721Received executes      |
          |  |           |       _mint #1: 0x0->0x6aa7         |  Mint X BRO
          |  |           |                                     |
          |  |           +--[f] onERC3525Received executes     |
          |  |                   _mint #2: 0x0->0x6aa7         |  Mint additional X BRO !!
          |  |                                                 |
          |  |    +--[g] Burn: 0x6aa7 -> 0x0, 2X BRO          |  Input for next cycle
          |  |                                                 |
          |  +---------------------------------------------+
          |
          |  [Cumulative BRO per cycle]
          |   Cycle  1:  135 BRO  ->       271 BRO
          |   Cycle  5:  2,165    ->     4,331
          |   Cycle 10:  138,612  ->   277,225
          |   Cycle 15:  4,435,615 -> 8,871,231
          |   Cycle 20:  141,939,704 -> 283,879,408
          |   Cycle 22:  567,758,816 BRO (final)
          |
  +--[3] Withdraw all BRO: 0x6aa7 -> AttackContract  (567,758,816 BRO)
  |
  +--[4] Profit realization
          |
          +--[4a] Sell BRO: 165,592,064 BRO -> DEX pool (0xfb2d)
          |                                 -> 38.047 SolvBTC ERC20
          |
          +--[4b] SolvBTC -> GOEFS (0x5738) -> ~38 WBTC
          |
          +--[4c] WBTC -> UniV3 (0x4585) -> 1,211.054 WETH
          |
          +--[4d] Unwrap WETH -> withdraw ETH
          |
          +--[4e] Return remaining 402,166,752 BRO -> Attacker EOA
```

---

## 4. Vulnerability Classification (CWE)

| CWE ID | Name | Application |
|--------|------|-------------|
| **CWE-841** | Improper Enforcement of Behavioral Workflow | Design flaw where both `onERC721Received` and `onERC3525Received` callbacks perform minting |
| **CWE-362** | Race Condition / Concurrent Execution | `_mint` executed twice with the same value in a callback chain without intermediate state updates |
| **CWE-284** | Improper Access Control | The `fromSftOwner == address(this)` check trusts sibling instances under the same beacon, causing the filter to fail |
| **CWE-693** | Protection Mechanism Failure | `nonReentrant` guards are applied per-function, failing to block cross-function reentrancy |

> **DASP Classification:** Business Logic — Double Minting via Cross-Callback Reentrancy

---

## 5. Remediation Recommendations

### Immediate Actions (Short-term)

1. **Register beacon instance whitelist**
   Introduce a `trustedInstances` mapping in `onERC3525Received` to explicitly register all sibling instances under the same beacon, returning immediately without minting when a callback originates from those addresses.

2. **Apply cross-function mutex**
   Modify `onERC721Received`, `onERC3525Received`, and `mint` to share a single reentrancy lock. Note that OpenZeppelin `ReentrancyGuard`'s `nonReentrant` only blocks cross-function reentrancy when **the same modifier is shared within the same contract**.

3. **Per-SFT minting record flag**
   Introduce a `mapping(uint256 sftId => bool minted)` to enforce that minting occurs at most once per `sftId`.

### Design Improvements (Long-term)

4. **Document inter-callback call paths explicitly**
   When integrating ERC-3525, explicitly analyze and document at the design stage that internal calls within `onERC721Received` can recursively trigger `onERC3525Received`.

5. **Establish a trust model between sibling beacon instances**
   When deploying multiple instances under an `UpgradeableBeacon` pattern, clearly define the trust boundary for inter-instance interactions (callbacks, transfers, etc.) and do not rely solely on `address(this)` comparisons.

6. **Achieve full test coverage for the entire callback chain**
   Validate all possible callback sequences that can arise from combinations of ERC-3525, ERC-721, and ERC-20 transfers via unit tests.

---

## 6. Lessons Learned

**1. A standalone `address(this)` comparison cannot identify sibling instances under the same beacon**

Under the `UpgradeableBeacon` pattern, multiple instances sharing the same implementation each have a distinct `address(this)`. Logic that relies solely on `fromSftOwner == address(this)` to confirm an internal transfer leaves a bypass path open through sibling instances.

**2. ERC-3525 callback paths can recursively trigger ERC-721 callbacks internally**

As in the `onERC721Received` → `doTransfer` → `onERC3525Received` chain, the two callback paths of the ERC-3525 standard can cause one to internally invoke the other. When both paths affect the same state (minting), the possibility of cross-invocation must be explicitly analyzed at the design stage.

**3. Per-function `nonReentrant` guards do not prevent cross-function reentrancy**

Applying separate `nonReentrant` guards to `burn` and `mint` individually only blocks **self-reentrancy within each function**. Reentrancy occurring between two different functions (cross-function reentrancy) cannot be blocked without a shared mutex.

**4. Double-minting vulnerabilities amplify losses exponentially through loops**

As demonstrated by this incident — where 135 BRO grew into 568 million BRO in just 22 cycles — a structure that doubles output each cycle provides the attacker with exponential gains. The possibility of duplicate execution in minting logic must be treated as a top-priority verification target regardless of the initial amount.

**5. ERC-3525 SFT integration requires a dedicated security audit checklist**

ERC-3525 is a standard that combines the properties of ERC-721 (NFT) and ERC-20 (FT), and features multiple callback paths. Vulnerabilities arising from the interaction between these two paths are easily missed by audit methodologies designed solely for ERC-721 or ERC-20. Protocols using ERC-3525 must establish a dedicated audit checklist that covers inter-callback interactions.

---

## References

- **Attack Tx (Etherscan):** https://etherscan.io/tx/0x44e637c7d85190d376a52d89ca75f2d208089bb02b7c4708ad2aaae3a97a958d
- **Phalcon Analysis:** https://app.blocksec.com/phalcon/explorer/tx/eth/0x44e637c7d85190d376a52d89ca75f2d208089bb02b7c4708ad2aaae3a97a958d
- **BRO Token (0x014e6f):** https://etherscan.io/token/0x014e6f6ba7a9f4c9a51a0aa3189b5c0a21006869
- **Conversion Contract (0x6aa78a):** https://etherscan.io/address/0x6aa78a9b245cc56377b21401b517ec8c03a40f03
- **Implementation (0x15F7c1):** https://etherscan.io/address/0x15F7c1Ac69f0C102e4f390e45306BD917f21cFCf
- **Attacker EOA:** https://etherscan.io/address/0xA407fE273DB74184898CB56D2cb685615e1C0D6e
- **Attack Contract:** https://etherscan.io/address/0xb32D389901f963E7C87168724fBDCC3A9DB20dc9