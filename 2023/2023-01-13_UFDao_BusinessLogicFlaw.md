# UFDao — LP Token Purchase Business Logic Flaw Analysis

| Field | Details |
|------|------|
| **Date** | 2023-01-13 |
| **Protocol** | UFDao |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | [0x933d19d7...](https://bscscan.com/tx/0x933d19d7d822e84e34ca47ac733226367fbee0d9c0c89d88d431c4f99629d77a) |
| **Vulnerable Contract** | Unknown |
| **Root Cause** | Missing LP amount validation in `buyPublicOffer()` allows token purchases under abnormal conditions |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/UFDao_exp.sol) |

---
## 1. Vulnerability Overview

The `buyPublicOffer()` function of the UFDao protocol provides functionality to purchase DAO governance tokens with LP tokens. However, due to the absence of proper validation on the LP amount, an attacker was able to purchase governance tokens at a favorable price using an abnormal LP amount.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable buyPublicOffer function
interface SHOP {
    function buyPublicOffer(address _dao, uint256 _lpAmount) external;
}

// Presumed vulnerable implementation
function buyPublicOffer(address _dao, uint256 _lpAmount) external {
    // ❌ No minimum/maximum validation on _lpAmount
    // ❌ Price calculation relies solely on the current LP ratio
    uint256 tokenPrice = getLPBasedPrice(_lpAmount);  // manipulable
    uint256 tokenAmount = _lpAmount * RATE / tokenPrice;

    IERC20(lpToken).transferFrom(msg.sender, address(this), _lpAmount);
    ITokenDAO(_dao).mint(msg.sender, tokenAmount);  // excessive token minting
}

// ✅ Fix
function buyPublicOffer(address _dao, uint256 _lpAmount) external {
    require(_lpAmount >= MIN_LP_AMOUNT, "Too small");
    require(_lpAmount <= MAX_LP_AMOUNT, "Too large");
    // Use TWAP-based pricing
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Missing LP amount validation in `buyPublicOffer()` allows token purchases under abnormal conditions
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Borrow large amount of tokens via flash loan
  │
  ├─2─▶ Manipulate LP pair liquidity (distort price)
  │
  ├─3─▶ SHOP.buyPublicOffer(_dao, manipulated_lpAmount)
  │       Processed without validation → receive UFT tokens at favorable ratio
  │
  ├─4─▶ Extract value via UFT.burn() etc.
  │
  └─5─▶ Repay flash loan → net profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public {
    // 1. Acquire large amount of tokens via flash loan
    flashBorrow(largeAmount);

    // 2. Manipulate LP pair price
    manipulatePrice();

    // 3. Purchase UFT at favorable terms via buyPublicOffer
    IERC20(lpToken).approve(address(shop), type(uint256).max);
    shop.buyPublicOffer(daoAddress, manipulatedAmount);

    // 4. Burn or sell the acquired UFT tokens
    uint256[] memory tokens = new uint256[](1);
    address[] memory adapters = new address[](1);
    UFT(uft).burn(uft.balanceOf(address(this)), tokens, adapters);

    // 5. Repay flash loan
    repayFlashLoan();
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Business Logic Flaw + Missing Input Validation |
| **Attack Vector** | Flash Loan + LP Price Manipulation |
| **Impact Scope** | DAO Token Minting Mechanism |
| **DASP Classification** | Business Logic Flaw |
| **CWE** | CWE-20: Improper Input Validation |

## 6. Remediation Recommendations

1. **LP Amount Range Validation**: Set minimum/maximum purchase limits.
2. **TWAP-Based Price Calculation**: Remove dependency on spot price.
3. **Purchase Cooldown**: Add a time restriction to prevent consecutive purchases.

## 7. Lessons Learned

- DAO token minting mechanisms are directly tied to price manipulation, making oracle security essential.
- LP token-based price calculations are inherently vulnerable to flash loan manipulation.
- BlockSec's analysis publicly documented this incident.