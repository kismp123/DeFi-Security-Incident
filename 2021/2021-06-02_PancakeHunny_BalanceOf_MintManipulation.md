# PancakeHunny — balanceOf-Based mintFor() Manipulation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-06-02 |
| **Protocol** | PancakeHunny |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$7,000,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | HUNNY Minter (mintFor function) |
| **Root Cause** | mintFor() calculates mint amount using the contract's current balanceOf() instead of the received token amount, making it manipulable via direct transfer |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-06/PancakeHunny_exp.sol) |

---
## 1. Vulnerability Overview

The `mintFor()` function in the HUNNY Minter contract used the contract's current `CAKE.balanceOf(address(this))` — rather than the amount passed as a function parameter — to calculate the HUNNY reward mint amount. The attacker inflated the balance by directly transferring CAKE tokens to the Minter contract before calling `getReward()`, causing an excessive amount of HUNNY to be minted based on that inflated balance.

---
## 2. Vulnerable Code Analysis

### 2.1 mintFor() — Using balanceOf() Instead of Parameter

```solidity
// ❌ HUNNY Minter — incorrect balanceOf usage
function mintFor(address flip, uint256 _withdrawalFee, uint256 _performanceFee, address to, uint256 timestamp)
    external override onlyMinter
{
    uint256 feeSum = _performanceFee.add(_withdrawalFee);
    IBEP20(flip).safeTransferFrom(msg.sender, address(this), feeSum);

    // ❌ Uses the entire current contract balance instead of the passed feeSum
    // Directly transferring CAKE inflates hunnyBNBValue
    uint256 hunnyBNBValue = tokenToHunnyBNB(
        CAKE.balanceOf(address(this)),  // manipulable
        CAKE
    );
    uint256 mintHunny = safeHunnyMintAmount(hunnyBNBValue);
    if (mintHunny > 0) {
        _mint(mintHunny, to);
    }
}
```

**Fixed Code**:
```solidity
// ✅ Use only the feeSum passed as parameter
function mintFor(address flip, uint256 _withdrawalFee, uint256 _performanceFee, address to, uint256 timestamp)
    external override onlyMinter
{
    uint256 feeSum = _performanceFee.add(_withdrawalFee);
    IBEP20(flip).safeTransferFrom(msg.sender, address(this), feeSum);

    // ✅ Calculate based on the received feeSum (no external balance reference)
    uint256 hunnyBNBValue = tokenToHunnyBNB(feeSum, IBEP20(flip));
    uint256 mintHunny = safeHunnyMintAmount(hunnyBNBValue);
    if (mintHunny > 0) {
        _mint(mintHunny, to);
    }
}
```


### On-Chain Source Code

Source: Unconfirmed

> ⚠️ No on-chain source code — only bytecode exists or source is unverified

**Vulnerable Function** — `vulnerableFunction()`:
```solidity
// ❌ Root Cause: mintFor() calculates mint amount using the contract's current balanceOf() instead of the received token amount, making it manipulable via direct transfer
// Source code unconfirmed — bytecode analysis required
// Vulnerability: mintFor() calculates mint amount using the contract's current balanceOf() instead of the received token amount, making it manipulable via direct transfer
```

## 3. Attack Flow

```
┌────────────────────────────────────────────────────────┐
│ Step 1: Swap 5.752 BNB for CAKE (PancakeSwap)         │
│ ~59.88 CAKE acquired                                   │
└─────────────────────┬──────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 2: Directly transfer CAKE to HUNNY Minter         │
│ CAKE.transfer(hunnyMinter, 59.88e18)                   │
│ → Inflate Minter's CAKE.balanceOf()                    │
└─────────────────────┬──────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 3: Call stake() then getReward()                  │
│ → mintFor() internally reads CAKE.balanceOf(minter)    │
│ → Excessive HUNNY minted based on inflated balance     │
└─────────────────────┬──────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 4: Sell excess minted HUNNY → WBNB for profit     │
└────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
function testExploit() public {
    // 1. Swap BNB → CAKE
    // router.swapExactETHForTokens{value: 5.752 ether}(0, [WBNB, CAKE], ...)

    // 2. Directly transfer CAKE to HUNNY Minter (inflate balance)
    // CAKE.transfer(address(hunnyMinter), CAKE.balanceOf(address(this)));

    // 3. Call stake() then getReward()
    // → mintFor() reads CAKE.balanceOf(minter) and mints excess HUNNY
    // hunnyMinter.mintFor(CAKE, 0, performanceFee, address(this), block.timestamp);

    // 4. Sell HUNNY → WBNB
    // router.swapExactTokensForETH(hunnyBalance, 0, [HUNNY, WBNB], ...)
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | mintFor() references balanceOf() instead of parameter — manipulable via direct transfer | CRITICAL | CWE-682 |
| V-02 | HUNNY minting with no mint amount cap | HIGH | CWE-20 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Use only the passed amount; do not reference the contract's total balance
// ✅ Use a pre-mint balance snapshot to verify the actual amount received

function mintFor(address flip, uint256 _withdrawalFee, uint256 _performanceFee, address to, uint256 timestamp)
    external override onlyMinter
{
    uint256 feeSum = _performanceFee.add(_withdrawalFee);
    uint256 before = IBEP20(flip).balanceOf(address(this));
    IBEP20(flip).safeTransferFrom(msg.sender, address(this), feeSum);
    uint256 received = IBEP20(flip).balanceOf(address(this)).sub(before);
    // Use only the actual received amount
    uint256 hunnyBNBValue = tokenToHunnyBNB(received, IBEP20(flip));
    // ...
}
```

---
## 7. Lessons Learned

- **`balanceOf(address(this))` is easily manipulated via direct external transfers.** The amount of tokens received should be calculated as the balance difference before and after transfer (`after - before`), or the parameter value should be trusted directly.
- **The same pattern from PancakeBunny was repeated in PancakeHunny.** Forking a codebase inherits its vulnerabilities as well.
- **Reward mint calculation logic must be validated with independent unit tests.** This is especially true when the logic references external balances.