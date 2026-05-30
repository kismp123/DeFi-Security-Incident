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


### On-Chain Source Code

Source: **Sourcify partial-match** — Pool.sol / `0x3de669c4F1f167a8aFBc9993E4753b84b576426f` (BSC)
https://sourcify.dev/server/files/any/56/0x3de669c4f1f167a8afbc9993e4753b84b576426f

```solidity
// ── State variables ─────────────────────────────────────────────────────────
uint public baseAmount;   // internal accounting of BASE tokens in pool
uint public tokenAmount;  // internal accounting of TOKEN tokens in pool

// ── _getAddedBaseAmount ──────────────────────────────────────────────────────
// Called by addLiquidityForMember to detect newly arrived BASE tokens.
// ❌ Uses live balanceOf(pool) minus the stored baseAmount.
//    A direct token donation inflates this delta without minting LP for the donor.
function _getAddedBaseAmount() internal view returns (uint256 _actual) {
    uint _baseBalance = iBEP20(BASE).balanceOf(address(this)); // ❌ spot balance
    if (_baseBalance > baseAmount) {
        _actual = _baseBalance.sub(baseAmount);
    } else {
        _actual = 0;
    }
    return _actual;
}

// ── addLiquidityForMember ───────────────────────────────────────────────────
// ❌ Passes the spot delta (including donated tokens) to calcLiquidityUnits,
//    so the next LP minter is credited for tokens the attacker donated.
function addLiquidityForMember(address member) public returns (uint liquidityUnits) {
    uint256 _actualInputBase  = _getAddedBaseAmount();  // ❌ inflated by donation
    uint256 _actualInputToken = _getAddedTokenAmount(); // ❌ inflated by donation
    liquidityUnits = _DAO().UTILS().calcLiquidityUnits(
        _actualInputBase, baseAmount,
        _actualInputToken, tokenAmount,
        totalSupply
    );
    _incrementPoolBalances(_actualInputBase, _actualInputToken);
    _mint(member, liquidityUnits);
    emit AddLiquidity(member, _actualInputBase, _actualInputToken, liquidityUnits);
    return liquidityUnits;
}

// ── removeLiquidityForMember ────────────────────────────────────────────────
// ❌ calcLiquidityShare(units, token, pool, member) is implemented in the
//    external UTILS contract using baseAmount/tokenAmount as pool reserves.
//    Because those reserves were inflated by the donation→addLiquidity trick,
//    the attacker's LP units entitle them to far more than they deposited.
function removeLiquidityForMember(address member) public returns (uint outputBase, uint outputToken) {
    uint units  = balanceOf(address(this));
    outputBase  = _DAO().UTILS().calcLiquidityShare(units, BASE,  address(this), member); // ❌ excess share
    outputToken = _DAO().UTILS().calcLiquidityShare(units, TOKEN, address(this), member); // ❌ excess share
    _decrementPoolBalances(outputBase, outputToken);
    _burn(address(this), units);
    iBEP20(BASE).transfer(member, outputBase);
    iBEP20(TOKEN).transfer(member, outputToken);
    emit RemoveLiquidity(member, outputBase, outputToken, units);
    return (outputBase, outputToken);
}
```

**Why it is exploitable (identify the bug from the code):**
- `_getAddedBaseAmount()` returns `balanceOf(pool) − baseAmount`. Any `WBNB.transfer(pool, X)` that bypasses `addLiquidity` increases `balanceOf` but leaves `baseAmount` unchanged, so the delta is silently attributed to the *next* `addLiquidityForMember` caller.
- The attacker donates WBNB before calling `addLiquidityForMember`, receiving LP tokens backed by both their real deposit *and* the donated amount — an LP over-issuance.
- `removeLiquidityForMember` then pays out proportionally to those inflated units, draining more WBNB than was legitimately deposited.
- The cycle was repeated **8 times**, compounding the drain to ~$30.5 M.

```solidity
// ✅ Fix: maintain independent reserve variables — mirror Uniswap V2 pattern
uint112 private reserve0;
uint112 private reserve1;

function _update(uint balance0, uint balance1) private {
    reserve0 = uint112(balance0);
    reserve1 = uint112(balance1);
    emit Sync(reserve0, reserve1);
}
// addLiquidity computes deltas vs. reserve0/reserve1, not balanceOf().
// removeLiquidity pays proportional to reserve0/reserve1.
// Direct donations never touch reserves, so they cannot inflate LP shares.
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