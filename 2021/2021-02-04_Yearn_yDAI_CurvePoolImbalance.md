# Yearn Finance yDAI — Curve 3Pool Imbalance Manipulation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-02-04 |
| **Protocol** | Yearn Finance (yVDAI Vault) |
| **Chain** | Ethereum |
| **Loss** | ~$11,000,000 |
| **Attacker** | Address unidentified |
| **Attack Tx** | [0x59faab5a](https://etherscan.io/tx/0x59faab5a1911618064f1ffa1e4649d85c99cfd9f0d64dcebbc1af7d7630da98b) |
| **Vulnerable Contract** | [0xACd43E627e64355f1861cEC6d3a6688B31a6F952](https://etherscan.io/address/0xACd43E627e64355f1861cEC6d3a6688B31a6F952) (yVDAI) |
| **Root Cause** | yVault calculates prices based on Curve 3Pool's current balances, allowing price distortion when pool imbalance is manipulated |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-02/Yearn_ydai_exp.sol) |

---
## 1. Vulnerability Overview

Yearn's yVDAI vault internally uses Curve 3Pool (DAI/USDC/USDT) to generate yield. When the vault evaluates asset value, it references the current balance ratio of the Curve pool. The attacker exploited large-scale flash loans to create an extreme pool imbalance, manipulating the vault's internal accounting.

The attacker used `remove_liquidity_imbalance` to withdraw USDT in a skewed manner, placing the 3Pool into an imbalanced state. In this state, the attacker triggered a deposit into yVDAI followed by an `earn()` call, causing the vault to operate under distorted prices. By repeating this cycle, the attacker progressively drained assets from other LP providers.

---
## 2. Vulnerable Code Analysis

### 2.1 earn() — Price Recalculation Under Imbalanced Pool State

```solidity
// ❌ Price calculated using Curve pool's current spot balances (manipulable)
function earn() public {
    uint256 _bal = available();
    token.safeTransfer(controller, _bal);
    IController(controller).earn(address(token), _bal);
    // Internally calls Curve 3Pool's get_virtual_price() or
    // calc_withdraw_one_coin() — depends on current pool state
}

// Vulnerable price query from Curve 3Pool
function get_virtual_price() external view returns (uint256) {
    // Calculated as D / total_supply — manipulable when pool is imbalanced
    uint256 D = get_D(xp(), amp);
    uint256 token_supply = CurveToken(lp_token).totalSupply();
    return D * PRECISION / token_supply;
}
```

**Fixed Code**:
```solidity
// ✅ Use TWAP or time-weighted price, detect sharp changes within a single block
function earn() public {
    // Check pool imbalance ratio
    uint256[3] memory balances = ICurve3Pool(curve).get_balances();
    uint256 totalBal = balances[0] + balances[1] * 1e12 + balances[2] * 1e12;
    for (uint i = 0; i < 3; i++) {
        uint256 normalized = i == 0 ? balances[i] : balances[i] * 1e12;
        // Abnormal state if a single asset exceeds 80% of total
        require(normalized * 100 / totalBal < 80, "Pool imbalanced");
    }
    uint256 _bal = available();
    token.safeTransfer(controller, _bal);
    IController(controller).earn(address(token), _bal);
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**yVault.sol** — Entry point:
```solidity
// ❌ Root cause: yVault calculates prices based on Curve 3Pool's current balances, allowing price distortion when pool imbalance is manipulated
    function deposit(uint _amount) public {
        uint _pool = balance();
        uint _before = token.balanceOf(address(this));  // ❌ Direct reference to current balance — manipulable
        token.safeTransferFrom(msg.sender, address(this), _amount);
        uint _after = token.balanceOf(address(this));
        _amount = _after.sub(_before); // Additional check for deflationary tokens
        uint shares = 0;
        if (totalSupply() == 0) {
            shares = _amount;
        } else {
            shares = (_amount.mul(totalSupply())).div(_pool);
        }
        _mint(msg.sender, shares);
    }
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────┐
│ Step 1: Obtain DAI/USDC/USDT via large-scale flash loan   │
│ dYdX / Aave flash loan                                    │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 2: Call Curve 3Pool.remove_liquidity_imbalance()     │
│ Withdraw only USDT in skewed manner → create extreme pool imbalance │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 3: Call yVDAI.deposit() → yVDAI.earn()               │
│ 0xACd43E627e64355f1861cEC6d3a6688B31a6F952               │
│ Update vault internal state with distorted prices         │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 4: Re-add liquidity to 3Pool (restore balance)       │
│ Curve 3Pool.add_liquidity()                               │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 5: Withdraw full yVDAI balance — excess withdrawal at distorted price │
│ yVDAI.withdraw() @ 0xACd43E627e64355f1861cEC6d3a6688B31a6F952 │
└──────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() core logic excerpt
function testExploit() public {
    // 1. Large-scale flash loan (DAI, USDT, etc.)
    // dydx.flashLoan(...)

    // 2. Create Curve 3Pool imbalance
    // curve3Pool.remove_liquidity_imbalance(
    //     [0, 0, large_usdt_amount],  // Withdraw USDT only
    //     max_burn_amount
    // );

    // 3. Deposit into yVDAI then trigger earn()
    // yVDAI.deposit(dai_amount);   // 0xACd43E627e64355f1861cEC6d3a6688B31a6F952
    // yVDAI.earn();                // Yield calculation under distorted state

    // 4. Restore pool balance
    // curve3Pool.add_liquidity([large_usdt, 0, 0], 0);

    // 5. Withdraw full yVDAI balance to realize excess profit
    // yVDAI.withdraw(yVDAI.balanceOf(address(this)));
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Spot balance-based price calculation from Curve pool — yVault internal accounting distorted when pool imbalance is manipulated | CRITICAL | CWE-829 |
| V-02 | Deposit-earn-withdraw permitted within a single transaction — no block delay (contributing factor: enables flash loan-scale attacks) | HIGH | CWE-841 |

> **Root Cause**: yVault prices assets using the current balance ratio of Curve 3Pool during `earn()`, so making the pool imbalanced via `remove_liquidity_imbalance` distorts the price. Flash loans are merely a funding mechanism to concentrate large capital in a single transaction; the same attack is possible with sufficient real capital.

---
## 6. Remediation Recommendations

```solidity
// ✅ Validate pool imbalance state when earn() is called
// ✅ Enforce minimum block interval between deposit and withdrawal (withdraw delay)

mapping(address => uint256) public lastDepositBlock;

function withdraw(uint256 _shares) public {
    // Allow withdrawal only after at least 1 block (flash loan prevention)
    require(
        block.number > lastDepositBlock[msg.sender],
        "Vault: cannot deposit and withdraw in same block"
    );
    // ... existing withdrawal logic
}

function deposit(uint256 _amount) public {
    lastDepositBlock[msg.sender] = block.number;
    // ... existing deposit logic
}
```

---
## 7. Lessons Learned

- **Vault price calculations must not use spot pool balances directly.** TWAP or external oracles such as Chainlink should be used as supplementary price sources.
- **A block delay constraint between deposit and withdrawal is an effective defense that blocks not only flash loans but all single-transaction manipulation.**
- **Curve pools offer an imbalanced withdrawal function (`remove_liquidity_imbalance`).** Protocol designers must account for the price manipulation vector this creates.
- **Flash loans are a funding mechanism for the attack, not the vulnerability itself.** Removing the spot price oracle is the essential fix.