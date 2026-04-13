# Turing (TR) + NOBEL — Burn-Redistribution Drain & EIP-7702 Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2026-03-26 |
| **Protocol** | Turing (TR) + NOBEL Token Ecosystem |
| **Chain** | BNB Chain (BSC) |
| **Loss** | ~$133,490 USDT (Turing Distributor fully drained + Pool USDT extracted) |
| **Attacker** | [0xC93A5Ab3...F692](https://bscscan.com/address/0xC93A5Ab3737081F00788B61DA42281955d3dF692) |
| **EIP-7702 Code** | [0x7b3928c1...772c](https://bscscan.com/address/0x7b3928c1cef617810484589f400e8056dd2d772c) |
| **Attack Tx** | [0x96c9ce3c...1e348](https://bscscan.com/tx/0x96c9ce3c527681bf0da18511d142efb5769ad8dac1d9d659a6b70a697381e348) |
| **Vulnerable Contract** | TR Distributor [0x03d8096...15abe](https://bscscan.com/address/0x03d8096377ea7683d840e395d72439f7b6415abe) |
| **Attack Block** | 88,871,542 |
| **Transaction Type** | **Type 4 (EIP-7702 SetCode)** |
| **Root Cause** | 2.45x multiplier vulnerability in TR burn-redistribution mechanism + `tx.origin` validation bypass via EIP-7702 |

---

## 1. Vulnerability Overview

This attack combines two independent vulnerabilities:

### Vulnerability A: Turing (TR) Burn-Redistribution Multiplier Error

The TR token ecosystem includes a mechanism where burning TR (sending to 0x0000dead) causes the Distributor contract (0x03d809...) to redistribute its held TR to registered recipients. The attacker exploited the fact that this mechanism redistributes **more than 2.45x the burned amount**:

- Burned: 7,770,707 TR
- Received via redistribution: 19,048,865 TR (fully draining 18,797,013 TR from the Distributor)
- The Distributor's entire 18.8M TR was emptied in a single attack

### Vulnerability B: `tx.origin == msg.sender` Bypass via EIP-7702

EIP-7702 is a new transaction type that allows an EOA to temporarily "borrow" and execute bytecode from an external contract. This enables:

- The attacker's EOA to call itself (`to = from`)
- `msg.sender == tx.origin == 0xC93A5Ab3...` → both equal the EOA address
- Bypassing protocols that block contracts via `require(msg.sender == tx.origin)` by masquerading as an EOA, including flash loan providers

---

## 2. Transaction Structure (EIP-7702)

```
Transaction Type: 4 (EIP-7702 SetCode)
from: 0xC93A5Ab3737081F00788B61DA42281955d3dF692  (attacker EOA)
to:   0xC93A5Ab3737081F00788B61DA42281955d3dF692  (itself!)

authorizationList:
  - chainId: 0x38 (BSC)
  - address: 0x7b3928c1cef617810484589f400e8056dd2d772c  ← attack code address
  - nonce: 0x29 (41)   ← matches the EOA's current nonce

calldata: 0x1a2998c8(...) calls itself
          → executes with EOA's bytecode replaced by 0x7b3928c1...'s code
```

When the EIP-7702 SetCode transaction is processed:
1. The bytecode of `0x7b3928c1...` is temporarily set in the EOA's code slot
2. The EOA address effectively behaves as a smart contract
3. `msg.sender == tx.origin` evaluates to TRUE, passing EOA validation

---

## 3. Attack Flow

### 3.1 Preparation Phase

Before the attack, the attacker pre-registered recipient addresses (`0xce2aceab`, `0xe2be550b`) in the Turing ecosystem so that TR would be sent to those addresses upon burn-redistribution.

### 3.2 Execution Phase

```
[Step 1] EIP-7702 SetCode + Flash Loan
┌──────────────────────────────────────────────────────────────┐
│ EOA code → temporarily replaced with 0x7b3928c1...'s bytecode │
│ Lista DAO Moolah → Attacker EOA: 1,900,000 USDT flash loan  │
└──────────────────────────────────────────────────────────────┘
                           │
                           ▼
[Step 2] USDT → NOBEL Buy (Pool_B Price Manipulation)
┌──────────────────────────────────────────────────────────────┐
│ Input: 1,900,000 USDT → PCS Pool_B (NOBEL/USDT)             │
│ Output: 696.122 NOBEL                                         │
│                                                               │
│ Pool_B state change:                                          │
│   BEFORE: 1,002 NOBEL + 779,111 USDT → price 777 USDT/NOBEL  │
│   AFTER:  292 NOBEL  + 2,679,111 USDT → price 9,175 USDT/NOBEL │
│   NOBEL price pumped 11.8x!                                   │
└──────────────────────────────────────────────────────────────┘
                           │
                           ▼
[Step 3] NOBEL → TR Buy (Pool_A)
┌──────────────────────────────────────────────────────────────┐
│ Input: 682.223 NOBEL → PCS Pool_A (NOBEL/TR)                 │
│ Output: 7,818,634.625 TR                                      │
│                                                               │
│ Pool_A state change:                                          │
│   BEFORE: 2,036 NOBEL + 31,219,647 TR                        │
│   AFTER:  2,719 NOBEL + 23,401,012 TR                        │
└──────────────────────────────────────────────────────────────┘
                           │
                           ▼
[Step 4] TR Burn → Distributor Drain (Core Vulnerability)
┌──────────────────────────────────────────────────────────────┐
│ Attacker → 0x0000dead: 7,770,707.051 TR burned (99.4%)      │
│                                                               │
│ ↓ Burn-redistribution mechanism triggered!                    │
│                                                               │
│ Distributor(0x03d809) → 0x39789923: 471,307 TR              │
│ Distributor(0x03d809) → 0xce2aceab: 15,238,941 TR ←┐        │
│ 0xce2aceab → Attacker EOA: 15,238,941 TR ←━━━━━━━━━┘ attacker receives
│                                                               │
│ Distributor(0x03d809) → 0x39789923: 117,832 TR              │
│ Distributor(0x03d809) → 0xe2be550b: 3,809,924 TR ←┐         │
│ 0xe2be550b → Attacker EOA: 3,809,924 TR ←━━━━━━━━━┘ attacker receives
│                                                               │
│ Attacker → Distributor: 840,992 TR (partial return)          │
│                                                               │
│ Distributor TR: 18,797,013 → 1 wei (fully drained!)          │
│ Burned 7.77M TR → received 18.2M TR in redistribution (2.45x+!) │
└──────────────────────────────────────────────────────────────┘
                           │
                           ▼
[Step 5] TR → NOBEL → USDT Sell
┌──────────────────────────────────────────────────────────────┐
│ Attacker → Pool_A: 17,708,468.523 TR                         │
│ Pool_A → Pool_B: 1,111.953 NOBEL (NOBEL received by Attacker)│
│ Pool_B → Attacker: 2,033,398.303 USDT ← final proceeds       │
│                                                               │
│ Pool_A final: 1,532 NOBEL + 41,565,885 TR                    │
│ Pool_B final: 1,420 NOBEL + 570,182 USDT                     │
└──────────────────────────────────────────────────────────────┘
                           │
                           ▼
[Step 6] Repayment and Profit Realization
┌──────────────────────────────────────────────────────────────┐
│ Attacker → Lista DAO Moolah: 1,900,000 USDT repaid          │
│ Attacker → 0x1b4e5898: 133,490.392 USDT (profit)            │
└──────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| Flash Loan Size | 1,900,000 USDT |
| TR Distributor Drained | 18,797,013 TR (100%) |
| Total Profit | **133,490 USDT** |
| Pool_B USDT Loss | 779,111 → 570,182 (-208,929 USDT) |
| Pool_A NOBEL Loss | 2,036 → 1,532 (-504 NOBEL) |

---

## 4. Vulnerable Code Analysis

### 4.1 Turing (TR) Burn-Redistribution Mechanism Vulnerability

```solidity
// TR token's _update() function (called on ERC-20 transfer)
function _update(address from, address to, uint256 value) internal virtual override {
    if (from == nobelPair) {
        // ① Handle LP removal
        uint256 lpAmount = isRemoveLiquidity();
        if (lpAmount > 0) {
            userLPs[to] -= lpAmount;
            LPTotal -= lpAmount;
        }
    } else if (to == nobelPair) {
        // ② Execute dividend distribution only when selling TR into pool
        require(usersBuyTime[tx.origin] < block.timestamp - 10, "cd");
        uint256 lpAmount = isAddLiquidity(value);
        if (lpAmount > 0) {
            userLPs[from] += lpAmount;
            LPTotal += lpAmount;
        }
        if (from != address(this)) {
            processDividend();   // distribute TR/NOBEL to LP holders
            sellFee2Fund();
            sellFee();
        }
    }
    return super._update(from, to, value);
}
```

**Core vulnerability**: When burning TR to 0x0000dead (to ≠ nobelPair):
- `processDividend()` is not called
- However, a separate Distributor contract listens for the burn event and redistributes its held TR
- **The redistribution multiplier exceeds 2.45x** → it is possible to receive more TR than was burned

```solidity
// ❌ Vulnerable distribution logic in Distributor contract (inferred)
function onBurn(uint256 burnAmount) external {
    // Distribute held TR to registered recipients proportional to burn amount
    // Issue: total redistributed > burned amount (no multiplier validation)
    uint256 distributeAmount = getDistributeAmount(burnAmount);  // returns 2.45x+!
    for (address recipient : registeredRecipients) {
        uint256 share = distributeAmount * shares[recipient] / totalShares;
        TR.transfer(recipient, share);  // ❌ distributes without pre-burn validation
    }
}
```

**Fixed code:**

```solidity
// ✅ Fix: cap total redistribution to not exceed the burn amount
function onBurn(uint256 burnAmount) external {
    uint256 distributeAmount = getDistributeAmount(burnAmount);
    // Redistribution cap: maximum 1x the burn amount (1:1 ratio)
    require(distributeAmount <= burnAmount, "Redistribute: exceeds burn amount");
    // Or cap at a fixed percentage of circulating supply
    require(distributeAmount <= totalDistributable / 100, "Redistribute: exceeds cap");
    for (address recipient : registeredRecipients) {
        uint256 share = distributeAmount * shares[recipient] / totalShares;
        TR.transfer(recipient, share);
    }
}
```

### 4.2 EIP-7702 `tx.origin` Validation Bypass

```solidity
// EOA validation pattern used by many DeFi protocols
modifier onlyEOA() {
    require(msg.sender == tx.origin, "Only EOA allowed");
    _;
}

// Traditional defense: contracts are blocked because tx.origin != msg.sender
// ❌ EIP-7702 bypass: EOA temporarily sets its own code, then calls itself
//    → msg.sender = 0xC93A5Ab3 (EOA)
//    → tx.origin = 0xC93A5Ab3 (same EOA)
//    → condition passes!
```

```solidity
// ✅ Fix: add code size check (valid even in EIP-7702 environments)
modifier onlyEOA() {
    require(msg.sender == tx.origin, "Only EOA allowed");
    require(msg.sender.code.length == 0, "No contract code allowed");  // blocks EIP-7702
    _;
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | TR burn-redistribution multiplier vulnerability (2.45x redistribution vs. burn) | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | `tx.origin == msg.sender` validation bypass via EIP-7702 | HIGH | CWE-284 (Improper Access Control) |
| V-03 | Flash loan-based NOBEL price manipulation | HIGH | CWE-841 |
| V-04 | Redistribution recipient pre-registration allowed without authorization | HIGH | CWE-284 |

### V-01: TR Burn-Redistribution Multiplier Vulnerability

- **Description**: When TR is burned, the total TR redistributed by the Distributor contract to registered recipients (19.05M) exceeds the burned amount (7.77M) by 2.45x. The Distributor's entire 18.8M TR was drained in a single attack.
- **Impact**: All accrued rewards in the Distributor contract were stolen. Ecosystem rewards completely depleted.
- **Attack Conditions**: Ability to pre-register recipient addresses + sufficient TR holdings to burn.

### V-02: EIP-7702 `tx.origin` Bypass

- **Description**: An EIP-7702 Type 4 transaction allows an EOA to temporarily execute external contract code. `msg.sender == tx.origin` remains TRUE, passing EOA validation.
- **Impact**: Bypasses contract-blocking mechanisms such as EOA-only flash loans. Enables complex multi-step attacks without deploying a separate attack contract.
- **Attack Conditions**: Target chain supports EIP-7702 (including BSC and Ethereum post-Pectra upgrade).

---

## 6. On-Chain Verification

### 6.1 EIP-7702 Authorization List

```
authorizationList:
  chainId:  0x38 (BSC mainnet)
  address:  0x7b3928c1cef617810484589f400e8056dd2d772c  (attack code)
  nonce:    0x29 = 41  (matches the attacker EOA's current nonce)
  yParity:  0x0
  r:        0x4e5e3595dfa7c89...
  s:        0x5884ac41e6272f6...
```

### 6.2 Key Metrics Verification

| Item | Value | On-Chain Confirmation |
|------|-----|------------|
| Flash Loan | 1,900,000 USDT | [Log 1] ListaDAO_Moolah → Attacker |
| NOBEL Bought | 696.122 NOBEL | [Log 8] Pool_B → Attacker |
| TR Bought | 7,818,634.625 TR | [Log 13] Pool_A → Attacker |
| TR Burned | 7,770,707.051 TR | [Log 18] Attacker → 0x0000dead |
| Distributor Drained | 18,797,013.73 TR | 0x03d809: 18.8M → 1 wei |
| TR Redistribution Received | 19,048,865 TR | [Log 22,26] |
| Final USDT Extracted | 2,033,398.303 USDT | [Log 71] Pool_B → Attacker |
| Net Profit | **133,398 USDT** | 2,033,398 - 1,900,000 |

### 6.3 TR Redistribution Multiplier Analysis

```
Burned:       7,770,707.051 TR  (burned to 0x0000dead)
Redistributed:   19,048,865.000 TR  (received from Distributor)
Returned:           840,992.453 TR  (returned to Distributor)
───────────────────────────
Net Received: 18,207,872.547 TR  (net TR received)
Multiplier:   18,207,872 / 7,770,707 = 2.342x  ← over 2.3x the burned amount!

Distributor Total Loss: 18,797,013.73 TR (fully drained)
```

---

## 7. Remediation Recommendations

### Immediate Actions

**① Set a cap on the Distributor redistribution multiplier**

```solidity
// Cap total redistribution to maximum 100% of burn amount
uint256 constant MAX_REDIST_RATIO = 100;  // 100% = 1:1

function processRedistribution(uint256 burnAmount) internal {
    uint256 maxRedist = burnAmount * MAX_REDIST_RATIO / 100;
    uint256 actualRedist = Math.min(pendingRewards, maxRedist);
    _distribute(actualRedist);
}
```

**② Limit total redistribution per single burn event**

```solidity
// Prevent a single burn from draining the entire Distributor
uint256 constant MAX_SINGLE_REDIST = totalSupply / 1000;  // max 0.1% per burn

function processRedistribution(uint256 burnAmount) internal {
    uint256 redist = Math.min(
        burnAmount * ratio / 100,
        MAX_SINGLE_REDIST
    );
    _distribute(redist);
}
```

**③ EIP-7702 mitigation: add `msg.sender.code.length` check**

```solidity
modifier strictEOAOnly() {
    require(msg.sender == tx.origin, "Only EOA");
    require(msg.sender.code.length == 0, "EIP-7702 not allowed");
    _;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Burn-redistribution multiplier | Total redistribution ≤ burn amount; set daily/per-transaction caps |
| V-02 EIP-7702 | Add `extcodesize(msg.sender) == 0` check; migrate to whitelist-based address model |
| V-03 Price manipulation | Use TWAP oracle; restrict large single-block swaps |
| V-04 Recipient registration | Apply minimum holding period + registration limits for redistribution recipient registration |

---

## 8. Lessons Learned

1. **EIP-7702 introduces a new attack vector**: Since the Ethereum Pectra upgrade, EOAs can temporarily execute contract code. The legacy pattern of blocking contracts solely via `msg.sender == tx.origin` is no longer safe. `msg.sender.code.length == 0` must also be checked.

2. **Reward redistribution mechanisms must enforce economic invariants**: In burn-based redistribution systems, the distribution ratio must be validated. Without a cap such as `total redistributed ≤ burned amount` or `total redistributed ≤ X% of circulating supply`, the entire Distributor can be drained in a single attack.

3. **Multi-hop flash loan attacks**: A 5-step chain of USDT → NOBEL → TR → TR burn → TR redistribution → TR → NOBEL → USDT was executed within a single transaction. Each step appears harmless in isolation, but the combination exposes the vulnerability.

4. **Access control on recipient registration**: The attacker was able to pre-register 0xce2aceab and 0xe2be550b as redistribution recipients. Redistribution recipient registration must be gated with minimum holding periods, staking requirements, governance approval, or similar controls.

5. **Concentration risk in small token ecosystems**: The NOBEL/USDT Pool_B had only ~779K USDT in liquidity, allowing 1.9M USDT to manipulate the price by 11.8x. Pools with shallow liquidity are far more susceptible to price manipulation.

---

## 9. Reference Information

| Contract | Address |
|---------|------|
| Turing (TR) Token | 0xe83EE4A30e97887e6b9745Be40E5F5Aa88888888 |
| NOBEL Token | 0x19EF250285B0F632bC17fafa67c7EfeCF0D3B864 |
| TR Distributor | 0x03d8096377ea7683d840e395d72439f7b6415abe |
| PCS Pool_A (NOBEL/TR) | 0xdb051a2a2a936b83c942aa40e74ff273b0f8c2e2 |
| PCS Pool_B (NOBEL/USDT) | 0x5743b2bc41c844c99de3a7f0e5da046224f6786e |
| Lista DAO Moolah | 0x8f73b65b4caaf64fba2AF91cc5D4a2a1318e5D8c |
| EIP-7702 Attack Code | 0x7b3928c1cef617810484589f400e8056dd2d772c |
| Attacker EOA | 0xC93A5Ab3737081F00788B61DA42281955d3dF692 |

- **Reference**: [EIP-7702 Specification](https://eips.ethereum.org/EIPS/eip-7702) — a new transaction type also activated on BSC