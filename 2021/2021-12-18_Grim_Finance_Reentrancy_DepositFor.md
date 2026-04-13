# Grim Finance — depositFor() Reentrancy Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-12-18 |
| **Protocol** | Grim Finance (GrimBoostVault) |
| **Chain** | Fantom |
| **Loss** | ~$30,000,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | GrimBoostVault (`depositFor()` function) |
| **Root Cause** | `depositFor()` is reenterable when calling `transferFrom()` on an external token — 7 nested reentrant calls via a malicious token contract |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-12/Grim_exp.sol) |

---
## 1. Vulnerability Overview

Grim Finance's GrimBoostVault allowed external addresses to deposit tokens on behalf of a specific user via `depositFor(token, amount, user)`. When `token.transferFrom()` was called inside this function, the custom `transferFrom()` of a malicious token contract executed, triggering reentrancy. The attacker borrowed 937,830 WFTM via a BeethovenX flash loan, created SpiritSwap LP tokens, then used a malicious token to reenter `depositFor()` 7 times in a nested fashion, inflating the vault's total supply and extracting illegitimate profit.

---
## 2. Vulnerable Code Analysis

### 2.1 depositFor() — Reentrancy Allowed During transferFrom() Call

```solidity
// ❌ GrimBoostVault
// depositFor() accepts an arbitrary token address and calls transferFrom()
// Reentrancy possible via the malicious token's transferFrom() hook
function depositFor(address token, uint256 _amount, address user) public {
    // ❌ No nonReentrant guard
    // ❌ No token address validation

    uint256 _pool = balance(); // Already inflated value on reentry

    // Malicious token's transferFrom() executes → triggers reentrancy
    IERC20(token).transferFrom(msg.sender, address(this), _amount);

    uint256 _after = balance();
    _amount = _after.sub(_pool); // Calculate actual amount received

    uint256 shares;
    if (totalSupply() == 0) {
        shares = _amount;
    } else {
        // totalSupply can be manipulated via reentrancy
        shares = (_amount.mul(totalSupply())).div(_pool);
    }
    _mint(user, shares);
}
```

**Fixed Code**:
```solidity
// ✅ nonReentrant + only whitelisted tokens allowed
modifier nonReentrant() {
    require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
    _status = _ENTERED;
    _;
    _status = _NOT_ENTERED;
}

function depositFor(address token, uint256 _amount, address user)
    public nonReentrant
{
    // ✅ Only whitelisted tokens allowed
    require(token == want, "GrimBoostVault: invalid token");

    uint256 _pool = balance();
    IERC20(token).safeTransferFrom(msg.sender, address(this), _amount);
    uint256 _after = balance();
    _amount = _after.sub(_pool);

    uint256 shares = totalSupply() == 0
        ? _amount
        : (_amount.mul(totalSupply())).div(_pool);
    _mint(user, shares);
}
```


### On-Chain Original Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — only bytecode exists or source is unverified

**Vulnerable Function** — `vulnerableFunction()`:
```solidity
// ❌ Root cause: depositFor() is reenterable when calling transferFrom() on an external token — 7 nested reentrant calls via a malicious token contract
// Source code unconfirmed — bytecode analysis required
// Vulnerability: depositFor() is reenterable when calling transferFrom() on an external token — 7 nested reentrant calls via a malicious token contract
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────┐
│ Step 1: BeethovenX flash loan 937,830 WFTM + 30 BTC     │
│ IBeethovenxVault.flashLoan(tokens, amounts, this, data)  │
└─────────────────────┬────────────────────────────────────┘
                      │ receiveFlashLoan() callback
┌─────────────────────▼────────────────────────────────────┐
│ Step 2: Add liquidity to SpiritSwap → obtain LP tokens   │
│ ISpiritRouter.addLiquidity(WFTM, BTC, ...)               │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 3: GrimBoostVault.depositFor(maliciousToken, ...)   │
│ maliciousToken.transferFrom() → triggers reentrancy      │
└─────────────────────┬────────────────────────────────────┘
                      │ transferFrom() reentrance (7 times)
┌─────────────────────▼────────────────────────────────────┐
│ Step 4: 7 nested reentrant calls — manipulate vault      │
│ totalSupply; replace with real LP token address on final │
│ call; mint excess shares based on inflated totalSupply   │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 5: Withdraw vault assets with excess shares +       │
│ repay flash loan; steal ~$30M WFTM + BTC                 │
└──────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
uint8 public reentrancyCount = 0;

// Reenters via the transferFrom() hook inside GrimBoostVault.depositFor()
function transferFrom(address from, address to, uint256 amount) external returns (bool) {
    // Reenter 7 times
    if (reentrancyCount < 7) {
        reentrancyCount++;
        // Reenter: call depositFor with progressively different parameters
        grimBoostVault.depositFor(address(this), amount, address(this));
    } else {
        // Final call: swap in the real LP token
        grimBoostVault.depositFor(address(lpToken), lpAmount, address(this));
    }
    return true;
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Arbitrary token `transferFrom()` call in `depositFor()` — reentrancy allowed | CRITICAL | CWE-841 |
| V-02 | Arbitrary token accepted without token address validation | CRITICAL | CWE-284 |

---
## 6. Remediation Recommendations

```solidity
// ✅ nonReentrant mandatory + only want token allowed
// ✅ Apply CEI pattern

function depositFor(address token, uint256 _amount, address user)
    public nonReentrant
{
    require(token == want, "GrimBoostVault: only want token");

    // Effect: calculate shares first
    uint256 _pool = balance();
    uint256 shares = totalSupply() == 0
        ? _amount
        : (_amount.mul(totalSupply())).div(_pool);
    _mint(user, shares); // Effect

    // Interaction: transfer last
    IERC20(token).safeTransferFrom(msg.sender, address(this), _amount);
}
```

---
## 7. Lessons Learned

- **Functions that accept a token address as a parameter — like `depositFor(address token, ...)` — are a perfect reentrancy entry point.** Allowed tokens must always be validated against a whitelist.
- **The same vulnerability pattern was repeated in the Fantom ecosystem.** Identical code patterns are deployed across chain ecosystems, and those patterns are exploited in identical ways.
- **The fact that 7 nested reentrant calls were possible means there was absolutely no `nonReentrant` guard in place.** DeFi vaults must never be deployed without at minimum basic reentrancy protection.