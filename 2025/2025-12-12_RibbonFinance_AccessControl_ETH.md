# Ribbon Finance — Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-12-12 |
| **Protocol** | Ribbon Finance (Aevo) |
| **Chain** | Ethereum |
| **Loss** | $2,700,000 (~846 WETH + 178,000 USDC) |
| **Attacker (Mastermind)** | [0x4c0d...F397](https://etherscan.io/address/0x4c0dc529C4252e7Be0Db8D00592e04f878e4F397) |
| **Attacker (Executor)** | [0x4BFD...1aAb](https://etherscan.io/address/0x4BFD5C65082171DF83fd0fBBe54aa74909529b2c) |
| **Attack Tx (Oracle Hijacking)** | [0xb73e...0e1e](https://etherscan.io/tx/0xb73e45948f4aabd77ca888710d3685dd01f1c81d24361d4ea0e4b4899d490e1e) |
| **Attack Tx (Primary Drain)** | [0x16ed...687](https://etherscan.io/tx/0x16eded2553e0793472a6283093738152de1dd0e2504836856fbcaf88cc4a2687) |
| **Vulnerable Contract (Proxy Admin)** | [0x9D7b...B76](https://etherscan.io/address/0x9D7b3586f361e3621Bf4F099cBC9d155e8ae6B76) |
| **Victim Vault** | [0x3c21...10bE](https://etherscan.io/address/0x3c212A044760DE5a529B3Ba59363ddeCcc2210bE) |
| **Root Cause** | Insufficient access control on oracle proxy upgrade — anyone could call `transferOwnership` / `setImplementation` |
| **References** | [Rekt News](https://rekt.news/aevo-rekt) · [Halborn Analysis](https://www.halborn.com/blog/post/explained-the-aevo-ribbon-finance-hack-december-2025) |

---

## 1. Vulnerability Overview

While operating legacy Opyn-based DeFi Options Vaults (DOVs), Ribbon Finance (now Aevo) performed an oracle upgrade on December 6, 2025. The upgrade was designed to support 18-decimal precision for new assets, while legacy assets (e.g., USDC) still used 8 decimals.

The more critical issue was that **access control on the oracle proxy admin contract was completely removed**. After the upgrade, sensitive admin functions such as `transferOwnership` and `setImplementation` became **open to anyone**. The attacker exploited this to replace the oracle implementation with malicious code and inject arbitrary expiry prices to manipulate option settlements.

The two vulnerabilities acted in combination:
1. **Access Control Failure**: The `tx.origin`-based validation in the proxy admin was removed, allowing arbitrary calls
2. **Decimal Precision Mismatch**: The difference between 18-decimal and 8-decimal precision caused option settlement amounts to be abnormally inflated

---

## 2. Vulnerable Code Analysis

### 2.1 Oracle Proxy Admin — Complete Access Control Exposure (Core Vulnerability)

Prior to the upgrade, the oracle proxy admin performed `tx.origin`-based authorization checks. After the upgrade, this validation logic was removed (or made bypassable), resulting in the following state:

**Vulnerable Code (inferred — post-upgrade state)**:
```solidity
contract OracleProxyAdmin {
    address public implementation;
    address public owner;

    // ❌ Access control completely missing — anyone can replace the implementation
    function setImplementation(address _newImpl) external {
        // No onlyOwner or msg.sender validation
        implementation = _newImpl;
    }

    // ❌ Ownership transfer also unrestricted
    function transferOwnership(address _newOwner) external {
        // No require(msg.sender == owner, "Not owner")
        owner = _newOwner;
    }

    // ❌ tx.origin-based validation (bypassable)
    function setExpiryPrice(address _asset, uint256 _expiry, uint256 _price) external {
        require(tx.origin == authorizedDispatcher, "Unauthorized"); // tx.origin is bypassed when called via contract
        // Price setting logic...
    }
}
```

**Fixed Code**:
```solidity
contract OracleProxyAdmin {
    address public implementation;
    address public owner;

    // ✅ msg.sender-based owner validation
    modifier onlyOwner() {
        require(msg.sender == owner, "OracleProxyAdmin: caller is not owner");
        _;
    }

    // ✅ Only owner can replace implementation
    function setImplementation(address _newImpl) external onlyOwner {
        require(_newImpl != address(0), "OracleProxyAdmin: zero address");
        emit ImplementationUpgraded(implementation, _newImpl);
        implementation = _newImpl;
    }

    // ✅ Only owner can transfer ownership
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "OracleProxyAdmin: zero address");
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }

    // ✅ msg.sender validation + whitelist instead of tx.origin
    function setExpiryPrice(address _asset, uint256 _expiry, uint256 _price) external {
        require(authorizedDispatchers[msg.sender], "OracleProxyAdmin: unauthorized dispatcher");
        // Price setting logic...
    }
}
```

**Issue**: During the oracle upgrade, the proxy admin's authorization logic was removed, making `setImplementation` and `transferOwnership` completely public. An attacker could replace the oracle implementation with a malicious contract and set arbitrary expiry prices in a single transaction.

### 2.2 Decimal Precision Mismatch — Expiry Price Inflation

```solidity
// ❌ Vulnerable code: price stored without precision validation
function setExpiryPrice(address _asset, uint256 _expiry, uint256 _price) external {
    // Price submitted with 18-decimal precision misinterpreted as 8-decimal
    // e.g., USDC strike 3,800 → actually 38,000,000,000 (10x inflation)
    expiryPrice[_asset][_expiry] = _price;
    emit ExpiryPriceUpdated(_asset, _expiry, _price, block.timestamp);
}

// ❌ Vulnerable settlement calculation
function getPayoutForOption(
    address _collateral,   // WETH (18 decimals)
    address _strike,       // USDC (8 decimals)
    uint256 _strikePrice,
    uint256 _expiryPrice
) internal view returns (uint256 payout) {
    // Direct division without precision normalization — unit mismatch occurs
    payout = (_expiryPrice - _strikePrice) * COLLATERAL_AMOUNT / _strikePrice;
}
```

**Fixed Code**:
```solidity
// ✅ Explicitly normalize precision per asset
function getPayoutForOption(
    address _collateral,
    address _strike,
    uint256 _strikePrice,
    uint256 _expiryPrice
) internal view returns (uint256 payout) {
    uint8 collateralDecimals = IERC20Metadata(_collateral).decimals();
    uint8 strikeDecimals = IERC20Metadata(_strike).decimals();

    // ✅ Normalize to 18 decimals before calculation
    uint256 normalizedStrike = _strikePrice * (10 ** (18 - strikeDecimals));
    uint256 normalizedExpiry = _expiryPrice * (10 ** (18 - strikeDecimals));
    uint256 normalizedCollateral = COLLATERAL_AMOUNT * (10 ** (18 - collateralDecimals));

    if (normalizedExpiry <= normalizedStrike) return 0;
    payout = (normalizedExpiry - normalizedStrike) * normalizedCollateral / normalizedExpiry;
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase (D-6 ~ D-1)

- **2025-12-06**: Aevo deploys oracle upgrade → proxy admin access control unintentionally removed
- Attacker discovers vulnerability and builds attack infrastructure:
  - Mastermind distributes funds across 5 role-specific wallets
  - "Fall Guy" wallet creates normal transaction history to avoid detection
  - "Engineer" wallet deploys malicious oracle implementation
  - "Frankenstein" wallet creates counterfeit options products

### 3.2 Execution Phase (2025-12-12)

```
┌──────────────────────────────────────────────────────────────────┐
│                     Attacker Wallet Infrastructure               │
│  Mastermind(0x4c0d)  →  Executor(0x4BFD) + Engineer(0x9c61)     │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  [Phase 1] Oracle Proxy Hijacking                                │
│                                                                  │
│  Tx: 0xb73e...0e1e                                               │
│  Engineer → ProxyAdmin(0x9D7b).setImplementation(malicious)     │
│  → No access control → Immediately succeeds                      │
│  → Malicious oracle implementation (0xE1f0) installed            │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  [Phase 2] Arbitrary Expiry Price Injection                      │
│                                                                  │
│  Malicious oracle → setExpiryPrice(wstETH, expiry, extreme)      │
│  Malicious oracle → setExpiryPrice(AAVE,   expiry, near +∞)     │
│  Malicious oracle → setExpiryPrice(LINK,   expiry, extreme)      │
│  → ExpiryPriceUpdated event emitted → System accepts as valid    │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  [Phase 3] Frankenstein oToken Settlement                        │
│                                                                  │
│  Executor (Bagman) → Burns 225 oTokens                           │
│  → Settlement based on forged expiry prices                      │
│  → Settlement amount abnormally inflated by decimal mismatch     │
│  → 22.46 WETH extracted per transaction                          │
│  → Repeated execution fully drains vault                         │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  [Phase 4] Oracle Restoration (Evidence Concealment)            │
│                                                                  │
│  Legitimate oracle implementation reinstalled after attack       │
│  → Attempts to minimize on-chain traces                          │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  [Phase 5] Money Laundering                                      │
│                                                                  │
│  Distributor(0x354a) → Splits across 15 wallets                  │
│  → Batches of 100.1 ETH (split as 99 + 1 + 0.1 ETH)            │
│  → Funds moved toward Tornado Cash                               │
└──────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Field | Value |
|------|------|
| ETH Stolen | ~846 WETH |
| Stablecoin Stolen | ~178,000 USDC |
| Total Loss (USD) | ~$2,700,000 |
| Vault Loss Rate | ~32% |
| DAO Voluntary Compensation | ~$400,000 (net loss after compensation: $2,300,000) |
| Time to Detection | 19 hours until public acknowledgment |

---

## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Oracle proxy admin access control completely missing | CRITICAL | CWE-284 | 03_access_control.md (Pattern 1) |
| V-02 | `tx.origin`-based authorization — bypassable via contract | HIGH | CWE-287 | 03_access_control.md (Pattern 4) |
| V-03 | Decimal precision mismatch — expiry price inflation | HIGH | CWE-682 | 05_integer_issues.md |
| V-04 | Missing input validation on oracle expiry price | HIGH | CWE-20 | 04_oracle_manipulation.md |

### V-01: Oracle Proxy Admin Access Control Completely Missing

- **Description**: After the December 6 oracle upgrade, caller validation logic such as `onlyOwner` was removed from the `setImplementation` and `transferOwnership` functions of the proxy admin contract. Any EOA or contract could replace the oracle implementation without restriction.
- **Impact**: Attacker could replace the oracle with a malicious implementation under their control and inject arbitrary expiry prices for any asset, gaining complete control over the protocol's entire option settlement logic.
- **Attack Condition**: Knowing only the address of the proxy admin contract with missing access control (publicly available on-chain data).

### V-02: `tx.origin`-Based Authorization

- **Description**: Some legacy oracle code validated the caller using `tx.origin` instead of `msg.sender`. Since `tx.origin` returns the original EOA even when called through an intermediate contract, whitelist checks can be bypassed via a proxy contract.
- **Impact**: Attacker could deploy a contract that routes through a whitelisted address, neutralizing the authorization check.
- **Attack Condition**: Scenarios where a whitelisted EOA does not call the contract directly.

### V-03: Decimal Precision Mismatch

- **Description**: After the oracle upgrade, new assets use 18-decimal precision while legacy assets such as USDC continue using 8 decimals. Settlement calculations performed without normalizing precision result in values inflated by up to 10^10x.
- **Impact**: A USDC strike of 3,800 on a stETH call option causes settlement amounts to be abnormally inflated, allowing 22.46 WETH to be extracted per vault.
- **Attack Condition**: Option products combining 18-decimal collateral (WETH/wstETH) with 8-decimal strike (USDC).

### V-04: Missing Input Validation on Oracle Expiry Price

- **Description**: The `setExpiryPrice` function lacks sanity checks (range validation, deviation limits, etc.) on submitted price values, allowing extreme values to be stored as-is.
- **Impact**: AAVE price set to effectively infinity, maximizing settlement value for options on that asset.
- **Attack Condition**: Requires price-setting authority (obtained by exploiting V-01).

---

## 5. Remediation Recommendations

### Immediate Actions

**1) Apply standard OpenZeppelin `Ownable` pattern to proxy admin**

```solidity
import "@openzeppelin/contracts/access/Ownable.sol";

// ✅ Inherit OpenZeppelin Ownable — msg.sender-based validation
contract OracleProxyAdmin is Ownable {

    function setImplementation(address _newImpl) external onlyOwner {
        require(_newImpl != address(0), "Zero address");
        emit ImplementationUpgraded(implementation, _newImpl);
        implementation = _newImpl;
    }

    function transferOwnership(address _newOwner) public override onlyOwner {
        require(_newOwner != address(0), "Zero address");
        super.transferOwnership(_newOwner);
    }
}
```

**2) Completely remove `tx.origin` — replace with `msg.sender` + whitelist**

```solidity
mapping(address => bool) public authorizedDispatchers;

modifier onlyDispatcher() {
    // ✅ No tx.origin — msg.sender-based validation
    require(authorizedDispatchers[msg.sender], "Not authorized dispatcher");
    _;
}

function setExpiryPrice(
    address _asset,
    uint256 _expiry,
    uint256 _price
) external onlyDispatcher {
    _validatePriceRange(_asset, _price); // Price range validation
    expiryPrice[_asset][_expiry] = _price;
    emit ExpiryPriceUpdated(_asset, _expiry, _price, block.timestamp);
}
```

**3) Add expiry price sanity validation**

```solidity
uint256 public constant MAX_PRICE_DEVIATION = 5000; // 50% max deviation (basis points)

function _validatePriceRange(address _asset, uint256 _price) internal view {
    // ✅ Compare against Chainlink reference to reject anomalous prices
    (, int256 refPrice,,,) = chainlinkFeeds[_asset].latestRoundData();
    uint256 refPriceUint = uint256(refPrice);
    uint256 deviation = _price > refPriceUint
        ? ((_price - refPriceUint) * 10000) / refPriceUint
        : ((refPriceUint - _price) * 10000) / refPriceUint;
    require(deviation <= MAX_PRICE_DEVIATION, "Price deviation too high");
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Missing access control | Mandate `onlyOwner` + 2-of-N multisig on all upgrade functions |
| V-02: `tx.origin` usage | Remove all `tx.origin` from codebase, replace with `msg.sender` whitelist |
| V-03: Precision mismatch | Standardize 18-decimal normalization before all price calculations; enforce with unit tests |
| V-04: Missing input validation | Apply Chainlink TWAP-based price deviation limits + timelock |
| Upgrade process | Require independent security audit + staging environment validation before deploying changes |
| Legacy contract management | Conduct regular audits of interaction points between legacy vaults and new infrastructure |

---

## 6. Lessons Learned

1. **Upgrades == Re-audit**: Smart contract upgrades can invalidate existing security assumptions. Even seemingly minor changes — like an oracle precision upgrade — can inadvertently remove access control logic or introduce precision mismatches. **Every upgrade must be treated as a full re-audit target.**

2. **Never use `tx.origin`**: `tx.origin` returns the original EOA in a call chain, which means any intermediate contract can neutralize intended caller validation. Always use `msg.sender` for authorization, and adopt OpenZeppelin `Ownable` or `AccessControl` as standard.

3. **Normalize decimal precision explicitly**: When a DeFi protocol supports multiple tokens (ERC-20), each token's `decimals()` value may differ. Always normalize to a single base (18 decimals) before price calculations or amount comparisons, and validate this with unit tests.

4. **Legacy + new system integration points are vulnerability hotspots**: After Ribbon Finance rebranded to Aevo, legacy vaults were retained, creating interface mismatches between old and new systems. Interaction points between legacy contracts and new infrastructure require especially focused auditing.

5. **Always validate oracle price inputs against bounds**: When an on-chain oracle accepts external data, the absence of reference price deviation limits, timelocks, and multi-signature requirements creates a single point of failure that can expose the entire protocol.

6. **Incident response speed determines the scale of damage**: Despite real-time detection by security researchers, it took 19 hours for Aevo to publicly acknowledge the incident. Automated on-chain monitoring and a rapid emergency pause mechanism would have significantly limited the losses.

---

## References

- [Rekt News — Aevo Rekt](https://rekt.news/aevo-rekt)
- [Halborn — Explained: The Aevo/Ribbon Finance Hack (December 2025)](https://www.halborn.com/blog/post/explained-the-aevo-ribbon-finance-hack-december-2025)
- [The Block — Aevo's legacy Ribbon DOV vaults exploited](https://www.theblock.co/post/382461/aevos-legacy-ribbon-dov-vaults-exploited-for-2-7-million-following-oracle-upgrade)
- [Web3 is Going Great](https://www.web3isgoinggreat.com/?id=ribbon-finance-exploit)
- [CoinMarketCap — Aevo's Ribbon Vaults Lose $2.7M](https://coinmarketcap.com/academy/article/aevos-ribbon-vaults-lose-dollar27m-in-oracle-exploit)