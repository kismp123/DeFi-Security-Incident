# Cork Protocol — Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-05-28 |
| **Protocol** | Cork Protocol |
| **Chain** | Ethereum |
| **Loss** | $11,979,183 (3,761.878 wstETH converted to 4,527 ETH) |
| **Attacker** | [0xEA6f...da98](https://etherscan.io/address/0xEA6f30e360192bae715599E15e2F765B49E4da98) |
| **Attack Contract** | [0x9Af3...bb09](https://etherscan.io/address/0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09) |
| **Attack Tx (Preparation)** | [0x14cd...ec0](https://etherscan.io/tx/0x14cdf1a643fc94a03140b7581239d1b7603122fbb74a80dd4704dfb336c1dec0) |
| **Attack Tx (Execution)** | [0xfd89...f64d](https://etherscan.io/tx/0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d) |
| **Vulnerable Contract (CorkHook)** | [0x5287...ea88](https://etherscan.io/address/0x5287e8915445aee78e10190559d8dd21e0e9ea88) |
| **Vulnerable Contract (Victim Market)** | [0xccd9...2a9](https://etherscan.io/address/0xccd90f6435dd78c4ecced1fa4db0d7242548a2a9) |
| **RouterState** | [0x55b9...fc3](https://etherscan.io/address/0x55b90b37416dc0bd936045a8110d1af3b6bf0fc3) |
| **Initial Funding** | 4.861 ETH from Swapuz.com |
| **Root Cause** | Insufficient access control in CorkHook.beforeSwap() + unauthorized market creation enabling unauthorized fund withdrawal |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

Cork Protocol is an on-chain derivatives protocol that provides hedging (insurance) mechanisms against depeg risk. Users can issue DS (Depeg Swap) and CT (Cover Token) pairs in liquidity markets and redeem them through the PSM (Peg Stability Module).

On May 28, 2025, the attacker chained two critical vulnerabilities to steal approximately $12M worth of 3,761 wstETH:

1. **Lack of access control in CorkHook.beforeSwap()**: The Uniswap V4 hook's `beforeSwap` function had no `onlyPoolManager` check, allowing the attacker to call it directly and arbitrarily.

2. **Abuse of unrestricted market creation**: The protocol allowed market creation with any arbitrary asset designated as the RA (Redemption Asset). The attacker created a fake market using DS tokens from an existing legitimate market as the RA, inducing token double-counting.

By chaining these two vulnerabilities, the attacker fraudulently minted 3,761 DS+CT derivative token pairs without depositing any real assets, then successfully redeemed them for wstETH from the legitimate market.

---

## 2. Vulnerable Code Analysis

### 2.1 CorkHook.beforeSwap() — Missing Access Control (Core Vulnerability)

**Vulnerable code (inferred)**:
```solidity
// ❌ Vulnerable: no onlyPoolManager modifier — anyone can call directly
function beforeSwap(
    address sender,
    PoolKey calldata key,
    IPoolManager.SwapParams calldata params,
    bytes calldata hookData  // ❌ no validation of hookData contents
) external override returns (bytes4, BeforeSwapDelta delta, uint24) {
    // Parses hookData to execute DS token transfer and minting logic
    // ❌ does not verify that msg.sender is the PoolManager
    _processHookData(hookData);
    return (BaseHook.beforeSwap.selector, delta, 0);
}
```

**Fixed code**:
```solidity
// ✅ Fixed: restricted to PoolManager calls only
modifier onlyPoolManager() {
    require(msg.sender == address(poolManager), "CorkHook: only pool manager allowed");
    _;
}

function beforeSwap(
    address sender,
    PoolKey calldata key,
    IPoolManager.SwapParams calldata params,
    bytes calldata hookData
) external override onlyPoolManager returns (bytes4, BeforeSwapDelta delta, uint24) {
    // ✅ executes only within a legitimate swap flow via PoolManager
    _processHookData(hookData);
    return (BaseHook.beforeSwap.selector, delta, 0);
}
```

**Issue**: Uniswap V4 hooks are intended to be called exclusively by the PoolManager within specific swap flows. However, the absence of an `onlyPoolManager` check allowed the attacker to trigger `beforeSwap()` directly with arbitrary hookData via the Pool Manager's `unlock()` → `unlockCallback()` path. This caused ModuleCore to incorrectly treat 3,761 weETH8DS-2 tokens as received without any actual DS token deposit.

---

### 2.2 Unrestricted Market Creation — DS Tokens Permitted as RA

**Vulnerable code (inferred)**:
```solidity
// CorkConfig contract
// ❌ Vulnerable: no token type validation on RA (Redemption Asset)
function createMarket(
    address ra,        // ❌ derivative tokens (DS, CT) are accepted as RA
    address pa,
    address exchangeRateProvider,
    // ... other parameters
) external returns (Id marketId) {
    // does not check whether ra address is an existing DS/CT token
    Id id = _createMarket(ra, pa, exchangeRateProvider, ...);
    return id;
}
```

**Fixed code**:
```solidity
// ✅ Fixed: validates that RA is not a derivative token
mapping(address => bool) private _isDerivativeToken;

function createMarket(
    address ra,
    address pa,
    address exchangeRateProvider,
    // ...
) external returns (Id marketId) {
    // ✅ RA must be a base asset and must not be a derivative token
    require(!_isDerivativeToken[ra], "CorkConfig: RA cannot be a derivative token");
    require(!_isDerivativeToken[pa], "CorkConfig: PA cannot be a derivative token");
    Id id = _createMarket(ra, pa, exchangeRateProvider, ...);
    // ✅ register newly issued DS/CT tokens in the derivative registry
    _isDerivativeToken[marketDsToken[id]] = true;
    _isDerivativeToken[marketCtToken[id]] = true;
    return id;
}
```

**Issue**: The attacker created a fake market (the wstETH5 market) by designating the `weETH8DS-2` token from a legitimate market as the RA. This structure created a **double-counting** condition where the DS token of one market was treated as the underlying asset of another market.

---

### 2.3 depositPsm() — Misinterpretation of RouterState Balance

**Vulnerable code (inferred)**:
```solidity
// PSM (Peg Stability Module)
// ❌ Vulnerable: tokens already present in RouterState contract are treated as user deposits
function depositPsm(Id id, uint256 amount) external returns (uint256 dsAmount, uint256 ctAmount) {
    // ❌ uses RouterState's current balance as deposit amount without verifying actual user transfer
    uint256 raBalance = IERC20(markets[id].ra).balanceOf(address(routerState));
    _mint(id, raBalance, msg.sender);  // ❌ treats entire routerState balance as a deposit
}
```

**Fixed code**:
```solidity
// ✅ Fixed: processes only the actually transferred amount
function depositPsm(Id id, uint256 amount) external returns (uint256 dsAmount, uint256 ctAmount) {
    // ✅ calculates actual deposit via pre/post balance difference (or uses safeTransferFrom)
    uint256 balanceBefore = IERC20(markets[id].ra).balanceOf(address(routerState));
    IERC20(markets[id].ra).safeTransferFrom(msg.sender, address(routerState), amount);
    uint256 balanceAfter = IERC20(markets[id].ra).balanceOf(address(routerState));
    uint256 actualDeposit = balanceAfter - balanceBefore;  // ✅ actual deposited amount
    _mint(id, actualDeposit, msg.sender);
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker sourced 4.861 ETH from Swapuz.com, deployed the attack contract, and in the preparation transaction purchased 3,760.88 weETH8CT-2 tokens using a small amount of wstETH in the legitimate wstETH:weETH market. (Exploiting risk premium distortion just before expiry, only 0.0000029 wstETH was required to acquire 3,760.88 CT tokens.)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Attacker EOA                                  │
│           0xEA6f30e360192bae715599E15e2F765B49E4da98                │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ 1) Request fake market creation
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       CorkConfig                                     │
│   createMarket(RA=weETH8DS-2, PA=wstETH,                           │
│                exchangeRateProvider=attacker contract)               │
│   ❌ No RA validation — DS token accepted as RA                     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ 2) Fake wstETH5 market created
                           │    (wstETH5DS-3, wstETH5CT-3 issued)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Uniswap V4 PoolManager                            │
│                     unlock(malicious calldata)                      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ 3) unlockCallback executed → attacker contract takes control
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                Attacker contract (unlockCallback)                    │
│           Direct call to CorkHook.beforeSwap()                      │
│           hookData = {market: fakeWstETH5Market, ...}               │
│   ❌ No onlyPoolManager check — anyone can call directly            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ 4) beforeSwap instructs ModuleCore to
                           │    transfer 3,761 weETH8DS-2
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        ModuleCore / PSM                             │
│       depositPsm() executed: RouterState balance misread as deposit │
│   ❌ 3,761 DS + 3,761 CT minted with no actual user deposit        │
│       → wstETH5DS-3, wstETH5CT-3 delivered to attacker            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ 5) Combine stolen derivative tokens + pre-acquired CT
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Combined: legitimate CT + forged DS               │
│      weETH8CT-2 (3,760.88) + weETH8DS-2 (3,761 — fraudulently minted) │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ 6) Call returnRaWithCtDs()
                           │    Redeem CT+DS in legitimate market
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Legitimate wstETH:weETH market vault              │
│              Withdraw 3,761 wstETH (actual user deposits)           │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ 7) Convert wstETH → ETH
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│           Attacker profit: 4,527 ETH (~$11,979,183)                 │
│           Attacker wallet currently holds 4,530.5955 ETH            │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit**: ~$11,979,183 (4,527 ETH)
- **Protocol loss**: 3,761.878 wstETH (entire legitimate user deposits drained)
- **Protocol response**: Smart contracts immediately paused upon attack detection

---

## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Incidents |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Missing access control in CorkHook.beforeSwap() | CRITICAL | CWE-284 | 03_access_control.md | Seneca Protocol (2024) |
| V-02 | Unrestricted market creation — DS token permitted as RA | CRITICAL | CWE-20 | 11_logic_error.md | PrismaFi (2024) |
| V-03 | depositPsm() RouterState balance misinterpretation | HIGH | CWE-682 | 16_accounting_sync.md | Gamma Strategies (2024) |
| V-04 | Unhandled risk premium extreme values near expiry | HIGH | CWE-682 | 05_integer_issues.md | — |

### V-01: Missing Access Control in CorkHook.beforeSwap()

- **Description**: The `beforeSwap()` function of the Uniswap V4 hook interface lacked an `onlyPoolManager` restriction, allowing the attacker to call it directly with arbitrary hookData via the Pool Manager's `unlock()` callback mechanism.
- **Impact**: Attacker caused ModuleCore to mint 3,761 DS derivative tokens without any actual asset transfer, draining all liquidity from the legitimate market.
- **Attack condition**: Only requires access to the Uniswap V4 Pool Manager's `unlock()` function. No special prior privileges required.

### V-02: Unrestricted Market Creation — DS Token Permitted as RA

- **Description**: `CorkConfig.createMarket()` did not validate whether the address designated as the RA (Redemption Asset) was an existing derivative token. The attacker created a fake market using a DS token from a legitimate market as the RA, establishing a double-counting condition where one market's derivative acted as the underlying asset of another market.
- **Impact**: Destruction of accounting integrity due to cross-market token conflation within the protocol.
- **Attack condition**: Anyone can create a market (permissionless market creation architecture).

### V-03: depositPsm() RouterState Balance Misinterpretation

- **Description**: The PSM's `depositPsm()` function incorrectly interpreted the RouterState contract's current balance as the user's actual deposit amount. After DS tokens were injected into RouterState via the `beforeSwap()` callback, the PSM treated them as a legitimate user deposit and minted CT+DS tokens.
- **Impact**: Minting of derivative tokens with no underlying asset backing.
- **Attack condition**: Requires V-01 and V-02 vulnerabilities as prerequisites.

### V-04: Unhandled Risk Premium Extreme Values Near Expiry

- **Description**: Just before market expiry, the risk premium calculation returned extreme values, creating an abnormal price ratio that allowed the purchase of 3,760.88 CT tokens for only 0.0000029 wstETH. The attacker exploited this to acquire a large number of CT tokens at near-zero cost during the preparation phase.
- **Impact**: Attack position established at minimal cost during the preparation phase.
- **Attack condition**: Exploiting the time window immediately before market expiry.

---

## 5. Remediation Recommendations

### Immediate Actions

**1) CorkHook — Apply onlyPoolManager**:
```solidity
// ✅ Add modifier to validate PoolManager address
modifier onlyPoolManager() {
    if (msg.sender != address(poolManager)) {
        revert CorkHook__CallerIsNotPoolManager();
    }
    _;
}

// ✅ Apply to all hook callbacks
function beforeSwap(
    address sender,
    PoolKey calldata key,
    IPoolManager.SwapParams calldata params,
    bytes calldata hookData
) external override onlyPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
    // ...
}
```

**2) CorkConfig — RA/PA Type Validation**:
```solidity
// ✅ Introduce derivative token registry
mapping(address => bool) public isDerivativeToken;

function createMarket(address ra, address pa, ...) external {
    // ✅ DS/CT tokens cannot be used as RA/PA
    require(!isDerivativeToken[ra], "RA cannot be a derivative token");
    require(!isDerivativeToken[pa], "PA cannot be a derivative token");
    // Register issued DS/CT in the registry after market creation
    isDerivativeToken[newDsToken] = true;
    isDerivativeToken[newCtToken] = true;
}
```

**3) depositPsm() — Validate Actual Transfer Amount**:
```solidity
// ✅ Calculate actual deposit via pre/post balance difference
function depositPsm(Id id, uint256 expectedAmount) external {
    uint256 before = IERC20(markets[id].ra).balanceOf(address(this));
    IERC20(markets[id].ra).safeTransferFrom(msg.sender, address(this), expectedAmount);
    uint256 actual = IERC20(markets[id].ra).balanceOf(address(this)) - before;
    require(actual >= expectedAmount, "Deposit amount mismatch");
    _mint(id, actual, msg.sender);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Hook access control | Correctly encode permission bits via CREATE2 address mining per Uniswap V4 hook standard; apply `onlyPoolManager` to all hook entry points |
| V-02 Unrestricted market creation | Introduce an RA whitelist system or block circular dependencies via a derivative token registry; only allow audited assets as RA |
| V-03 PSM balance misinterpretation | Apply CEI (Checks-Effects-Interactions) pattern; determine actual deposit via pre/post balance difference or safeTransferFrom return value |
| V-04 Risk premium extreme values | Apply a risk premium cap near expiry; add a circuit breaker to halt trading when extreme price ratios occur |
| General architecture | Strengthen cross-market token isolation in singleton architecture; manage state independently per market; include cross-market scenarios in integration tests |

---

## 6. Lessons Learned

1. **Uniswap V4 Hook Security**: V4 hooks must apply `onlyPoolManager` or equivalent access control to all callbacks. If a hook function can be called directly from outside, it can lead to arbitrary logic execution. When developing Uniswap V4 hooks, permission bit encoding via CREATE2 address mining should also be reviewed.

2. **Risks of Permissionless Market Creation**: Protocols that support fully permissionless market creation must strictly validate the permitted token types for RA/PA. If internal derivative tokens can be misused as underlying assets, cross-market accounting integrity is destroyed.

3. **Callback Data Validation**: All functions that process externally supplied calldata/hookData must strictly validate the data's origin and contents. Processing untrusted data as-is allows attackers to inject arbitrary markets or parameters.

4. **Pitfalls of Balance-Based Accounting**: The pattern of directly using a contract's current balance as a user deposit amount is dangerous. Contract balances can be manipulated via external callbacks or direct transfers, so processing must always be based on actual `transferFrom` or pre/post balance differences.

5. **Chained Composite Vulnerabilities**: Vulnerabilities that appear low-risk in isolation can become devastating when combined. In this incident, "anyone can create a market" combined with "no hook access control" resulted in $12M in losses. Threat modeling during protocol design must include combination scenarios of independently assessed vulnerabilities.

6. **Expiry-Time Edge Cases**: In time-constrained financial instruments, the period immediately before expiry is a high-risk window where extreme parameter values can emerge. Boundary value testing and circuit breaker mechanisms for price calculations, exchange rates, and risk indicators in this window must be incorporated.

---

## 7. On-Chain Verification

### 7.1 PoC vs. On-Chain Amount Comparison

| Item | On-chain Actual Value | Verified |
|------|-------------|------|
| Attacker initial funding | 4.861 ETH (Swapuz.com) | ✅ |
| Pre-acquired CT tokens | 3,760.88 weETH8CT-2 | ✅ |
| Fraudulently minted DS+CT | 3,761 wstETH5DS/CT-3 each | ✅ |
| wstETH redeemed from legitimate market | 3,761.878 wstETH | ✅ |
| Final converted ETH | 4,527 ETH | ✅ |
| Total loss | ~$11,979,183 | ✅ |

### 7.2 On-Chain Event Log Sequence

1. `Transfer`: Swapuz.com → Attacker EOA (4.861 ETH)
2. `Swap`: wstETH → weETH8CT-2 (legitimate market, 0.0000029 wstETH → 3,760.88 CT)
3. `unlock()` call: malicious calldata passed to Pool Manager
4. `beforeSwap()` direct call: crafted hookData to CorkHook
5. `Transfer`: RouterState → ModuleCore (3,761 weETH8DS-2)
6. `Mint`: 3,761 wstETH5DS-3 + wstETH5CT-3 minted (to attacker)
7. `returnRaWithCtDs()`: CT (3,760.88) + DS (3,761) burned
8. `Transfer`: ModuleCore → Attacker (3,761.878 wstETH)
9. `Swap`: wstETH → ETH (4,527 ETH)

### 7.3 Precondition Verification

| Condition | Status |
|------|------|
| Attacker contract deployed | Completed before attack Tx |
| Attacker contract designated as exchange rate provider | Completed at fake market creation |
| CT tokens pre-acquired | Completed in preparation Tx (0x14cd...) |
| Protocol paused | Executed immediately upon attack detection |

---

## References

- [Halborn — Cork Protocol Hack Analysis (May 2025)](https://www.halborn.com/blog/post/explained-the-cork-protocol-hack-may-2025)
- [SlowMist — Cork Protocol Exploit Analysis](https://slowmist.medium.com/exploit-analysis-cork-protocol-attacked-over-10-million-lost-75de9f229307)
- [CertiK — Cork Protocol Incident Analysis](https://www.certik.com/resources/blog/cork-protocol-incident-analysis)
- [Dedaub — The $11M Cork Protocol Hack: Uniswap V4 Hook Security](https://dedaub.com/blog/the-11m-cork-protocol-hack-a-critical-lesson-in-uniswap-v4-hook-security/)
- [QuillAudits — Cork Protocol Hack Explained](https://www.quillaudits.com/blog/hack-analysis/cork-protocol-hack-explained)
- [Verichains — Cork Protocol Exploit Analysis](https://blog.verichains.io/p/cork-protocol-exploit-analysis)
- [CoinDesk — Cork Protocol Suffers $12M Exploit](https://www.coindesk.com/business/2025/05/28/a16z-backed-cork-protocol-suffers-usd12m-smart-contract-exploit)
- [Cork Protocol Official Post-Mortem](https://www.cork.tech/blog/post-mortem)
- [DeFiHackLabs Repository](https://github.com/SunWeb3Sec/DeFiHackLabs)