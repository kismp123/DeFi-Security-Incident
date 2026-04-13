# Ronin Bridge — Misconfiguration Vulnerability Analysis (2024)

| Field | Details |
|------|------|
| **Date** | 2024-08-06 |
| **Protocol** | Ronin Bridge (MainchainGatewayV3) |
| **Chain** | Ethereum |
| **Loss** | ~$11,810,813 (3,996 ETH + 1,998,046 USDC) |
| **Attacker (MEV Bot 1)** | [0x4ab1...c0b](https://etherscan.io/address/0x4ab12e7ce31857ee022f273e8580f73335a73c0b) |
| **Attacker (MEV Bot 2)** | [0x6980...DD0](https://etherscan.io/address/0x6980a47beE930a4584B09Ee79eBe46484FbDBDD0) |
| **Attack Tx (ETH)** | [0x2619...cb](https://etherscan.io/tx/0x2619570088683e6cc3a38d93c3d98899e5783864e15525d5f5810c11189ba6cb) |
| **Attack Tx (USDC)** | [0xbce5...8](https://etherscan.io/tx/0xbce5b8548db486c561948e8a177c8ccaa72810f972cee3909ea50af015a60ad8) |
| **Vulnerable Contract (Proxy)** | [0x6419...f08](https://etherscan.io/address/0x64192819ac13ef72bf6b5ae239ac672b43a9af08) |
| **Implementation Contract** | [0xfc27...ee](https://etherscan.io/address/0xfc274ec92bbb1a1472884558d1b5caac6f8220ee) |
| **Root Cause** | `initializeV3` not called during bridge contract upgrade → `_totalOperatorWeight = 0` → `minimumVoteWeight = 0` → signature verification bypassed |

---

## 1. Vulnerability Overview

On August 6, 2024, Ronin Bridge (the Axie Infinity cross-chain bridge) suffered approximately $11.81M in losses due to an initialization error that occurred during a smart contract upgrade.

During the upgrade transaction, only `initializeV4` was executed and `initializeV3` was not called, leaving the total validator weight (`_totalOperatorWeight`) at `0`. As a result, the minimum vote weight required for withdrawal approval (`minimumVoteWeight`) was calculated as `0`, creating a state where **any signature — even an invalid one — would pass verification**.

MEV bots detected this vulnerability first, front-ran the original attack attempt in the mempool, drained the funds, and then returned everything as white-hats in exchange for a $500,000 bounty.

**Key Vulnerability Summary**

| # | Vulnerability | Severity |
|---|--------|--------|
| V-01 | Missing upgrade initialization function (`initializeV3` not called) | CRITICAL |
| V-02 | `minimumVoteWeight()` returns 0 when `_totalOperatorWeight = 0` | CRITICAL |
| V-03 | Signature verification logic allows `minimumWeight = 0` condition | HIGH |

---

## 2. Vulnerable Code Analysis

### 2.1 Missing Initialization Function (Core Vulnerability)

**Vulnerable upgrade call (the missing part in the actual upgrade Tx)**:

```solidity
// ❌ Vulnerable state: initializeV3 was never called
// Only initializeV4 was executed in the upgrade transaction

function initializeV3() external reinitializer(3) {
    // This function should have been called — syncs validator weights from BridgeManager
    IBridgeManager mainchainBridgeManager = IBridgeManager(getContract(ContractType.BRIDGE_MANAGER));
    (, address[] memory operators, uint96[] memory weights) = mainchainBridgeManager.getFullBridgeOperatorInfos();

    uint96 totalWeight;
    for (uint i; i < operators.length; i++) {
        _operatorWeight[operators[i]] = weights[i];
        totalWeight += weights[i];
    }
    _totalOperatorWeight = totalWeight; // ← This value should have been initialized
}

function initializeV4(address payable wethUnwrapper_) external reinitializer(4) {
    wethUnwrapper = WethUnwrapper(wethUnwrapper_); // ✅ Only this function was executed
    // ❌ _totalOperatorWeight remains 0
}
```

**Problem**: `reinitializer(3)` and `reinitializer(4)` are independent initialization steps. The upgrade transaction author included only V4 and omitted V3. Solidity's uninitialized `uint96` defaults to `0`, so `_totalOperatorWeight` remained `0`.

---

### 2.2 `_totalOperatorWeight` State Variable

```solidity
// MainchainGatewayV3.sol

uint96 private _totalOperatorWeight; // ❌ Remains 0 because initializeV3 was not called
mapping(address operator => uint96 weight) private _operatorWeight; // ❌ All remain 0
```

---

### 2.3 `minimumVoteWeight()` Calculation — Returns 0

```solidity
// GatewayV3.sol

function minimumVoteWeight() public view virtual returns (uint256) {
    return _minimumVoteWeight(_getTotalWeight());
    // ❌ _getTotalWeight() returns 0, so the result is also 0
}

function _minimumVoteWeight(uint256 _totalWeight) internal view virtual returns (uint256) {
    return (_num * _totalWeight + _denom - 1) / _denom;
    // ❌ When _totalWeight = 0: (num * 0 + denom - 1) / denom = 0
    //    → minimumWeight = 0
}
```

```solidity
// MainchainGatewayV3.sol

function _getTotalWeight() internal view override returns (uint256) {
    return _totalOperatorWeight; // ❌ Returns 0
}
```

---

### 2.4 Withdrawal Signature Verification — Bypassable

```solidity
// MainchainGatewayV3.sol

function _submitWithdrawal(Transfer.Receipt calldata receipt, Signature[] memory signatures)
    internal virtual returns (bool locked)
{
    // ... validates recipient, chain ID, token mapping ...

    uint256 minimumWeight;
    (minimumWeight, locked) = _computeMinVoteWeight(receipt.info.erc, tokenAddr, quantity);
    // ❌ minimumWeight = 0 is returned

    {
        bool passed;
        address signer;
        address lastSigner;
        Signature memory sig;
        uint256 weight;
        for (uint256 i; i < signatures.length; i++) {
            sig = signatures[i];
            signer = ecrecover(receiptDigest, sig.v, sig.r, sig.s);
            if (lastSigner >= signer) revert ErrInvalidOrder(msg.sig);
            lastSigner = signer;

            weight += _getWeight(signer);
            if (weight >= minimumWeight) { // ❌ 0 >= 0 → passes immediately!
                passed = true;
                break;
            }
        }

        if (!passed) revert ErrQueryForInsufficientVoteWeight();
        // ❌ weight=0, minimumWeight=0 so even a single signature passes
        withdrawalHash[id] = receiptHash;
    }
    // → Funds withdrawn via handleAssetOut()
}
```

```solidity
function _computeMinVoteWeight(TokenStandard _erc, address _token, uint256 _quantity)
    internal virtual returns (uint256 _weight, bool _locked)
{
    uint256 _totalWeight = _getTotalWeight(); // ❌ Returns 0
    _weight = _minimumVoteWeight(_totalWeight); // ❌ Returns 0
    if (_erc == TokenStandard.ERC20) {
        if (highTierThreshold[_token] <= _quantity) {
            _weight = _highTierVoteWeight(_totalWeight); // ❌ Also returns 0
        }
        _locked = _lockedWithdrawalRequest(_token, _quantity);
    }
}
```

**Patched code (correct upgrade procedure)**:

```solidity
// ✅ Correct upgrade: call initializeV3 first, then initializeV4

function initializeV3() external reinitializer(3) {
    // ✅ Sync validator info from BridgeManager
    IBridgeManager mainchainBridgeManager = IBridgeManager(getContract(ContractType.BRIDGE_MANAGER));
    (, address[] memory operators, uint96[] memory weights) = mainchainBridgeManager.getFullBridgeOperatorInfos();

    uint96 totalWeight;
    for (uint i; i < operators.length; i++) {
        _operatorWeight[operators[i]] = weights[i];
        totalWeight += weights[i];
    }
    _totalOperatorWeight = totalWeight; // ✅ Proper weight set (e.g., ~10,000)
}

// ✅ Both functions must be called in order in the upgrade deployment script
// 1. proxy.upgradeToAndCall(impl, abi.encodeCall(initializeV3, ()))
// 2. proxy.upgradeToAndCall(impl, abi.encodeCall(initializeV4, (wethUnwrapper)))
// Or executed atomically in a single multicall
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- 2024-08-06 08:48:47 UTC: Ronin team upgrades `MainchainGatewayV3` implementation to V4
- Only `initializeV4` is executed in the upgrade transaction; `initializeV3` is not called
- Bridge goes live with `_totalOperatorWeight = 0`
- MEV bot detects the vulnerability by monitoring the mempool or on-chain state

### 3.2 Execution Phase

```
 [Attack initiated — 09:37:23 UTC]
 
 ┌─────────────────────────────────────────┐
 │   MEV Bot (0x4ab1...c0b)               │
 │   Detects attacker's original Tx in    │
 │   the mempool                          │
 │   → Executes front-run                 │
 └──────────────┬──────────────────────────┘
                │  calls submitWithdrawal()
                │  (withdrawal receipt with arbitrary signatures)
                ▼
 ┌─────────────────────────────────────────────────────────┐
 │   MainchainGatewayV3 (0x6419...f08)                    │
 │                                                         │
 │   _computeMinVoteWeight()                               │
 │     └─ _getTotalWeight() → 0   ← ❌ Uninitialized       │
 │     └─ _minimumVoteWeight(0) → 0  ← ❌ Verification     │
 │                                        bypassed         │
 │                                                         │
 │   Signature loop:                                       │
 │     weight = _getWeight(arbitrary signer) → 0          │
 │     if (0 >= 0) passed = true  ← ❌ Passes immediately! │
 │                                                         │
 │   withdrawalHash[id] = receiptHash  ← Withdrawal logged │
 └──────────────┬──────────────────────────────────────────┘
                │  handleAssetOut() executed
                ▼
 ┌──────────────────────────────────┐
 │   Ronin Bridge Vault             │
 │   ETH: 3,996 ETH               │
 │   USDC: 1,998,046 USDC         │
 └──────────┬───────────────────────┘
            │  Funds transferred
            ▼
 ┌──────────────────────────────────────────┐
 │   MEV Bot Wallet                         │
 │   (0x4ab1...c0b / 0x6980...DD0)         │
 │   Receives ~$11.8M                      │
 └──────────────────────────────────────────┘
            │  Subsequently returned as white-hat
            ▼
 ┌───────────────────────────────────────┐
 │   Ronin Team receives funds           │
 │   Bounty paid: $500,000              │
 └───────────────────────────────────────┘

 [Bridge paused — 10:15:23 UTC, ~38 minutes after attack]
```

### 3.3 Attack Timeline

| Time (UTC) | Event |
|-----------|------|
| 08:48:47 | Ronin team upgrades MainchainGatewayV3 to V4 |
| ~09:37:23 | MEV bot withdraws 3,996 ETH (~$9.8M) |
| ~09:xx:xx | MEV bot withdraws 1,998,046 USDC (~$2M) |
| 10:15:23 | Bridge paused |
| After | White-hat returns full amount; $500K bounty paid |

### 3.4 Outcome

- **Funds drained**: 3,996 ETH (~$9.8M) + 1,998,046 USDC (~$2M) = ~$11.8M
- **Returned**: Full amount returned (white-hat action)
- **Bounty**: $500,000

---

## 4. PoC Code (Conceptual Reproduction)

No separate PoC file exists in DeFiHackLabs, but the core attack logic is as follows.

```solidity
// Conceptual reproduction — Ronin Bridge initializeV3 missing vulnerability
// Actual attack was executed by MEV bot after detecting in mempool

interface IMainchainGatewayV3 {
    // Withdrawal submission function — validates signatures and withdraws assets
    function submitWithdrawal(
        Transfer.Receipt calldata receipt,
        Signature[] calldata signatures
    ) external returns (bool locked);
}

contract RoninExploit {
    IMainchainGatewayV3 constant BRIDGE = IMainchainGatewayV3(
        0x64192819ac13ef72bf6b5ae239ac672b43a9af08 // Ronin Bridge V2 proxy
    );

    function exploit() external {
        // ① Verify vulnerable state: minimumVoteWeight() == 0
        //   → _totalOperatorWeight is 0, so calculation result is 0
        // uint256 minWeight = BRIDGE.minimumVoteWeight();
        // require(minWeight == 0, "Not yet vulnerable");

        // ② Construct an arbitrary withdrawal receipt
        //    Set chain ID, token address, quantity, and recipient
        Transfer.Receipt memory receipt = _buildWithdrawalReceipt(
            ETH_ADDRESS,           // Withdrawal token: ETH
            DAILY_LIMIT_AMOUNT,    // Max daily limit (per single Tx cap)
            address(this)          // Recipient: attacker contract
        );

        // ③ Generate a single arbitrary signature (even invalid signatures pass)
        //    minimumWeight = 0, so weight(0) >= 0 is satisfied immediately
        Signature[] memory sigs = _buildDummySignature();

        // ④ Call submitWithdrawal → passes signature verification → handleAssetOut executes
        BRIDGE.submitWithdrawal(receipt, sigs);
        // → ETH or USDC transferred to address(this)
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing upgrade initialization function | CRITICAL | CWE-665: Improper Initialization |
| V-02 | Zero vote weight due to uninitialized state variable | CRITICAL | CWE-909: Missing Initialization |
| V-03 | Signature verification allows `minimumWeight = 0` condition | HIGH | CWE-285: Improper Authorization |
| V-04 | Lack of review for upgrade deployment script | MEDIUM | CWE-1068: Inconsistency Between Specification and Implementation |

### V-01: Missing Upgrade Initialization Function

- **Description**: The `TransparentUpgradeableProxy` pattern required two initialization steps — `initializeV3` and `initializeV4` — when deploying the new implementation, but the deployment script only called `initializeV4`.
- **Impact**: `_totalOperatorWeight` remained `0`, completely disabling the bridge's signature verification mechanism.
- **Attack Window**: Approximately 48 minutes from immediately after the upgrade until the bridge was paused.

### V-02: Zero Vote Weight Due to Uninitialized State Variable

- **Description**: In Solidity, the default value of a `uint96` variable is `0`. Because `_totalOperatorWeight` was never initialized, all weight calculations were based on `0`.
- **Impact**: `minimumVoteWeight() = 0`, `_highTierVoteWeight(0) = 0` → any withdrawal unconditionally approved.
- **Attack Window**: All `submitWithdrawal` calls were affected while `initializeV3` remained uncalled.

### V-03: Signature Verification Allows Zero Minimum

- **Description**: In the `weight >= minimumWeight` check inside `_submitWithdrawal`, when `minimumWeight = 0`, a `weight` of `0` also passes. An empty signature array or a single invalid signature is sufficient to pass verification.
- **Impact**: Any third party could drain the bridge's entire asset reserves.
- **Attack Window**: Daily withdrawal limits per single Tx capped the damage at ~$12M.

### V-04: Lack of Deployment Script Review

- **Description**: The multi-step initialization procedure was neither documented nor automated, leading operators to skip a step.
- **Impact**: Risk of bridge outage and asset loss.
- **Attack Window**: Potentially triggered on any proxy upgrade.

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Call the missing initialization function immediately**:

```solidity
// ✅ Proxy admin calls initializeV3 immediately to restore state
// (Possible because initializeV3 has never been called, so the reinitializer guard permits it)

proxy.upgradeToAndCall(
    implementation,
    abi.encodeCall(MainchainGatewayV3.initializeV3, ())
);
```

**2) Immediately pause the bridge** (already completed):

```solidity
// ✅ Emergency pause via PauseEnforcer
IPauseEnforcer(pauseEnforcer).triggerPause();
```

**3) Harden the minimum weight check (defensive coding)**:

```solidity
// ✅ Add additional check inside _submitWithdrawal

function _submitWithdrawal(...) internal virtual returns (bool locked) {
    uint256 minimumWeight;
    (minimumWeight, locked) = _computeMinVoteWeight(...);

    // ✅ Revert immediately if minimumWeight is 0 — guards against initialization errors
    if (minimumWeight == 0) revert ErrBridgeNotInitialized();

    // ... signature verification logic ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Multi-step initialization omission | Bundle all `reinitializer` steps into a single atomic transaction (multicall) for deployment |
| Deployment script errors | Add post-initialization state validation step to deployment scripts (assert `_totalOperatorWeight > 0`) |
| Lack of zero-value defense | Add invariant check that blocks withdrawals when `minimumVoteWeight == 0` |
| Lack of monitoring | Emit `minimumVoteWeight` value as an on-chain event and build an alerting system |
| Lack of upgrade testing | Verify `minimumVoteWeight > 0` in fork tests before deploying upgrades |

**Improved Deployment Script Example**:

```solidity
// ✅ Upgrade deployment script (Foundry)

function run() external {
    // Step 1: Deploy new implementation
    MainchainGatewayV3 newImpl = new MainchainGatewayV3();

    // Step 2: Upgrade proxy to new implementation and atomically call initializeV3
    proxy.upgradeToAndCall(
        address(newImpl),
        abi.encodeCall(MainchainGatewayV3.initializeV3, ())
    );

    // Step 3: Call initializeV4 (configure WETH Unwrapper)
    proxy.upgradeToAndCall(
        address(newImpl),
        abi.encodeCall(MainchainGatewayV3.initializeV4, (wethUnwrapper))
    );

    // ✅ Step 4: State validation — the absence of this step caused the incident
    uint256 minWeight = IMainchainGatewayV3(address(proxy)).minimumVoteWeight();
    require(minWeight > 0, "[Deployment Failed] minimumVoteWeight is 0. initializeV3 is missing.");

    console.log("[Success] minimumVoteWeight:", minWeight);
}
```

---

## 7. Lessons Learned

1. **Multi-step initialization must always be executed atomically**: When `reinitializer(N)` is split across multiple steps, the deployment script must bundle them into a single multicall or sequential atomic transactions to prevent any step from being skipped.

2. **Automatically verify critical invariants after upgrades**: Immediately after upgrading security-critical contracts such as bridges, staking systems, and governance contracts, the deployment script must enforce invariant checks like `require(minimumVoteWeight > 0)`.

3. **Use defensive coding to block zero-value operations**: If a signature verification threshold becomes `0`, all verification is disabled. Adding a check inside the function that immediately reverts when the threshold is `0` can mitigate the damage from initialization errors.

4. **Pre-simulate upgrades in a fork environment**: Use Foundry's `vm.createSelectFork()` to run the full upgrade procedure on a mainnet fork, and include tests in CI that verify post-upgrade state (`_totalOperatorWeight`, `minimumVoteWeight`).

5. **Bridge contracts must have emergency pause mechanisms and monitoring**: The fact that the bridge pause took 48 minutes in this incident demonstrates the absence of automated monitoring. On-chain events and an alerting system capable of detecting sudden changes in `minimumVoteWeight` are necessary.

6. **Deployment procedures must be documented and code-reviewed**: Whenever a new `reinitializer` function is added, the deployment checklist must be updated, and the deployment script itself must be reviewed with the same rigor as a smart contract audit.

7. **Repeated incidents in the same project signal systemic security failures**: Ronin suffered major incidents in both 2022 ($624M) and 2024. This indicates the need for a comprehensive review of the entire security framework, including audits, deployment procedures, and monitoring.

---

## 8. On-Chain Verification

### 8.1 PoC vs On-Chain Amount Comparison

| Item | Analysis Estimate | On-Chain Actual | Match |
|------|------------|-------------|---------|
| ETH withdrawn | ~4,000 ETH | 3,996 ETH | ✅ Match |
| USDC withdrawn | ~2,000,000 USDC | 1,998,046.875 USDC | ✅ Match |
| Total loss | ~$12M | ~$11.81M | ✅ Approximate match |
| minimumVoteWeight | 0 | 0 (initializeV3 not called) | ✅ Confirmed |

### 8.2 On-Chain Event Log Sequence

**ETH drain Tx** (`0x2619...cb`):
1. `Withdrew` event — emitted from Ronin Bridge V2
2. 3,996 ETH transferred to MEV Bot (0x4ab1...c0b)
3. Builder (beaverbuild, `0x9522...e5`) receives MEV fee

**USDC drain Tx** (`0xbce5...8`):
1. `Withdrew` event — emitted from Ronin Bridge V2
2. 1,998,046 USDC transferred to MEV Bot (0x6980...DD0)
3. 796.41 ETH swapped via Uniswap V3 USDC/ETH pool (MEV profit optimization)

### 8.3 Pre-Condition Verification (State Immediately Before Attack)

| Condition | Status |
|------|------|
| `_totalOperatorWeight` | `0` (initializeV3 not called) |
| `minimumVoteWeight()` | `0` (calculation result: `0 * 0 / denom = 0`) |
| Bridge ETH balance | ~4,000+ ETH (within daily withdrawal limit) |
| Bridge USDC balance | ~2,000,000+ USDC (within daily withdrawal limit) |
| Attack window duration | ~48 minutes (08:48 ~ 09:37 UTC) |

> **Note**: The daily withdrawal limit mechanism (`_reachedWithdrawalLimit`) capped the amount drainable in a single transaction, preventing losses that could have been far larger.

---

## References

- [Three Sigma — Ronin Bridge 2024 Exploit Analysis](https://threesigma.xyz/blog/exploit/ronin-network-12m-exploit-analysis)
- [Halborn — Explained: The Ronin Network Hack (August 2024)](https://www.halborn.com/blog/post/explained-the-ronin-network-hack-august-2024)
- [Olympix — Ronin's $12M Exploit Wasn't a Hack. It Was a Misconfiguration.](https://olympixai.medium.com/ronins-12m-exploit-wasn-t-a-hack-it-was-a-misconfiguration-ca5cd3547448)
- [CoinDesk — Ronin Bridge Paused After $12M Drained](https://www.coindesk.com/tech/2024/08/06/ronin-bridge-paused-after-9m-drained-in-apparent-whitehat-hack)
- [Etherscan — MainchainGatewayV3 Implementation](https://etherscan.io/address/0xfc274ec92bbb1a1472884558d1b5caac6f8220ee#code)
- [Etherscan — Ronin Bridge V2 Proxy](https://etherscan.io/address/0x64192819ac13ef72bf6b5ae239ac672b43a9af08)
- [Etherscan — ETH Drain Tx](https://etherscan.io/tx/0x2619570088683e6cc3a38d93c3d98899e5783864e15525d5f5810c11189ba6cb)
- [Etherscan — USDC Drain Tx](https://etherscan.io/tx/0xbce5b8548db486c561948e8a177c8ccaa72810f972cee3909ea50af015a60ad8)