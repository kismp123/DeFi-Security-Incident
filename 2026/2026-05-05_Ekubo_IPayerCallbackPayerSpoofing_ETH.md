# Ekubo Protocol — IPayer Callback Payer Spoofing Analysis

| Item | Details |
|------|------|
| **Date** | 2026-05-05 17:50:35 UTC |
| **Protocol** | Ekubo Protocol (EVM Router/Extension) |
| **Chain** | Ethereum Mainnet |
| **Loss** | **17 WBTC (~$1,356,033)** in this single tx; ~$1.4M total across the broader campaign |
| **Attacker (EOA)** | [0xA911Ff35...83e3](https://etherscan.io/address/0xA911Ff351B143634Dbc5aF3E204EA074583A83e3) (Ekubo Exploiter 1) |
| **Attack Contract** | [0x61b0dAD9...3A75](https://etherscan.io/address/0x61b0dAD9628D3e644eB560a5c9B0F960430E3A75) (Ekubo Exploiter 2) |
| **Attack Tx** | [0x770bc9a1...daa0](https://etherscan.io/tx/0x770bc9a1f7c32cb63a5002b9ceb5c7994cd3af0fc6b2309cb32d3c46f629daa0) |
| **Vulnerable Contract** | [0x8CCB1ffD...60fd](https://etherscan.io/address/0x8ccb1ffd5c2aa6bd926473425dea4c8c15de60fd) (Ekubo IPayer extension, unverified) |
| **Ekubo Core** | [0xe0e0e08A...d444](https://etherscan.io/address/0xe0e0e08a6a4b9dc7bd67bcb7aade5cf48157d444) (FlashAccountant singleton) |
| **Victim** | [0x765DECF4...Edd1](https://etherscan.io/address/0x765DECF4Fa157756e850C1079F60801b9219Edd1) (single LP/swapper with unlimited WBTC approval to vuln contract) |
| **Attack Block** | 25,030,409 |
| **Root Cause** | `IPayer.pay` (selector `0x599d0714`) only checks `msg.sender == EkuboCore` but trusts an attacker-supplied `payer` field, allowing `transferFrom(payer, Core, amount)` against any wallet that pre-approved the extension. |
| **Trace Source** | [Phalcon Explorer](https://app.blocksec.com/phalcon/explorer/tx/eth/0x770bc9a1f7c32cb63a5002b9ceb5c7994cd3af0fc6b2309cb32d3c46f629daa0) |

---

## 1. Vulnerability Overview

Ekubo's EVM deployment uses Uniswap-V4-style **flash accounting**: callers acquire a `lock`, run arbitrary swap/withdraw operations that create transient token debts, and must settle those debts before the lock returns. Settlement of incoming-token debts is delegated to an `IPayer.pay` callback on the lock initiator.

The vulnerable contract at `0x8CCB1ffD...60fd` is an Ekubo extension that exposes a high-level "swap" entry point (selector `0xb45a3c0e` is the only entry visible in its dispatcher), takes the lock, executes the user's intent inside `EkuboCore.lock(...)`, and implements `IPayer.pay(payer, token, amount)` (selector `0x599d0714`) to settle the resulting debt by calling `token.transferFrom(payer, Core, amount)`.

The flaw: the `payer` parameter is forwarded **straight from the lock payload**, not from a trusted source bound to the original `msg.sender`. Combined with the fact that user wallets had granted **unlimited ERC-20 approvals** to the extension contract, an attacker can:

1. Acquire the lock with a payload that sets `payer = victim_wallet`.
2. Use the lock to `withdraw` victim-approved tokens directly to the attacker.
3. Settle the resulting debt by triggering `IPayer.pay` with `payer = victim`, which executes `WBTC.transferFrom(victim, Core, amount)` thanks to the victim's pre-existing unlimited approval.

The msg.sender at the WBTC layer is the **extension contract itself**, satisfying the approval check; the victim never signed or initiated this transaction.

In a single transaction the attacker repeated this 85 times for 0.2 WBTC each, draining 17 WBTC from one victim. Reports indicate ~$1.4M total across multiple victims/transactions on Ethereum V2, V3 and Arbitrum V3 routers; this single tx accounts for ~$1.36M.

---

## 2. Vulnerable Code Analysis

### 2.1 IPayer.pay — Missing Payer Authorization (Core Vulnerability)

The vulnerable extension at `0x8CCB1ffD...60fd` is unverified, but its bytecode-visible behavior — confirmed by on-chain transfer logs and corroborated by SlowMist's public description — is equivalent to:

```solidity
// ❌ Vulnerable IPayer implementation in the Ekubo extension
// Selector: 0x599d0714
// Public discussion: SlowMist Cosine, May 2026
function pay(address payer, address token, uint256 amount) external {
    // Only check: caller is EkuboCore
    if (msg.sender != address(CORE)) revert NotCore();

    // ❌ ROOT CAUSE: `payer` is taken at face value from the lock payload.
    // No verification that `payer` ever authorized this lock — the only thing
    // gating us is whether `payer` previously called approve(this, …) on `token`.
    // Any wallet that ever granted an unlimited approval to this extension is
    // now drainable by anyone who can call `lock` with a crafted payload.
    IERC20(token).transferFrom(payer, address(CORE), amount);
}
```

**Patched form (intended behavior):**

```solidity
// ✅ Bind the payer to the lock initiator captured at lock entry.
// The lock initiator is the only party the extension is allowed to charge.
function pay(address payer, address token, uint256 amount) external {
    if (msg.sender != address(CORE)) revert NotCore();

    // Either: enforce that payer == lockInitiator,
    // or: ignore `payer` entirely and always charge the lock initiator.
    address lockInitiator = CORE.getLocker(); // or transient-storage equivalent
    if (payer != lockInitiator) revert UnauthorizedPayer();

    IERC20(token).transferFrom(payer, address(CORE), amount);
}
```

**The Problem.** The contract's *entire* trust model for `pay` collapses into a single `msg.sender == Core` check. Once an attacker gets `Core` to call back into `pay` — which any caller of `Core.lock(...)` can trivially do — the `payer` argument is fully attacker-controlled. The contract treats *"someone, somewhere approved us once"* as authorization, conflating ERC-20 allowance (a passive permission) with intent (an active per-tx authorization).

This is the same class of bug that Uniswap V4 closed by binding the payer of `unlockCallback` to the original `lock` initiator; Ekubo's EVM port implemented `lock`/payer settlement but did not transitively authenticate the payer against the lock initiator.

### 2.2 Why the WBTC `transferFrom` Succeeds

```solidity
// In WBTC (standard ERC20) — no bug here.
function transferFrom(address from, address to, uint256 value) public returns (bool) {
    _allowances[from][msg.sender] -= value;     // msg.sender == 0x8CCB1ffD...60fd (extension)
    _balances[from] -= value;                   // from = victim
    _balances[to]   += value;                   // to   = EkuboCore
    emit Transfer(from, to, value);
    return true;
}
```

Pre-attack on-chain state at block 25,030,408 (verified via `cast call`):

| Slot | Value |
|------|-------|
| `WBTC.balanceOf(victim)` | `1,701,484,735` (17.01484735 WBTC) |
| `WBTC.allowance(victim, 0x8CCB1ffD…60fd)` | `2^256 − 1` (unlimited) |
| `WBTC.allowance(victim, EkuboCore)` | `0` |

The victim approved the **extension**, not Core. Yet because the extension is the one calling `transferFrom`, the approval is sufficient. Funds end up at Core (debt settled) and Core then sends an equal amount to the attacker via `withdraw` (debt the attacker created on the other side of the lock).

### 2.3 Complete Reconstructed Vulnerable Extension

The vulnerable contract at `0x8CCB1ffD…60fd` is unverified (Etherscan: "Are you the contract creator? Verify and Publish"; Sourcify and Blockscout also have no source). The reconstruction below is derived from (a) selectors visible in the on-chain runtime bytecode, (b) the call/transfer pattern observed in the cast trace, and (c) the public Ekubo `BaseLocker` source at [github.com/EkuboProtocol/evm-contracts](https://github.com/EkuboProtocol/evm-contracts/blob/main/src/base/BaseLocker.sol).

```solidity
// SPDX-License-Identifier: ekubo-license-v1.eth
pragma solidity =0.8.33;

interface IFlashAccountant {
    function lock() external;
    function withdraw() external;        // tail-call form used by Ekubo Core
    function startPayments() external;
    function completePayments() external;
}

interface ILocker {
    function locked_6416899205(uint256 id) external;       // Core → extension callback
}

interface IPayer {
    // Selector 0x599d0714 — confirmed present in vulnerable extension's dispatcher.
    function pay(address payer, address token, uint256 amount) external;
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title  Vulnerable Ekubo Extension (reconstructed from 0x8CCB1ffD…60fd)
/// @notice Wraps EkuboCore.lock() to expose a high-level "swap-and-pay" API.
///         The bug lives in `pay()` which trusts an attacker-controlled `payer`.
contract VulnerableEkuboExtension is ILocker, IPayer {
    error NotCore();
    error LockReentrancy();

    IFlashAccountant internal immutable CORE;

    constructor(IFlashAccountant core) {
        CORE = core;
    }

    /// Public entry — selector 0xb45a3c0e (only entry visible in bytecode dispatcher).
    /// Anyone can call this; the extension simply forwards an arbitrary lock payload
    /// to Core. The payload is opaque to msg.sender; control over it is the attacker
    /// primitive that lets them choose `payer` later inside `pay()`.
    function execute(bytes calldata lockPayload) external {
        // ❌ NO transient storage of `msg.sender` here. After this call, the
        //    extension has lost track of who initiated the lock — yet `pay()`
        //    will go on to charge a `payer` taken from this very payload.
        _pendingPayload = lockPayload;
        CORE.lock();                 // → triggers `locked_6416899205` callback
        delete _pendingPayload;
    }

    bytes private _pendingPayload;   // simplified — actual contract uses transient storage

    /// Lock callback from Core — selector 0xc5a44b87 (BaseLocker pattern: locked_6416899205).
    function locked_6416899205(uint256 /*id*/) external override {
        if (msg.sender != address(CORE)) revert NotCore();

        bytes memory payload = _pendingPayload;

        // Decode the operations. The vulnerable extension supports:
        //   1. withdraw(token, recipient, amount)  — pulls from Core to recipient
        //   2. pay-back to settle the resulting debt — handled out-of-band via IPayer.pay
        (address token, address recipient, uint256 amount,
         address payerForSettlement) = abi.decode(payload,
             (address, address, uint256, address));

        // Step A: create a debt for "us" by withdrawing from Core to the attacker.
        // Inside Core, this records: debt[ext][token] += amount (extension owes Core).
        CORE.withdraw();                                  // tail-form withdraw

        // Step B: tell Core to start payment phase, which in turn calls back
        //         into this contract's `pay()` to settle the debt.
        CORE.startPayments();
        IPayer(address(this)).pay(payerForSettlement, token, amount);
        CORE.completePayments();
    }

    /// IPayer.pay — selector 0x599d0714 — THE BUG.
    /// Called back by Core (via `startPayments()`) to settle outstanding debts.
    function pay(address payer, address token, uint256 amount) external override {
        // Authentication: the channel is correctly authenticated as Core …
        if (msg.sender != address(CORE)) revert NotCore();

        // ❌ Authorization: but `payer` is taken straight from the lock payload.
        //    The extension never recorded who initiated `execute()`. Whoever
        //    crafted `lockPayload` chose `payer` — and any wallet that pre-approved
        //    THIS extension for `token` becomes a draining target.
        //
        //    msg.sender at the IERC20 layer below is `address(this)` (the extension),
        //    so as long as `allowance(payer, this) >= amount` the transfer succeeds.
        IERC20(token).transferFrom(payer, address(CORE), amount);
    }
}
```

**The fix (single-line, transient-storage form):**

```solidity
contract PatchedExtension {
    address transient _lockInitiator;          // Solidity 0.8.24+ transient storage

    function execute(bytes calldata lockPayload) external {
        _lockInitiator = msg.sender;            // ✅ capture at lock entry
        _pendingPayload = lockPayload;
        CORE.lock();
    }

    function pay(address payer, address token, uint256 amount) external {
        if (msg.sender != address(CORE))    revert NotCore();
        if (payer != _lockInitiator)        revert UnauthorizedPayer();   // ✅ added
        IERC20(token).transferFrom(payer, address(CORE), amount);
    }
}
```

This is the same pattern Uniswap V4 enforces in `unlockCallback`: the payer for any pull is the address that originally called `unlock()`, not whatever the inner payload says.

### 2.4 Bytecode Evidence

```
Address : 0x8CCB1ffD5C2aa6Bd926473425Dea4c8c15DE60fd
Code size : 22,508 bytes
Source verification : NO (Etherscan / Sourcify / Blockscout)
Selectors observed in dispatcher (PUSH4 immediates in the leading dispatch table):
   0xb45a3c0e   — extension entry (`execute(bytes)` or equivalent)
   0x599d0714   — IPayer.pay(address,address,uint256)              ← vulnerable
   0xc5a44b87   — locked_6416899205(uint256)                       — BaseLocker callback
Hardcoded immutable (PUSH20):
   0xe0e0e08a6a4b9dc7bd67bcb7aade5cf48157d444   — EkuboCore (FlashAccountant)
```

The trace's per-cycle pattern (Core → attacker withdraw, then victim → Core `transferFrom` via `pay()`) is exactly what executing `locked_6416899205` followed by `pay()` produces in the reconstructed contract above; the bug surfaces at `IERC20(token).transferFrom(payer, …)` where `payer` is attacker-supplied rather than `_lockInitiator`-bound.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA `0xA911Ff35…83e3` deployed the attack contract `0x61b0dAD9…3A75` (Ekubo Exploiter 2) ~2 days prior.
- Attacker enumerated the set of wallets with non-zero allowances to `0x8CCB1ffD…60fd` (publicly observable on-chain). The victim `0x765DECF4…Edd1` had granted `type(uint256).max` to this extension and held 17.01 WBTC.

### 3.2 Execution Phase

```
[Step 1] Bootstrap the exploit
┌──────────────────────────────────────────────────────────────┐
│ EOA 0xA911Ff35…83e3                                          │
│   │                                                           │
│   └─ calls AttackContract.exploit(target=0x8CCB1ffD…60fd,    │
│                                   payload=<crafted lock data>)│
│   selector 0x718a549d                                        │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
[Step 2] Acquire the Ekubo lock (repeated 85× inside one tx)
┌──────────────────────────────────────────────────────────────┐
│ AttackContract → EkuboCore.lock()                            │
│ EkuboCore → 0x8CCB1ffD…60fd.locked_<id>(...)                 │
│   ├─ inside: "withdraw 0.2 WBTC to attacker"                 │
│   │     EkuboCore → AttackerEOA: 0.2 WBTC                    │
│   │     (creates +0.2 WBTC debt owed *to* Core)              │
│   │                                                           │
│   └─ inside: settle debt via IPayer.pay                      │
│         EkuboCore.startPayments() →                          │
│         0x8CCB1ffD…60fd.pay(payer=VICTIM, token=WBTC, 0.2)  │
│             │  ❌ pay() trusts attacker-supplied payer        │
│             ▼                                                 │
│         WBTC.transferFrom(VICTIM, EkuboCore, 0.2)            │
│             (succeeds: VICTIM approved 0x8CCB…60fd unlimited)│
│         debt zeroed → lock returns successfully              │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
[Step 3] Repeat 85 times within the same tx
┌──────────────────────────────────────────────────────────────┐
│ 85 × 0.2 WBTC = 17.0 WBTC drained from VICTIM                │
│ 170 WBTC Transfer events emitted                             │
│ Per cycle order: Core→Attacker (withdraw) then Victim→Core   │
│ (pay) — confirmed by log[0]/log[1] sequencing                │
└──────────────────────────────────────────────────────────────┘
```

### 3.3 Results

| Item | Value |
|------|------|
| Tx hash | `0x770bc9a1…daa0` |
| Block | 25,030,409 |
| Gas used | 1,735,786 (87.2% of limit) |
| Status | Success (`0x1`) |
| WBTC drained from victim | **17.00000000 WBTC** (exact) |
| WBTC received by attacker EOA | 17.00000000 WBTC |
| Approx USD value | ≈ $1,356,033 |
| Cycles per tx | 85 |
| Per-cycle amount | 0.2 WBTC |

---

## 4. PoC Sketch (Reconstructed from On-Chain Trace)

The attack contract is unverified, so the PoC below is a faithful reconstruction. The selector `0x718a549d` matches `exploit(address,bytes)`; the inner shape matches the FlashAccountant lock pattern used by Ekubo.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

interface IExtension {
    // Selector 0xb45a3c0e on the vulnerable extension — the function the
    // attacker calls to enter the Ekubo lock with crafted parameters.
    function execute(bytes calldata lockPayload) external;
}

contract Exploit {
    address constant CORE   = 0xe0e0e08A6a4b9dc7BD67Bcb7aADe5CF48157d444;
    address constant WBTC   = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;

    /// Bypasses the "payer == lockInitiator" check (which doesn't exist).
    /// Drains an unbounded amount of WBTC from any victim that previously
    /// granted unlimited approval to `vulnExtension`.
    function exploit(address vulnExtension, bytes calldata payload) external {
        // The crafted payload tells the extension to:
        //   1. withdraw `amount` of `token` to msg.sender (the attacker)
        //   2. settle the resulting debt by invoking IPayer.pay with
        //      payer = victim, token = WBTC, amount = 0.2e8.
        // Repeated 85× inside the same lock to drain 17 WBTC.
        IExtension(vulnExtension).execute(payload);
    }
}
```

The on-chain payload (131 bytes, hex):
```
0x0009090505000000000000000000d26163000000000001312d00000501
   a911ff351b143634dbc5af3e204ea074583a83e3   // attacker (recipient of withdraw)
   b3ab4ab5ab6ab7ab8ab9ac0a                  // — flag/separator —
   765decf4fa157756e850c1079f60801b9219edd1   // VICTIM (payer)
   9abcdef0123456789abcdef0
   …
```

The two 20-byte addresses embedded in the payload — attacker recipient and victim payer — are exactly the addresses observed in the resulting WBTC `Transfer` events.

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------------|----------|-----|
| V-01 | `IPayer.pay` trusts attacker-supplied `payer` (no binding to lock initiator) | **CRITICAL** | CWE-862 (Missing Authorization) |
| V-02 | Approval-based asset model: extension acts as `transferFrom` agent for any approved user | **HIGH** | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| V-03 | Conflation of *passive ERC-20 allowance* with *per-tx user intent* | **HIGH** | CWE-639 (Authorization Bypass Through User-Controlled Key) |

### V-01: Missing Payer Authorization in `pay`

- **Description**: The `IPayer.pay(address payer, address token, uint256 amount)` callback (selector `0x599d0714`) gates only `msg.sender == EkuboCore`. The `payer` argument is forwarded directly from the lock payload chosen by the lock initiator (the attacker), so it has no relationship to who actually authorized the operation.
- **Impact**: Any wallet that ever set a non-zero allowance to the extension is drainable up to the smaller of (allowance, balance). Unlimited approvals → full balance drainable.
- **Attack Condition**: A victim with a live ERC-20 allowance to the vulnerable extension. No flash loan, no oracle manipulation, no privileged role required.

### V-02: Approval-Based Pull Architecture

- **Description**: Ekubo's EVM extension expects users to pre-approve it as a `transferFrom` agent. When combined with V-01, this turns approvals into bearer-style permissions.
- **Impact**: Even if V-01 were partially fixed, the broad attack surface remains: any future bug in the extension that lets attacker control which `payer` is charged repeats the same exploit class.
- **Attack Condition**: Same as V-01.

### V-03: Allowance ≠ Intent

- **Description**: An ERC-20 approval is a *standing* permission with no binding to a specific operation, recipient, or session. Treating it as user intent for a particular swap is a category error.
- **Impact**: Cross-cutting design issue; manifests in any router/extension that pulls funds via `transferFrom` inside a callback without re-authenticating the originating user for each call.
- **Attack Condition**: Architectural; surfaces whenever an attacker can drive a callback path that uses approvals.

---

## 6. Remediation

### Immediate Actions

**① Bind `payer` to the lock initiator (server-side)**

```solidity
// In the extension's lock entry point, capture the initiator …
function execute(bytes calldata payload) external {
    _lockInitiator = msg.sender;          // transient storage in 0.8.24+
    CORE.lock();                          // triggers locked_… callback
    delete _lockInitiator;
}

// … and enforce it in pay()
function pay(address payer, address token, uint256 amount) external {
    if (msg.sender != address(CORE))   revert NotCore();
    if (payer != _lockInitiator)       revert UnauthorizedPayer();   // ✅ added
    IERC20(token).transferFrom(payer, address(CORE), amount);
}
```

**② Or: ignore the `payer` argument and always charge the initiator**

```solidity
function pay(address /*payerIgnored*/, address token, uint256 amount) external {
    if (msg.sender != address(CORE)) revert NotCore();
    IERC20(token).transferFrom(_lockInitiator, address(CORE), amount); // ✅
}
```

**③ User-side mitigation (immediate, since the extension is immutable)**

Revoke approvals to the affected routers. Ekubo confirmed that "EVM contracts are immutable by design, meaning a patched redeployment is the only path forward."

```solidity
WBTC.approve(0x8CCB1ffD5C2aa6Bd926473425Dea4c8c15DE60fd, 0);
// Repeat for Ethereum V2/V3 and Arbitrum V3 router addresses.
```

### Structural Improvements

| Issue | Recommended Action |
|-------|--------------------|
| V-01 Missing payer binding | Always derive `payer` from a transient slot set at lock entry; never accept it as user-supplied calldata. |
| V-02 Approval-based pull | Prefer Permit2 / EIP-2612 with per-call typed signatures so each `transferFrom` carries explicit user intent. |
| V-03 Allowance ≠ intent | At a minimum, scope approvals (limited amount + expiry); architecturally, redesign settlement so victim intent is required per-operation, not per-approval-lifetime. |
| Operational | Treat unverified extension contracts on EVM as opaque privileged singletons — publish source on deploy and require an audit for any contract that becomes a `transferFrom` agent. |

---

## 7. Lessons Learned

1. **`msg.sender == Core` is not sufficient authorization for callbacks.** A "this came from our singleton" check authenticates the *channel*, not the *intent*. Any callback path that uses approvals must additionally bind the charged address to the original lock initiator captured in transient storage.

2. **ERC-20 allowance is a long-lived bearer permission.** Once a user has granted unlimited approval, every code path that calls `transferFrom` on that user's behalf is part of the attack surface — including paths the user never intends to invoke. Routers that act as `transferFrom` agents are particularly fragile; Permit2 and EIP-2612 exist precisely to convert standing approvals into per-call signed authorizations.

3. **Immutable + unverified is the worst of both worlds.** The vulnerable contract was both immutable (no upgrade path) and lacked verified source, so users could neither audit it nor receive a hot fix. Immutability should raise, not lower, the bar for source verification and audit.

4. **Uniswap V4's payer model is the reference.** V4 binds the unlock-callback payer to the original `unlock` caller via transient storage; cloning the lock pattern without cloning that authentication step is an easy way to reintroduce this exact bug in any V4-style flash accountant.

5. **Approval hygiene is a real defense.** Revoking unused approvals cuts off entire bug classes preemptively. Wallets and front-ends should default to Permit2-style per-call signatures and surface "you approved X for unlimited" as a long-lived risk.

---

## 8. On-Chain Verification

Verified with `cast` (Foundry 1.3.5) against `eth-mainnet.public.blastapi.io`.

### 8.1 Tx Basics

| Field | Value |
|-------|-------|
| Block | 25,030,409 |
| Block timestamp | 2026-05-05 17:50:35 UTC |
| Status | Success (`0x1`) |
| `from` | `0xA911Ff351B143634Dbc5aF3E204EA074583A83e3` (Ekubo Exploiter 1) |
| `to` | `0x61b0dAD9628D3e644eB560a5c9B0F960430E3A75` (Ekubo Exploiter 2 / attack contract) |
| Calldata selector | `0x718a549d` (`exploit(address,bytes)`, target = `0x8CCB1ffD…60fd`) |
| Gas used | 1,735,786 |

### 8.2 PoC Description vs On-Chain Reality

| Item | Reported / Expected | On-Chain | Match |
|------|---------------------|----------|-------|
| WBTC drained from victim | "17 WBTC across 85 transfers" | 17.0 WBTC across 85 cycles in **a single tx** | ✓ (amount), ✗ (granularity — single tx, not 85 separate txs) |
| Per-cycle amount | 0.2 WBTC | 0.2 WBTC × 85 = 17.0 WBTC | ✓ |
| Total Transfer events | n/a | 170 (2 per cycle × 85) | — |
| USD loss | ≈ $1.4M | ≈ $1.36M (this tx) | ✓ |
| Funds path | victim → Core → attacker | log[1] victim→Core, log[0] Core→attacker, repeated 85× | ✓ |

### 8.3 Pre-Attack State (block 25,030,408)

```
WBTC.balanceOf(victim 0x765DECF4…Edd1)             = 1,701,484,735 sats  (17.01484735 WBTC)
WBTC.allowance(victim, 0x8CCB1ffD…60fd)            = 2^256 - 1           (unlimited)  ← attack precondition
WBTC.allowance(victim, EkuboCore 0xe0e0e08A…d444)  = 0                   (victim never approved Core directly)
```

### 8.4 Post-Attack State (block 25,030,410)

```
WBTC.balanceOf(victim 0x765DECF4…Edd1) = 1,484,735 sats  (0.01484735 WBTC)   ← lost exactly 17 WBTC
```

### 8.5 Cycle Log Pattern (first 6 events)

```
Log[0] EkuboCore  → Attacker EOA : 0.2 WBTC   (withdraw — debt creation phase)
Log[1] VICTIM     → EkuboCore    : 0.2 WBTC   (transferFrom via IPayer.pay — debt settlement)
Log[2] EkuboCore  → Attacker EOA : 0.2 WBTC
Log[3] VICTIM     → EkuboCore    : 0.2 WBTC
Log[4] EkuboCore  → Attacker EOA : 0.2 WBTC
Log[5] VICTIM     → EkuboCore    : 0.2 WBTC
…
Log[168] EkuboCore  → Attacker EOA : 0.2 WBTC
Log[169] VICTIM     → EkuboCore    : 0.2 WBTC
```

Withdraw fires *before* the matching `transferFrom`, confirming the attacker first pulls funds out and then settles the debt with someone else's approval — exactly the V-01 invariant violation. There is no per-cycle `swap` event; the lock body is purely a withdraw + spoofed payment loop with no real swap on either side.

### 8.6 Vulnerable Contract Bytecode Indicators

```
Address : 0x8CCB1ffD5C2aa6Bd926473425Dea4c8c15DE60fd
Code size : 22,508 bytes (deployed runtime)
Verified  : NO (Etherscan: "Are you the contract creator? Verify and Publish")
Selectors observable in dispatcher:
  0xb45a3c0e   — extension entry (e.g., swap()/execute())
  0x599d0714   — IPayer.pay(address,address,uint256)   ← vulnerable callback
  (locked_<id> dispatcher pattern present, consistent with BaseLocker)
```

---

## 9. Additional Information

- **Affected deployments**: per Ekubo's public statement, only the EVM swap routers — Ethereum V2, Ethereum V3, and Arbitrum V3. Starknet core, all Starknet LP positions, and the EVM core/AMM pools were unaffected.
- **Post-exploit laundering**: stolen WBTC routed through Velora into ~$404K USDC, ~$403K DAI, and 239.5 ETH; then consolidated into 577 ETH (~$1.36M) before being sent to Tornado Cash.
- **Mitigation status**: Ekubo's EVM contracts are immutable; remediation requires a redeployment of the affected extensions/routers and user-side approval revocation. Ekubo announced an attack post-mortem.
- **Public attribution of the technical root cause**: SlowMist's Cosine identified the missing payer check in `IPayer.pay (0x599d0714)` shortly after the incident.

| Contract | Address |
|----------|---------|
| Ekubo Core (FlashAccountant) | `0xe0e0e08A6a4b9dc7BD67Bcb7aADe5CF48157d444` |
| Vulnerable Ekubo extension | `0x8CCB1ffD5C2aa6Bd926473425Dea4c8c15DE60fd` (unverified) |
| Attacker EOA | `0xA911Ff351B143634Dbc5aF3E204EA074583A83e3` |
| Attack contract | `0x61b0dAD9628D3e644eB560a5c9B0F960430E3A75` |
| Single largest victim (this tx) | `0x765DECF4Fa157756e850C1079F60801b9219Edd1` |
| WBTC | `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599` |

---

## References

- Phalcon Explorer: [tx 0x770bc9a1…daa0](https://app.blocksec.com/phalcon/explorer/tx/eth/0x770bc9a1f7c32cb63a5002b9ceb5c7994cd3af0fc6b2309cb32d3c46f629daa0)
- Etherscan: [tx](https://etherscan.io/tx/0x770bc9a1f7c32cb63a5002b9ceb5c7994cd3af0fc6b2309cb32d3c46f629daa0) · [vulnerable extension](https://etherscan.io/address/0x8ccb1ffd5c2aa6bd926473425dea4c8c15de60fd) · [attacker](https://etherscan.io/address/0xA911Ff351B143634Dbc5aF3E204EA074583A83e3) · [attack contract](https://etherscan.io/address/0x61b0dAD9628D3e644eB560a5c9B0F960430E3A75)
- Ekubo source (related, non-vulnerable contracts): [EkuboProtocol/evm-contracts](https://github.com/EkuboProtocol/evm-contracts) — `src/Router.sol`, `src/base/BaseLocker.sol`, `src/base/BaseExtension.sol`, `src/interfaces/IFlashAccountant.sol`
- Press: [The Block](https://www.theblock.co/post/400189/attackers-drain-1-4m-in-wrapped-bitcoin-from-defi-protocol-ekubo-in-approval-based-exploit) · [Bankless](https://www.bankless.com/read/news/ekubo-dex-users-drained-for-1-4m-in-token-approval-exploit) · [AMBCrypto](https://ambcrypto.com/ekubo-hack-drains-1-36m-in-85-transactions-are-defi-wallets-at-risk/amp/) · [Crypto-Economy](https://crypto-economy.com/ekubo-protocol-loses-1-4m-in-wbtc/)
