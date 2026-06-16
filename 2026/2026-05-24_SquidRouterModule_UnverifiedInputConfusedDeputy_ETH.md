# SquidRouterModule — Unverified-Input Confused-Deputy Exploit Analysis

| Field | Details |
|-------|---------|
| **Date** | 2026-05-24 22:25:00 UTC (drain executed ~2026-05-25, over ~2 hours) |
| **Protocol** | "The SquidRouterModule Contract" — a **third-party** Gnosis Safe module interfacing with Squid Router / Axelar (likely linked to New Market Trading). **NOT** an official Squid product. |
| **Chain** | Base + Ethereum + Arbitrum (module deployed on all three); proceeds consolidated into DAI |
| **Total Loss** | **$3,978,833 (~$3.98M)** — canonical Common Prefix figure: 88 victim Safes / 313 txs / 3 chains — Base ~$2,814,305 (132 drains), Ethereum ~$1,083,764 (125 drains), Arbitrum ~$80,765 (51 drains); Halborn reported $3.2M / 86 Safes |
| **Attacker EOA(s)** | [0x7c82cb4b…0a23bb8](https://etherscan.io/address/0x7c82cb4b2909c50c7c0f2b696eee7565e0a23bb8), [0x9bdc7301…fa645b91](https://etherscan.io/address/0x9bdc730183821b6bb2b51be30b77c964fa645b91) (funded via Tornado Cash, ~2.1 ETH); receiver [0xa447f717…7aa54859](https://etherscan.io/address/0xa447f71782135ab96a71374271a749ff7aa54859) |
| **Vulnerable Contract** | [0x1f1d37a3Bf840e35c6a860c7C2dA71Fe555123ca](https://basescan.org/address/0x1f1d37a3Bf840e35c6a860c7C2dA71Fe555123ca) (SquidRouterModule, deployed identically on ETH/Base/ARB; **verified source** visible on BaseScan) |
| **Attacker Contract** | [0xfac74596…5dc8760c](https://etherscan.io/address/0xfac7459683cdb9b6f367b42eedfebd745dc8760c) (Ethereum) |
| **Attack Tx** | [0x8de614bd…f24c3](https://etherscan.io/tx/0x8de614bdb7acf5dcbdfe5ce8ed17ec2a2058e7708e6a4cf44f0e523c72df24c3) (example drain tx; 313 txs total — see §8); the two original source-list hashes (`0xcd864ec4…` and `0x39e52302…`) were **synthetic / not found on-chain** |
| **Entry Selector / Function** | `executeSameChainActions(...)` style action handler inheriting Axelar's `expressExecuteWithToken()` entrypoint (no added access control) |
| **Root Cause** | Confused deputy via unverified input: module's action handler had no access control, trusted a hardcoded "verification string" baked into its source, and decoded the authorized delegate address from attacker-controlled payload bytes — letting any caller make any Safe that trusted the module execute arbitrary transfers. |
| **GitHub / Source** | Verified contract source on BaseScan for 0x1f1d37a3…123ca; Squid core router unaffected: [0xce16F69375520ab01377ce7B88f5BA8C48F8D666](https://etherscan.io/address/0xce16F69375520ab01377ce7B88f5BA8C48F8D666) |
| **Source Verification** | Module source verified on BaseScan; full addresses and canonical loss/tx figures corroborated by Common Prefix and QuillAudits forensics. The two original source-list tx hashes were synthetic (not found on-chain); real drain txs published by Common Prefix (`0x8de614bd…`) and QuillAudits (`0x59d17fd3…`). |

---

> ### ⚠️ Scope Clarification — This Was NOT a Squid Protocol Hack
>
> **Squid publicly disowned the exploited contract**, stating "we don't know who deployed this." The drained component is a **third-party Gnosis Safe module** (likely associated with New Market Trading) that *interfaced* with Squid Router and Axelar, not a Squid-authored contract.
>
> - **Squid's own core router** ([0xce16F69375520ab01377ce7B88f5BA8C48F8D666](https://etherscan.io/address/0xce16F69375520ab01377ce7B88f5BA8C48F8D666)) was **UNAFFECTED**.
> - **User token approvals to Squid's official contracts were UNAFFECTED.**
> - Only Gnosis Safes that had explicitly **added the malicious/insecure module as a trusted Safe Module** were drained.
>
> The "SquidRouterModule" name is descriptive of the contract's intended integration target — it is not an endorsement or product of the Squid team. This is the same *class* of bug as the 2023 Squid/Multicall arbitrary-call issue, but it is a **separate contract and a separate event**.

---

## 1. Vulnerability Overview

A Gnosis Safe **module** is a contract that, once enabled by a Safe's owners, can call `execTransactionFromModule()` to move that Safe's assets **without** collecting the normal owner multisig threshold. Modules are therefore extremely privileged: a Safe that enables a module is, in effect, delegating spending authority to whatever logic that module contains.

The "SquidRouterModule" contract (0x1f1d37a3…123ca) was a third-party module deployed on Base, Ethereum, and Arbitrum to automate cross-chain swaps through Squid Router and the Axelar network. Roughly 88 Gnosis Safes — many belonging to market-making and trading operations — enabled it as a trusted module.

The module's action handler (an `executeSameChainActions`-style function) was built on top of Axelar's `expressExecuteWithToken()` pattern, which is **intentionally permissionless** at the gateway level (it is designed to be called by Axelar relayers). The module inherited that permissionless entrypoint **without adding any access control of its own**. Worse, the module attempted to substitute *real* authentication with two broken mechanisms:

1. A **hardcoded "verification string"** baked directly into the verified contract source, used as a "proof of authenticity." Because the source was verified and public on BaseScan, this string was visible to anyone — it authenticated nothing.
2. The **authorized delegate address** used for the Safe's local permission checks was **decoded directly out of attacker-controlled payload bytes** and used without validation.

The combination is a textbook **confused deputy**: a privileged actor (the module, which can move any enabling Safe's funds) performs actions on behalf of an unauthenticated caller, using authorization data that the caller themselves supplied. Any attacker could craft calldata that (a) passed the trivially-known verification string, (b) named *themselves* (or their contract) as the "authorized delegate," and (c) instructed the module to make a victim Safe transfer out its assets. The attacker then swapped the drained tokens via Uniswap V3 and consolidated into DAI.

This is the **"Unverified User Input"** vulnerability class (arbitrary-call / confused-deputy family, CWE-20 / CWE-862 / CWE-863): the contract treats caller-supplied bytes as trusted identity and authority.

---

## 2. Vulnerable Code Analysis

> **Source status**: The module at 0x1f1d37a3…123ca is **verified** on BaseScan, so the structure below reflects the real, public source pattern (function shape, the hardcoded verification string, and the payload-decoded delegate). Exact variable names are normalized for readability; the security-relevant logic — permissionless entrypoint + hardcoded string + caller-supplied delegate — is faithful to the verified source and the Common Prefix / Halborn write-ups.

### 2.1 ❌ Vulnerable — Permissionless Entrypoint + Caller-Supplied Delegate

```solidity
// SquidRouterModule.sol (third-party Gnosis Safe module) — VULNERABLE
// Built on Axelar's permissionless expressExecuteWithToken entrypoint,
// with NO module-level access control added.

contract SquidRouterModule {
    // ❌ A "secret" baked into VERIFIED, PUBLIC source. Authenticates nothing.
    string private constant VERIFICATION_STRING = "SQUID_ROUTER_MODULE_OK";

    // Axelar-style entrypoint. On the gateway this is meant to be relayer-only,
    // but the module re-exposes it with no guard of its own.
    function executeSameChainActions(
        bytes calldata payload      // ❌ fully attacker-controlled
    ) external {                    // ❌ NO onlyRelayer / NO access control
        // ❌ 1. "Authentication" via a hardcoded, publicly-visible string.
        //        Anyone reading BaseScan knows this value.
        (
            string memory providedString,
            address authorizedDelegate,   // ❌ decoded straight from attacker bytes
            address safe,                 // target victim Safe
            address token,
            address to,
            uint256 amount,
            bytes memory swapCalldata
        ) = abi.decode(
            payload,
            (string, address, address, address, address, uint256, bytes)
        );

        require(
            keccak256(bytes(providedString)) == keccak256(bytes(VERIFICATION_STRING)),
            "bad verification string"     // ❌ trivially satisfied by anyone
        );

        // ❌ 2. The "authorized delegate" used for the Safe's local permission
        //        check is whatever the CALLER put in the payload. No validation
        //        that authorizedDelegate is a real, pre-approved operator.
        require(_isDelegate(safe, authorizedDelegate), "not delegate");
        // ... but authorizedDelegate was supplied by the attacker, so an attacker
        // simply names an address they control that the broken check accepts.

        // ❌ 3. The module is a trusted Safe Module → it can move the Safe's funds
        //        with no owner signatures. Confused deputy completes here.
        IGnosisSafe(safe).execTransactionFromModule(
            token,
            0,
            abi.encodeWithSelector(IERC20.transfer.selector, to, amount),
            Enum.Operation.Call
        );

        // Drained tokens are routed through Uniswap V3 → DAI
        if (swapCalldata.length > 0) {
            IGnosisSafe(safe).execTransactionFromModule(
                UNISWAP_V3_ROUTER, 0, swapCalldata, Enum.Operation.Call
            );
        }
    }
}
```

**Why each line fails:**

- The function is `external` with **no `onlyRelayer` / `onlyOwner` / signature check** — it inherits Axelar's permissionless express-execute shape but is not gated by the gateway, so *anyone* can call it directly.
- `VERIFICATION_STRING` is a constant embedded in **verified, public** source. Using a known public value as a secret is no authentication at all.
- `authorizedDelegate` is decoded from `payload` — **the attacker chooses it**. The "is delegate" check therefore validates the attacker's own claim against the attacker's own input.
- Because the module is an **enabled Safe Module**, `execTransactionFromModule()` moves victim funds with **zero owner signatures**.

### 2.2 ✅ Fixed — Authenticated Relayer + Immutable Delegate, Reject Caller-Supplied Identity

```solidity
// SquidRouterModule.sol — HARDENED
contract SquidRouterModule {
    // ✅ Real authority: an immutable, on-chain relayer/operator set at deploy,
    //    NOT a string anyone can read.
    address public immutable authorizedRelayer;
    // ✅ Trusted delegate is fixed at construction — NOT read from calldata.
    address public immutable trustedDelegate;

    constructor(address relayer, address delegate) {
        authorizedRelayer = relayer;
        trustedDelegate   = delegate;
    }

    // ✅ Only the authenticated relayer may invoke action execution.
    modifier onlyAuthorizedRelayer() {
        require(msg.sender == authorizedRelayer, "unauthorized relayer");
        _;
    }

    function executeSameChainActions(
        bytes calldata payload
    ) external onlyAuthorizedRelayer {          // ✅ access control restored
        (
            address safe,
            address token,
            address to,
            uint256 amount,
            bytes memory swapCalldata
        ) = abi.decode(payload, (address, address, address, uint256, bytes));

        // ✅ Authorization uses the IMMUTABLE trustedDelegate — the caller cannot
        //    supply or override the authorized identity.
        require(_isDelegate(safe, trustedDelegate), "not delegate");

        // ✅ Optional: per-Safe explicit allow-list of (token,to) destinations
        require(_isApprovedDestination(safe, token, to), "destination not allowed");

        IGnosisSafe(safe).execTransactionFromModule(
            token, 0,
            abi.encodeWithSelector(IERC20.transfer.selector, to, amount),
            Enum.Operation.Call
        );

        if (swapCalldata.length > 0) {
            require(_isWhitelistedTarget(UNISWAP_V3_ROUTER), "bad swap target");
            IGnosisSafe(safe).execTransactionFromModule(
                UNISWAP_V3_ROUTER, 0, swapCalldata, Enum.Operation.Call
            );
        }
    }
}
```

The fix rests on three invariants: **(1)** the entrypoint is gated by `onlyAuthorizedRelayer` so callers are authenticated by `msg.sender`, not by a public string; **(2)** the authorized delegate is an `immutable` set at construction, so it can never be sourced from attacker-controlled bytes; **(3)** caller-supplied identity fields are removed from the payload entirely — the payload may only describe *what* to do, never *who* is allowed to do it.

---

## 3. Attack Flow

### 3.1 Preparation

1. The attacker withdrew **~2.1 ETH from Tornado Cash** to anonymize the funding trail, splitting it across operating wallets `0x7c82cb4b…0a23bb8` and `0x9bdc7301…fa645b91`.
2. The attacker read the **verified source of the module on BaseScan**, extracting (a) the hardcoded `VERIFICATION_STRING` and (b) the calldata layout of `executeSameChainActions`, including the fact that the "authorized delegate" was an `abi.decode`'d field rather than an immutable.
3. The attacker enumerated Gnosis Safes that had **enabled the module** (queryable via each Safe's `getModules()` / `isModuleEnabled`), building a target list of ~88 victim Safes across Base, Ethereum, and Arbitrum.
4. The attacker deployed a helper attack contract on Ethereum (`0xfac74596…5dc8760c`) to batch and route the drains and Uniswap V3 swaps.

### 3.2 Execution

For each victim Safe, the attacker submitted calldata to the module's `executeSameChainActions`-style handler:

- **`providedString`** = the publicly-known `VERIFICATION_STRING` → passes the fake auth check.
- **`authorizedDelegate`** = an address the attacker controls / that satisfies the broken `_isDelegate` check → impersonates a pre-authorized delegate.
- **`safe`** = the victim Safe; **`token` / `to` / `amount`** = drain instructions sending the Safe's assets to the receiver `0xa447f717…7aa54859`.
- **`swapCalldata`** = Uniswap V3 swap routing the drained tokens into **DAI**.

Because the module is a trusted Safe Module, `execTransactionFromModule()` executed the transfers **with no owner signatures**. The campaign ran for **~2 hours**, spanning **313 transactions** against **88 Safes** on the three chains, consolidating proceeds into DAI.

### 3.3 Attack Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│  Tornado Cash → ~2.1 ETH                                      │
│  → attacker wallets 0x7c82cb4b… / 0x9bdc7301…                 │
└───────────────────────────────┬──────────────────────────────┘
                                │ read VERIFIED source on BaseScan
                                │ (VERIFICATION_STRING + calldata layout)
                                ▼
┌──────────────────────────────────────────────────────────────┐
│  Attacker contract 0xfac74596…5dc8760c (ETH)                 │
│  Craft payload:                                              │
│   providedString   = "<public verification string>"  ✓ fake  │
│   authorizedDelegate = attacker-chosen address      ❌ spoof  │
│   safe / token / to / amount = drain instructions            │
│   swapCalldata     = Uniswap V3 → DAI                         │
└───────────────────────────────┬──────────────────────────────┘
                                │ call executeSameChainActions(payload)
                                │  (NO access control — permissionless)
                                ▼
┌──────────────────────────────────────────────────────────────┐
│  SquidRouterModule 0x1f1d37a3…123ca  (ETH / Base / ARB)      │
│   ├─ require(providedString == VERIFICATION_STRING) ✓ PASS    │
│   ├─ require(_isDelegate(safe, authorizedDelegate)) ✓ PASS    │
│   │     ❌ delegate came from attacker payload                │
│   └─ execTransactionFromModule(...)  ← CONFUSED DEPUTY        │
└───────────────────────────────┬──────────────────────────────┘
                                │ no owner signatures required
                                ▼
┌──────────────────────────────────────────────────────────────┐
│  ~88 Victim Gnosis Safes (had enabled the module)            │
│   assets transferred out → Uniswap V3 swap → DAI             │
│   → receiver 0xa447f717…7aa54859                             │
│   313 txs over ~2 hours → $3,978,833 (~$3.98M)               │
└──────────────────────────────────────────────────────────────┘

        ╔══════════════════════════════════════════════╗
        ║  UNAFFECTED: Squid core router               ║
        ║  0xce16F69375520ab01377ce7B88f5BA8C48F8D666   ║
        ║  + all user approvals to official Squid        ║
        ╚══════════════════════════════════════════════╝
```

### 3.4 Outcome

| Item | Value |
|------|-------|
| Victim Safes | 88 Gnosis Safes (across ETH / Base / ARB) |
| Transactions | 313 over ~2 hours |
| Total drained | $3,978,833 (~$3.98M) — Base ~$2,814,305 (132 drains), ETH ~$1,083,764 (125 drains), ARB ~$80,765 (51 drains); Halborn reported $3.2M / 86 Safes |
| Consolidation asset | DAI (via Uniswap V3 swaps) |
| Squid core protocol | **Unaffected** — no loss to official router or user approvals |

---

## 4. Vulnerability Classification

### 4.1 Classification Table

| ID | Vulnerability | Severity | CWE | Category | Similar Incidents |
|----|---------------|----------|-----|----------|-------------------|
| V-01 | Authorized delegate decoded from unverified, attacker-controlled input | CRITICAL | CWE-20 | unverified-input / arbitrary-call | SwapNet, Gyro, Aperture |
| V-02 | Missing access control on privileged module entrypoint | CRITICAL | CWE-862 | access-control | Squid/Multicall 2023 |
| V-03 | Confused deputy — privileged module acts for unauthenticated caller | CRITICAL | CWE-863 | confused-deputy | Squid/Multicall 2023 |
| V-04 | Hardcoded "secret" in verified public source used as authentication | HIGH | CWE-798 | hardcoded-credential | — |

### 4.2 V-01 — Unverified User Input (Delegate from Calldata)

- **Description**: The module decoded the `authorizedDelegate` used for its permission check directly from the caller-supplied `payload` and used it without validating it against any trusted on-chain registry. The caller therefore authored the very identity the module then "authorized."
- **Impact**: Any caller could impersonate a pre-approved delegate and direct any enabling Safe's funds. $3,978,833 (~$3.98M) drained.
- **Preconditions**: Knowledge of the public calldata layout (trivial — source verified). No privileges required.

### 4.3 V-02 — Missing Access Control (CWE-862)

- **Description**: The `executeSameChainActions`-style entrypoint inherited Axelar's permissionless `expressExecuteWithToken()` shape but added **no** module-level guard (no `onlyRelayer`, no `onlyOwner`, no signature verification). The Axelar express pattern is only safe when the gateway gates the caller; a standalone module re-exposing it is wide open.
- **Impact**: Direct, unauthenticated invocation of a function that can move funds from every enabling Safe.
- **Preconditions**: None.

### 4.4 V-03 — Confused Deputy (CWE-863)

- **Description**: The module is a maximally-privileged deputy (an enabled Safe Module can move funds with no owner signatures). It performed transfers on behalf of an unauthenticated caller, using authorization data the caller supplied — the defining shape of a confused deputy.
- **Impact**: Full drain of any Safe that trusted the module, with no involvement from the Safe owners.
- **Preconditions**: Victim Safe must have enabled the module.

### 4.5 V-04 — Hardcoded Verification String (CWE-798)

- **Description**: A constant string baked into **verified, public** source was used as a "proof of authenticity." Verified source means the value is readable by anyone, so it provides zero authentication.
- **Impact**: Defeated the only nominal gate on the entrypoint.
- **Preconditions**: Ability to read BaseScan.

---

## 5. Comparison with Similar Incidents

| Incident | Date | Loss | Flaw Type | Difference from SquidRouterModule |
|----------|------|------|-----------|-----------------------------------|
| **Squid / Multicall** | 2023 | ~$0 (patched) | Arbitrary external call via unverified multicall payload | **Same arbitrary-call class**, but a different Squid-adjacent contract & event; SquidRouterModule adds the Safe-module privilege and confused-deputy twist |
| **Aperture Finance** | 2026-01-25 | — | Unverified user input passed to external call | Same "Unverified User Input" class; SquidRouterModule weaponizes it through a Gnosis Safe module |
| **SwapNet** | 2026-01-25 | — | Arbitrary call from unvalidated calldata | Same arbitrary-call family; SwapNet targets a router, SquidRouterModule targets enabling Safes |
| **Gyro** | 2026-01-30 | — | Arbitrary call via attacker-controlled target | Same family; SquidRouterModule additionally fakes auth via a public hardcoded string |
| **SquidRouterModule** | 2026-05-24 | $3,978,833 (~$3.98M) | Confused deputy: permissionless entrypoint + delegate decoded from attacker bytes + public hardcoded "secret" | Combines arbitrary-call, missing access control, and a privileged Safe module |

The unifying theme across these incidents is **trusting attacker-controlled input as authority** — whether as a call target (SwapNet, Gyro), as a routing parameter (Aperture, Squid/Multicall), or, here, as the *delegate identity* checked for permission. The SquidRouterModule case is the most damaging variant because the deputy in question (an enabled Safe Module) can move funds with no owner signatures.

---

## 6. Remediation Recommendations

### 6.1 Immediate — Authenticate the Caller, Fix the Delegate

```solidity
// ✅ Gate the privileged entrypoint by msg.sender, not by a public string.
address public immutable authorizedRelayer;
address public immutable trustedDelegate;   // set once, never from calldata

modifier onlyAuthorizedRelayer() {
    require(msg.sender == authorizedRelayer, "unauthorized relayer");
    _;
}

function executeSameChainActions(bytes calldata payload)
    external
    onlyAuthorizedRelayer
{
    // payload carries ONLY the action, never the authorizing identity
    (address safe, address token, address to, uint256 amount, bytes memory swap)
        = abi.decode(payload, (address, address, address, uint256, bytes));

    require(_isDelegate(safe, trustedDelegate), "not delegate"); // immutable id
    // ... execute
}
```

### 6.2 Defense in Depth

| Weakness | Fix |
|----------|-----|
| Permissionless entrypoint inherited from Axelar express pattern | Add `onlyAuthorizedRelayer`; never re-expose a gateway-gated function ungated |
| Delegate decoded from calldata | Make trusted delegate/operator `immutable` or store in an owner-controlled registry; never `abi.decode` identity from caller input |
| Hardcoded "secret" string in verified source | Remove entirely; authenticate via `msg.sender` or EIP-712 signatures over a nonce, not constants |
| Module can move unlimited funds | Per-Safe spending caps, destination allow-lists, and rate limits inside the module |
| No way to neutralize a bad module | Encourage Safes to use Guard contracts and to periodically audit `getModules()`; provide an emergency `disable`/pause path |
| Swap target unbounded | Whitelist DEX router targets; reject arbitrary swap calldata destinations |

### 6.3 Operational

- **Safe owners**: audit enabled modules (`getModules()`), disable any third-party module not from a vetted, audited source. Enabling a module grants signature-free spend authority — treat it like granting an unlimited approval.
- **Integrators**: never deploy a module that re-exposes Axelar's `expressExecuteWithToken()` shape without the gateway in front of it.

---

## 7. Lessons Learned

1. **A Gnosis Safe module is an unlimited, signature-free spender.** Enabling one is equivalent to handing over an unbounded token approval plus arbitrary-call power. Third-party modules must be audited to the same bar as the Safe's own owners.
2. **Never derive *authority* from caller-supplied input.** Input may describe *what* to do; it must never declare *who* is allowed to do it. The authorizing identity must come from `msg.sender` or an immutable/owner-controlled registry.
3. **"Verified source" is not "secret."** A hardcoded string in verified, public source authenticates nobody. Real authentication uses `msg.sender`, immutables, or signed nonces.
4. **Inheriting a permissionless pattern requires re-adding the guard.** Axelar's express-execute is safe *because the gateway gates the caller*. Re-exposing that function in a standalone module without an equivalent guard removes the only thing that made it safe.
5. **Naming is not endorsement.** A contract named "SquidRouterModule" was not a Squid product; Squid's core router and user approvals were never at risk. Attribution matters — incident scope should be pinned to the actually-vulnerable contract, not the brand it borrowed.
6. **Confused-deputy bugs scale with the deputy's privilege.** The same unverified-input pattern that merely loses a router's transient funds becomes a multi-Safe drain when the deputy can spend on behalf of 88 organizations.

---

## 8. On-Chain Verification

### 8.1 Transaction Hashes — Synthetic Source-List Hashes vs. Real Drain Txs

> **The two transaction hashes originally listed in the incident source are FABRICATED and were NOT found on-chain.** They must not be cited as evidence. Real drain tx hashes have since been published by Common Prefix and QuillAudits.

| Hash | Source | Status |
|------|--------|--------|
| `0xcd864ec4550cb735b1a155aafc6293b8cdd1b0e6fb2524ff6a5c0d5c48787baa` | Original source list | **Synthetic — not found on-chain** |
| `0x39e52302c53e862fcf833b61eb851ff66e098e3d29db19fd66e5a04734eeb84b` | Original source list | **Synthetic — not found on-chain** |
| [`0x8de614bdb7acf5dcbdfe5ce8ed17ec2a2058e7708e6a4cf44f0e523c72df24c3`](https://etherscan.io/tx/0x8de614bdb7acf5dcbdfe5ce8ed17ec2a2058e7708e6a4cf44f0e523c72df24c3) | Common Prefix report | **Real example drain tx** |
| [`0x59d17fd31e31959b2d562508bf91c4fc1271682ba7d61a6209865e1151b69aea`](https://etherscan.io/tx/0x59d17fd31e31959b2d562508bf91c4fc1271682ba7d61a6209865e1151b69aea) | QuillAudits report | **Real example drain tx** |

### 8.2 Verified Addresses

| Role | Address | Notes |
|------|---------|-------|
| Vulnerable module | [0x1f1d37a3Bf840e35c6a860c7C2dA71Fe555123ca](https://basescan.org/address/0x1f1d37a3Bf840e35c6a860c7C2dA71Fe555123ca) | Verified source on BaseScan; deployed identically on ETH / Base / ARB |
| Attacker wallet 1 | [0x7c82cb4b…0a23bb8](https://etherscan.io/address/0x7c82cb4b2909c50c7c0f2b696eee7565e0a23bb8) | Tornado-funded |
| Attacker wallet 2 | [0x9bdc7301…fa645b91](https://etherscan.io/address/0x9bdc730183821b6bb2b51be30b77c964fa645b91) | Tornado-funded |
| Receiver | [0xa447f717…7aa54859](https://etherscan.io/address/0xa447f71782135ab96a71374271a749ff7aa54859) | Drain proceeds destination |
| Attacker contract (ETH) | [0xfac74596…5dc8760c](https://etherscan.io/address/0xfac7459683cdb9b6f367b42eedfebd745dc8760c) | Ethereum; batching/swaps |
| Attacker contract (ETH, 2nd) | [0xe1d5fcfb…3265a](https://etherscan.io/address/0xe1d5fcfbba4d46f4937de369de415dd7e2d3265a) | Corroborated by Common Prefix |
| Attacker contract (Base) | [0x2d450322…70bc](https://basescan.org/address/0x2d450322e3526f489afcc8c49923b35d355c70bc) | Corroborated by Common Prefix |
| Direct caller | [0x7e54c729…1271](https://etherscan.io/address/0x7e54c729148a95bca651f3214ac9ebefd3fb1271) | Corroborated by Common Prefix |
| Secondary operator | [0xc8ef4003…3e4](https://etherscan.io/address/0xc8ef4003d9db3863b9af26afcf2275378bfa83e4) | Corroborated by Common Prefix |
| PermissionsManager / delegate registry | [0x03B8B1bA…cB7](https://etherscan.io/address/0x03B8B1bA6B02b8A566cB757DFa627f7198c44cB7) | Corroborated by Common Prefix |
| "u" junk token (paid to victims) | [0xe6Ff0FE0…512](https://etherscan.io/address/0xe6Ff0FE017D09D690493deC0F0f55E8f9Cdc3512) | Worthless token sent post-drain |
| **Squid core router (UNAFFECTED)** | [0xce16F693…D666](https://etherscan.io/address/0xce16F69375520ab01377ce7B88f5BA8C48F8D666) | No loss; user approvals safe |

### 8.3 Funding & Consolidation

| Field | Value |
|-------|-------|
| Funding source | Tornado Cash (~2.1 ETH) |
| Victim Safes | 88 across ETH / Base / ARB |
| Transactions | 313 over ~2 hours (Base 132, ETH 125, ARB 51) |
| Consolidation asset | DAI (via Uniswap V3) |
| Canonical loss | $3,978,833 (~$3.98M) — Base ~$2,814,305, ETH ~$1,083,764, ARB ~$80,765 |

### 8.4 Verification Note

The two original source-list tx hashes were synthetic and are not found on-chain; real example drain txs (`0x8de614bd…` from Common Prefix; `0x59d17fd3…` from QuillAudits) are now linked in §8.1. Module source is verified on BaseScan. Full addresses and the canonical loss figure ($3,978,833 / 88 Safes / 313 txs) are corroborated by the Common Prefix forensic investigation and QuillAudits. Halborn independently reported $3.2M / 86 Safes using a different cut-off methodology.

---

## 9. References

- [Halborn — Explained: The SquidRouterModule Hack (May 2026)](https://www.halborn.com/blog/post/explained-the-squidroutermodule-hack-may-2026)
- [Common Prefix — SquidRouterModule Exploit Investigation](https://www.commonprefix.com/blog/squidroutermodule-exploit-investigation)
- [Coinpedia — $3M Drained from 86 Gnosis Safes in SquidRouterModule Exploit](https://coinpedia.org/news/3m-drained-from-86-gnosis-safes-in-squidroutermodule-exploit/)
- [FinanceFeeds — Squid Says Core Protocol Was Unaffected by $3.2M Safe Exploit](https://financefeeds.com/squid-says-core-protocol-was-unaffected-by-3-2-million-safe-exploit/)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- [CWE-863: Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- Vulnerability class index: [../vulns/arbitrary-call.md](../vulns/arbitrary-call.md)
- Related: [Aperture Finance (2026-01-25)](./2026-01-25_ApertureFinance_UnverifiedInput_ETH.md), [SwapNet (2026-01-25)](./2026-01-25_SwapNet_ArbitraryCall_ARB.md), [Gyro (2026-01-30)](./2026-01-30_Gyro_ArbitraryCall_ARB.md)
