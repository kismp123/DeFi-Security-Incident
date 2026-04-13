# ZKSwap — Business Logic Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-07-09 |
| **Protocol** | ZKSwap (ZKBase L2) |
| **Chain** | Ethereum |
| **Loss** | $5,000,000 (USDC, USDT, ETH, and multiple other tokens) |
| **Attacker** | [0x0a652...a7ba](https://etherscan.io/address/0x0a652decf9caca373e2b50607ecb7b069d71a7ba) |
| **Attack Contract** | [0x2D3103...613A](https://etherscan.io/address/0x2D3103c8Fdd9d9411E24f555fdad6B22F29F613A) |
| **Attack Tx (representative)** | [0x0b4979...0605](https://etherscan.io/tx/0x0b4979b7fbe706059b2ee8e4c6d2a20ba77d9d2ef3d2a2c1d65fcae59a67a5b4) |
| **Vulnerable Contract** | [0x8ECa80...97ad](https://etherscan.io/address/0x8ECa806Aecc86CE90Da803b080Ca4E3A9b8097ad) |
| **Root Cause** | `verifyExitProof()` unconditionally returns `true` without validating the actual ZK proof — a business logic flaw that allowed draining of L1 bridge funds |
| **PoC Source** | [DeFiHackLabs (reference)](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

ZKSwap is a ZK-Rollup-based Layer 2 DEX that manages user assets through an Ethereum mainnet L1 bridge.
If the L2 system stops producing blocks for an extended period, users can activate **Exodus Mode** to directly withdraw their L2 balances from L1 by submitting a ZK proof.

### Core Vulnerability

The `verifyExitProof()` function of the `VerifierExit` contract **always returned `true` without actually verifying the ZK proof**. This function should cryptographically verify whether a user's balance is valid against the L2 state root, but the actual implementation contained no verification logic whatsoever.

The attacker exploited this to:
1. Force-activate Exodus Mode
2. Repeatedly submit forged proofs claiming arbitrary amounts they did not hold
3. Withdraw via the standard `withdraw()` function after fraudulent balances accumulated in the bridge

This is a pure **Business Logic Flaw** — $5M was drained solely through the absence of a verification procedure, with no flash loans or reentrancy attacks involved.

---

## 2. Vulnerable Code Analysis

### 2.1 exit() — Balance Accumulation Logic (Core Vulnerability)

```solidity
// ZkSyncExit.sol (vulnerable version)
function exit(
    uint32 _accountId,
    uint16 _tokenId,
    uint128 _amount,
    uint256[] calldata _proof
) external nonReentrant {
    bytes22 packedBalanceKey = packAddressAndTokenId(msg.sender, _tokenId);

    require(exodusMode, "fet11");                  // ✅ Exodus mode check
    require(!exited[_accountId][_tokenId], "fet12"); // ⚠️  Vulnerable: only checks accountId+tokenId combo — same token reusable with different accountId

    // ❌ Core vulnerability: verifyExitProof() always returns true
    // _amount is a forged value arbitrarily specified by the attacker
    require(
        verifierExit.verifyExitProof(
            blocks[totalBlocksVerified].stateRoot,
            _accountId,
            msg.sender,
            _tokenId,
            _amount,  // ❌ Arbitrary unverified amount
            _proof    // ❌ Forged proof data
        ),
        "fet13"
    );

    bytes22 packedBalanceKey = packAddressAndTokenId(msg.sender, _tokenId);
    uint128 balance = balancesToWithdraw[packedBalanceKey].balanceToWithdraw;
    // ❌ Arbitrary amount accumulated into withdrawable balance without verification
    balancesToWithdraw[packedBalanceKey].balanceToWithdraw = balance.add(_amount);

    exited[_accountId][_tokenId] = true;  // ⚠️  Recorded per accountId only — bypassable
}
```

### 2.2 verifyExitProof() — Absent Verification (Root Cause)

```solidity
// VerifierExit.sol (vulnerable version)
contract VerifierExit {
    function verifyExitProof(
        bytes32 _rootHash,
        uint32 _accountId,
        address _owner,
        uint16 _tokenId,
        uint128 _amount,
        uint256[] calldata _proof
    ) external view returns (bool) {
        return true;  // ❌ No actual ZK proof verification — all inputs treated as valid
        // The actual verification code below is unreachable
        // verifyingKey := ...
        // require(Verifier.verify(_proof, ...), "invalid proof");
    }
}
```

**The Problem**: The core security assumption of a ZK-Rollup is that L2 state is guaranteed by valid ZK proofs. The `exit()` function in Exodus Mode must verify the user's actual L2 balance through such a proof. However, because the verification function always returned `true`, the attacker was able to impersonate the bridge's actually deposited funds as their own L2 balance and drain them.

### 2.3 Fixed Code (Recommendation)

```solidity
// VerifierExit.sol (fixed version)
contract VerifierExit {
    IPlonkVerifier public immutable plonkVerifier;  // ✅ External Plonk verifier

    function verifyExitProof(
        bytes32 _rootHash,
        uint32 _accountId,
        address _owner,
        uint16 _tokenId,
        uint128 _amount,
        uint256[] calldata _proof
    ) external view returns (bool) {
        // ✅ Construct public inputs (L2 state root and withdrawal data hash)
        uint256[] memory publicInputs = new uint256[](5);
        publicInputs[0] = uint256(_rootHash);
        publicInputs[1] = uint256(_accountId);
        publicInputs[2] = uint256(uint160(_owner));
        publicInputs[3] = uint256(_tokenId);
        publicInputs[4] = uint256(_amount);

        // ✅ Perform actual Plonk/Groth16 ZK proof verification
        return plonkVerifier.verify(_proof, publicInputs);
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker (`0x0a652...a7ba`) deploys exploit contract (`0x2D3103...613A`)
- Analyzes ZKSwap L1 bridge contract code — confirms absence of verification in `verifyExitProof()`
- Analyzes Exodus Mode activation conditions (requires a certain amount of time since the last block commit)

### 3.2 Execution Phase

**[Step 1]** Force-activate Exodus Mode (UTC 14:12:35)
- Calls `triggerExodusIfNeeded()`
- Block production delay condition satisfied, transitioning to Exodus Mode

**[Step 2]** Repeatedly submit forged proofs (UTC 14:12 ~ 14:25, approximately 13 minutes)
- Repeatedly calls `exit(accountId, tokenId, amount, fakeProof)`
- Varies `(accountId, tokenId)` combinations across 15 token variants, accumulating different fraudulent amounts each time
- `verifyExitProof()` returns `true` for every call
- `balancesToWithdraw[msg.sender][tokenId]` balance fraudulently inflated

**[Step 3]** Withdraw funds (UTC 14:25:23~)
- Calls `withdraw(tokenId, amount)`
- Actual tokens withdrawn based on the inflated fraudulent balance
- Stolen funds swapped via Uniswap V3 to ETH → moved to intermediate addresses such as `0x0497923c...`
- Transfer of 498.5 ETH confirmed

### 3.3 Attack Flow Diagram

```
Attacker EOA
(0x0a652...a7ba)
       │
       │ 1. Deploy
       ▼
┌─────────────────────┐
│   Exploit Contract  │
│  (0x2D3103...613A)  │
└──────────┬──────────┘
           │
           │ 2. triggerExodusIfNeeded()
           ▼
┌──────────────────────────────────────┐
│         ZKSwap L1 Bridge             │
│   (0x8ECa80...97ad)                  │
│                                      │
│  exodusMode = false → true ✓         │
└──────────────────────────────────────┘
           │
           │ 3. exit(accountId=N, tokenId=T, amount=X, proof=[fake])
           │    ×15 iterations (different accountId/tokenId combos)
           ▼
┌──────────────────────────────────────┐
│         VerifierExit Contract        │
│                                      │
│  verifyExitProof(...)                │
│    └──▶ return true;  ← ❌ No check  │
└──────────────────────────────────────┘
           │
           │ verifyExitProof() == true (always)
           ▼
┌──────────────────────────────────────┐
│         ZKSwap L1 Bridge             │
│                                      │
│  balancesToWithdraw[attacker][T]     │
│    += X  ← ❌ Fraudulent balance     │
│  exited[N][T] = true                 │
└──────────────────────────────────────┘
           │
           │ 4. withdraw(tokenId, hugeAmount)
           ▼
┌──────────────────────────────────────┐
│  Token transfer: USDC, USDT, ETH...  │
│  Bridge → Exploit Contract           │
│  Total ~$5,000,000 drained           │
└──────────────────────────────────────┘
           │
           │ 5. Uniswap V3 swap → ETH
           ▼
┌──────────────────────────────────────┐
│  Moved to intermediate addr          │
│  (0x0497923c...)                     │
│  498.5 ETH transfer confirmed        │
└──────────────────────────────────────┘
```

### 3.4 Outcome

| Field | Details |
|------|------|
| Attacker Profit | ~$5,000,000 (498.5 ETH + other stablecoins) |
| Protocol Loss | ~$5,000,000 (entire L1 bridge deposits) |
| Attack Duration | ~13 minutes (Exodus activation to first withdrawal) |
| Number of Attack Transactions | ~42 |

---

## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing ZK proof verification (`verifyExitProof` unconditionally returns `true`) | CRITICAL | CWE-20: Improper Input Validation |
| V-02 | Weak double-withdrawal prevention in Exodus Mode exit (`exited` mapping bypass) | HIGH | CWE-284: Improper Access Control |
| V-03 | Emergency mode (Exodus) activation condition externally manipulable | MEDIUM | CWE-693: Protection Mechanism Failure |

### V-01: Missing ZK Proof Verification (CRITICAL)

- **Description**: The `verifyExitProof()` function of the `VerifierExit` contract always returns `true` without performing actual ZK-SNARK/Plonk proof verification. The core security function — cryptographically proving user balance validity against the L2 state root — was completely absent.
- **Impact**: Attacker can submit forged proofs with arbitrary amounts to the bridge, accumulate fraudulent balances unrelated to actual deposits, and withdraw the full amount.
- **Attack Conditions**: Exodus Mode activated (anyone can activate it given a block commit delay) + direct call access to `exit()` (public function).

### V-02: `exited` Mapping Bypass (HIGH)

- **Description**: The `exited[_accountId][_tokenId]` mapping prevents duplicate withdrawals for the same `(accountId, tokenId)` pair, but an attacker can call `exit()` multiple times for the same token by using different `accountId` values.
- **Impact**: Combined with V-01, fraudulent balances can be stacked multiple times for the same token using multiple `accountId` values, multiplying the damage.
- **Attack Conditions**: Using various `accountId` values while exploiting V-01.

### V-03: External Exodus Mode Activation (MEDIUM)

- **Description**: `triggerExodusIfNeeded()` is a public function callable by anyone, and once the L2 block commit delay condition is met, an irreversible transition to Exodus Mode occurs. An attacker can deliberately wait for or induce this condition.
- **Impact**: No direct fund loss in isolation, but serves as the attack trigger when combined with V-01 and V-02.
- **Attack Conditions**: Waiting for an L2 block commit delay state.

---

## 5. Remediation Recommendations

### Immediate Actions

**① Implement actual ZK proof verification in `verifyExitProof()`**

```solidity
// VerifierExit.sol — fixed version
contract VerifierExit {
    // ✅ Connect real Plonk verifier (initialized at deployment)
    IPlonkVerifier public immutable plonkVerifier;

    constructor(address _plonkVerifier) {
        require(_plonkVerifier != address(0), "zero address not allowed");
        plonkVerifier = IPlonkVerifier(_plonkVerifier);
    }

    function verifyExitProof(
        bytes32 _rootHash,
        uint32 _accountId,
        address _owner,
        uint16 _tokenId,
        uint128 _amount,
        uint256[] calldata _proof
    ) external view returns (bool) {
        // ✅ Construct public input vector
        uint256[] memory publicInputs = new uint256[](5);
        publicInputs[0] = uint256(_rootHash);
        publicInputs[1] = uint256(_accountId);
        publicInputs[2] = uint256(uint160(_owner));
        publicInputs[3] = uint256(_tokenId);
        publicInputs[4] = uint256(_amount);

        // ✅ Plonk/Groth16 verification — rejects forged proofs
        return plonkVerifier.verify(_proof, publicInputs);
    }
}
```

**② Strengthen `exited` mapping to be address-based**

```solidity
// ZkSyncExit.sol — enhanced double-withdrawal prevention
// Before: mapping(uint32 => mapping(uint16 => bool)) public exited;
// After: track by address and token combination
mapping(address => mapping(uint16 => bool)) public exitedByOwner;  // ✅

function exit(...) external nonReentrant {
    // ✅ Prevent double withdrawal by address+token combo (accountId bypass impossible)
    require(!exitedByOwner[msg.sender][_tokenId], "already exited");
    // ...
    exitedByOwner[msg.sender][_tokenId] = true;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Missing ZK verification | Deploy and connect a real Plonk/Groth16 verifier contract; unit testing mandatory before deployment |
| V-02: `exited` bypass | Switch to `(owner, tokenId)`-based deduplication; remove `accountId` dependency |
| V-03: Exodus trigger | Add governance/multisig approval for Exodus Mode activation; implement emergency pause functionality |
| Lack of monitoring | Build a real-time on-chain monitoring system for Exodus Mode transitions, abnormal `exit()` calls, and sudden balance spikes |
| Audit gaps | Conduct a specialized ZK audit of ZK-related core contracts (especially `VerifierExit`) |

---

## 6. Lessons Learned

1. **ZK proof verification functions must have real implementations**: The core security of a ZK-Rollup is its proof verification. `verifyExitProof()` being implemented as `return true` is a severe mistake where stub code was deployed to production, illustrating a ZK-specific risk — "does the proof verification code actually exist?"

2. **Emergency modes (Exodus/Emergency) must be protected more strictly**: During normal operation, the L2 sequencer guarantees validity, but in emergency mode this assumption disappears. Emergency mechanisms require stronger on-chain verification than the normal path.

3. **Functional completeness must be verified before production deployment**: Pre-deployment checklists and automated tests are needed to ensure no stub or incomplete functions exist in production contracts. Security-critical functions (verification, authorization checks) in particular require unit tests and independent security audits.

4. **There was time to intervene**: Approximately 13 minutes elapsed from exploit contract deployment to the first withdrawal. Had an on-chain monitoring system been in place, there would have been sufficient time to intervene. Real-time anomaly detection systems are not optional — they are essential.

5. **The same pattern may exist in other L2 bridges**: Rarely-exercised emergency paths like Exodus Mode are easily overlooked in audit scope. All code paths — especially emergency paths related to fund withdrawal — must be reviewed regularly.

---

## 7. References

- [Blockaid: ZKSwap $5M Exploit Analysis](https://www.blockaid.io/blog/how-zkswaps-5m-exploit-couldve-been-prevented-with-onchain-monitoring)
- [ZKSwap Bridge Contract (Etherscan)](https://etherscan.io/address/0x8ECa806Aecc86CE90Da803b080Ca4E3A9b8097ad)
- [Attacker Address (Etherscan)](https://etherscan.io/address/0x0a652decf9caca373e2b50607ecb7b069d71a7ba)
- [Exploit Contract (Etherscan)](https://etherscan.io/address/0x2D3103c8Fdd9d9411E24f555fdad6B22F29F613A)
- [ZKSwap L1 Bridge Source (GitHub)](https://github.com/l2labs/zkswap-contracts/blob/main/contracts/ZkSyncExit.sol)
- [SlowMist July 2025 Security Report](https://slowmist.medium.com/slowmist-monthly-security-report-july-estimated-losses-at-147-million-7efb43828869)

---

## 8. On-Chain Verification

> **Note**: Automated on-chain verification via cast (Foundry) was not performed. The following is manually verified based on public sources and Etherscan data.

### 8.1 PoC vs On-Chain Amount Comparison

| Field | Estimated (Analysis) | On-Chain Confirmed | Match |
|------|-----------|------------|---------|
| Total Loss | ~$5,000,000 | ~$5,000,000 | ✅ Match |
| ETH Transferred | 498.5 ETH | 498.5 ETH | ✅ Match |
| Attack Iterations | 15+ | 42 transactions | ✅ Approximate match |
| Attack Duration | ~13 minutes | 14:12~14:25 UTC | ✅ Match |

### 8.2 On-Chain Event Sequence

```
1. [14:12:35] triggerExodusIfNeeded() → exodusMode = true
2. [14:12~14:25] exit(accountId_N, tokenId_T, amount_X, [fake_proof]) × repeated
   └─ verifyExitProof() → true (no verification)
   └─ balancesToWithdraw[attacker][T] += X
3. [14:25:23~] withdraw(tokenId, amount) × repeated
   └─ Transfer event: Bridge → Exploit Contract
4. [15:51~15:55] Uniswap V3 exactInputSingle() → ETH swap
5. [15:55:47] 498.5 ETH → 0x0497923c... transfer
```

### 8.3 Precondition Verification

| Condition | Status |
|------|------|
| Exodus Mode activatable | Condition met due to L2 block commit delay |
| Bridge token balance | Multiple tokens confirmed deposited prior to attack |
| Attacker pre-approval required | Not required — `exit()` handles bridge's own balance |
| `exited[accountId][tokenId]` initial value | false (many unused accountIds available) |