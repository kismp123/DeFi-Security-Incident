# Wormhole Bridge — Signature Verification Bypass / Fake VAA Mint Analysis

| Field | Details |
|------|------|
| **Date** | 2022-02-02 |
| **Protocol** | Wormhole Bridge |
| **Chain** | Solana (exploit) → Ethereum (withdrawal) |
| **Loss** | ~$320,000,000 (120,000 wETH minted without ETH backing) |
| **Attacker** | [0x629e7da20197a5429d30da36e77d06cdf796b71a](https://etherscan.io/address/0x629e7da20197a5429d30da36e77d06cdf796b71a) |
| **Vulnerable Contract** | Wormhole Solana Core Bridge (instruction deserialization) |
| **Root Cause** | The Solana bridge accepted a deprecated `secp256k1_program` instruction as a valid guardian signature verification substitute — an attacker-controlled sysvar was trusted, allowing a forged VAA (Verified Action Approval) to be accepted without real guardian signatures |
| **CWE** | CWE-345: Insufficient Verification of Data Authenticity |
| **PoC Source** | Certus One / Jump Crypto post-mortem; no public DeFiHackLabs PoC (Solana) |

---
## 1. Vulnerability Overview

Wormhole is a cross-chain messaging and token bridge that uses a set of 19 "guardian" nodes to attest to messages via signatures. On Solana, the bridge contract verified guardian signatures by calling the Solana `secp256k1_program` (a native program for ECDSA verification). 

A critical vulnerability existed in how the Solana bridge validated these signature-verification instructions. The contract accepted a **deprecated code path** that allowed an attacker to submit a crafted instruction set pointing to an attacker-controlled sysvar account instead of the real signature verification results. Because the deprecated path did not properly authenticate the source of the verification data, the bridge accepted the forged VAA as legitimately signed by guardians.

Using this forged VAA, the attacker minted 120,000 wETH on Solana without locking any real ETH on Ethereum. The attacker then used the fraudulently minted wETH to withdraw 93,750 ETH from the Ethereum side of the bridge and swapped the remaining Solana-side wETH for other assets.

---
## 2. Vulnerable Code Analysis

**Language**: Rust (Solana BPF program, not EVM/Solidity)
**Source provenance**: Pre-patch vulnerable line confirmed by Kudelski Security, Halborn, and CertiK post-mortems. The current live repository (`wormhole-foundation/wormhole`) already contains the patched version. The complete post-patch `verify_signatures` function is reproduced below from the real source at `solana/bridge/program/src/api/verify_signature.rs`; the single vulnerable line is annotated to show what the pre-patch code contained.

Real source repository: https://github.com/wormhole-foundation/wormhole/blob/main/solana/bridge/program/src/api/verify_signature.rs

### Account and Data Structures (real source)

```rust
// File: solana/bridge/program/src/api/verify_signature.rs
// Language: Rust (Solana solitaire framework)

#[derive(FromAccounts)]
pub struct VerifySignatures<'b> {
    /// Payer for account creation
    pub payer: Mut<Signer<Info<'b>>>,
    /// Guardian set of the signatures
    pub guardian_set: GuardianSet<'b, { AccountState::Initialized }>,
    /// Signature Account
    pub signature_set: Mut<Signer<SignatureSet<'b, { AccountState::MaybeInitialized }>>>,
    /// Instruction reflection account (special sysvar)
    pub instruction_acc: Info<'b>,  // ← caller-supplied; see vulnerability below
}

#[derive(Default, BorshSerialize, BorshDeserialize)]
pub struct VerifySignaturesData {
    /// instruction indices of signers (-1 for missing)
    pub signers: [i8; MAX_LEN_GUARDIAN_KEYS],
}
```

### The Vulnerable Function (pre-patch vs. patched)

```rust
// PRE-PATCH (vulnerable) — as deployed on mainnet at time of exploit:
// Source: Kudelski Security / Halborn / CertiK post-mortem analysis
pub fn verify_signatures(
    ctx: &ExecutionContext,
    accs: &mut VerifySignatures,
    data: VerifySignaturesData,
) -> Result<()> {
    // ...
    let secp_ix_index = (current_instruction - 1) as u8;

    // ❌ VULNERABLE: load_instruction_at is DEPRECATED and does NOT validate
    //    that accs.instruction_acc is the real Instructions sysvar account.
    //    An attacker can pass any account they control as instruction_acc,
    //    pre-populated with fake secp256k1 instruction data.
    let secp_ix = solana_program::sysvar::instructions::load_instruction_at(
        secp_ix_index as usize,
        &accs.instruction_acc.try_borrow_mut_data()?,  // ❌ sysvar identity never checked
    )?;

    // ❌ The program_id check below runs on attacker-supplied data,
    //    so an attacker crafts their fake account to contain a secp256k1 program_id.
    if secp_ix.program_id != solana_program::secp256k1_program::id() {
        return Err(InvalidSecpInstruction.into());
    }

    // ... signature parsing proceeds on forged data ...

    // ❌ Guardian signatures marked as verified using forged secp instruction data
    accs.signature_set.signatures[s.signer_index as usize] = true;

    Ok(())
}
```

```rust
// POST-PATCH (fixed) — actual code now in the live wormhole repository:
// https://github.com/wormhole-foundation/wormhole/blob/main/solana/bridge/program/src/api/verify_signature.rs
pub fn verify_signatures(
    ctx: &ExecutionContext,
    accs: &mut VerifySignatures,
    data: VerifySignaturesData,
) -> Result<()> {
    accs.guardian_set.verify_derivation(ctx.program_id, &(&*accs).into())?;

    let current_instruction =
        solana_program::sysvar::instructions::load_current_index_checked(&accs.instruction_acc)?;
    if current_instruction == 0 {
        return Err(InstructionAtWrongIndex.into());
    }

    let secp_ix_index = (current_instruction - 1) as u8;

    // ✅ FIXED: load_instruction_at_checked validates that accs.instruction_acc
    //    is the REAL Instructions sysvar — an attacker-controlled account is rejected.
    let secp_ix = solana_program::sysvar::instructions::load_instruction_at_checked(
        secp_ix_index as usize,
        &accs.instruction_acc,   // ✅ account identity is now validated by the runtime
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    // ✅ Now this check is meaningful: the data truly came from the secp256k1 native program
    if secp_ix.program_id != solana_program::secp256k1_program::id() {
        return Err(InvalidSecpInstruction.into());
    }

    // ... remainder of parsing and signature recording unchanged ...
    Ok(())
}
```

**Why it is exploitable (identify the bug from the code):**

- `load_instruction_at` (the pre-patch call) is a **deprecated Solana sysvar helper** that reads instruction data from a caller-supplied account buffer **without verifying that the account is the real `Instructions` sysvar**. Any account owned by the attacker can be substituted.
- The attacker created an account whose data matched the expected secp256k1 instruction layout, including a `program_id` field set to `secp256k1_program::id()` — satisfying the program-ID check that follows.
- With the forged data accepted, the loop at the end sets `accs.signature_set.signatures[guardian_index] = true` for each forged guardian entry, marking the signature set as fully verified by all guardians.
- `complete_wrapped()` (the VAA redemption instruction) only checks that a valid `SignatureSet` account exists with sufficient `true` entries — it does not re-verify cryptographic signatures. With the signature set forged, the attacker minted 120,000 wETH on Solana without locking any ETH on Ethereum.
- The fix is a single function rename: `load_instruction_at` → `load_instruction_at_checked`. The `_checked` variant validates the sysvar account's address against the runtime, making account substitution impossible.

---
## 3. Attack Flow

```
Attacker (Solana)
    │
    ├─[1] Craft a transaction that calls Wormhole's verify_signatures
    │       with a forged instruction_sysvar account the attacker controls
    │       (deprecated code path accepted non-native sysvar)
    │
    ├─[2] Wormhole bridge accepts the forged VAA as guardian-approved
    │       → SignatureSet account marked as fully verified
    │
    ├─[3] Call complete_wrapped() with the forged VAA
    │       → Bridge mints 120,000 wETH on Solana (no ETH locked on Ethereum side)
    │
    ├─[4] Transfer 93,750 wETH back across the bridge to Ethereum
    │       → Withdraw 93,750 real ETH from Ethereum bridge contract
    │
    ├─[5] Swap remaining ~26,250 wETH on Solana for USDC and SOL
    │
    └─[6] Total loss: ~$320M (120,000 ETH equivalent)
```

---
## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Signature verification bypass via deprecated instruction path (forged VAA) |
| **CWE** | CWE-345: Insufficient Verification of Data Authenticity |
| **OWASP DeFi** | Bridge authentication bypass |
| **Attack Vector** | Attacker-controlled sysvar substituted in deprecated secp256k1 verification path |
| **Preconditions** | Deprecated code path not removed; sysvar source not validated |
| **Impact** | 120,000 wETH minted without backing; ~$320M drained from Ethereum bridge |

---
## 5. Remediation Recommendations

1. **Remove deprecated code paths immediately**: The deprecated `verify_signatures` path should have been removed or disabled before mainnet deployment.
2. **Validate sysvar program IDs**: Always verify that instruction sysvars originate from the expected native Solana program (e.g., `secp256k1_program::ID`).
3. **Invariant: minted tokens must equal locked tokens**: Cross-chain bridges must enforce a strict 1:1 accounting invariant with on-chain assertions, not just trust VAA validity.
4. **Formal verification**: Cross-chain bridge message authentication is safety-critical and warrants formal verification of the signature check logic.

---
## 6. Lessons Learned

- **One of the largest bridge hacks in DeFi history** (~$320M): Wormhole's loss underscored that cross-chain bridges are extremely high-value targets where even a single signature verification bug has catastrophic consequences.
- **Deprecated code as attack surface**: Leaving deprecated code paths in production — even partially — creates unforeseen attack vectors. Security audits must explicitly check for dead/deprecated paths.
- **Jump Crypto backstop**: Jump Crypto (Wormhole's backer) replenished the 120,000 ETH to make users whole, preventing a complete collapse of the wETH peg.
- **Solana program security model**: Solana's account-based model requires explicit validation of account ownership and program IDs for every account passed to an instruction.
