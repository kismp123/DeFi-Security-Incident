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

> ⚠️ Contract not verified on Sourcify — source unavailable. Wormhole is a Solana program (non-EVM, written in Rust). The behavior below is reconstructed from the Certus One / Jump Crypto post-mortem and on-chain traces, not verified source.

The exploit targeted the Solana-side `verify_signatures` instruction in the Wormhole Core Bridge program (written in Rust / Anchor). The program is not an EVM contract and is not indexed by Sourcify.

**Reconstructed logic (labeled — not verified source):**

```rust
// ⚠️ RECONSTRUCTED — not verified Rust source
// Real language: Rust (Solana Anchor program)
// Vulnerability: deprecated code path accepted attacker-supplied sysvar account

fn verify_signatures(ctx: Context<VerifySignatures>, data: VerifySignaturesData) -> Result<()> {
    // ❌ Used a deprecated helper that read from ctx.accounts.instruction_sysvar
    //    without verifying the preceding instruction genuinely came from
    //    the native secp256k1_program (program ID: KeccakSecp256k11HDMpKqnYnvyd...).
    //    An attacker-controlled account could be passed as instruction_sysvar.
    let secp_ix = &ctx.accounts.instruction_sysvar.load()?; // ❌ source of secp_ix never validated
    // ❌ No check: secp_ix.program_id == solana_program::secp256k1_program::ID
    validate_secp256k1_results(secp_ix, &data.signers)?;
    // ❌ signature_set account is now marked fully verified using forged data
    Ok(())
}
```

**Why it is exploitable (identify the bug from the code):**
- The deprecated path read signature verification results from `instruction_sysvar` without asserting the preceding instruction was from the real `secp256k1_program` native program.
- An attacker crafted a transaction providing an attacker-controlled account as `instruction_sysvar`, pre-populated with forged guardian signature data that passed `validate_secp256k1_results`.
- The resulting `SignatureSet` was accepted by `complete_wrapped()` as guardian-approved, allowing 120,000 wETH to be minted on Solana with zero ETH locked on Ethereum.

```rust
// ✅ Fix (as deployed in post-exploit patch):
fn verify_signatures_fixed(ctx: Context<VerifySignatures>, data: VerifySignaturesData) -> Result<()> {
    let secp_ix = get_instruction_relative(-1, &ctx.accounts.instruction_sysvar)?;
    // ✅ Verify the preceding instruction is from the real secp256k1 native program
    require!(
        secp_ix.program_id == solana_program::secp256k1_program::ID,
        WormholeError::InvalidSysvar
    );
    validate_secp256k1_results(&secp_ix, &data.signers)?;
    Ok(())
}
```

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
