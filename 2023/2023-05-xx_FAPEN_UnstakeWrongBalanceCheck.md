# FAPEN Exploit — unstake() Wrong Balance Check Allows Draining Contract

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05 |
| Project | FAPEN Token |
| Chain | BSC |
| Loss | ~$600 |
| Attacker | Unconfirmed |
| Attack TX | Unconfirmed |
| Vulnerable Contract | FAPEN: 0xf3F1aBae8BfeCA054B330C379794A7bf84988228 |
| Block | Unconfirmed |
| CWE | CWE-20 (Improper Input Validation — wrong balance check) |
| Vulnerability Type | unstake() Incorrect Balance Validation Enables Full Contract Drain |

## Summary
The FAPEN token's `unstake()` function contained a flawed balance check that validated the wrong balance — likely checking the caller's balance instead of the staked amount, or checking after the transfer rather than before. This allowed the attacker to unstake the entire contract balance regardless of how much they had staked.

## Vulnerability Details
- **CWE-20**: `unstake(uint256 amount)` performed its balance check incorrectly (e.g., `require(balanceOf(address(this)) >= amount)` instead of `require(stakedBalances[msg.sender] >= amount)`). This let any caller specify the full contract balance as `amount` and receive it.

### On-chain Original Code

Source: Bytecode Decompilation

```solidity
// 파일: FAPEN_decompiled.sol
    function balanceOf(address account) external view returns (uint256) {}  // ❌

// ...

    function owner() external view returns (address) {}  // ❌

// ...

    function decreaseAllowance(address account, uint256 value) external {}  // ❌

// ...

    function transfer(address account, uint256 value) external returns (bool) {}  // ❌

// ...

    function allowance(address account, address recipient) external view returns (uint256) {}  // ❌
```

## Attack Flow (from testExploit())
```solidity
// 1. contractBalance = FAPEN.balanceOf(address(FAPEN))
// 2. FAPEN.unstake(contractBalance)
//    → wrong balance check passes (checks contract.balance not caller.staked)
//    → transfers entire FAPEN contract balance to attacker
// 3. Router.approve(address(Router), type(uint256).max)
// 4. Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
//       FAPEN.balanceOf(this), 0, [FAPEN, WBNB], address(this), deadline
//    )  → swap FAPEN → BNB
```

## Interfaces from PoC
```solidity
interface IFAPEN is IERC20 {
    function unstake(uint256 amount) external;
}

interface Uni_Router_V2 {
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| FAPEN Token | 0xf3F1aBae8BfeCA054B330C379794A7bf84988228 |
| WBNB | 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c |
| PancakeRouter | 0x10ED43C718714eb63d5aA57B78B54704E256024E |

## Root Cause
`unstake()` validated the contract's FAPEN balance rather than the individual staker's recorded stake, allowing any address to claim the full contract balance.

## Fix
```solidity
mapping(address => uint256) public stakedBalance;

function unstake(uint256 amount) external {
    require(stakedBalance[msg.sender] >= amount, "Insufficient staked balance");
    stakedBalance[msg.sender] -= amount;
    IERC20(token).safeTransfer(msg.sender, amount);
}
```

## References
- BSC FAPEN: 0xf3F1aBae8BfeCA054B330C379794A7bf84988228
- PancakeRouter: 0x10ED43C718714eb63d5aA57B78B54704E256024E