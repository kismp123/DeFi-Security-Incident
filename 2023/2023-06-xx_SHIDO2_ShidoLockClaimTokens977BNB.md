# SHIDO2 Exploit — ShidoLock claimTokens() Second Attack (~977 WBNB)

## Metadata
| Field | Value |
|---|---|
| Date | 2023-06 |
| Project | SHIDO Token (Second Exploit) |
| Chain | BSC |
| Loss | ~977 WBNB |
| Attacker | Address unconfirmed |
| Attack TX | Address unconfirmed |
| Vulnerable Contract | ShidoLock: 0xaF0CA21363219C8f3D8050E7B61Bb5f04e02F8D4 |
| Block | 29,365,171 |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow — lock/claim same transaction) |
| Vulnerability Type | ShidoLock.claimTokens() Second Exploitation — Larger Scale |

## Summary
A second attacker exploited the same ShidoLock vulnerability (claimTokens() without time-lock enforcement) for a larger extraction of ~977 WBNB. The flow was identical: DODO flash loan → swap to SHIDOINU → add liquidity → lockTokens() → claimTokens() → swap SHIDO → WBNB → repay.

## Vulnerability Details
- **CWE-841**: Same root cause as SHIDO exploit (block address unconfirmed): `claimTokens()` could be called immediately after `lockTokens()` without a lock duration check. The second attacker used a larger flash loan (40 WBNB from DPPAdvanced instead of DODO standard) and extracted ~977 WBNB by converting flash-funded LP positions into SHIDO and swapping.

### On-chain Original Code

Source: Bytecode Decompiled

```solidity
// File: SHIDO2_decompiled.sol
contract SHIDO2 {  // ❌

    // Selector: 0x0a56293d
    function lockTokens() external {}  // ❌

    // Selector: 0x48c54b9d
    function claimTokens() external {}  // ❌

    // Selector: 0x608c3781
    function userShidoV2(address account) external {}

    // Selector: 0xa49f4126
    function userShidoV1(address account) external {}

    // Selector: 0xb544bf83
    function lockTimestamp() external {}  // ❌

    // Selector: 0xbeb31d9d
    function shidoV1() external {}

    // Selector: 0xce091bde
    function shidoV2() external {}

    // Selector: 0xfb75b2c7
    function rewardWallet() external {}

}

// ...

    function lockTokens() external {}  // ❌

// ...

    function claimTokens() external {}  // ❌

// ...

    function lockTimestamp() external {}  // ❌
```

## Attack Flow (from testExploit())
```solidity
// 1. DPPAdvanced.flashLoan(WBNB, 40 ether, ...)
// 2. DPPFlashLoanCall():
//    a. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
//          39 WBNB → SHIDOInu
//       )
//    b. WETH.withdraw(0.01 ether) → native BNB
//    c. AddRemoveLiquidity.addLiquidityETH{value: 0.01 ether}(SHIDOInu, ...)
//    d. ShidoLock.lockTokens(lpAmount)
//    e. ShidoLock.claimTokens()
//       → issues SHIDO tokens immediately (no time check)
//    f. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
//          SHIDO → WBNB
//       )
// 3. Repay 40 WBNB to DPPAdvanced
// 4. Total extracted: ~977 WBNB
```

## Interfaces from PoC
```solidity
interface IShidoLock {
    function lockTokens(uint256 amount) external;
    function claimTokens() external;
}

interface IDPPOracle {
    function flashLoan(
        uint256 baseAmount, uint256 quoteAmount,
        address assetTo, bytes calldata data
    ) external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| SHIDO Token | 0xa963eE460Cf4b474c35ded8fFF91c4eC011FB640 |
| SHIDOINU | 0x733Af324146DCfe743515D8D77DC25140a07F9e0 |
| ShidoLock | 0xaF0CA21363219C8f3D8050E7B61Bb5f04e02F8D4 |
| DPPAdvanced | 0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d |
| AddRemoveLiquidityForFeeOnTransferTokens | 0x9869674E80D632F93c338bd398408273D20a6C8e |
| WBNB | 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c |
| PancakeRouter | 0x10ED43C718714eb63d5aA57B78B54704E256024E |

## Root Cause
Identical to first SHIDO exploit: `claimTokens()` had no minimum lock duration. The contract was not patched between the two attacks, allowing the vulnerability to be exploited a second time for ~977 WBNB.

## Fix
Same as SHIDO first exploit — enforce `MIN_LOCK_DURATION = 30 days` in `claimTokens()` and verify `block.timestamp >= lockedAt + MIN_LOCK_DURATION`.

## References
- BSC block 29,365,171
- ShidoLock: 0xaF0CA21363219C8f3D8050E7B61Bb5f04e02F8D4
- Second exploit: ~977 WBNB extracted