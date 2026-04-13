# Security Incident Analysis: Molt EVM (mEVM) Unauthorized Minting via Fake Spawner

---

## Overview

| Field | Details |
|------|------|
| **Date** | 2026-03-06 19:19:17 UTC |
| **Network** | Base Mainnet (chainId 8453) |
| **Block** | 43,017,705 |
| **TX** | `0xca64f5dc107afb6eb71d612bb7156aa218aaab07b961e0cb83892727e941630a` |
| **Attacker EOA** | `0x5e4C45725b1A7c9D42e903e06AEE90271842bFE4` (nonce: 17) |
| **Fake Spawner** | `0xd1B3C23955C41A4e6Dd9CA3Ccb46F132dE1bb07e` (custom deployment) |
| **Victim Token** | Molt EVM (`mEVM`) `0x225da3d879d379ff6510c1cc27ac8535353f501f` |
| **Attack Function** | `0x131eaa43` (undisclosed custom function) |
| **Unauthorized Mint Amount** | **100,000,000 mEVM** |

---

## Attack Summary

The attacker directly deployed a **fake spawner contract** without going through the Molt EVM protocol's official factory,  
then called the mEVM token's minting function (`mintFromSpawner`) to **illegitimately mint 100 million mEVM tokens**.

The mEVM token's minting access control **only checked whether the caller is a contract** (`msg.sender.code.length > 0`)  
**without verifying whether the spawner was created by the official factory**, allowing any arbitrary contract to mint without limit.

---

## Molt EVM Protocol Architecture

### Normal Operation (Design Intent)

```
[User]
  │
  └─▶ Factory.createMoltling()
        │
        ├─ Deploy new Moltling token (based on moltImplementation code)
        ├─ Create spawner contract (using official code)
        │    allowedTarget = mEVM token
        │    expiresAt = limited future timestamp
        │    authorized_amount = MOLTLING_SUPPLY (= 1,000,000)
        └─ Spawner ownership → granted to user
              │
              └─ User calls spawner → mEVM.mintFromSpawner(user, 1M)
```

### Official Related Contracts

| Role | Address | Description |
|------|------|------|
| mEVM Token | `0x225da3d879d379ff6510c1cc27ac8535353f501f` | Primary token |
| Official Factory | `0x420dd381b31aef6683db6b902084cb0ffece40da` | Moltling creation factory |
| Official Spawner Implementation | `0x509c44e59491094a6782d9108f1c90615387fb46` | Spawner standard code |
| Genesis Deployer | `0x68eccd584cfb83d874c407c27a862d7dca2f9973` | Protocol team |

### mEVM Token Key Constants

| Constant | Value | Meaning |
|------|-----|------|
| `MOLTLING_SUPPLY` | 1,000,000 | Allowed mint amount per moltling |
| `FACTORY_ADDR` | `0x420dd381...` | Official factory address |
| `moltImplementation` | `0x509c44e5...` | Standard spawner bytecode |

---

## Attack Flow

```
Attacker EOA (0x5e4c...)
  │
  ├─[1] Deploy fake spawner contract (bypassing official factory)
  │      0xd1B3C23955C41A4e6Dd9CA3Ccb46F132dE1bb07e
  │      - owner()        = Attacker EOA
  │      - allowedTarget() = mEVM token address
  │      - expiresAt()    = 2026-03-06 20:44:17 UTC (+85 min)
  │      - initialized()  = true
  │
  └─[2] spawner.0x131eaa43(mEVM, attacker, 100_000_000e18)
         │
         └─[3] mEVM.mintFromSpawner(attacker, 100_000_000e18)
                │
                ├─ msg.sender.code.length > 0? → ✅ (spawner is a contract)
                ├─ factory.isAuthorizedSpawner(msg.sender)? → ❌ check missing!
                │
                └─ _mint(attacker, 100_000_000e18) ← unauthorized mint succeeded!
                   Transfer event: 0x0 → attacker, 100,000,000 mEVM
```

---

## Bytecode Comparison: Fake Spawner Confirmation

| Contract | Address | Bytecode MD5 |
|---------|------|--------------|
| **Fake Spawner** (attacker) | `0xd1B3C23955...` | `19dcda3836763082ac6195e0468a0f01` |
| **Official moltImplementation** | `0x509c44e594...` | `bda3553f6cb8a7f30d479d869425c8d9` |

**→ Bytecodes differ = custom deployment that bypassed the official factory**

---

## Fake Spawner Contract Interface

```solidity
// 0xd1B3C23955C41A4e6Dd9CA3Ccb46F132dE1bb07e key functions
contract FakeSpawner {
    function allowedTarget() external view returns (address);  // 0x76c21baa → mEVM address
    function expiresAt() external view returns (uint256);       // 0x76c21baa / 0x8622a689
    function owner() external view returns (address);           // 0x8da5cb5b → Attacker EOA
    function initialized() external view returns (bool);        // 0x63898e2b → true
    function used() external view returns (bool);               // 0x9720d1fc → true (after use)
    
    // Core attack function (undisclosed custom)
    function exploit(
        address token,     // mEVM token address
        address recipient, // token recipient (attacker)
        uint256 amount     // 100,000,000 * 1e18
    ) external;  // selector: 0x131eaa43
}
```

---

## Event Log Analysis

**Only 1 event emitted in the TX:**

| Log | Contract | Event | Details |
|-----|---------|--------|------|
| 0x231 | mEVM (`0x225da3d879`) | `Transfer` | **from:** `0x0` → **to:** Attacker EOA, **amount:** 100,000,000 mEVM |

Transfer from `0x0` = **Mint event** — emitted when `_mint` is called in ERC20.

---

## Root Cause: Missing Access Control in mintFromSpawner

### Vulnerable Code (Inferred)

```solidity
// mEVM Token — VULNERABLE
function mintFromSpawner(address to, uint256 amount) external {
    // ❌ Only checks "is caller a contract", does not verify factory authorization!
    require(msg.sender.code.length > 0, "not contract");
    
    // ❌ The following checks are absent:
    // require(factory.isOfficialSpawner(msg.sender), "unauthorized spawner");
    // require(amount <= MOLTLING_SUPPLY, "exceeds per-moltling limit");
    
    _mint(to, amount);  // unbounded mint executes
}
```

### EXTCODESIZE Pattern Found in mEVM Token Bytecode

```
Position 7764: 333b610f46 57...
  = CALLER(0x33) EXTCODESIZE(0x3b) PUSH2(0x61) 0x0f46 JUMPI(0x57)
  → "if msg.sender has no code → jump to revert"
  
This pattern exists at multiple locations:
  - 0x7764 (presumed mintFromSpawner)
  - 0x8614, 0x9370 (other protected functions)
```

### Missing Validations

| Validation | Current | Required |
|------|------|------|
| Caller = contract | ✅ | ✅ |
| Caller = factory-authorized spawner | ❌ | ✅ |
| Mint amount ≤ MOLTLING_SUPPLY | ❌ | ✅ |
| Spawner expiry not exceeded | ❌ (internal check) | ✅ |
| Spawner single-use limit | ❌ (internal check) | ✅ |

---

## Impact

### Immediate Damage

| Item | Details |
|------|------|
| Unauthorized mint | 100,000,000 mEVM |
| Normal per-moltling limit | 1,000,000 mEVM |
| Excess mint multiplier | **100x** |
| Attacker balance after attack | 0 (transferred to another address) |

### Systemic Damage

- mEVM token **total supply inflated abnormally**  
  - Current total supply: **~5.79 × 10⁵⁸ mEVM** (far exceeding normal supply)
  - This 100M mint is a small fraction, yet the same vulnerability can be exploited repeatedly
- **Token value dilution** for all mEVM holders
- Anyone can deploy a spawner using the same method → repeat minting possible (unlimited attack)

---

## Remediation

### Option 1: Factory Whitelist Registration and Verification

```solidity
// mEVM Token
mapping(address => bool) public officialSpawners;

function mintFromSpawner(address to, uint256 amount) external {
    // ✅ Only allow official spawners created by the factory
    require(officialSpawners[msg.sender], "not authorized spawner");
    // ✅ Prevent exceeding per-moltling limit
    require(amount <= MOLTLING_SUPPLY, "exceeds moltling supply limit");
    _mint(to, amount);
}

// Callable only by Factory
function registerSpawner(address spawner) external onlyFactory {
    officialSpawners[spawner] = true;
}
```

### Option 2: Direct Factory Call Verification

```solidity
// mEVM Token
IFactory public immutable factory;

function mintFromSpawner(address to, uint256 amount) external {
    // Ask factory whether this spawner is valid
    require(factory.isValidSpawner(msg.sender), "invalid spawner");
    _mint(to, amount);
}
```

### Option 3: Spawner Codehash Verification

```solidity
bytes32 public immutable OFFICIAL_SPAWNER_CODEHASH;

function mintFromSpawner(address to, uint256 amount) external {
    // ✅ Verify caller has the same bytecode as the official spawner
    require(msg.sender.codehash == OFFICIAL_SPAWNER_CODEHASH, "invalid spawner code");
    _mint(to, amount);
}
```

---

## Timeline

| Time (UTC) | Event |
|-----------|------|
| 2026-03-06 (~19:00) | Attacker deploys fake spawner contract |
| **2026-03-06 19:19:17** | **Unauthorized mint TX executed (block 43,017,705)** |
| 2026-03-06 20:44:17 | Spawner expiresAt reached (irrelevant after attack completion) |

---

## Comparison: Official vs. Fake Spawner

| Property | Official Spawner | Fake Spawner (Attack) |
|------|-----------|------------------|
| Creator | Official factory (`0x420dd381`) | Attacker EOA direct deployment |
| Bytecode | Matches `moltImplementation` | Custom (differs) |
| Mint limit | MOLTLING_SUPPLY (1,000,000) | Unlimited (100,000,000 used) |
| Factory registration | Yes | No |
| Owner | Moltling creator | Attacker EOA |

---

## Reference Links

- **Phalcon Explorer**: https://app.blocksec.com/phalcon/explorer/tx/base/0xca64f5dc107afb6eb71d612bb7156aa218aaab07b961e0cb83892727e941630a
- **BaseScan TX**: https://basescan.org/tx/0xca64f5dc107afb6eb71d612bb7156aa218aaab07b961e0cb83892727e941630a
- **mEVM Token**: https://basescan.org/token/0x225da3d879d379ff6510c1cc27ac8535353f501f
- **Attack Spawner**: https://basescan.org/address/0xd1B3C23955C41A4e6Dd9CA3Ccb46F132dE1bb07e
- **Official Factory**: https://basescan.org/address/0x420dd381b31aef6683db6b902084cb0ffece40da

---

## Lessons Learned

1. **Checking "is it a contract" alone is insufficient**  
   `msg.sender.code.length > 0` or an EXTCODESIZE check only guarantees the caller is a contract —  
   it does **not** guarantee that it is an **authorized contract**.

2. **Minting privileges must be managed via whitelist**  
   In a factory-spawner-token architecture, the token must **only allow spawners created by the factory**,  
   and this should be managed via an on-chain registry (mapping).

3. **Codehash verification is available**  
   Verifying identical bytecode (`msg.sender.codehash == OFFICIAL_CODEHASH`) is an effective defense mechanism  
   that fundamentally blocks spawner forgery.

4. **Mint amount caps must also be enforced in the token contract**  
   Relying solely on internal spawner limits can be bypassed using a custom spawner.