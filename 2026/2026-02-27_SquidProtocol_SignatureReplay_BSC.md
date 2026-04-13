# Squid Protocol* — Signature Replay Attack Analysis (3 Consecutive Incidents)

> \* The protocol name originates from BSCScan community tags ("Squid Exploiter 1/2/3", based on Tikkala Security Twitter report). The **official protocol name is unconfirmed**.

| Item | Details |
|------|---------|
| **Date** | 2026-02-27 |
| **Protocol** | Squid Protocol* (based on BSCScan community tag, unconfirmed) |
| **Chain** | BNB Chain (BSC) |
| **Total Loss** | **~$179,748 USDT** (3 attacks executed within ~7 hours) |
| **Root Cause** | Signature Replay Attack — nonce `0xf9a0d115` not invalidated after use |
| **Vulnerable Contract (Pool)** | [0x20dbf429...9596](https://bscscan.com/address/0x20dbf42970eb3fabe62615534c4ef15fd4d59596) (UUPS Proxy) |
| **Implementation Contract** | [0x72ed1822...f0e1](https://bscscan.com/address/0x72ed1822262f52115a9cac501f9ebb92a03af0e1) (deployed ~2026-02-28, unverified) |
| **Pool Owner** | [0x22c89137...84Fe](https://bscscan.com/address/0x22c89137525b593Dd2A18434348b550ffA5984Fe) |
| **Required Signatures** | `requiredSignatures()` = 3 |
| **Attack 1 (TX3)** | [0x3d936c59...e475](https://bscscan.com/tx/0x3d936c59c9d446ee222361acc820be47054aea45f9f5fc92482fe973a596e475) — 59,781.25 USDT |
| **Attack 2 (TX1)** | [0x0d9e4478...ca80](https://bscscan.com/tx/0x0d9e4478567aa33dad3bd7c9a79de5f2afc9c7037c026795aa838f5ab834ca80) — 59,974.61 USDT |
| **Attack 3 (TX2)** | [0x91f45260...d784](https://bscscan.com/tx/0x91f4526052060d7137919a8e2bb3ce6c2169e5a376ab002c4745f69841cfd784) — 59,991.77 USDT |

---

## 1. Vulnerability Overview

This attack exploited a single vulnerability — **missing nonce invalidation** — in a multisig withdrawal pool, resulting in a Signature Replay attack.

The pool contract uses a multi-signature verification scheme requiring 3 signatures (`requiredSignatures = 3`) for withdrawals. Although signature data includes a nonce parameter, the contract has a critical flaw: **it does not mark used nonces as 'spent'**.

The attacker obtained a validly signed withdrawal bundle (nonce `0xf9a0d115`) and replayed it across **3 different pools (Pool IDs 15, 5, and 20)** over approximately 7 hours, stealing a total of ~$179,748 USDT.

Notably, the nonce value `0xf9a0d115` = decimal `4,188,066,069` = Unix timestamp **2102-09-18 23:41:09 UTC** — deliberately set as a far-future deadline that effectively never expires.

---

## 2. Vulnerable Code Analysis

### 2.1 Missing Nonce Invalidation (Core Vulnerability)

The pool contract's withdrawal function (`0xc7e36d91`) contains no logic to consume the nonce after signature verification.

**❌ Vulnerable Code (pseudocode):**

```solidity
// Vulnerable withdrawal function — no nonce invalidation
function withdraw(
    uint256 poolId,
    uint256 amount,
    uint256 nonce,        // Acts as deadline/nonce (0xf9a0d115 = year 2102)
    bytes[] calldata signatures
) external {
    // Signature verification: checks for requiredSignatures(3) valid signatures
    require(signatures.length >= requiredSignatures, "insufficient sigs");
    
    bytes32 hash = keccak256(abi.encodePacked(poolId, amount, nonce, msg.sender));
    for (uint i = 0; i < requiredSignatures; i++) {
        address signer = ecrecover(hash, signatures[i]);
        require(isAuthorizedSigner[signer], "invalid signer");
    }

    // ❌ MISSING: usedNonces[nonce] = true is never set
    // ❌ Nonce is never consumed, allowing infinite replay with the same signature bundle

    // Execute fund transfer
    IERC20(usdt).transfer(msg.sender, amount);
    
    emit Withdrawal(poolId, msg.sender, amount, nonce);
}
```

**✅ Fixed Code:**

```solidity
// Fixed withdrawal function — nonce invalidation added
mapping(uint256 => bool) public usedNonces; // ✅ Nonce tracking mapping

function withdraw(
    uint256 poolId,
    uint256 amount,
    uint256 nonce,
    bytes[] calldata signatures
) external {
    // ✅ Check whether nonce has been used
    require(!usedNonces[nonce], "nonce already used");
    
    // Signature verification
    require(signatures.length >= requiredSignatures, "insufficient sigs");
    
    bytes32 hash = keccak256(abi.encodePacked(poolId, amount, nonce, msg.sender));
    for (uint i = 0; i < requiredSignatures; i++) {
        address signer = ecrecover(hash, signatures[i]);
        require(isAuthorizedSigner[signer], "invalid signer");
    }

    // ✅ Mark nonce as 'spent' — prevents replay
    usedNonces[nonce] = true;

    // Execute fund transfer
    IERC20(usdt).transfer(msg.sender, amount);
    
    emit Withdrawal(poolId, msg.sender, amount, nonce);
}
```

The fix comes down to just two lines:
1. `require(!usedNonces[nonce], "nonce already used")` — pre-check
2. `usedNonces[nonce] = true` — invalidation after use

---

## 3. Attack Flow

### 3.1 Preconditions — Signature Bundle Leak

The following conditions must have been met prior to the attack:

1. **Obtaining a valid signature bundle**: A withdrawal signature bundle created by 3 authorized signers was leaked
2. **Nonce selection**: `0xf9a0d115` (= 2102-09-18 timestamp) — a practically permanent nonce that never expires
3. **Prior knowledge** that the signature bundle could be replayed regardless of pool ID

The leak vector for the signature bundle cannot be confirmed from on-chain data alone; possibilities include an insider leak or compromise of an off-chain signing system.

### 3.2 Execution Steps (Each of the 3 Attacks)

**Attack 1 (TX3) — Block 83574859, 01:09:54 UTC**

```
Attacker: 0x8C98770C (EIP-7702 account)
  │
  │  EIP-7702 delegation → 0xa124d385...8b21 (batch execution code)
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│ Step 1: Pool withdrawal call                             │
│ Pool(0x20dbf429).withdraw(poolId=15, nonce=0xf9a0d115)  │
│ → 59,781.25 USDT drained                                │
└─────────────────────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│ Step 2: USDT → WBNB swap                                │
│ PancakeSwap USDT/WBNB LP (0x16b9a828...)                │
│ 59,781.25 USDT ──▶ 95.17 WBNB                          │
└─────────────────────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│ Step 3: WBNB → BNB unwrap                               │
│ WBNB.withdraw(95.17 WBNB) ──▶ 95.17 BNB                │
└─────────────────────────────────────────────────────────┘
```

**Attack 2 (TX1) — Block 83603918, 04:47:51 UTC (~3.6 hours later)**

```
Attacker: 0xd25F4344 (EIP-7702 account)
  │
  │  EIP-7702 delegation → 0xa124d385...8b21 (same batch execution code)
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│ Step 1: Pool withdrawal call                             │
│ Pool(0x20dbf429).withdraw(poolId=5, nonce=0xf9a0d115)   │
│ → 59,974.609375 USDT drained                            │
└─────────────────────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│ Step 2: USDT → WBNB swap                                │
│ PancakeSwap USDT/WBNB LP (0x16b9a828...)                │
│ 59,974.61 USDT ──▶ 94.13 WBNB                          │
└─────────────────────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│ Step 3: WBNB → BNB unwrap                               │
│ WBNB.withdraw(94.13 WBNB) ──▶ 94.13 BNB                │
└─────────────────────────────────────────────────────────┘
```

**Attack 3 (TX2) — Block 83630514, 08:08:34 UTC (~3.3 hours later)**

```
Attacker EOA: 0xc6E82...868e ("Squid Exploiter 1")
  │
  │  Uses router contract (no EIP-7702)
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│ Step 1: Router call                                      │
│ Router(0xEbD571A9).0x2d0cb456(...)                      │
│ → Router forwards withdrawal request to Pool             │
│ (Router subsequently self-destructs and is redeployed)   │
└─────────────────────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│ Step 2: Pool withdrawal                                  │
│ Pool(0x20dbf429).withdraw(poolId=20, nonce=0xf9a0d115)  │
│ → 59,991.77 USDT drained                                │
└─────────────────────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│ Step 3: USDT held (no swap)                              │
│ 59,991.77 USDT retained as-is                           │
└─────────────────────────────────────────────────────────┘
```

### 3.3 Summary Table

| Attack | Block | Time (UTC) | Target Pool ID | Amount Stolen (USDT) | Final Asset |
|--------|-------|-----------|----------------|----------------------|-------------|
| TX3 (1st) | 83,574,859 | 01:09:54 | Pool 15 | 59,781.25 | 95.17 WBNB → BNB |
| TX1 (2nd) | 83,603,918 | 04:47:51 | Pool 5 | 59,974.61 | 94.13 WBNB → BNB |
| TX2 (3rd) | 83,630,514 | 08:08:34 | Pool 20 | 59,991.77 | USDT (no swap) |
| **Total** | | | | **~179,747.63** | |

---

## 4. Transaction Details

### TX3 — First Attack

| Item | Value |
|------|-------|
| **Tx Hash** | [0x3d936c59...e475](https://bscscan.com/tx/0x3d936c59c9d446ee222361acc820be47054aea45f9f5fc92482fe973a596e475) |
| **Block** | 83,574,859 |
| **Time** | 2026-02-27 01:09:54 UTC |
| **Attacker** | [0x8C98770Cba177B55Fd60dfEEd2870cd1dCdB9d40](https://bscscan.com/address/0x8C98770Cba177B55Fd60dfEEd2870cd1dCdB9d40) |
| **Type** | EIP-7702 account (delegation: `0xa124d3858ab98f75534ad9a2a2fbd1cb1f678b21`) |
| **Pool ID** | 15 (0x0f) |
| **Amount Stolen** | 59,781.25 USDT |
| **Output** | 95.17 WBNB (PancakeSwap USDT/WBNB LP `0x16b9a828...`) |

### TX1 — Second Attack

| Item | Value |
|------|-------|
| **Tx Hash** | [0x0d9e4478...ca80](https://bscscan.com/tx/0x0d9e4478567aa33dad3bd7c9a79de5f2afc9c7037c026795aa838f5ab834ca80) |
| **Block** | 83,603,918 |
| **Time** | 2026-02-27 04:47:51 UTC |
| **Attacker** | [0xd25F43449231218C8Be3871073938FCC2202Ab56](https://bscscan.com/address/0xd25F43449231218C8Be3871073938FCC2202Ab56) |
| **Type** | EIP-7702 account (delegation: `0xa124d3858ab98f75534ad9a2a2fbd1cb1f678b21`) |
| **Pool ID** | 5 (0x05) |
| **Amount Stolen** | 59,974.609375 USDT |
| **Output** | 94.13 WBNB (PancakeSwap) |

### TX2 — Third Attack

| Item | Value |
|------|-------|
| **Tx Hash** | [0x91f45260...d784](https://bscscan.com/tx/0x91f4526052060d7137919a8e2bb3ce6c2169e5a376ab002c4745f69841cfd784) |
| **Block** | 83,630,514 |
| **Time** | 2026-02-27 08:08:34 UTC |
| **Attacker EOA** | [0xc6E8210E47602860C97EDc0BD7556641F048868e](https://bscscan.com/address/0xc6E8210E47602860C97EDc0BD7556641F048868e) (BSCScan label: "Squid Exploiter 1") |
| **Router Contract** | [0xEbD571A9C9Cdee56C0c24ab91B0825f820748a29](https://bscscan.com/address/0xEbD571A9C9Cdee56C0c24ab91B0825f820748a29) (self-destructed then redeployed) |
| **Called Function** | `0x2d0cb456` (router relaying withdrawal to pool) |
| **Pool ID** | 20 (0x14) |
| **Amount Stolen** | 59,991.77 USDT |
| **Output** | USDT held as-is (no swap) |

---

## 5. EIP-7702 Analysis

### 5.1 What is EIP-7702?

EIP-7702 is a transaction type that allows an EOA (Externally Owned Account) to temporarily delegate and execute smart contract bytecode. This enables EOAs to leverage smart account features such as batch transactions and gas sponsorship.

### 5.2 Usage in the Attack

The following bytecode is observed at the attacker addresses in TX3 and TX1:

```
0xef0100a124d3858ab98f75534ad9a2a2fbd1cb1f678b21
│    │
│    └─ 0xa124d385...8b21 = delegated implementation contract address
│
└─ 0xEF 0x01 0x00 = EIP-7702 delegation designator
```

| Attacker Address | EIP-7702 Delegation Target |
|-----------------|---------------------------|
| `0x8C98770C...9d40` (TX3) | `0xa124d3858ab98f75534ad9a2a2fbd1cb1f678b21` |
| `0xd25F4344...Ab56` (TX1) | `0xa124d3858ab98f75534ad9a2a2fbd1cb1f678b21` |

Both attackers delegate to the **same implementation contract**, which contains batch execution logic:

```
Batch execution flow (EIP-7702 delegated code):
┌─────────────────────────────────────────────┐
│ (1) Pool.withdraw() — drain USDT            │
│ (2) USDT.transfer() → PancakeSwap           │
│ (3) PancakeSwap swap → receive WBNB         │
│ (4) WBNB.withdraw() → unwrap to BNB         │
└─────────────────────────────────────────────┘
```

EIP-7702 allows an EOA to atomically execute multiple contract calls within a single transaction. This increases attack efficiency and eliminates the risk of failure at intermediate steps.

TX2 (3rd attack) did not use EIP-7702 and instead executed through a separate router contract (`0xEbD571A9...`), which was destroyed via `selfdestruct` after the attack and then redeployed.

---

## 6. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Description |
|----|--------------|----------|-----|-------------|
| V-01 | Signature Replay | **CRITICAL** | [CWE-294](https://cwe.mitre.org/data/definitions/294.html) | Valid signature bundle can be replayed without limit |
| V-02 | Missing Nonce Invalidation | **HIGH** | [CWE-613](https://cwe.mitre.org/data/definitions/613.html) | Used nonces are never marked as 'spent', causing sessions/authentication to never expire |
| V-03 | Far-Future Deadline | **HIGH** | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | Nonce `0xf9a0d115` = 2102 timestamp, effectively permanently valid |

**V-01** is a direct consequence of V-02. If the nonce had been invalidated, the signature replay would have been impossible. V-03 is a contributing factor that maximized the attack window; a reasonable deadline would have limited the damage.

---

## 7. On-Chain Verification

### 7.1 Amount Verification Per Attack

Data extracted from pool event topic `0x71b63ec0f23930009ab7dc4baf363556229effde574a1d1cf26d15ee210e839d` (function name unconfirmed):

| Attack | Event Data Value (hex) | Calculated Amount (USDT, 6 decimals) | Verification |
|--------|------------------------|--------------------------------------|--------------|
| TX3 (Pool 15) | USDT Transfer event | 59,781.25 USDT | `59781250000 / 1e6 = 59,781.25` |
| TX1 (Pool 5) | USDT Transfer event | 59,974.609375 USDT | `59974609375 / 1e6 = 59,974.609375` |
| TX2 (Pool 20) | USDT Transfer event | 59,991.77 USDT | `59991770000 / 1e6 = 59,991.77` |
| **Total** | | **~179,747.63 USDT** | |

### 7.2 Nonce Non-Tracking Verification

On-chain storage slot analysis confirms that **all nonce-related storage slots in the pool contract are `0x00`**:

```
// Pool contract storage query results
// All possible storage slots for nonce 0xf9a0d115
slot = keccak256(abi.encode(0xf9a0d115, <mapping_slot>))

Result: 0x0000000000000000000000000000000000000000000000000000000000000000
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        All slots remain 0 even after 3 attacks — proving nonces are not tracked
```

This means the contract either does not implement a `usedNonces` mapping, or implements it without actually writing values.

### 7.3 Attacker Profit

| Attack | Amount Stolen | Final Asset | Notes |
|--------|--------------|-------------|-------|
| TX3 | 59,781.25 USDT | 95.17 WBNB → BNB | PancakeSwap swap |
| TX1 | 59,974.61 USDT | 94.13 WBNB → BNB | PancakeSwap swap |
| TX2 | 59,991.77 USDT | 59,991.77 USDT | Held without swap |
| **Total** | **~179,747.63 USDT** | **189.30 BNB + 59,991.77 USDT** | |

---

## 8. Remediation Recommendations

### Immediate Actions

```solidity
// === Immediate Action 1: Add nonce invalidation mapping ===
mapping(uint256 => bool) public usedNonces;

modifier onlyUnusedNonce(uint256 nonce) {
    require(!usedNonces[nonce], "nonce already used"); // Reject used nonces
    _;
    usedNonces[nonce] = true; // Invalidate immediately after use
}

function withdraw(
    uint256 poolId,
    uint256 amount,
    uint256 nonce,
    bytes[] calldata signatures
) external onlyUnusedNonce(nonce) {  // ✅ Apply nonce validation modifier
    // ... signature verification and withdrawal logic
}

// === Immediate Action 2: Enforce reasonable deadline ===
require(nonce <= block.timestamp + 7 days, "deadline too far in future");
// If nonce is used as a timestamp-based deadline,
// cap it at 7 days (or an appropriate duration)

// === Immediate Action 3: Bind signature to poolId ===
bytes32 hash = keccak256(abi.encodePacked(
    address(this),    // ✅ Include contract address (prevents cross-contract replay)
    block.chainid,    // ✅ Include chain ID (prevents cross-chain replay)
    poolId,           // ✅ Include pool ID in signature hash
    amount,
    nonce,
    msg.sender
));
```

### Structural Improvements

1. **Adopt EIP-712 Structured Signatures**: Use EIP-712 typed hashing with a `DOMAIN_SEPARATOR` to clearly separate signature domains. This structurally prevents cross-chain and cross-contract replay.

2. **Per-Signer Sequential Nonces**: Use per-signer incremental nonces (`signerNonce[signer]++`) instead of a global nonce to eliminate replay potential at the source.

3. **Withdrawal Limits and Timelocks**: Implement per-transaction withdrawal caps, daily total withdrawal limits, and timelocks for large withdrawals.

4. **Multisig Key Rotation**: Rotate signing keys on a regular schedule and establish a key revocation mechanism for immediate invalidation upon key compromise.

5. **Monitoring and Alerting**: Deploy on-chain/off-chain monitoring systems to detect abnormal withdrawal patterns (repeated use of the same nonce, multiple pool withdrawals in a short time window, etc.).

6. **Audit**: The implementation contract (`0x72ed1822...`) for the UUPS proxy is unverified — source code verification and a professional audit should be conducted immediately.

---

## 9. Lessons Learned

1. **Nonces must be consumed after use.** Including a nonce/deadline parameter in a multisig or off-chain signature-based system is not sufficient to prevent replay. The contract must record used nonces in storage and reject any reuse.

2. **A far-future deadline is effectively no deadline at all.** An expiry as unrealistically distant as nonce `0xf9a0d115` (year 2102) is functionally equivalent to no expiration from a security standpoint. Deadlines must be constrained to a reasonable window aligned with business logic.

3. **Replaying a single signature bundle across multiple pools indicates a failure of signature domain separation.** If the signature hash does not include the pool ID, contract address, and chain ID, a single signature becomes valid in unintended scopes. The EIP-712 `DOMAIN_SEPARATOR` pattern structurally addresses this problem.

4. **EIP-7702 increases the efficiency of attack execution.** With EOAs able to directly execute smart contract logic, attackers can atomically perform withdrawal-swap-unwrap within a single transaction. Protocols must re-evaluate their threat models in EIP-7702 environments.

5. **Unverified contracts are blind spots for community oversight.** Because the implementation contract (`0x72ed1822...`) was unverified on BSCScan, the vulnerability was difficult to discover publicly. Protocols should publish verified source code to maintain user trust and security.

6. **Attackers escalate incrementally.** The 3 attacks were carried out over ~7 hours using different addresses and methods (2 via EIP-7702, 1 via router contract). Had emergency measures been taken immediately after the first attack (pool freeze, signing key revocation), subsequent losses could have been prevented. Real-time monitoring and a rapid incident response framework are essential.