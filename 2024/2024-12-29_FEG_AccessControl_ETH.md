# FEG (Feed Every Gorilla) — Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-12-29 |
| **Protocol** | FEG (Feed Every Gorilla) |
| **Chain** | Ethereum (+ BSC, Base integration) |
| **Loss** | ~$1,000,000 (Ethereum chain alone ~$98,842 · total across 3 chains ~$1.3M) |
| **Attacker** | [0xcb96...0b3c](https://etherscan.io/address/0xcb96dde53f43035f7395d8dbdb652987f7630b3c) |
| **Attack Contract** | [0xEf7B...fDa](https://etherscan.io/address/0xEf7Bd1543bDAcAdD7e42822e3F15Dd0af0410fDa) |
| **Attack Tx** | [0x6c3c...1759](https://etherscan.io/tx/0x6c3cf48e9c8b22f60fc2b702b03f93926ee8624639b100fe851b757947e61759) |
| **Vulnerable Contract** | [FEG SmartBridge Relayer 0x8d5c...6243](https://etherscan.io/address/0x8d5c8d2856d518a5edc7473a3127341492b56243) |
| **FEG Token** | [0xf3c7...79ac](https://etherscan.io/address/0xf3c7cecf8cbc3066f9a87b310cebe198d00479ac) |
| **Root Cause** | Missing source address validation on cross-chain messages (access control flaw) |
| **Attack Block** | 21,506,154 |
| **References** | [CertiK Analysis](https://www.certik.com/resources/blog/feg-bridge-exploit-technical-analysis) · [Halborn Analysis](https://www.halborn.com/blog/post/explained-the-feed-every-gorilla-feg-hack-december-2024) |

---

## 1. Vulnerability Overview

The FEG protocol's SmartBridge supports cross-chain FEG token transfers between Ethereum, BSC, and Base via a Wormhole relayer. This relayer (`0x8d5c8d28`) is designed to receive bridge messages and, if the `user` field in the message matches the admin address, call `setAdmin(address, bool)` to update the whitelist.

**Core Flaw**: When the relayer processes Wormhole bridge messages, it does not verify whether the message's **sourceAddress** is actually a trusted address. As a result, an attacker could craft a forged Wormhole message from another chain (Base) to:

1. Register their own contract on the whitelist
2. Register a large FEG withdrawal via `registerWithdraw` against the bridge contract
3. Withdraw approximately 57.5 trillion FEG without any actual deposit and swap it for ETH

This vulnerability did not stem from Wormhole itself but from the absence of message validation logic in FEG, and the FEG token price collapsed by 99%.

---

## 2. Vulnerable Code Analysis

### 2.1 Missing Source Address Validation — Whitelist Hijacking (Core Vulnerability)

```solidity
// ❌ Vulnerable code (estimated FEG SmartBridge Relayer logic)
function receiveWormholeMessages(
    bytes memory payload,
    bytes[] memory additionalVaas,
    bytes32 sourceAddress,       // ❌ No validation — arbitrary address accepted
    uint16 sourceChain,
    bytes32 deliveryHash
) external onlyWormholeRelayer {
    // Decode payload to extract user and sourceAddress
    (address user, address srcAddr, /* ... */) = abi.decode(payload, (address, address, /* ... */));

    // ❌ Critical vulnerability: if user matches admin, unconditionally whitelist sourceAddress
    // No check that sourceAddress is actually a trusted FEG bridge address
    if (user == admin) {
        _setAdmin(srcAddr, true);   // ❌ Attacker address added to whitelist
    }
}
```

```solidity
// ✅ Fixed code
// Mapping of trusted source addresses
mapping(uint16 => bytes32) public trustedSourceAddresses;

function receiveWormholeMessages(
    bytes memory payload,
    bytes[] memory additionalVaas,
    bytes32 sourceAddress,
    uint16 sourceChain,
    bytes32 deliveryHash
) external onlyWormholeRelayer {
    // ✅ First validate that sourceAddress is trusted for this source chain
    require(
        trustedSourceAddresses[sourceChain] == sourceAddress,
        "Untrusted source address"
    );

    (address user, address srcAddr, /* ... */) = abi.decode(payload, (address, address, /* ... */));

    // ✅ Admin changes require additional signature or governance approval
    if (user == admin) {
        require(_verifyAdminSignature(srcAddr, payload), "Invalid admin signature");
        _setAdmin(srcAddr, true);
    }
}
```

**Issue**: The Wormhole relayer only guarantees message delivery integrity; it is the responsibility of the receiving contract to verify whether the source address is trusted. The FEG relayer omitted this check, allowing messages from arbitrary chains to be treated as admin messages.

---

### 2.2 Unvalidated Withdrawal Registration — Creating Balance From Nothing

```solidity
// ❌ Vulnerable code (registerWithdraw)
function registerWithdraw(
    address recipient,
    uint256 amount,
    uint16 sourceChain,
    uint256 depositId
) external {
    // ❌ Executable as long as msg.sender is on the whitelist
    // No 1:1 verification against an actual deposit
    require(admin[msg.sender], "Not admin");

    // ❌ Register arbitrary amount to withdrawal balance
    withdrawBalance[recipient] += amount;

    emit WithdrawRegistered(recipient, amount, sourceChain, depositId);
}
```

```solidity
// ✅ Fixed code
mapping(bytes32 => bool) public processedDeposits;

function registerWithdraw(
    address recipient,
    uint256 amount,
    uint16 sourceChain,
    uint256 depositId,
    bytes32 depositProof   // ✅ Add actual deposit proof from source chain
) external {
    require(admin[msg.sender], "Not admin");

    // ✅ Prevent duplicate processing of the same depositId
    bytes32 depositKey = keccak256(abi.encodePacked(sourceChain, depositId));
    require(!processedDeposits[depositKey], "Already processed");
    processedDeposits[depositKey] = true;

    // ✅ Verify deposit event on source chain via Merkle proof or equivalent
    require(
        _verifyDepositProof(sourceChain, depositId, recipient, amount, depositProof),
        "Invalid deposit proof"
    );

    withdrawBalance[recipient] += amount;
    emit WithdrawRegistered(recipient, amount, sourceChain, depositId);
}
```

**Issue**: Anyone on the whitelist could add an arbitrary amount to `withdrawBalance`. There was no verification against an actual deposit transaction on the source chain.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker (0xcb96...0b3c) deploys attack contract (0xEf7B...fDa)
- Prepares two forged Wormhole messages from the Base chain:
  - **Message 1**: `user = FEG datareader admin`, `sourceAddress = attacker contract` → for whitelist registration
  - **Message 2**: `registerWithdraw` call command → for inflating withdrawal balance

### 3.2 Execution Phase

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         FEG SmartBridge Exploit                              │
│                         2024-12-29 Block #21,506,154                         │
└──────────────────────────────────────────────────────────────────────────────┘

Step 1: Whitelist Hijacking (Base → Ethereum)
┌─────────────────────────┐      Wormhole VAA       ┌──────────────────────────┐
│  Attacker Contract      │ ──────────────────────▶ │  FEG SmartBridge Relayer │
│  (Base chain)           │  user = admin address   │  0x8d5c...6243           │
│  0xe7ba...03c           │  src = attacker contract│                          │
└─────────────────────────┘                          │  setAdmin(attacker,true) │
                                                     │  ← executed without      │
                                                     │    validation ❌         │
                                                     └──────────────────────────┘

Step 2: Withdrawal Balance Registration (Base → Ethereum)
┌─────────────────────────┐      Wormhole VAA       ┌──────────────────────────┐
│  Attacker Contract      │ ──────────────────────▶ │  FEG SmartBridge Relayer │
│  (Base chain)           │  registerWithdraw call  │  0x8d5c...6243           │
└─────────────────────────┘  amount = 45.7T FEG     │                          │
                                                     │  withdrawBalance[attacker]│
                                                     │  += 45,715,693,242 FEG  │
                                                     └──────────────────────────┘

Step 3: FEG Withdrawal on Ethereum
┌─────────────────────────┐                          ┌──────────────────────────┐
│  Attack Contract        │ ─── withdraw() ────────▶ │  FEG SmartBridge Relayer │
│  0xEf7B...fDa           │                          │  0x8d5c...6243           │
│  (Ethereum)             │ ◀── 57.5T FEG ───────────│  FEG balance: 5.78e28   │
└─────────────────────────┘                          └──────────────────────────┘
         │
         │ FEG Transfer (Log #2)
         ▼
┌─────────────────────────┐
│  Attack Contract holds  │
│  57,532,022,461 FEG     │  (18 decimals, ~57.5B FEG)
└─────────────────────────┘

Step 4: FEG → ETH Swap on Uniswap V2
┌─────────────────────────┐                          ┌──────────────────────────┐
│  Attack Contract        │ ── FEG swap ───────────▶ │  FEG/WETH Uniswap Pool   │
│  0xEf7B...fDa           │  11.16T FEG sent         │  0x671c...9ed837         │
│                         │ ◀── 68.09 WETH ──────────│  (1st swap)              │
└─────────────────────────┘                          └──────────────────────────┘
         │
         │ Additional swap (Log #17→#18)
         ▼
┌─────────────────────────┐                          ┌──────────────────────────┐
│  Attack Contract        │ ── additional FEG ─────▶ │  FEG/WETH Pool           │
│                         │ ◀── 28.24 WETH ──────────│  0xb803...db20           │
└─────────────────────────┘                          └──────────────────────────┘

Step 5: WETH → ETH Withdrawal and Profit Secured
┌─────────────────────────┐
│  Attacker Profit        │
│  28.24 ETH (Ethereum)   │  ≈ $98,842
│  + BSC & Base profits   │  ≈ $900,000+
│  Total: ~$1,000,000     │
└─────────────────────────┘
         │
         ▼
┌─────────────────────────┐
│  Sent to TornadoCash    │  (money laundering)
└─────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit**: 28.24 ETH on Ethereum + additional profit from BSC/Base chains = ~$1,000,000 total
- **Protocol loss**: FEG bridge balance largely drained, FEG token value down 99%
- **Impact**: All FEG token holders suffered losses; protocol credibility destroyed in its third major hack

---

## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing cross-chain message source address validation | CRITICAL | CWE-20 (Improper Input Validation) |
| V-02 | Access control flaw in whitelist management | CRITICAL | CWE-284 (Improper Access Control) |
| V-03 | Missing deposit-withdrawal 1:1 correspondence validation | HIGH | CWE-345 (Insufficient Verification of Data Authenticity) |
| V-04 | Absence of emergency pause mechanism | MEDIUM | CWE-693 (Protection Mechanism Failure) |

### V-01: Missing Cross-Chain Message Source Address Validation

- **Description**: When receiving a Wormhole message, the contract does not verify that `sourceAddress` is a trusted FEG bridge contract. The Wormhole protocol only guarantees message delivery integrity; trust of the source address is the responsibility of the receiving application.
- **Impact**: An arbitrary attacker can impersonate an "admin-privileged address" from any chain and manipulate the relayer's whitelist.
- **Attack Conditions**: Access to the Wormhole network + ability to craft forged messages

### V-02: Access Control Flaw in Whitelist Management

- **Description**: If the `user` field in a cross-chain message matches the admin address, `setAdmin` is called unconditionally. The admin address within the message payload can be forged.
- **Impact**: Attacker registers their own address on the whitelist, gaining the ability to call `registerWithdraw`.
- **Attack Conditions**: Requires prior exploitation of V-01

### V-03: Missing Deposit-Withdrawal 1:1 Correspondence Validation

- **Description**: `registerWithdraw(address, uint256, uint16, uint256)` allows any whitelisted caller to register an arbitrary `amount` to the withdrawal balance. There is no verification that this corresponds to an actual deposit transaction on the source chain.
- **Impact**: Unlimited withdrawal balance can be created without any real deposit.
- **Attack Conditions**: Requires prior exploitation of V-01 and V-02, with whitelist registration

### V-04: Absence of Emergency Pause Mechanism

- **Description**: No circuit breaker exists to immediately halt bridge operations upon detecting abnormal mass withdrawals.
- **Impact**: No ability to respond during an ongoing attack; damage spreads across all 3 chains.
- **Attack Conditions**: Not a standalone vulnerability but an operational deficiency

---

## 5. Remediation Recommendations

### Immediate Actions

**1) Register trusted source addresses whitelist**

```solidity
// ✅ Register trusted addresses per chain
mapping(uint16 => bytes32) public trustedEmitters;

function setTrustedEmitter(uint16 chainId, bytes32 emitter) external onlyOwner {
    trustedEmitters[chainId] = emitter;
    emit TrustedEmitterSet(chainId, emitter);
}

function receiveWormholeMessages(
    bytes memory payload,
    bytes[] memory additionalVaas,
    bytes32 sourceAddress,
    uint16 sourceChain,
    bytes32 deliveryHash
) external onlyWormholeRelayer {
    // ✅ Validate both source chain and address
    require(
        trustedEmitters[sourceChain] == sourceAddress,
        "Untrusted emitter"
    );
    // ...remaining logic
}
```

**2) Deposit-proof-based withdrawal registration**

```solidity
// ✅ Link with source chain deposit records (e.g., depositId-based tracking)
mapping(bytes32 => bool) public usedDepositIds;

function registerWithdraw(
    address recipient,
    uint256 amount,
    uint16 sourceChain,
    uint256 depositId
) external {
    require(admin[msg.sender], "Not admin");

    bytes32 key = keccak256(abi.encodePacked(sourceChain, depositId));
    require(!usedDepositIds[key], "Deposit already used");
    usedDepositIds[key] = true;

    withdrawBalance[recipient] += amount;
}
```

**3) Withdrawal limits and time delays**

```solidity
uint256 public constant MAX_SINGLE_WITHDRAW = 1_000_000 * 1e18; // e.g., 1M FEG
uint256 public constant WITHDRAW_DELAY = 1 hours;

mapping(address => uint256) public withdrawRequestTime;

function requestWithdraw(uint256 amount) external {
    require(amount <= MAX_SINGLE_WITHDRAW, "Exceeds single withdraw limit");
    withdrawRequestTime[msg.sender] = block.timestamp;
    pendingWithdrawAmount[msg.sender] = amount;
}

function executeWithdraw() external {
    require(
        block.timestamp >= withdrawRequestTime[msg.sender] + WITHDRAW_DELAY,
        "Timelock not expired"
    );
    // Execute actual withdrawal
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Missing source address validation | Use Wormhole `IWormhole.parseAndVerifyVM()` + mandatory emitter verification |
| Whitelist manipulation | Admin change logic requiring multisig (2-of-3 or more) signatures |
| Deposit-withdrawal imbalance | Periodic cross-chain state synchronization verification (reconciliation) |
| Lack of emergency response | Automatic pause + security team notification upon detection of abnormal withdrawals |
| Single relayer | Multiple relayers + threshold-based consensus |

---

## 6. Lessons Learned

1. **Mandatory audit of cross-chain composability**: When using messaging protocols such as Wormhole or LayerZero, the boundary of responsibility between the message delivery layer and the application layer must be clearly defined. Source address trustworthiness, which the messaging protocol does not guarantee, must always be verified directly by the application.

2. **Include composability in audit scope**: FEG SmartBridge had previously been audited, but composability vulnerabilities arising from the Wormhole integration were classified as out of scope. Integration points with external protocols must always be included in the audit scope.

3. **Whitelist changes require the highest level of access control**: Addresses registered on the bridge whitelist have direct access to protocol funds. The logic that modifies this list must be protected by strong safeguards such as multisig, time delays, and governance votes.

4. **Validate deposit-withdrawal invariants**: Bridge contracts must always maintain the invariant "total withdrawals ≤ total deposits." Implement on-chain assertions or periodic checks to enforce this.

5. **Restoring trust in repeatedly hacked protocols**: FEG was hacked twice in 2022 and once in 2024 — three times in total. Adding new features after prior hacks without a fundamental architectural redesign continuously expands the attack surface.

---

## 7. PoC Core Logic (Reconstructed from On-Chain Data)

No official DeFiHackLabs PoC has been confirmed, but the following attack logic has been reconstructed based on on-chain analysis and the CertiK/Halborn reports.

```solidity
// Attack contract core logic (reconstructed, for educational purposes)
// Actual attack contract: 0xEf7Bd1543bDAcAdD7e42822e3F15Dd0af0410fDa

contract FEGAttack {
    IFEGRelayer constant relayer =
        IFEGRelayer(0x8d5c8d2856d518a5edc7473a3127341492b56243);
    IERC20 constant FEG =
        IERC20(0xf3c7cecf8cbc3066f9a87b310cebe198d00479ac);
    IUniswapV2Router constant router =
        IUniswapV2Router(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

    // Step 1: Forged Wormhole messages sent in advance from Base chain
    //   - Message 1: user = FEG admin address, sourceAddress = address(this)
    //     → relayer.setAdmin(address(this), true) is executed
    //   - Message 2: registerWithdraw(address(this), 45_715_693_242e18, ...)
    //     → withdrawal balance registered

    // Step 2: Withdraw registered balance on Ethereum
    function attack() external {
        // Execute withdrawal after whitelist registration
        // Registered balance: 57,532,022,461.47 FEG (onchain: 57532022461471026362052505299)
        relayer.withdraw(); // Withdraw FEG from bridge

        uint256 fegBalance = FEG.balanceOf(address(this));
        // Obtained 57.5B FEG from bridge balance

        // Step 3: Swap FEG → ETH via Uniswap V2
        FEG.approve(address(router), type(uint256).max);

        address[] memory path = new address[](2);
        path[0] = address(FEG);
        path[1] = router.WETH();

        // 1st swap: 11.16B FEG → 68.09 ETH
        router.swapExactTokensForETHSupportingFeeOnTransferTokens(
            fegBalance / 5,     // Use a portion of FEG
            0,
            path,
            address(this),
            block.timestamp
        );

        // 2nd swap: remaining FEG → 28.24 ETH
        router.swapExactTokensForETHSupportingFeeOnTransferTokens(
            FEG.balanceOf(address(this)),
            0,
            path,
            address(this),
            block.timestamp
        );
        // Final Ethereum chain profit: 28.24 ETH (~$98,842)
    }
}
```

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Field | On-Chain Value |
|------|----------|
| Block Number | 21,506,154 |
| `from` | 0xCB96ddE53F43035f7395D8DbdB652987F7630b3c (attacker EOA) |
| `to` | 0xEf7Bd1543bDAcAdD7e42822e3F15Dd0af0410fDa (attack contract) |
| Function Selector | `0xd625e24c` (custom attack function, signature not registered) |
| Parameters | `address=0x8d5c...6243` (FEG relayer), includes chain ID list |
| Gas Used | 1,510,382 (limit) |
| Wormhole Sequence | 73,395 |

### 8.2 PoC vs On-Chain Amount Comparison

| Item | Analyzed Value | On-Chain Actual | Match |
|------|---------|-------------|------|
| FEG withdrawn from bridge | ~57.5B FEG | 57,532,022,461.47 FEG | ✅ |
| Uniswap 1st swap WETH | ~68 ETH | 68.0899 ETH | ✅ |
| Uniswap 2nd swap WETH | ~28 ETH | 28.2406 ETH | ✅ |
| Ethereum chain profit | ~$98K | 28.24 ETH (~$98,842) | ✅ |
| Total cross-chain profit | ~$1M | ~$1M~1.3M (3 chains combined) | ✅ |

### 8.3 On-Chain Event Log Sequence

| Log # | Contract | Event | Details |
|-------|---------|--------|------|
| 0 | Wormhole Core (0x98f3) | `LogMessagePublished` | Wormhole message published |
| 1 | Wormhole Delivery (0x2742) | Delivery event | sequence=73395 delivery complete |
| 2 | FEG (0xf3c7) | `Transfer` | Bridge→AttackContract 57.5B FEG |
| 3-5 | FEG (0xf3c7) | `Approval` | Uniswap router approve (unlimited) |
| 6 | FEG (0xf3c7) | `Transfer` | AttackContract→Pool1 partial FEG |
| 7 | FEG (0xf3c7) | `Transfer` | AttackContract→0xdead (burn) |
| 8 | FEG (0xf3c7) | `Transfer` | AttackContract→Pool1 additional FEG |
| 9-10 | FEG (0xf3c7) | `Transfer` | Forwarded to tax distribution addresses |
| 11 | FEG (0xf3c7) | `Transfer` | AttackContract→Uniswap Pool 11.16B FEG |
| 12 | WETH (0xc02a) | `Transfer` | Pool→Router 68.09 WETH (1st swap) |
| 13-14 | Uniswap Pool | `Sync`, `Swap` | 1st swap complete |
| 15 | WETH (0xc02a) | `Withdrawal` | Router withdraws WETH→ETH |
| 17 | FEG (0xf3c7) | `Transfer` | AttackContract→Pool2 additional FEG |
| 18 | WETH (0xc02a) | `Transfer` | Pool2→AttackContract 28.24 WETH |
| 19 | WETH (0xc02a) | `Withdrawal` | Attacker final WETH→ETH withdrawal |

### 8.4 Pre-Condition Verification (Block #21,506,153)

| Item | Pre-Attack State |
|------|------------|
| FEG bridge balance | 57,821,128,101.98 FEG (= 5.782e28 wei) |
| Attacker's registered withdrawal balance | 57,532,022,461.47 FEG (already registered from Base) |
| FEG total supply | 100,000,000,000 FEG (1e29 wei) |
| Bridge owner (admin) | 0x8d5E1CD48b17d807e81DBfBe6c591CB7faB63971 |

**Verification Conclusion**: Prior to the attack tx, `registerWithdraw` had already been completed via the Base chain and the withdrawal balance was pre-registered. This Ethereum chain tx was purely the execution phase — simply withdrawing and swapping the pre-registered balance.

---

*Analysis basis: On-chain data (Block #21,506,154), CertiK report, Halborn report*
*Written: 2026-04-11*