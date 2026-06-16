# TOP (Token of Power) — Governance Mint Takeover Exploit Analysis

| Field | Details |
|-------|---------|
| **Date** | 2026-06-09 04:32:00 UTC (reported June 9–10, 2026) |
| **Protocol** | TOP / "Token of Power" governance — an **Aragon DAO** on Ethereum. Total supply only **16,384 TOP** (trivial supply / value). |
| **Chain** | Ethereum |
| **Total Loss** | **~$1.58M** = **944.2 WETH** drained from the TOP/WETH **Balancer V1** pool. (Balancer itself was **NOT** vulnerable — it was merely the swap venue.) |
| **Attacker EOA** | [0xff8eF7bC455a57e5893232203052Ce0232b39Fa2](https://etherscan.io/address/0xff8eF7bC455a57e5893232203052Ce0232b39Fa2) (funded via Tornado Cash) |
| **Vulnerable Contract** | Aragon Voting + TokenManager (mint authority) for the TOP DAO. **TOP token contract address NOT disclosed in public reporting (unconfirmed).** |
| **Attack Tx** | `0x8ae66025236aa0c05e78beb46bde7d6d75b188822f3cb5d338e2493a35bc83c4` — **NOT found on Etherscan or BscScan (synthetic / fabricated)**; flagged in §8 |
| **Entry Selector / Function** | Aragon `newVote(...)` → `vote(...)` → `executeVote(...)` (create + vote + execute in a single transaction), executing a proposal calling TokenManager `mint(address,uint256)` |
| **Root Cause** | Low-cost quorum capture + no timelock: attacker cheaply bought >50% voting power, then atomically created, voted, and executed a malicious proposal minting 10B new TOP to itself, swapped for WETH on Balancer V1. |
| **GitHub / Source** | Aragon DAO framework (Voting / TokenManager apps); TOP token source not publicly confirmed |
| **Source Verification** | Provided tx hash not found on-chain (synthetic); analysis based on public reports (AMBCrypto, CryptoTimes, Crypto.news, Bitcoinist) and the well-documented Aragon Voting/TokenManager design. |

---

> ### ⚠️ Scope Clarification — Balancer Was Not Vulnerable
>
> The 944.2 WETH was extracted from a **Balancer V1** TOP/WETH pool, but **Balancer had no vulnerability**. The pool simply acted as a price-taking venue for the attacker to dump 10 billion freshly-minted, unbacked TOP tokens. The entire flaw lives in the **TOP DAO's Aragon governance configuration** (no timelock, trivially-cheap quorum, mint authority bound to a passing vote).

---

## 1. Vulnerability Overview

TOP ("Token of Power") was governed by an **Aragon DAO** on Ethereum. Two properties combined to make it fatally cheap to capture:

1. **Trivial supply and value.** Total supply was only **16,384 TOP**. Acquiring a majority therefore required only **8,192.000001 TOP** (just over 50% of voting power) — a tiny dollar cost given the token's low market value.
2. **Atomic, timelock-free governance.** Aragon's `Voting` app, when configured with a short/zero vote duration and instant execution, lets a holder **create a proposal, cast the deciding vote, and execute it — all in a single transaction**. With no `TimelockController` delay between approval and execution, the community has zero window to react.

The proposal's `executionScript` invoked the Aragon **TokenManager**'s `mint(address,uint256)` function. TokenManager holds the mint authority over the DAO's token, and it mints on behalf of **whatever the passing vote instructs**. The attacker minted **10,000,000,000 (10 billion) new TOP** directly to their own address — a ~610,000x inflation over the original 16,384 supply — then swapped the unbacked tokens for **944.2 WETH (~$1.58M)** through the Balancer V1 TOP/WETH pool, draining the pool's real WETH liquidity.

This is a **Governance Attack** (CWE-284 improper access control / CWE-840 business-logic): governance authority that should have required broad, time-delayed consensus was capturable for a trivial sum and executed atomically, with mint power gated only by a vote the attacker themselves controlled.

---

## 2. Vulnerable Code Analysis

> **Source status**: The TOP token contract address is **not disclosed** in public reporting, so exact bytecode is unverified. The structures below are **reconstructed/estimated** from the **well-documented Aragon `Voting` and `TokenManager` apps** and the reported attack mechanics (8,192.000001 TOP majority, single-tx create+vote+execute, 10B mint). Aragon's app logic is open-source and stable, so the reconstruction is faithful at the design level even though TOP-specific parameters are estimated.

### 2.1 ❌ Vulnerable — Instant Execution + No Timelock + Vote-Gated Mint

```solidity
// Aragon Voting app (reconstructed/estimated config) — VULNERABLE SETUP

contract Voting {
    uint64 public supportRequiredPct;   // e.g. 50% — relative to VOTES CAST
    uint64 public minAcceptQuorumPct;   // ❌ low / relative to a tiny 16,384 supply
    uint64 public voteTime;             // ❌ near-zero → no waiting period

    // Create a new vote AND, if instant-execution is enabled, run it now.
    function newVote(bytes calldata _executionScript, string calldata _meta)
        external
        returns (uint256 voteId)
    {
        voteId = _newVote(_executionScript, _meta);
        // ❌ If the creator already holds >50%, the vote can pass and execute
        //    in this same transaction. No timelock, no cooldown.
    }

    function vote(uint256 _voteId, bool _supports, bool _executesIfDecided) external {
        _vote(_voteId, _supports, msg.sender);
        // ❌ _executesIfDecided=true → execute immediately upon reaching support
        if (_executesIfDecided && _canExecute(_voteId)) {
            _executeVote(_voteId);          // ❌ no delay between approval & action
        }
    }

    function _executeVote(uint256 _voteId) internal {
        // ❌ Runs the attacker-authored executionScript with the DAO's authority,
        //    which here calls TokenManager.mint(attacker, 10_000_000_000e18).
        runScript(votes[_voteId].executionScript, ...);
    }
}

// Aragon TokenManager (reconstructed/estimated) — mint authority
contract TokenManager {
    MiniMeToken public token;

    // ❌ Callable by anything the DAO's governance approves. With a captured
    //    Voting app, "approved" means "whatever the attacker's vote says."
    function mint(address _receiver, uint256 _amount) external authP(MINT_ROLE) {
        token.generateTokens(_receiver, _amount);   // ❌ unbounded mint
    }
}
```

**Why this is exploitable:**

- **`supportRequiredPct` is measured against votes cast, and quorum against a 16,384 supply** — so **8,192.000001 TOP** (a hair over 50%) decides any vote. The token's low value makes that majority cheap to buy on the open market.
- **`voteTime` ≈ 0 + instant execution** means `newVote` → `vote(executesIfDecided=true)` → `_executeVote` happen **atomically in one transaction**. No `TimelockController` delay exists.
- **`TokenManager.mint` is unbounded** — there is no cap relative to circulating supply, no guard, no rate limit. A passing vote can mint arbitrarily, here **10,000,000,000 TOP**.

### 2.2 ✅ Fixed — Timelock Delay + Supply-Relative Quorum + Guarded Mint

```solidity
// ✅ HARDENED governance: route execution through a TimelockController.

contract Voting {
    uint64 public voteTime;             // ✅ meaningful voting period (e.g. days)
    uint64 public supportRequiredPct;   // ✅ high bar
    uint64 public minAcceptQuorumPct;   // ✅ quorum relative to CIRCULATING supply

    TimelockController public immutable timelock;  // ✅ enforced delay

    function vote(uint256 _voteId, bool _supports) external {
        require(getTimestamp64() < votes[_voteId].startDate + voteTime, "voting closed");
        _vote(_voteId, _supports, msg.sender);
        // ✅ NO instant execution — approval only queues into the timelock.
    }

    function queueApproved(uint256 _voteId) external {
        require(_canExecute(_voteId), "not approved");
        // ✅ Schedule with a mandatory delay; community can review & cancel.
        timelock.schedule(
            target, 0, votes[_voteId].executionScript,
            bytes32(0), salt, MIN_DELAY      // ✅ e.g. 48h
        );
    }
}

// ✅ Guarded mint — cannot inflate beyond a supply-relative cap per epoch.
contract TokenManager {
    MiniMeToken public token;
    uint256 public constant MAX_MINT_BPS = 500;     // ✅ ≤5% of supply per action
    uint256 public mintEpoch;
    uint256 public mintedThisEpoch;

    function mint(address _receiver, uint256 _amount)
        external
        onlyTimelock                    // ✅ only the delayed timelock may call
    {
        uint256 cap = token.totalSupply() * MAX_MINT_BPS / 10_000;
        require(_amount <= cap, "mint exceeds supply-relative cap");   // ✅
        token.generateTokens(_receiver, _amount);
    }
}
```

The fix rests on three invariants: **(1)** a **`TimelockController` delay** separates approval from execution so a malicious proposal is visible and cancellable before it runs (no single-tx create+vote+execute); **(2)** **quorum and thresholds are measured against circulating supply** and set high enough that capturing a majority is economically prohibitive; **(3)** **mint is capped relative to total supply** and callable only via the delayed timelock, so even a passed proposal cannot conjure a 610,000x inflation.

---

## 3. Attack Flow

### 3.1 Preparation

1. The attacker (`0xff8eF7bC455a57e5893232203052Ce0232b39Fa2`) withdrew funds from **Tornado Cash** to anonymize the trail.
2. The attacker observed that TOP's total supply was only **16,384 TOP**, making >50% voting power cheap to acquire, and that the Aragon Voting app permitted **single-transaction create+vote+execute** with **no timelock**.
3. The attacker accumulated **8,192.000001 TOP** — just over 50% of total voting power — by purchasing on the market (cheap given the token's trivial value). The `.000001` margin is the minimal amount needed to cross the majority threshold.

### 3.2 Execution

In a single governance transaction the attacker:

1. **`newVote(executionScript, …)`** — created a proposal whose execution script called the Aragon **TokenManager**'s `mint(attacker, 10_000_000_000e18)`.
2. **`vote(voteId, support=true, executesIfDecided=true)`** — cast the deciding vote with their >50% stake; support threshold met instantly.
3. **`_executeVote(voteId)`** — because instant execution was enabled and **no timelock delay existed**, the proposal executed in the same transaction, minting **10,000,000,000 (10B) TOP** directly to the attacker. This dwarfed the original 16,384 supply by ~610,000x.
4. **Swap on Balancer V1** — the attacker dumped the unbacked TOP into the **TOP/WETH Balancer V1 pool**, extracting **944.2 WETH (~$1.58M)** of real liquidity. The pool's pricing curve absorbed the inflationary mint as a sell, leaving the pool holding worthless TOP.
5. Proceeds (WETH) were retained / laundered out.

### 3.3 Attack Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│  Tornado Cash → attacker 0xff8eF7bC…b39Fa2                    │
└───────────────────────────────┬──────────────────────────────┘
                                │ buy >50% of a 16,384-supply token (cheap)
                                ▼
┌──────────────────────────────────────────────────────────────┐
│  Acquire 8,192.000001 TOP  (just over 50% voting power)       │
└───────────────────────────────┬──────────────────────────────┘
                                │  ── single transaction ──
                                ▼
┌──────────────────────────────────────────────────────────────┐
│  Aragon Voting (TOP DAO)                                      │
│   1. newVote(script = TokenManager.mint(attacker, 10e9))      │
│   2. vote(support=true, executesIfDecided=true) → PASS        │
│   3. _executeVote()  ❌ NO TIMELOCK → runs immediately        │
└───────────────────────────────┬──────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│  Aragon TokenManager.mint()                                  │
│   ❌ generateTokens(attacker, 10,000,000,000 TOP)            │
│   (orig supply 16,384 → ~610,000x inflation, all unbacked)    │
└───────────────────────────────┬──────────────────────────────┘
                                │ swap 10B unbacked TOP
                                ▼
┌──────────────────────────────────────────────────────────────┐
│  Balancer V1  TOP/WETH pool  (NOT vulnerable — just venue)   │
│   → attacker extracts 944.2 WETH  (~$1.58M)                   │
│   → pool left holding worthless TOP                           │
└──────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

| Item | Value |
|------|-------|
| Voting power acquired | 8,192.000001 TOP (>50% of 16,384 supply) |
| TOP minted | 10,000,000,000 (10B) — ~610,000x original supply |
| WETH drained | 944.2 WETH (~$1.58M) from Balancer V1 TOP/WETH pool |
| Execution | Single transaction: create + vote + execute (no timelock) |
| Balancer protocol | **Unaffected** — only the TOP/WETH pool's liquidity was taken |

---

## 4. Vulnerability Classification

### 4.1 Classification Table

| ID | Vulnerability | Severity | CWE | Category | Similar Incidents |
|----|---------------|----------|-----|----------|-------------------|
| V-01 | Low-cost quorum capture (majority of a 16,384-supply token) | CRITICAL | CWE-840 | governance | Beanstalk, Tornado Gov |
| V-02 | No timelock — atomic create+vote+execute | CRITICAL | CWE-284 | governance | Tornado Gov, Beanstalk |
| V-03 | Unbounded vote-gated mint via TokenManager | CRITICAL | CWE-284 | access-control / governance | Tornado Gov |
| V-04 | Quorum/threshold not relative to circulating supply | HIGH | CWE-840 | business-logic | — |

### 4.2 V-01 — Low-Cost Quorum Capture (CWE-840)

- **Description**: With a total supply of only 16,384 TOP, acquiring 8,192.000001 TOP (>50%) was economically trivial given the token's low value. Governance security that depends on the cost of acquiring a majority collapses when that majority is cheap.
- **Impact**: An individual attacker single-handedly controlled every governance decision.
- **Preconditions**: Open-market availability of >50% of supply; no vote-escrow / time-weighting.

### 4.3 V-02 — No Timelock (CWE-284)

- **Description**: Aragon Voting was configured for **instant execution** with **no `TimelockController` delay**, so a proposal could be created, approved, and executed in a single transaction. The community had no window to detect or veto the malicious mint.
- **Impact**: The attack was atomic and irreversible; defenders could not react.
- **Preconditions**: Instant-execution config + majority voting power.

### 4.4 V-03 — Unbounded Vote-Gated Mint (CWE-284)

- **Description**: The Aragon **TokenManager** could mint arbitrary amounts on behalf of any passing vote, with no cap relative to supply and no additional guard. A captured vote thus controlled unlimited token issuance.
- **Impact**: 10 billion unbacked TOP minted — ~610,000x the original supply — then sold for real WETH.
- **Preconditions**: Control of a passing proposal (V-01 + V-02).

### 4.5 V-04 — Quorum Not Supply-Relative (HIGH, CWE-840)

- **Description**: Support/quorum thresholds were evaluated against votes cast / a tiny fixed supply rather than against meaningful circulating supply, so the practical bar to pass anything was negligible.
- **Impact**: Lowered the effective cost of capturing governance.
- **Preconditions**: Misconfigured Aragon quorum parameters.

---

## 5. Comparison with Similar Incidents

| Incident | Date | Loss | Flaw Type | Difference from TOP |
|----------|------|------|-----------|---------------------|
| **Beanstalk** | 2022-04-17 | ~$182M | Flash-loan governance: borrowed majority voting power to pass a malicious proposal with instant execution | Beanstalk used a **flash loan** for instant majority; TOP bought a cheap majority outright due to a **16,384 total supply** |
| **Tornado Cash Governance** | 2023-05 | ~$1M+ control | Malicious proposal with hidden `selfdestruct`/`emergencyStop` granted attacker fake votes, then full governance control | Tornado smuggled malicious logic into a proposal; TOP openly captured a >50% stake and minted unbacked tokens |
| **TOP (Token of Power)** | 2026-06-09 | ~$1.58M | Cheap majority of a tiny-supply token + no timelock + unbounded vote-gated mint, all in one tx | The mint authority bound to a passing vote with **no timelock** is the decisive amplifier |

The common denominator is **acquiring governance control faster/cheaper than the protocol assumed possible** — Beanstalk via flash-loaned voting power, Tornado via a deceptive proposal payload, and TOP via the sheer cheapness of a 16,384-supply token. In all three, the absence of a **timelock delay** between approval and execution removed the community's only chance to intervene.

---

## 6. Remediation Recommendations

### 6.1 Immediate — Add a Timelock Between Approval and Execution

```solidity
// ✅ Route every approved proposal through OpenZeppelin TimelockController.
TimelockController public immutable timelock;   // MIN_DELAY e.g. 48h

function queueApproved(uint256 _voteId) external {
    require(_canExecute(_voteId), "not approved");
    timelock.schedule(target, 0, executionScript, predecessor, salt, MIN_DELAY);
    // ✅ Community can review & cancel during the delay; NO single-tx execution.
}
```

### 6.2 Defense in Depth

| Weakness | Fix |
|----------|-----|
| Cheap majority of tiny-supply token | Use time-weighted / vote-escrowed voting (veToken); require sustained stake; raise meaningful supply |
| No timelock | Mandatory `TimelockController` delay (e.g. 24–72h) before execution |
| Atomic create+vote+execute | Disable instant execution; enforce a minimum voting period |
| Unbounded mint | Cap mint per epoch relative to total supply; require timelock + guard role |
| Quorum vs tiny fixed supply | Set quorum/threshold relative to circulating supply, set high enough to be costly to capture |
| No emergency brake | Add a guardian/pause that can veto a queued malicious proposal during the timelock window |

### 6.3 Operational

- **Monitoring**: alert on any proposal that calls `mint`/`generateTokens` or transfers treasury assets; alert on any single address crossing the support threshold.
- **Liquidity design**: avoid pairing a freely-mintable governance token against deep real-asset liquidity (WETH) without mint guards — the pool becomes the exit for any inflation bug.

---

## 7. Lessons Learned

1. **A governance token's security budget equals the cost of buying a majority.** A 16,384 total supply made that cost trivial. Low supply / low value is itself an attack surface for governance.
2. **A timelock is non-negotiable.** The single most important control is a mandatory delay between proposal approval and execution. Without it, create+vote+execute collapses into one atomic, unstoppable transaction.
3. **Never bind unbounded mint to a passing vote.** Mint authority must be capped relative to supply and gated behind a delayed timelock, so even a captured vote cannot conjure a 610,000x inflation.
4. **Quorum must track circulating supply, not a tiny fixed number.** Thresholds measured against a negligible supply provide no real barrier.
5. **The victim venue is not always the vulnerable protocol.** Balancer V1 was merely where the unbacked tokens were sold; the flaw lived entirely in the TOP DAO's governance configuration. Incident scope must follow the root cause, not the place the money left from.
6. **Governance attacks rhyme.** Beanstalk (flash-loaned votes) and Tornado (malicious proposal payload) taught the same lesson: control governance faster than defenders can react, and the treasury is yours. TOP repeated it with a cheaply-bought majority.

---

## 8. On-Chain Verification

### 8.1 Provided Transaction Hash — Synthetic / Not Found

> **The transaction hash supplied for this incident is FABRICATED and was NOT found on Etherscan or BscScan.** It must not be cited as evidence. Analysis relies on the verified attacker address and public reporting.

| Provided Hash | Status |
|---------------|--------|
| `0x8ae66025236aa0c05e78beb46bde7d6d75b188822f3cb5d338e2493a35bc83c4` | **Not found on Etherscan or BscScan (synthetic)** |

### 8.2 Verified / Reported Addresses

| Role | Address | Notes |
|------|---------|-------|
| Attacker EOA | [0xff8eF7bC455a57e5893232203052Ce0232b39Fa2](https://etherscan.io/address/0xff8eF7bC455a57e5893232203052Ce0232b39Fa2) | Funded via Tornado Cash |
| TOP token contract | **Not disclosed (unconfirmed)** | No public reporting confirmed the token address |
| Governance | Aragon Voting + TokenManager (TOP DAO) | Mint authority bound to passing votes |
| Swap venue | Balancer V1 TOP/WETH pool | **Not vulnerable**; liquidity drained |

### 8.3 Loss Detail

| Field | Value |
|-------|-------|
| WETH drained | 944.2 WETH |
| USD value | ~$1.58M |
| TOP minted | 10,000,000,000 (10B) |
| Original supply | 16,384 TOP |
| Inflation factor | ~610,000x |
| Voting power acquired | 8,192.000001 TOP (>50%) |

### 8.4 Verification Note

Provided tx hash not found on Etherscan or BscScan (synthetic); analysis based on public reports (AMBCrypto, CryptoTimes, Crypto.news, Bitcoinist) and the documented Aragon Voting/TokenManager design. The TOP token contract address was not disclosed in public reporting and is stated here as unconfirmed.

---

## 9. References

- [AMBCrypto — Governance Takeover Lets Attacker Mint 10B TOP Tokens in $1.5M Exploit](https://ambcrypto.com/governance-takeover-lets-attacker-mint-10b-top-tokens-in-1-5m-exploit/)
- [CryptoTimes — One Vote, $1.58M Gone: TOP Token Hit by Alleged Governance Attack](https://www.cryptotimes.io/2026/06/10/one-vote-1-58m-gone-top-token-hit-by-alleged-governance-attack/)
- [Crypto.news — Token of Power Exploit Drains $1.58M from Balancer Pool](https://crypto.news/token-of-power-exploit-drains-1-58m-from-balancer-pool/)
- [Bitcoinist — Token of Power Governance Exploit Drains $1.58 Million in WETH, TRM Says](https://bitcoinist.com/token-of-power-governance-exploit-drains-1-58-million-in-weth-trm-says/)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-840: Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)
- Vulnerability class index: [../vulns/governance.md](../vulns/governance.md)
- Related: [Beanstalk (2022-04-17)](../2022/2022-04-17_Beanstalk_GovernanceFlashLoan.md)
