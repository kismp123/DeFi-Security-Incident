# Levyathan — Private Key Leak + Timelock Abuse for Unlimited LEV Minting Analysis

| Field | Details |
|------|------|
| **Date** | 2021-07-20 |
| **Protocol** | Levyathan |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | Entire protocol TVL (exact amount unconfirmed) |
| **Attacker** | [0x7507f84610f6D656a70eb8CDEC044674799265D3](https://bscscan.com/address/0x7507f84610f6D656a70eb8CDEC044674799265D3) |
| **Attack Tx** | Address unconfirmed (fork block: 9,545,967) |
| **Vulnerable Contracts** | MasterChef [0xA3fDF7F376F4BFD38D7C4A5cf8AAb4dE68792fd4](https://bscscan.com/address/0xA3fDF7F376F4BFD38D7C4A5cf8AAb4dE68792fd4) / Timelock [0x16149999C85c3E3f7d1B9402a4c64d125877d89D](https://bscscan.com/address/0x16149999C85c3E3f7d1B9402a4c64d125877d89D) |
| **Root Cause** | Development team exposed the private key of the mint-privileged wallet on GitHub — attacker waited out the Timelock delay, seized MasterChef ownership, and minted unlimited LEV |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-07/Levyathan_exp.sol) |

---
## 1. Vulnerability Overview

The Levyathan development team accidentally exposed the private key of the wallet holding MasterChef mint privileges on GitHub. The attacker used this key to queue a MasterChef ownership transfer transaction in the Timelock contract. After the 172,800-second (2-day) Timelock delay elapsed, the ownership transfer was executed, and the attacker minted 100 octillion (10^26) LEV tokens from MasterChef and dumped them. Concurrently, some users exploited a separate bug allowing multiple calls to `emergencyWithdraw()` to perform duplicate withdrawals.

---
## 2. Vulnerable Code Analysis

### 2.1 MasterChef.mint() — Owner-only call, single EOA privilege

```solidity
// ❌ MasterChef @ 0xA3fDF7F376F4BFD38D7C4A5cf8AAb4dE68792fd4
// Once ownership is seized, unlimited minting is possible
function mint(address _to, uint256 _amount) public onlyOwner {
    LEV.mint(_to, _amount); // Unlimited LEV token minting
}

// Ownership transfer via Timelock — executed after delay
// Timelock @ 0x16149999C85c3E3f7d1B9402a4c64d125877d89D
function executeTransaction(
    address target, uint value, string memory signature,
    bytes memory data, uint eta
) public payable onlyAdmin returns (bytes memory) {
    // Executed after 172,800-second delay
    require(block.timestamp >= eta, "Timelock::executeTransaction: not ready");
    // Executes transferOwnership(attacker)
}
```

**Fixed Code**:
```solidity
// ✅ Manage MasterChef ownership via multisig wallet
// ✅ Emission cap + longer timelock + emergency pause functionality

contract SecureMasterChef {
    address public multisig; // Gnosis Safe (3-of-5 or higher)
    uint256 public constant MAX_EMISSION_PER_BLOCK = 10 * 1e18;
    bool public paused;

    modifier onlyMultisig() {
        require(msg.sender == multisig, "not multisig");
        _;
    }

    function updateEmissionRate(uint256 newRate) external onlyMultisig {
        require(newRate <= MAX_EMISSION_PER_BLOCK, "rate too high");
        LEV_PER_BLOCK = newRate;
    }

    function emergencyPause() external onlyMultisig {
        paused = true;
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**Levyathan_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: Development team exposed the private key of the mint-privileged wallet on GitHub — attacker waited out the Timelock delay, seized MasterChef ownership, and minted unlimited LEV
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────────┐
│ Step 1: Obtain exposed mint-privileged wallet private key    │
│         from GitHub                                          │
│ (Dev team accidentally exposed .env or hardcoded key)        │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 2: Queue MasterChef ownership transfer tx in Timelock   │
│ Timelock @ 0x16149999C85c3E3f7d1B9402a4c64d125877d89D       │
│ queueTransaction(masterChef, transferOwnership(attacker))   │
└─────────────────────┬────────────────────────────────────────┘
                      │ (172,800 seconds = 2-day delay)
┌─────────────────────▼────────────────────────────────────────┐
│ Step 3: Timelock.executeTransaction() — ownership transfer   │
│         complete                                             │
│ MasterChef owner → changed to attacker address              │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 4: MasterChef.mint(attacker, 100_000_000_000_000_000... │
│ Mint 100 octillion LEV → immediately dumped                  │
└─────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — BSC fork block 9,545,967
function testExploit() public {
    // Prank as attacker address
    // attacker = 0x7507f84610f6D656a70eb8CDEC044674799265D3

    // Queue ownership transfer in Timelock (already queued 2 days prior)
    // timelock @ 0x16149999C85c3E3f7d1B9402a4c64d125877d89D
    // timelock.queueTransaction(masterChef, "transferOwnership(address)", attacker, eta)

    // Execute after 2 days
    // timelock.executeTransaction(masterChef, "transferOwnership(address)", attacker, eta)

    // Mint unlimited LEV via MasterChef
    // masterChef @ 0xA3fDF7F376F4BFD38D7C4A5cf8AAb4dE68792fd4
    // masterChef.mint(attacker, 100_000_000_000_000_000_000_000_000_000)

    // Dump LEV
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Private key exposed on GitHub — mint privilege seized | CRITICAL | CWE-321 |
| V-02 | MasterChef ownership concentrated in single EOA | CRITICAL | CWE-284 |
| V-03 | Timelock duration (2 days) too short to respond | HIGH | CWE-840 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Never include private keys in version control (.gitignore is mandatory)
// ✅ Manage ownership exclusively via Gnosis Safe (3-of-5 multisig) wallet
// ✅ Set timelock minimum to 7 days or more

// .gitignore
// .env
// *.key
// mnemonic.txt

// Use environment variables in deployment scripts
// DEPLOYER_PRIVATE_KEY=$(cat ~/.secret/deployer.key)  # Store locally only
```

---
## 7. Lessons Learned

- **A private key leak nullifies all on-chain security mechanisms.** Never send private keys anywhere — GitHub, Slack, Discord, or email.
- **Even with a Timelock, 2 days is sufficient time for an attack.** Without an observer (monitoring system), a Timelock is meaningless.
- **A real-time monitoring system for the Timelock transaction queue is essential.** Any suspicious queue entry must be immediately communicated to the community.