# Sushi MISO — Dutch Auction init() Ownership Hijack Analysis

| Field | Details |
|------|------|
| **Date** | 2021-09-17 |
| **Protocol** | Sushi MISO (DutchAuction) |
| **Chain** | Ethereum |
| **Loss** | ~$3,000,000 (later returned) |
| **Attacker** | Insider attack (anonymous contractor) |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | MISO DutchAuction (Sushi Launchpad) |
| **Root Cause** | Attacker injected an init() callback into the deployment script, replacing the auction wallet address with the attacker's address |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-09/Sushimiso_exp.sol) |

---
## 1. Vulnerability Overview

The Dutch auction contract on the Sushi MISO platform is initialized via the `initAuction()` function after deployment. An anonymous contractor injected malicious code into the deployment script to set the auction wallet address (`wallet`) to their own address. As the auction progressed, approximately $3M worth of ETH that had accumulated flowed to the attacker's wallet instead of the legitimate wallet. This incident is also an example of a supply chain attack.

---
## 2. Vulnerable Code Analysis

### 2.1 initAuction() — No wallet address validation

```solidity
// ❌ MISO DutchAuction
// initAuction() does not verify that the wallet address is the actual project address
function initAuction(
    address _funder,
    address _token,
    uint256 _tokenSupply,
    uint256 _startTime,
    uint256 _endTime,
    address _paymentCurrency,
    uint256 _startPrice,
    uint256 _minimumPrice,
    address _operator,
    address _pointList,
    address payable _wallet   // ❌ This address receives auction proceeds
) external {
    // No wallet validation
    // Can be set to attacker's address from the deployment script
    wallet = _wallet;
    // ...
}
```

**Fixed code**:
```solidity
// ✅ Validate wallet address against the protocol registry
// ✅ Require timelock + public event when changing wallet after deployment

address public immutable registry;

function initAuction(
    // ...
    address payable _wallet
) external {
    require(_wallet != address(0), "DutchAuction: zero wallet");
    require(
        IRegistry(registry).isApprovedWallet(_wallet),
        "DutchAuction: wallet not registered"
    );
    wallet = _wallet;
    emit AuctionWalletSet(_wallet);
    // ...
}

function setWallet(address payable _wallet) external onlyOperator {
    require(block.timestamp >= walletChangeTime + 48 hours, "DutchAuction: timelock");
    wallet = _wallet;
    emit AuctionWalletChanged(_wallet);
}
```


### On-chain Original Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — only bytecode exists or source is unverified

**Vulnerable function** — `vulnerableFunction()`:
```solidity
// ❌ Root cause: Attacker injected an init() callback into the deployment script, replacing the auction wallet address with the attacker's address
// Source code unconfirmed — bytecode analysis required
// Vulnerability: Attacker injected an init() callback into the deployment script, replacing the auction wallet address with the attacker's address
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────────┐
│ Step 1: Anonymous contractor injects malicious code into     │
│ the deployment script                                        │
│ initAuction(..., wallet=attacker_address)                    │
│ Initialized with attacker's wallet instead of legitimate one │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 2: Dutch auction proceeds normally                      │
│ Investors deposit ETH via commitEth()                        │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 3: After auction ends, upon finalize() or direct        │
│ withdrawal, ~$3M ETH is sent to wallet (attacker's address)  │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 4: Community pressure leads attacker to return ETH      │
│ (off-chain negotiation, legal threats)                       │
└──────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// Core of attack: setting wallet to attacker's address in initAuction()
// A supply chain attack that occurred in the actual deployment script

// Reproduction scenario:
function testExploit() public {
    // Deployment script controlled by attacker calls the following
    dutchAuction.initAuction(
        funder,
        token,
        tokenSupply,
        startTime,
        endTime,
        ETH,
        startPrice,
        minimumPrice,
        operator,
        pointList,
        payable(attacker)  // ← replaced with attacker's wallet
    );

    // After auction proceeds, finalize() sends ETH to attacker address
    // dutchAuction.finalize()
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing wallet address validation in initAuction() | CRITICAL | CWE-284 |
| V-02 | Supply chain attack — malicious code injected into deployment script | CRITICAL | CWE-494 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Include deployment script code review in the audit scope
// ✅ Publicly disclose wallet address via on-chain events — enables community monitoring

// Run wallet address verification script immediately after deployment
// script/verifyAuction.js
// assert(auction.wallet() === expectedWallet, "WALLET MISMATCH!")

// Display wallet address publicly on the frontend
// Guide users to confirm the wallet is the project's official address before investing
```

---
## 7. Lessons Learned

- **Deployment scripts must be included in the audit scope.** Even if the smart contract code is secure, a malicious deployment process renders it meaningless.
- **Any modifications to deployment scripts by open-source contributors or external parties must be reviewed via diff.** Granting deployment permissions to anonymous contractors is dangerous.
- **Fund recipient addresses (wallet) must be publicly verifiable on-chain immediately after deployment.** Community monitoring can serve as the last line of defense.