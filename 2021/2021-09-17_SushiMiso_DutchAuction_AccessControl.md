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


### On-Chain Original Code

Source: **Etherscan-verified** (V2 API, chainid 1) — DutchAuction `0x4c4564a1FE775D97297F9e3Dc2e762e0Ed5Dda0e`

```solidity
function initAuction(
    address _funder,
    address _token,
    uint256 _totalTokens,
    uint256 _startTime,
    uint256 _endTime,
    address _paymentCurrency,
    uint256 _startPrice,
    uint256 _minimumPrice,
    address _admin,
    address _pointList,
    address payable _wallet
) public {
    require(_startTime < 10000000000, "DutchAuction: enter an unix timestamp in seconds, not miliseconds");
    require(_endTime < 10000000000, "DutchAuction: enter an unix timestamp in seconds, not miliseconds");
    require(_startTime >= block.timestamp, "DutchAuction: start time is before current time");
    require(_endTime > _startTime, "DutchAuction: end time must be older than start price");
    require(_totalTokens > 0,"DutchAuction: total tokens must be greater than zero");
    require(_startPrice > _minimumPrice, "DutchAuction: start price must be higher than minimum price");
    require(_minimumPrice > 0, "DutchAuction: minimum price must be greater than 0"); 
    require(_admin != address(0), "DutchAuction: admin is the zero address");
    require(_wallet != address(0), "DutchAuction: wallet is the zero address");
    require(IERC20(_token).decimals() == 18, "DutchAuction: Token does not have 18 decimals");
    if (_paymentCurrency != ETH_ADDRESS) {
        require(IERC20(_paymentCurrency).decimals() > 0, "DutchAuction: Payment currency is not ERC20");
    }

    marketInfo.startTime = BoringMath.to64(_startTime);
    marketInfo.endTime = BoringMath.to64(_endTime);
    marketInfo.totalTokens = BoringMath.to128(_totalTokens);

    marketPrice.startPrice = BoringMath.to128(_startPrice);
    marketPrice.minimumPrice = BoringMath.to128(_minimumPrice);

    auctionToken = _token;
    paymentCurrency = _paymentCurrency;
    wallet = _wallet;  // ❌ wallet set to attacker-supplied address with no registry check

    initAccessControls(_admin);

    _setList(_pointList);
    _safeTransferFrom(_token, _funder, _totalTokens);
}

function commitEth(
    address payable _beneficiary,
    bool readAndAgreedToMarketParticipationAgreement
)
    public payable
{
    require(paymentCurrency == ETH_ADDRESS, "DutchAuction: payment currency is not ETH address"); 
    if(readAndAgreedToMarketParticipationAgreement == false) {
        revertBecauseUserDidNotProvideAgreement();
    }
    uint256 ethToTransfer = calculateCommitment(msg.value);

    uint256 ethToRefund = msg.value.sub(ethToTransfer);
    if (ethToTransfer > 0) {
        _addCommitment(_beneficiary, ethToTransfer);
    }
    if (ethToRefund > 0) {
        _beneficiary.transfer(ethToRefund);
    }
}

function finalize() public nonReentrant
{
    require(hasAdminRole(msg.sender) 
            || hasSmartContractRole(msg.sender) 
            || wallet == msg.sender
            || finalizeTimeExpired(), "DutchAuction: sender must be an admin");
    MarketStatus storage status = marketStatus;

    require(!status.finalized, "DutchAuction: auction already finalized");
    if (auctionSuccessful()) {
        /// @dev Successful auction
        /// @dev Transfer contributed tokens to wallet.
        _safeTokenPayment(paymentCurrency, wallet, uint256(status.commitmentsTotal)); // ❌ goes to attacker's wallet
    } else {
        /// @dev Failed auction
        /// @dev Return auction tokens back to wallet.
        require(block.timestamp > uint256(marketInfo.endTime), "DutchAuction: auction has not finished yet"); 
        _safeTokenPayment(auctionToken, wallet, uint256(marketInfo.totalTokens));
    }
    status.finalized = true;
    emit AuctionFinalized();
}
```

**Why it is exploitable (identify the bug from the code):**

- `initAuction()` checks `_wallet != address(0)` but performs no further validation — any non-zero address is accepted without checking against a registry or operator multisig.
- The function is called exactly once — during deployment — by the entity controlling the deployment script. An insider who controls the script can silently pass their own address as `_wallet`.
- No on-chain event announces the wallet address set at initialization, so there is no automated monitoring opportunity before funds accumulate.
- `finalize()` calls `_safeTokenPayment(paymentCurrency, wallet, uint256(status.commitmentsTotal))`, transferring all investor commitments to `wallet` — so all funds flow to the attacker's address the moment the auction finalizes successfully.

```solidity
// ✅ Fix: validate wallet against an on-chain operator registry and emit an auditable event
function initAuction(
    // ... other params ...
    address payable _wallet
) external {
    require(_wallet != address(0), "DutchAuction: zero wallet");
    require(
        IRegistry(registry).isApprovedWallet(_wallet),
        "DutchAuction: wallet not in registry"
    );
    wallet = _wallet;
    emit AuctionWalletSet(_wallet); // ✅ immediately observable on-chain
}
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