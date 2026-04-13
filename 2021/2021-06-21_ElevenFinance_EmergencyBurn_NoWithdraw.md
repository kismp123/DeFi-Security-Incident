# Eleven Finance — emergencyBurn() LP Burn Without Withdrawal Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-06-21 |
| **Protocol** | Eleven Finance |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$4,500,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | [0x6450d8f4](https://bscscan.com/tx/0x6450d8f4db09972853e948bee44f2cb54b9df786dace774106cd28820e906789) |
| **Vulnerable Contract** | [0x27DD6E51BF715cFc0e2fe96Af26fC9DED89e4BE8](https://bscscan.com/address/0x27DD6E51BF715cFc0e2fe96Af26fC9DED89e4BE8) (Eleven Vault) |
| **Root Cause** | emergencyBurn() burns vault shares without withdrawing actual LP from MasterChef, enabling double-withdrawal of LP via a subsequent withdraw() call |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-06/Eleven_exp.sol) |

---
## 1. Vulnerability Overview

The `emergencyBurn()` function in the Eleven Finance vault burns a user's vault share tokens but does not actually withdraw the LP tokens staked in MasterChef. Because of this, calling `withdraw()` after `emergencyBurn()` allows LP corresponding to already-burned shares to be pulled out again. The attacker borrowed 953M BUSD via flash loan, minted NRV LP, and exploited this pattern to drain vault assets.

---
## 2. Vulnerable Code Analysis

### 2.1 emergencyBurn() — Burns Shares Only, No LP Withdrawal

```solidity
// ❌ Eleven Vault @ 0x27DD6E51BF715cFc0e2fe96Af26fC9DED89e4BE8
function emergencyBurn() external {
    uint256 shares = balanceOf(msg.sender);
    require(shares > 0, "No shares");

    // Burns vault shares only — no LP withdrawal from MasterChef
    _burn(msg.sender, shares);

    // totalStaked is not updated either
    // Actual LP balance in MasterChef remains unchanged
    emit EmergencyBurn(msg.sender, shares);
}

function withdraw(uint256 _shares) external {
    // Withdraws LP equivalent to _shares from MasterChef
    uint256 lpAmount = _shares * balance() / totalSupply();
    _burn(msg.sender, _shares);
    IMasterChef(masterChef).withdraw(pid, lpAmount); // still withdrawable
    lpToken.transfer(msg.sender, lpAmount);
}
```

**Fixed Code**:
```solidity
// ✅ emergencyBurn() also withdraws MasterChef LP together
function emergencyBurn() external nonReentrant {
    uint256 shares = balanceOf(msg.sender);
    require(shares > 0, "No shares");

    uint256 lpAmount = shares * balance() / totalSupply();

    // 1. Burn shares (Effect)
    _burn(msg.sender, shares);

    // 2. Withdraw actual LP from MasterChef (Interaction)
    IMasterChef(masterChef).withdraw(pid, lpAmount);

    // 3. Transfer LP to user
    lpToken.transfer(msg.sender, lpAmount);
    emit EmergencyBurn(msg.sender, shares);
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**Eleven Vault_decompiled.sol** — Entry points:
```solidity
// ❌ Root cause: emergencyBurn() burns vault shares without withdrawing actual LP from MasterChef, enabling double-withdrawal via subsequent withdraw()
    function emergencyBurn() external {}  // 0xd8d7f96f  // ❌ Vulnerable

    function withdraw(uint256 arg0) external {}  // 0x2e1a7d4d  // ❌ Vulnerable
```

## 3. Attack Flow

```
┌───────────────────────────────────────────────────────────┐
│ Step 1: ApeSwap flash loan — borrow ~953.8M BUSD          │
└─────────────────────┬─────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────┐
│ Step 2: Swap BUSD → NRV (PancakeSwap)                     │
│ NRV Token @ 0x42F6f551ae042cBe50C739158b4f0CAC0Edb9096   │
└─────────────────────┬─────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────┐
│ Step 3: Mint NRV LP then deposit() into Eleven Vault      │
│ Eleven Vault @ 0x27DD6E51BF715cFc0e2fe96Af26fC9DED89e4BE8│
│ → Receive vault shares                                    │
└─────────────────────┬─────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────┐
│ Step 4: Call vault.emergencyBurn()                        │
│ → Shares burned only; MasterChef LP remains intact        │
└─────────────────────┬─────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────┐
│ Step 5: vault.withdraw(0) or re-withdraw with remaining shares │
│ → LP withdrawn again from MasterChef (double-withdrawal)  │
└─────────────────────┬─────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────┐
│ Step 6: Remove LP → Convert NRV → BUSD → Repay flash loan │
└───────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// Core attack sequence
function exploit() internal {
    // Swap BUSD → NRV
    // router.swapExactTokensForTokens(busd, 0, [BUSD, NRV], ...)

    // Mint NRV LP
    // router.addLiquidity(NRV, BUSD, ...)

    // Deposit LP into Eleven Vault
    // elevenVault.deposit(lpBalance); // 0x27DD6E51BF715cFc0e2fe96Af26fC9DED89e4BE8

    // emergencyBurn — burns shares only, MasterChef LP retained
    elevenVault.emergencyBurn();

    // withdraw — re-withdraw LP from MasterChef (double-withdrawal)
    elevenVault.withdraw(elevenVault.balanceOf(address(this)));

    // Remove LP → Convert NRV → BUSD
    // router.removeLiquidity(...)
    // router.swapExactTokensForTokens(nrv, 0, [NRV, BUSD], ...)
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | emergencyBurn() burns shares without withdrawing MasterChef LP — allows double-withdrawal | CRITICAL | CWE-841 |
| V-02 | State inconsistency between vault state (totalStaked) and MasterChef state after share burn | HIGH | CWE-682 |

---
## 6. Remediation Recommendations

```solidity
// ✅ emergencyBurn() performs the same withdrawal logic as withdraw() before burning shares
// ✅ Always sync with MasterChef on emergencyBurn/withdraw calls

function emergencyBurn() external nonReentrant {
    uint256 shares = balanceOf(msg.sender);
    uint256 lpAmount = shares * balance() / totalSupply();

    _burn(msg.sender, shares);                           // Effect
    IMasterChef(masterChef).withdraw(pid, lpAmount);     // Interaction
    lpToken.safeTransfer(msg.sender, lpAmount);
}
```

---
## 7. Lessons Learned

- **emergencyXxx functions must be held to a stricter standard than a normal withdraw.** This incident illustrates the paradox where an emergency exit path becomes the security hole itself.
- **Share burning and MasterChef LP withdrawal must always be processed atomically.** Executing only one of the two causes state inconsistency.
- **When a vault delegates LP to an external farming contract (MasterChef), every withdrawal path must guarantee synchronization with that contract.**