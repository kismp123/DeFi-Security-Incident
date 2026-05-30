# LocalTrader2 — Repeated Access Control Vulnerability Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-05-19 |
| **Protocol** | LocalTrader (2nd incident) |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | 4 additional transactions |
| **Vulnerable Contract** | LocalTrader Contract |
| **Root Cause** | Same missing access control as the 1st attack |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/LocalTrader2_exp.sol) |

---
## 1. Vulnerability Overview

Following the 1st attack on LocalTrader, a 2nd attack occurred exploiting the same vulnerability. A total of 8 attack transactions were recorded.

## 2. Attack Flow

Identical to the 1st attack. The same vulnerability was reused without any patch applied.

### On-chain Original Code

Source: **Sourcify-verified** (partial match) — LCTExchange `0xcE3e12bD77DD54E20a18cB1B94667F3E697bea06` (BSC)
Sourcify URL: https://sourcify.dev/server/files/any/56/0xcE3e12bD77DD54E20a18cB1B94667F3E697bea06

The attack targeted the upgradeable proxy `0x303554d4D8Bd01f18C6fA4A8df3FF57A96071a41` whose implementation is `LCTExchange`. Two unprotected storage-slot-writing selectors (`0xb5863c10`, `0x925d400c`) allowed anyone to overwrite `ownerWalletAddress` and the live price. Once price was set to 1, `buyTokens()` drained the pool.

```solidity
// ❌ buyTokens — price fed from an external interface with no bounds check
function buyTokens() public payable returns (uint, uint) {
    require(msg.value > 0, "Send ETH to buy some tokens");
    uint256 tokenAmount2 = msg.value / getLivePriceFromInheritance(); // ❌ if price == 1 (wei), tokenAmount2 == msg.value
    uint256 tokenAmount = tokenAmount2 * 1000000000000000000;
    require(
        token.balanceOf(address(this)) >= tokenAmount,
        "Vendor contract has not enough tokens in its balance"
    );
    bool sent = token.transfer(msg.sender, tokenAmount);
    require(sent, "Failed to transfer token to user");
    emit TokensPurchased(
        msg.sender,
        address(token),
        tokenAmount,
        getLivePriceFromInheritance()
    );
    return (getLivePriceFromInheritance(), msg.value);
}

// ❌ getLivePriceFromInheritance — fully controlled by whoever holds lctLivePriceInterfaceAddr
function getLivePriceFromInheritance() public view returns (uint) {
    return LCTLivePriceInterface(lctLivePriceInterfaceAddr).getTokenPrice(); // ❌ no validation of returned price
}

// ❌ handleSetInterfaceAddress — only guarded by onlyOwner, but owner was overwritten via unprotected selector
function handleSetInterfaceAddress(
    address _interfaceAddr
) public onlyOwner {
    lctLivePriceInterfaceAddr = _interfaceAddr; // ❌ attacker sets this to a malicious contract returning price=1
}
```

**Why it is exploitable (identify the bug from the code):**
- The proxy implementation exposes two unprotected selectors (`0xb5863c10` / `0x925d400c`) that write directly to storage slot 0 (owner) and slot 3 (price) without access control — the source of the identical 1st-attack vulnerability.
- After overwriting `ownerWalletAddress`, the attacker calls `handleSetInterfaceAddress()` with a malicious oracle that returns `getTokenPrice() == 1`.
- `buyTokens()` computes `tokenAmount2 = msg.value / 1`, then multiplies by `1e18` — issuing an enormous token quantity for trivial BNB.
- No minimum price floor, no pause mechanism, and no timelock on oracle changes exist.

```solidity
// ✅ Fix: add price bounds validation and multi-sig/timelock on oracle changes
function getLivePriceFromInheritance() public view returns (uint) {
    uint price = LCTLivePriceInterface(lctLivePriceInterfaceAddr).getTokenPrice();
    require(price >= MIN_PRICE && price <= MAX_PRICE, "Price out of bounds");
    return price;
}
// Also: remove unprotected storage-writing selectors from the proxy implementation
```

## 3. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Access Control (repeated) |
| **DASP Classification** | Access Control |

## 4. Remediation Recommendations
Immediate patching, temporary protocol suspension, and emergency asset migration.

## 7. Lessons Learned
The 2nd attack occurred without any immediate response following the 1st attack. A mechanism to immediately suspend the protocol upon vulnerability detection is essential.