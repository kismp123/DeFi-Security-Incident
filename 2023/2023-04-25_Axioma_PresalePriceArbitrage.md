# Axioma Presale Exploit — Presale Price vs DEX Price Arbitrage

## Metadata
| Field | Value |
|---|---|
| Date | 2023-04-25 |
| Project | Axioma |
| Chain | BSC |
| Loss | ~Unconfirmed BNB |
| Attacker | Unconfirmed |
| Attack TX | https://bscscan.com/tx/0x05eabbb665a5b99490510d0b3f93565f394914294ab4d609895e525b43ff16f2 |
| Vulnerable Contract | AxiomaPresale: 0x2C25aEe99ED08A61e7407A5674BC2d1A72B5D8E3 |
| Block | 27,620,321 |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Vulnerability Type | Presale Price / DEX Price Arbitrage |

## Summary
The Axioma presale contract sold AXT tokens at a fixed presale price via `buyToken()` payable with BNB. The DEX price (PancakeSwap V2) for AXT was higher than the presale price. The attacker flash-loaned 32.5 BNB via DODO, bought AXT at the cheaper presale price, then immediately sold on PancakeSwap at the market price for a profit.

## Vulnerability Details
- **CWE-841**: The presale contract did not implement any rate-limiting, maximum purchase limits, or price discovery mechanism to prevent arbitrage between the fixed presale price and the live DEX price. The workflow should have included a cliff or vesting period preventing immediate resale.

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: AxiomaPresale.sol
abstract contract Context {  // ❌
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}

// ...

    function transferFrom(

// ...

    function endPreSale() public onlyOwner() {  // ❌
        uint256 contractTokenBalance = token.balanceOf(address(this));  // ❌
        token.transfer(msg.sender, contractTokenBalance);  // ❌
    }

// ...

function ChangePresaleOwner(address walletAddress) public onlyOwner {  // ❌
        PresaleOwner = walletAddress;  // ❌
    }

// ...

    function buyToken() public payable {

        uint256 bnbAmountToBuy = msg.value;

        uint256 tokenAmount = bnbAmountToBuy.mul(rate).div(10**9);

        require(token.balanceOf(address(this)) >= tokenAmount, "INSUFFICIENT_BALANCE_IN_CONTRACT");  // ❌

        payable(PresaleOwner).transfer(bnbAmountToBuy);  // ❌

        uint256 taxAmount = tokenAmount.mul(buyTax).div(100);
        token.transfer(PresaleOwner, taxAmount);  // ❌

        (bool sent) = token.transfer(msg.sender, tokenAmount.sub(taxAmount));
        require(sent, "FAILED_TO_TRANSFER_TOKENS_TO_BUYER");

    }
```

## Attack Flow (from testExploit())
```solidity
// 1. DODO.flashLoan(32.5 BNB)
// 2. DPPFlashLoanCall():
//    a. WBNB.withdraw(32.5 BNB)
//    b. IAxiomaPresale(axiomaPresale).buyToken{value: 32.5 BNB}()
//       → receive AXT at presale price
//    c. bscSwap(AXT → WBNB) via PancakeSwap V2
//       → sell at higher DEX price
//    d. WBNB.transfer(dodo, 32.5 BNB) // repay flash
// Net profit: DEX price - presale price difference
```

## Interfaces from PoC
```solidity
interface IAxiomaPresale {
    function buyToken() external payable;
}
```

## Key Addresses
| Label | Address |
|---|---|
| AXT Token | 0xB6CF5b77B92a722bF34f6f5D6B1Fe4700908935E |
| AxiomaPresale | 0x2C25aEe99ED08A61e7407A5674BC2d1A72B5D8E3 |
| AXT/WBNB Pair | 0x6a3Fa7D2C71fd7D44BF3a2890aA257F34083c90f |
| DODO Oracle | 0xFeAFe253802b77456B4627F8c2306a9CeBb5d681 |
| PancakeRouter | 0x10ED43C718714eb63d5aA57B78B54704E256024E |

## Root Cause
Presale contract allowed immediate purchase with no vesting, cliff, or resale restriction, enabling flash-loan-powered arbitrage against the DEX price.

## Fix
```solidity
// Enforce vesting period before purchased tokens can be transferred:
mapping(address => uint256) public vestingUnlockTime;

function buyToken() external payable {
    uint256 axtAmount = msg.value * PRESALE_RATE;
    vestingUnlockTime[msg.sender] = block.timestamp + VESTING_PERIOD;
    // lock tokens in vesting contract, not transferable immediately
    vestingContract.vest(msg.sender, axtAmount, vestingUnlockTime[msg.sender]);
}
```

## References
- HypernativeLabs: https://twitter.com/HypernativeLabs/status/1650382589847302145
- BSCScan TX: 0x05eabbb665a5b99490510d0b3f93565f394914294ab4d609895e525b43ff16f2