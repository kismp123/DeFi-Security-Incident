# Bitpaidio Exploit — Lock_Token() / withdraw() Lock Period Bypass via Flash Swap

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05 |
| Project | Bitpaidio (BTP Staking) |
| Chain | BSC |
| Loss | ~$30,000 |
| Attacker | 0x878a36edfb757e8640ff78b612f839b63adc2e51 |
| Attack TX | Unconfirmed |
| Vulnerable Contract | Staking: 0x9D6d817ea5d4A69fF4C4509bea8F9b2534Cec108 |
| Block | Unconfirmed |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Vulnerability Type | Staking Lock Period Bypass via Flash Swap Callback |

## Summary
The Bitpaidio staking contract allowed `Lock_Token()` and `withdraw()` to be called within the same transaction via a flash swap callback. The intended time-lock was not enforced during callback execution, allowing an attacker to lock and immediately withdraw staked BTP tokens with profit.

## Vulnerability Details
- **CWE-841**: `withdraw()` did not validate that the current block timestamp exceeded the lock end time. Inside a PancakeSwap flash swap callback, the attacker locked tokens via `Lock_Token()` and immediately called `withdraw()` before the callback returned — bypassing the 6-month lock period entirely.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Staking.sol
     * CAUTION: This function is deprecated because it requires allocating memory for the error  // ❌

// ...

     * CAUTION: This function is deprecated because it requires allocating memory for the error  // ❌

// ...

    function _transferOwnership(address newOwner) internal {
      require(newOwner != address(0), "Ownable: new owner is the zero address");
      emit OwnershipTransferred(_owner, newOwner);
      _owner = newOwner;
    }

// ...

    function Lock_Token(uint256 plan, uint256 _amount) external {  // ❌
      if(plan == 1) {
          address contractAddress = address(this);
          uint256 currentAmount = sixMonth[msg.sender].amount;
          uint256 total = SafeMath.add(currentAmount,_amount);
          if(sixMonth[msg.sender].reinvest == 0) {
          uint256 startTime = block.timestamp;  // ❌
          uint256 endTime = block.timestamp + 180 days;  // ❌
          sixMonth[msg.sender] = TimeLock_Six_Month(msg.sender,total,startTime,endTime,1);  // ❌
          }
          else {
              uint256 startTime = sixMonth[msg.sender].start_time;
              uint256 endTime = sixMonth[msg.sender].end_time;
              sixMonth[msg.sender] = TimeLock_Six_Month(msg.sender,total,startTime,endTime,1);  // ❌
          }
          ERC20interface.transferFrom(msg.sender, contractAddress, _amount);
      }
      else if(plan == 2) {
          address contractAddress = address(this);
          uint256 currentAmount = nineMonth[msg.sender].amount;
          uint256 total = SafeMath.add(currentAmount,_amount);
           if(nineMonth[msg.sender].reinvest == 0) {
          uint256 startTime = block.timestamp;  // ❌
          uint256 endTime = block.timestamp + 270 days;  // ❌
          nineMonth[msg.sender] = TimeLock_Nine_Month(msg.sender,total,startTime,endTime,1);  // ❌
           }
           else {
              uint256 startTime = nineMonth[msg.sender].start_time;
              uint256 endTime = nineMonth[msg.sender].end_time;
              nineMonth[msg.sender] = TimeLock_Nine_Month(msg.sender,total,startTime,endTime,1);  // ❌
           }
          ERC20interface.transferFrom(msg.sender, contractAddress, _amount);
      }
      else if(plan == 3) {
          address contractAddress = address(this);
          uint256 currentAmount = twelveMonth[msg.sender].amount;
          uint256 total = SafeMath.add(currentAmount,_amount);
          if(twelveMonth[msg.sender].reinvest == 0) {
          uint256 startTime = block.timestamp;  // ❌
          uint256 endTime = block.timestamp + 365 days;  // ❌
          twelveMonth[msg.sender] = TimeLock_Twelve_Month(msg.sender,total,startTime,endTime,1);  // ❌
          }
          else {
              uint256 startTime = twelveMonth[msg.sender].start_time;
              uint256 endTime = twelveMonth[msg.sender].end_time;
              twelveMonth[msg.sender] = TimeLock_Twelve_Month(msg.sender,total,startTime,endTime,1);  // ❌
          }
          ERC20interface.transferFrom(msg.sender, contractAddress, _amount);
      }
    }

// ...

    function withdraw(uint256 _plan) public {  // ❌
        if(_plan == 1) {
        require(block.timestamp >= sixMonth[msg.sender].end_time, "You cant unstake now");  // ❌
        uint256 roi = sixMonth[msg.sender].amount;
        uint256 RoiReturn = plan_1_Roi(roi);
        uint256 investedAmount = sixMonth[msg.sender].amount;
        uint256 total = SafeMath.add(RoiReturn,investedAmount);
        ERC20interface.transfer(msg.sender, total);

        sixMonth[msg.sender] = TimeLock_Six_Month(msg.sender,0,0,0,0);  // ❌
         }

        else if(_plan == 2) {
        require(block.timestamp >= nineMonth[msg.sender].end_time, "You cant unstake now");  // ❌
        uint256 roi = nineMonth[msg.sender].amount;
        uint256 RoiReturn = plan_2_Roi(roi);
        uint256 investedAmount = nineMonth[msg.sender].amount;
        uint256 total = SafeMath.add(RoiReturn,investedAmount);
        ERC20interface.transfer(msg.sender, total);
        nineMonth[msg.sender] = TimeLock_Nine_Month(msg.sender,0,0,0,0);  // ❌
         }

         else if(_plan == 3) {
        require(block.timestamp >= twelveMonth[msg.sender].end_time, "You cant unstake now");  // ❌
        uint256 roi = twelveMonth[msg.sender].amount;
        uint256 RoiReturn = plan_3_Roi(roi);
        uint256 investedAmount = twelveMonth[msg.sender].amount;
        uint256 total = SafeMath.add(RoiReturn,investedAmount);
        ERC20interface.transfer(msg.sender, total);

        twelveMonth[msg.sender] = TimeLock_Twelve_Month(msg.sender,0,0,0,0);  // ❌
         }
    }
```

## Attack Flow (from testExploit())
```solidity
// 1. Staking.Lock_Token(1, 0)   // firstLock - initial position
// 2. vm.warp(block.timestamp + 180 days)
// 3. Pair.swap(219_349e18, 0, address(this), abi.encode("flash"))
//    → triggers pancakeCall() callback:
//      a. IERC20(BTP).approve(address(Staking), type(uint256).max)
//      b. Staking.Lock_Token(1, balance)   // lock inside callback
//      c. Staking.withdraw(1)              // withdraw immediately — NO time check
//      d. Repay flash swap: BTP.transfer(address(Pair), 219_349e18 + fee)
```

## Interfaces from PoC
```solidity
interface IStaking {
    function Lock_Token(uint256 lockType, uint256 amount) external;
    function withdraw(uint256 lockType) external;
}

interface Uni_Pair_V2 {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}
```

## Key Addresses
| Label | Address |
|---|---|
| Staking Contract | 0x9D6d817ea5d4A69fF4C4509bea8F9b2534Cec108 |
| Attack Contract | 0x7b9265c6aa4b026b7220eee2e8697bf5ffa6bb9a |
| Attacker EOA | 0x878a36edfb757e8640ff78b612f839b63adc2e51 |
| BTP Token | 0x40F75eD09c7Bc89Bf596cE0fF6FB2ff8D02aC019 |
| BTP Uniswap Pair | 0x858DE6F832c9b92E2EA5C18582551ccd6add0295 |

## Root Cause
`withdraw()` lacked a timestamp check verifying that the lock period had elapsed. Because the check was absent (or insufficient), a flash swap callback could lock and immediately withdraw within the same transaction.

## Fix
```solidity
struct LockInfo {
    uint256 amount;
    uint256 lockEnd;
}
mapping(address => mapping(uint256 => LockInfo)) public locks;

function withdraw(uint256 lockType) external {
    LockInfo storage info = locks[msg.sender][lockType];
    require(block.timestamp >= info.lockEnd, "Lock period not elapsed");
    require(info.amount > 0, "Nothing locked");
    uint256 amount = info.amount;
    info.amount = 0;
    IERC20(token).safeTransfer(msg.sender, amount);
}
```

## References
- BSC attacker: 0x878a36edfb757e8640ff78b612f839b63adc2e51
- BTP Staking: 0x9D6d817ea5d4A69fF4C4509bea8F9b2534Cec108