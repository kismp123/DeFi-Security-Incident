# FireBird Finance — AMM Reentrancy Analysis

| Field | Details |
|------|------|
| **Date** | 2023-09-26 |
| **Protocol** | FireBird Finance |
| **Chain** | Polygon |
| **Loss** | ~8536 MATIC |
| **Attacker** | [0x8e83cd1bad00cf93...](https://polygonscan.com/address/0x8e83cd1bad00cf933b86214aaaab4db56abf68aa) |
| **Attack Tx** | [0x96d80c609f7a39b4...](https://polygonscan.com/tx/0x96d80c609f7a39b45f2bb581c6ba23402c20c2b6cd528317692c31b8d3948328) |
| **Vulnerable Contract** | [0x5e9cd0861f927ade...](https://polygonscan.com/address/0x5e9cd0861f927adeccfeb2c0124879b277dd66ac) |
| **Root Cause** | Reentrancy vulnerability in FireBird AMM Pair contract during swap |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/FireBirdPair_exp.sol) |

---
## 1. Vulnerability Overview
The FireBird Finance AMM Pair contract was susceptible to reentrancy during callback processing after a swap. Approximately 8536 MATIC was lost.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)
```solidity
// ❌ Vulnerable code: reentrancy possible via swap callback
function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external {
    if (data.length > 0) IFireBirdCallee(to).fireBirdCall(msg.sender, amount0Out, amount1Out, data);
    uint256 balance0 = IERC20(token0).balanceOf(address(this));
    uint256 balance1 = IERC20(token1).balanceOf(address(this));
    _update(balance0, balance1); // ❌ Update after callback → reentrancy vulnerability
}
// ✅ Fix: add lock modifier
```

---
### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: FireBirdPair.sol
interface IFireBirdFactory {  // ❌
    event PairCreated(address indexed token0, address indexed token1, address pair, uint32 tokenWeight0, uint32 swapFee, uint);
    function feeTo() external view returns (address);
    function formula() external view returns (address);
    function protocolFee() external view returns (uint);
    function feeToSetter() external view returns (address);

    function getPair(address tokenA, address tokenB, uint32 tokenWeightA, uint32 swapFee) external view returns (address pair);
    function allPairs(uint) external view returns (address pair);
    function isPair(address) external view returns (bool);
    function allPairsLength() external view returns (uint);

    function createPair(address tokenA, address tokenB, uint32 tokenWeightA, uint32 swapFee) external returns (address pair);
    function getWeightsAndSwapFee(address pair) external view returns (uint32 tokenWeight0, uint32 tokenWeight1, uint32 swapFee);

    function setFeeTo(address) external;
    function setFeeToSetter(address) external;
    function setProtocolFee(uint) external;
}

// ...

    function initialize(address _token0, address _token1, uint32 _tokenWeight0, uint32 _swapFee) external {
        require(msg.sender == factory, 'FLP: FORBIDDEN');
        // sufficient check
        token0 = _token0;
        token1 = _token1;
        tokenWeight0 = _tokenWeight0;
        swapFee = _swapFee;
        formula = IFireBirdFactory(factory).formula();  // ❌
    }

// ...

    function _mintFee(uint112 _reserve0, uint112 _reserve1) private returns (bool feeOn) {
        address feeTo = IFireBirdFactory(factory).feeTo();  // ❌
        uint112 protocolFee = uint112(IFireBirdFactory(factory).protocolFee());  // ❌
        feeOn = feeTo != address(0);
        (uint112 _collectedFee0, uint112 _collectedFee1) = getCollectedFees();
        if (protocolFee > 0 && feeOn && (_collectedFee0 > 0 || _collectedFee1 > 0)) {
            uint32 _tokenWeight0 = tokenWeight0;
            uint liquidity = IFireBirdFormula(formula).mintLiquidityFee(  // ❌
                totalSupply, _reserve0, _reserve1,
                _tokenWeight0, 100 - _tokenWeight0,
                _collectedFee0 / protocolFee, _collectedFee1 / protocolFee
            );
            if (liquidity > 0) _mint(feeTo, liquidity);
        }
        if (_collectedFee0 > 0) collectedFee0 = 0;
        if (_collectedFee1 > 0) collectedFee1 = 0;
    }

// ...

    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external lock {
        require(amount0Out > 0 || amount1Out > 0, 'FLP: INSUFFICIENT_OUTPUT_AMOUNT');
        uint112 _reserve0 = reserve0; // gas savings
        uint112 _reserve1 = reserve1; // gas savings
        require(amount0Out < _reserve0 && amount1Out < _reserve1, 'FLP: INSUFFICIENT_LIQUIDITY');

        uint balance0;
        uint balance1;
        { // scope for _token{0,1}, avoids stack too deep errors
        address _token0 = token0;
        address _token1 = token1;
        require(to != _token0 && to != _token1, 'FLP: INVALID_TO');
        if (amount0Out > 0) _safeTransfer(_token0, to, amount0Out); // optimistically transfer tokens
        if (amount1Out > 0) _safeTransfer(_token1, to, amount1Out); // optimistically transfer tokens
        if (data.length > 0) IUniswapV2Callee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);
        balance0 = IERC20(_token0).balanceOf(address(this));
        balance1 = IERC20(_token1).balanceOf(address(this));
        }
        uint amount0In = balance0 > _reserve0 - amount0Out ? balance0 - (_reserve0 - amount0Out) : 0;
        uint amount1In = balance1 > _reserve1 - amount1Out ? balance1 - (_reserve1 - amount1Out) : 0;
        require(amount0In > 0 || amount1In > 0, 'FLP: INSUFFICIENT_INPUT_AMOUNT');
        { // scope for reserve{0,1}Adjusted, avoids stack too deep errors
            uint balance0Adjusted = balance0.mul(10000);
            uint balance1Adjusted = balance1.mul(10000);
            { // avoids stack too deep errors
                if (amount0In > 0) {
                    uint amount0InFee = amount0In.mul(swapFee);
                    balance0Adjusted = balance0Adjusted.sub(amount0InFee);
                    collectedFee0 = uint112(uint(collectedFee0).add(amount0InFee));
                }
                if (amount1In > 0) {
                    uint amount1InFee = amount1In.mul(swapFee);
                    balance1Adjusted = balance1Adjusted.sub(amount1InFee);
                    collectedFee1 = uint112(uint(collectedFee1).add(amount1InFee));
                }
                uint32 _tokenWeight0 = tokenWeight0;// gas savings
                if (_tokenWeight0 == 50) { // gas savings for pair 50/50
                    require(balance0Adjusted.mul(balance1Adjusted) >= uint(_reserve0).mul(_reserve1).mul(10000**2), 'FLP: K');
                } else {
                    require(IFireBirdFormula(formula).ensureConstantValue(uint(_reserve0).mul(10000), uint(_reserve1).mul(10000), balance0Adjusted, balance1Adjusted, _tokenWeight0), 'FLP: K');  // ❌
                }
            }
        }
        _update(balance0, balance1, _reserve0, _reserve1);
        emit Swap(msg.sender, amount0In, amount1In, amount0Out, amount1Out, to);
    }

// ...

    function createPair(address tokenA, address tokenB, uint32 tokenWeightA, uint32 swapFee) external returns (address pair) {
        require(tokenA != tokenB, 'FLP: IDENTICAL_ADDRESSES');
        require(tokenWeightA >= 2 && tokenWeightA <= 98 && (tokenWeightA % 2) == 0, 'FLP: INVALID_TOKEN_WEIGHT');
        // swap fee from [0.01% - 20%]
        require(swapFee >= 1 && swapFee <= 2000, 'FLP: INVALID_SWAP_FEE');
        (address token0, address token1, uint32 tokenWeight0) = tokenA < tokenB ? (tokenA, tokenB, tokenWeightA) : (tokenB, tokenA, 100 - tokenWeightA);
        require(token0 != address(0), 'FLP: ZERO_ADDRESS');
        // single check is sufficient
        bytes memory bytecode = type(FireBirdPair).creationCode;  // ❌
        bytes32 salt = keccak256(abi.encodePacked(token0, token1, tokenWeight0, swapFee));
        require(_pairSalts[salt] == address(0), 'FLP: PAIR_EXISTS');
        assembly {
            pair := create2(0, add(bytecode, 32), mload(bytecode), salt)
        }
        IFireBirdPair(pair).initialize(token0, token1, tokenWeight0, swapFee);  // ❌
        _pairSalts[salt] = address(pair);
        allPairs.push(pair);
        uint64 weightAndFee = uint64(swapFee);
        weightAndFee |= uint64(tokenWeight0)<<32;
        _pairs[address(pair)] = weightAndFee;
        emit PairCreated(token0, token1, pair, tokenWeight0, swapFee, allPairs.length);
    }
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Call swap() (with callback data)
  ├─② Reenter via fireBirdCall() callback
  │       └─ Exploit stale (not-yet-updated) reserve state
  └─③ Double withdrawal + ~8536 MATIC
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
function fireBirdCall(address sender, uint amount0, uint amount1, bytes calldata data) external {
    // Reenter while reserves have not yet been updated
    IFireBirdPair(pair).swap(amount0, 0, address(this), "");
}
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Reentrancy Attack |
| Severity | High |

---
## 6. Remediation Recommendations
1. Apply Uniswap V2-style `lock` modifier
2. Update reserves before the callback

---
## 7. Lessons Learned
AMM Pair contracts must faithfully implement the security patterns established by Uniswap V2.