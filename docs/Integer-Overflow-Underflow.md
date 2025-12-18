---
title: Integer Overflow / Underflow
---
## 2. Integer Overflow / Underflow

### Real Case
- **BatchOverflow Vulnerability (2018)**  
  Token multiplication overflow allowed attackers to mint enormous token amounts, which could then be dumped on exchanges.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract OverflowToken {
    mapping(address => uint256) public balanceOf;

    function batchTransfer(address[] calldata _to, uint256 _value) external {
        uint256 total = _value * _to.length; // ❌ overflow possible

        require(balanceOf[msg.sender] >= total, "not enough balance");

        balanceOf[msg.sender] -= total;
        for (uint i = 0; i < _to.length; i++) {
            balanceOf[_to[i]] += _value; // no overflow checks
        }
    }
}
```

### Explanation
Integer overflow occurs when an arithmetic operation exceeds the maximum representable value of the integer type, wrapping around to a much smaller value. Underflow is the opposite: going below the minimum representable value and wrapping around to a large number. In smart contracts, these wraparounds can cause balances, supply, or accounting variables to behave unexpectedly and can often be turned into direct exploits.

Prior to Solidity 0.8, arithmetic operations did not revert on overflow by default, so developers relied on libraries like SafeMath. When sensitive calculations such as token minting, distribution, or collateral accounting overflow, attackers can artificially inflate balances or bypass checks. Even with Solidity 0.8+, overflow can still be a risk when using inline assembly or custom math routines.
