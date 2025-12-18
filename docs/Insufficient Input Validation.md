# Smart Contract Vulnerabilities – Real Cases & Vulnerable Code Examples (15 Types)

## 14. Insufficient Input Validation

### Real Case
A variety of incidents have arisen from missing checks on parameters such as recipient addresses, token amounts, or array indices. The result can be transfers to the zero address, stuck tokens, underflows, or corrupted data structures.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract BadValidation {
    mapping(address => uint256) public balanceOf;

    function transfer(address _to, uint256 _amount) external {
        // ❌ No validation of _to or _amount
        balanceOf[msg.sender] -= _amount; // underflow (pre-0.8)
        balanceOf[_to] += _amount;        // _to could be zero address
    }
}
```

### Explanation
Input validation ensures that function arguments are within acceptable and safe ranges. Without these checks, users can trigger edge cases that the developer never intended to allow, such as transferring tokens to invalid recipients, passing zero amounts where they shouldn’t, or using extreme values that overflow downstream logic.

Best practices include validating non-zero addresses, enforcing reasonable upper and lower bounds on numerical inputs, checking array length consistency, and using `require` statements liberally for argument sanity. Combined with modern compiler checks, this greatly reduces attack surface.
