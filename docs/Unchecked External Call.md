# Smart Contract Vulnerabilities – Real Cases & Vulnerable Code Examples (15 Types)
## 4. Unchecked External Call

### Real Case
In multiple legacy contracts, developers used `call` or `send` without checking the returned boolean. Failures to send ETH (for example due to a reverting fallback) were silently ignored, leading to stuck funds or inconsistent accounting.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract UncheckedSend {
    mapping(address => uint256) public balances;

    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "not enough");

        // ❌ Ignoring return value
        msg.sender.call{value: _amount}("");

        balances[msg.sender] -= _amount; // accounting mismatch possible
    }
}
```

### Explanation
The low-level `call` returns a boolean indicating success or failure. If this return value is ignored, the contract might assume ETH was successfully transferred when it was not. This can create scenarios where internal balances are decremented but the user never receives the funds, or where further logic relies on transfers that never actually happened.

A secure pattern is to always check and handle the return value of low-level calls, use higher-level abstractions like `transfer` (with caveats in high-gas environments) or well-reviewed helper libraries. In modern patterns, pull-payment models and withdrawal patterns avoid pushing ETH unexpectedly to arbitrary addresses.
