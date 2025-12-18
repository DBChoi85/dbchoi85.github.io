# Smart Contract Vulnerabilities – Real Cases & Vulnerable Code Examples (15 Types)

## 1. Reentrancy Attack

### Real Case
- **The DAO Hack (2016)**  
  The withdraw function sent ETH *before* updating balances, allowing recursive calls through a fallback function. Result: ~3.6M ETH drained.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "not enough balance");

        // ❌ External call before state change
        (bool ok, ) = msg.sender.call{value: _amount}("");
        require(ok, "send failed");

        // ❌ State update afterward → reentrancy risk
        balances[msg.sender] -= _amount;
    }
}
```

### Explanation
A reentrancy vulnerability appears when a contract makes an external call to an untrusted address *before* it finishes updating its own internal state. Because control is temporarily handed to the callee, that callee can call back into the original contract (re-enter) and repeatedly execute sensitive logic such as withdrawals. If the balance is only reduced after the call returns, the attacker can drain funds by performing multiple withdrawals in a single transaction.

This pattern is especially dangerous in bank-like contracts, vaults, and DeFi protocols that move ETH or tokens. Even when the contract seems logically correct, a single misplaced external call can open the door to catastrophic losses. Modern defenses include the checks-effects-interactions pattern, reentrancy guards, or avoiding raw `call` to user-controlled contracts where possible.

