# Smart Contract Vulnerabilities – Real Cases & Vulnerable Code Examples (15 Types)
## 15. Token Standard Misimplementation (ERC-20/721/1155)

### Real Case
Some tokens deviate from ERC-20 by not returning `bool` from `transfer` or by not reverting on failure. This breaks assumptions in DEXs and DeFi protocols that rely on standard behavior, sometimes resulting in stuck funds or incorrect accounting.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract BadERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // ❌ No bool return value and no revert on failure
    function transfer(address _to, uint256 _amount) external {
        if (balanceOf[msg.sender] >= _amount) {
            balanceOf[msg.sender] -= _amount;
            balanceOf[_to] += _amount;
        }
    }

    // ❌ Simplistic approve that may conflict with expected semantics
    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }
}
```

### Explanation
The entire DeFi ecosystem depends on standard interfaces so that contracts can interact reliably. When a token misimplements ERC-20 or ERC-721—by changing return types, not reverting on failure, or deviating from expected semantics—integrations can silently fail or behave incorrectly. For example, a DEX might assume `transfer` reverted on failure, but a non-reverting implementation would instead leave balances unchanged without signaling an error.

To avoid this, developers should rely on well-reviewed reference implementations (e.g., OpenZeppelin) instead of rolling their own from scratch. Any intentional deviations from the standard must be clearly documented and understood by integrators, though in practice such deviations are strongly discouraged.
