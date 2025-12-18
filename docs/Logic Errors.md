# Smart Contract Vulnerabilities – Real Cases & Vulnerable Code Examples (15 Types)

## 12. Logic Errors / Business Logic Bypass

### Real Case
- **Compound COMP Distribution Bug (2021)**  
  A miscalculation in the reward distribution logic caused some users to receive far more COMP than intended. Similar logic errors have led to infinite reward minting or unbounded interest accrual in other protocols.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract RewardPool {
    mapping(address => uint256) public deposits;
    mapping(address => bool) public claimed;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function claimReward() external {
        require(deposits[msg.sender] > 0, "no deposit");

        uint256 reward = deposits[msg.sender] * 2; // ❌ flawed logic

        claimed[msg.sender] = true;
        payable(msg.sender).transfer(reward);
    }
}
```

### Explanation
Not all vulnerabilities are low-level technical bugs; many are simply incorrect implementations of the intended business logic. Errors in formulas, conditions, or edge-case handling can allow users to claim excessive rewards, bypass fees, or escape penalties that should apply. Since these behaviors are “valid” according to the code, they do not revert and are often exploitable at scale.

Thorough specification, property-based testing, formal verification, and adversarial thinking (e.g., “how would I maximize my gain within these rules?”) are vital to catching business logic flaws. Code reviews must go beyond syntax and match implementation to requirements.
