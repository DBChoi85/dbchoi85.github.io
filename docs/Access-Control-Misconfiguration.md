---
title: Access Control Misconfiguration
---
## 3. Access Control Misconfiguration

### Real Case
Many ERC-20 and governance contracts have accidentally exposed admin-only functions (like `mint`, `burn`, or parameter changes) without proper access modifiers. In several incidents, this allowed arbitrary users to mint tokens or seize control of the protocol.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract BadAccessControl {
    address public owner;
    mapping(address => uint256) public balanceOf;

    constructor() public {
        owner = msg.sender;
    }

    // ❌ No access control
    function mint(address _to, uint256 _amount) external {
        balanceOf[_to] += _amount;
    }

    // ❌ Anyone can change the owner
    function changeOwner(address _newOwner) external {
        owner = _newOwner;
    }
}
```

### Explanation
Access control vulnerabilities arise when privileged functions are either missing access checks or implement them incorrectly. Examples include missing `onlyOwner` modifiers, using incorrect role variables, or exposing initialization functions that can be called by anyone after deployment. Since admin functions often control minting, pausing, upgrading, or configuration, mistakes here can compromise the entire system.

Robust access control involves clearly defining roles (owner, admin, operator), using well-tested libraries like OpenZeppelin’s `Ownable` or `AccessControl`, and carefully reviewing every function that can change critical state. Additionally, ownership transfer and renounce flows must be well understood to avoid leaving the contract in an unsafe or unrecoverable state.
