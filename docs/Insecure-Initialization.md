---
title: Insecure Initialization / Constructor Issues
---
## 13. Insecure Initialization / Constructor Issues

### Real Case
- **Parity Multisig Hack #2 (2017)**  
  A wallet library’s initialization function (meant to act like a constructor) could be called by anyone, even after deployment. An attacker called it, set themselves as owner, and drained multiple multisig wallets.

### Vulnerable Example Code
```solidity
pragma solidity ^0.4.24;

contract WalletLibrary {
    address public owner;

    // ❌ Not a constructor → callable by anyone
    function WalletLibrary() public {
        owner = msg.sender;
    }

    function withdraw() public {
        require(msg.sender == owner);
        msg.sender.transfer(address(this).balance);
    }
}
```

### Explanation
Before Solidity introduced the `constructor` keyword, constructors were identified by having the same name as the contract. Typos, renames, or using such patterns in libraries and proxies could result in functions that were *intended* to be constructors but were actually public, callable methods. This allowed attackers to reinitialize ownership or critical parameters after deployment.

In modern code, using the `constructor` keyword, explicit initializer functions with access control, and one-time initialization guards (like OpenZeppelin’s `initializer` modifiers) is crucial, especially in upgradeable or proxy-based contracts where initialization happens separately from deployment.
