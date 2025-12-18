---
title: Denial of Service (DoS)
---
## 10. Denial of Service (DoS)

### Real Case
- **King of the Ether Throne**  
  A new “king” is paid by sending ETH to the previous king. If the previous king’s fallback always reverts, the entire function fails and no one can become king afterward, effectively freezing the game.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract KingGame {
    address public king;
    uint256 public prize;

    function claimThrone() external payable {
        require(msg.value > prize, "too low");

        // ❌ If previous king reverts, game breaks
        if (king != address(0)) {
            payable(king).transfer(prize);
        }

        king = msg.sender;
        prize = msg.value;
    }
}
```

### Explanation
Denial-of-service vulnerabilities emerge when a contract’s core functionality depends on external calls that might revert or consume too much gas. If a single malicious participant can cause those calls to fail consistently, they can block others from interacting with the contract, halting auctions, games, or governance processes.

Common mitigations include using pull-payment patterns (where recipients claim funds themselves), carefully bounding loops, and ensuring that failures in non-critical external interactions do not block overall progress of the contract’s main logic.
