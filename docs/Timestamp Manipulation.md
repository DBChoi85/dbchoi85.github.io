# Smart Contract Vulnerabilities – Real Cases & Vulnerable Code Examples (15 Types)
## 11. Timestamp Manipulation

### Real Case
Protocols relying on exact timestamps for lotteries, time locks, or interest calculations can be subtly influenced by miners, who can adjust the block time within a tolerance. While the window is small, it can still be exploitable in edge cases or combined with other weaknesses.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract TimeLockedFund {
    uint256 public unlockTime;
    address public owner;

    constructor(uint256 lockSeconds) public {
        owner = msg.sender;
        unlockTime = block.timestamp + lockSeconds; // miner-influenceable
    }

    function withdraw() external {
        require(msg.sender == owner, "not owner");
        require(block.timestamp >= unlockTime, "locked");
        payable(owner).transfer(address(this).balance);
    }
}
```

### Explanation
`block.timestamp` is not an absolute, trustworthy clock; miners can manipulate it slightly (usually within 15 seconds) as long as it remains roughly aligned with real time and protocol rules. For many use cases that tolerate small drift (like vesting), this is acceptable, but it must not be used in contexts where a small shift yields huge advantages, such as random draws.

Safer designs treat timestamps as approximate and may use block numbers or a combination of time-based checks with other constraints. For randomness, timestamps should not be treated as entropy at all.
