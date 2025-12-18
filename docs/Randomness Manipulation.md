# Smart Contract Vulnerabilities – Real Cases & Vulnerable Code Examples (15 Types)

## 7. Randomness Manipulation

### Real Case
Several on-chain games and lotteries relied on `block.timestamp`, `blockhash`, or similar values as “randomness”. Miners or strategic players could influence these values or selectively mine blocks to tilt odds in their favor.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract WeakRandomLottery {
    address public lastWinner;

    function draw() external {
        // ❌ predictable randomness
        uint256 random = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender))
        );

        if (random % 10 == 0) {
            lastWinner = msg.sender;
        }
    }
}
```

### Explanation
On-chain data like timestamps, block difficulty, and recent block hashes are not truly random. Miners have some control over timestamps and can decide whether to publish or discard a block that yields a favorable result. Additionally, if users can influence input parameters like `msg.sender`, they may brute-force or time their transactions to increase their chances of winning.

Secure randomness usually requires off-chain sources (e.g., VRF oracles like Chainlink VRF) or multi-party commit-and-reveal schemes where no single participant can unilaterally dictate the outcome. Using raw block parameters for high-value randomness is considered insecure.
