---
title: Front-running / MEV Exploits
---
## 8. Front-running / MEV Exploits

### Real Case
Front-running is ubiquitous in DeFi:
- Sandwich attacks on AMMs: attacker places a buy before and a sell after a victim’s large swap.
- Liquidation sniping: bots race to liquidate undercollateralized positions.
- NFT mint or auction sniping: buying desirable assets before the original user.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract SimpleAuction {
    address public highestBidder;
    uint256 public highestBid;

    function bid() external payable {
        require(msg.value > highestBid, "low bid");

        // ❌ front-runnable: others can see this tx and outbid it
        if (highestBidder != address(0)) {
            payable(highestBidder).transfer(highestBid);
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}
```

### Explanation
Because pending transactions sit in the public mempool, anyone (including miners and sophisticated bots) can see them and submit competing transactions with higher gas prices. This allows adversaries to “front-run” or “back-run” a victim’s transaction and capture value, especially in protocols where transaction order significantly affects outcomes.

Mitigations include using commit-and-reveal schemes, batch auctions, private mempools, or specialized anti-MEV designs. While front-running is not always a “bug” in the smart-contract code itself, the contract’s design can either amplify or mitigate the impact of MEV and ordering games.
