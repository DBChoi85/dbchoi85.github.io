# Smart Contract Vulnerabilities – Real Cases & Vulnerable Code Examples (15 Types)

## 9. Price Oracle Manipulation

### Real Case
- **bZx (2020)** and **Harvest Finance (2020)**  
  Attackers used flash loans to move AMM prices, causing oracle-dependent lending protocols to misprice collateral and allow over-borrowing or draining of pools.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

interface IUniswapLike {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract BadOracleLending {
    IUniswapLike public pool;
    mapping(address => uint256) public debt;

    constructor(address _pool) public {
        pool = IUniswapLike(_pool);
    }

    function getPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1,) = pool.getReserves();
        return uint256(r1) * 1e18 / uint256(r0); // ❌ manipulable ratio
    }

    function borrow(uint256 collateral) external {
        uint256 price = getPrice();
        uint256 maxBorrow = collateral * price / 1e18;

        debt[msg.sender] += maxBorrow;
    }
}
```

### Explanation
If a protocol uses a single AMM pool (or otherwise thin liquidity) as its price oracle, attackers can temporarily move the price by trading large volumes, often funded by flash loans. During this short-lived price distortion, they interact with the vulnerable protocol to borrow or swap on extremely favorable terms, then unwind the manipulation and keep the profit.

Robust oracle design involves using time-weighted average prices (TWAPs), multiple data sources, dedicated oracle networks, oracles with circuit breakers, and sanity checks. Protocols must assume that any manipulable on-chain metric will eventually be manipulated by an adversary.
