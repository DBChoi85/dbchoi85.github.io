# Smart Contract Vulnerabilities – Real Cases & Vulnerable Code Examples (15 Types)

_A curated list of major Ethereum smart contract vulnerability patterns, their historical incidents, minimal vulnerable code examples, and conceptual explanations._

---

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

---

## 2. Integer Overflow / Underflow

### Real Case
- **BatchOverflow Vulnerability (2018)**  
  Token multiplication overflow allowed attackers to mint enormous token amounts, which could then be dumped on exchanges.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract OverflowToken {
    mapping(address => uint256) public balanceOf;

    function batchTransfer(address[] calldata _to, uint256 _value) external {
        uint256 total = _value * _to.length; // ❌ overflow possible

        require(balanceOf[msg.sender] >= total, "not enough balance");

        balanceOf[msg.sender] -= total;
        for (uint i = 0; i < _to.length; i++) {
            balanceOf[_to[i]] += _value; // no overflow checks
        }
    }
}
```

### Explanation
Integer overflow occurs when an arithmetic operation exceeds the maximum representable value of the integer type, wrapping around to a much smaller value. Underflow is the opposite: going below the minimum representable value and wrapping around to a large number. In smart contracts, these wraparounds can cause balances, supply, or accounting variables to behave unexpectedly and can often be turned into direct exploits.

Prior to Solidity 0.8, arithmetic operations did not revert on overflow by default, so developers relied on libraries like SafeMath. When sensitive calculations such as token minting, distribution, or collateral accounting overflow, attackers can artificially inflate balances or bypass checks. Even with Solidity 0.8+, overflow can still be a risk when using inline assembly or custom math routines.

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

---

## 4. Unchecked External Call

### Real Case
In multiple legacy contracts, developers used `call` or `send` without checking the returned boolean. Failures to send ETH (for example due to a reverting fallback) were silently ignored, leading to stuck funds or inconsistent accounting.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract UncheckedSend {
    mapping(address => uint256) public balances;

    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "not enough");

        // ❌ Ignoring return value
        msg.sender.call{value: _amount}("");

        balances[msg.sender] -= _amount; // accounting mismatch possible
    }
}
```

### Explanation
The low-level `call` returns a boolean indicating success or failure. If this return value is ignored, the contract might assume ETH was successfully transferred when it was not. This can create scenarios where internal balances are decremented but the user never receives the funds, or where further logic relies on transfers that never actually happened.

A secure pattern is to always check and handle the return value of low-level calls, use higher-level abstractions like `transfer` (with caveats in high-gas environments) or well-reviewed helper libraries. In modern patterns, pull-payment models and withdrawal patterns avoid pushing ETH unexpectedly to arbitrary addresses.

---

## 5. Uninitialized Storage Pointer

### Real Case
Several audit reports between 2017–2018 identified uninitialized storage references that unintentionally overwrote important contract state, sometimes including ownership or configuration variables.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract UninitializedStorage {
    struct Data { uint256 value; }
    Data public globalData;

    function badSet(uint256 _value) external {
        Data storage dataRef; // ❌ uninitialized
        dataRef.value = _value; // overwrites random storage slot
    }
}
```

### Explanation
In Solidity, `storage` references map directly to slots in contract storage. If a storage pointer is declared but never properly initialized to point at an existing storage variable, writing through it may corrupt arbitrary storage slots. This can destroy or alter data such as balances, configuration, or ownership.

Differentiating correctly between `storage` and `memory` is essential, especially when working with structs, arrays, or libraries. When in doubt, initializing references carefully and avoiding uninitialized storage variables prevents these subtle but severe bugs.

---

## 6. Delegatecall Vulnerability

### Real Case
- **Parity Multisig Hack #1 (2017)**  
  A wallet referenced a library contract via `delegatecall`. Attackers were able to call an initialization function through this mechanism, resetting the owner and taking control of the wallet.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract LogicLibrary {
    address public owner;

    function initOwner(address _owner) external {
        owner = _owner;
    }
}

contract ProxyWallet {
    address public implementation;
    address public owner;

    constructor(address _impl) public {
        implementation = _impl;
    }

    // ❌ Arbitrary delegatecall
    function upgradeAndCall(address _impl, bytes calldata data) external {
        implementation = _impl;
        (bool ok, ) = _impl.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
```

### Explanation
`delegatecall` executes code from another contract in the context of the caller’s storage, msg.sender, and balance. This is powerful for upgradeable or modular architectures but extremely dangerous if untrusted or poorly controlled implementations are used. A malicious implementation can overwrite any storage variable of the proxy, including ownership, balances, or configuration.

Safe patterns involve locking down who can trigger `delegatecall`, using well-audited upgrade patterns (like OpenZeppelin’s proxies), and ensuring initialization functions cannot be called more than once or by unauthorized parties. Misuse of `delegatecall` often leads to full system compromise.

---

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

---

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

---

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

---

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

---

## 14. Insufficient Input Validation

### Real Case
A variety of incidents have arisen from missing checks on parameters such as recipient addresses, token amounts, or array indices. The result can be transfers to the zero address, stuck tokens, underflows, or corrupted data structures.

### Vulnerable Example Code
```solidity
pragma solidity ^0.6.0;

contract BadValidation {
    mapping(address => uint256) public balanceOf;

    function transfer(address _to, uint256 _amount) external {
        // ❌ No validation of _to or _amount
        balanceOf[msg.sender] -= _amount; // underflow (pre-0.8)
        balanceOf[_to] += _amount;        // _to could be zero address
    }
}
```

### Explanation
Input validation ensures that function arguments are within acceptable and safe ranges. Without these checks, users can trigger edge cases that the developer never intended to allow, such as transferring tokens to invalid recipients, passing zero amounts where they shouldn’t, or using extreme values that overflow downstream logic.

Best practices include validating non-zero addresses, enforcing reasonable upper and lower bounds on numerical inputs, checking array length consistency, and using `require` statements liberally for argument sanity. Combined with modern compiler checks, this greatly reduces attack surface.

---

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
