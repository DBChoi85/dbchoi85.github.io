# Smart Contract Vulnerabilities Patterns

A curated list of major Ethereum smart contract vulnerability patterns, their historical incidents, and minimal vulnerable code examples.

## 1. Reentrancy Attack
Real Case

The DAO Hack (2016)
The withdraw function sent ETH before updating balances, allowing recursive calls through a fallback function. Result: ~3.6M ETH drained.

Vulnerable Example Code
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

## 2. Integer Overflow / Underflow
Real Case

BatchOverflow Vulnerability (2018)
Token multiplication overflow allowed attackers to mint enormous token amounts.

Vulnerable Example Code
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

## 3. Access Control Misconfiguration
Real Case

Numerous ERC-20 tokens allowed anyone to mint tokens due to missing onlyOwner modifiers.

Vulnerable Example Code
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

## 4. Unchecked External Call
Real Case

Many old smart contracts ignored the return value of call() and send(), causing stuck funds and accounting inconsistencies.

Vulnerable Example Code
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

## 5. Uninitialized Storage Pointer
Real Case

Several 2017–2018 audits discovered contracts overwriting unintended storage slots due to uninitialized storage references.

Vulnerable Example Code
pragma solidity ^0.6.0;

contract UninitializedStorage {
    struct Data { uint256 value; }
    Data public globalData;

    function badSet(uint256 _value) external {
        Data storage dataRef; // ❌ uninitialized
        dataRef.value = _value; // overwrites random storage slot
    }
}

## 6. Delegatecall Vulnerability
Real Case

Parity Multisig Hack #1 (2017)
delegatecall allowed attackers to reinitialize the wallet library, taking ownership.

Vulnerable Example Code
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

## 7. Randomness Manipulation
Real Case

Games and lotteries using predictable randomness (timestamp, blockhash) were manipulated by miners or players.

Vulnerable Example Code
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

## 8. Front-running / MEV Exploits
Real Case

Sandwich attacks on DEXs

NFT mint sniping

Liquidation sniping in lending protocols

Vulnerable Example Code
pragma solidity ^0.6.0;

contract SimpleAuction {
    address public highestBidder;
    uint256 public highestBid;

    function bid() external payable {
        require(msg.value > highestBid, "low bid");

        // ❌ front-runnable: anyone can outbid after seeing your tx in mempool
        if (highestBidder != address(0)) {
            payable(highestBidder).transfer(highestBid);
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}

## 9. Price Oracle Manipulation
Real Case

bZx Hack (2020)

Harvest Finance Hack (2020)
Attackers manipulated AMM prices via flash loans → borrowed assets with inflated collateral value.

Vulnerable Example Code
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

## 10. Denial of Service (DoS)
Real Case

King of the Ether Throne
A malicious king used a reverting fallback function, freezing the game permanently.

Vulnerable Example Code
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

## 11. Timestamp Manipulation
Real Case

Miners can manipulate timestamps within ~15 seconds, influencing lotteries, vesting, and unlock logic.

Vulnerable Example Code
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

## 12. Logic Errors / Business Logic Bypass
Real Case

Compound COMP Distribution Bug (2021) → over-rewarding users

Several protocols suffered infinite reward minting from miscalculated formulas.

Vulnerable Example Code
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

## 13. Insecure Initialization / Constructor Issues
Real Case

Parity Multisig Hack #2 (2017)
Anyone could call the library's initialization function and seize wallet ownership.

Vulnerable Example Code
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

## 14. Insufficient Input Validation
Real Case

Missing validations led to:

transfers to address(0)

underflows

stuck assets

corrupted indexes and storage

Vulnerable Example Code
pragma solidity ^0.6.0;

contract BadValidation {
    mapping(address => uint256) public balanceOf;

    function transfer(address _to, uint256 _amount) external {
        // ❌ No validation of _to or _amount
        balanceOf[msg.sender] -= _amount; // underflow
        balanceOf[_to] += _amount;        // _to could be zero address
    }
}

## 15. Token Standard Misimplementation (ERC-20/721/1155)
Real Case

Some tokens did not return bool on transfer, breaking exchanges and causing lost funds.

Vulnerable Example Code
pragma solidity ^0.6.0;

contract BadERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // ❌ No bool return value
    function transfer(address _to, uint256 _amount) external {
        if (balanceOf[msg.sender] >= _amount) {
            balanceOf[msg.sender] -= _amount;
            balanceOf[_to] += _amount;
        }
    }

    // ❌ Incorrect approve logic
    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }
}
