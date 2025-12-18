# Smart Contract Vulnerabilities – Real Cases & Vulnerable Code Examples (15 Types)

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
