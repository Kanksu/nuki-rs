# nuki-rs
Bluetooth API for Nuki Smartlock

# Usage

## Pair
```rust
let mut nuki = NukiSmartLock::discover_nuki_device().await.unwrap();
nuki.pair("TestUser").await.unwrap();

// Save the credentials to file.
// The file contains the MAC adresse and the private key. 
nuki.save("nuki-credentials.json").unwrap();
```

## Perform actions

The following actions can be performed:
Perform one of the following actions:
- Unlock,
- Lock,
- Unlatch,
- LockAndGo,
- LockAnGoUnlatch,
- FullLock,
- FobAction1,
- FobAction2,
- FobAction3


```rust
// Perfom unlock
use nuki_command::LockAction;

let nuki = NukiSmartLock::load("nuki-credentials.json").unwrap();
nuki.perform_lock_action(LockAction::Unlock).unwrap();
```
# Example

see ```/example```.
