# nuki-rs

[![Crates.io Version](https://img.shields.io/crates/v/nuki-rs)](https://crates.io/crates/nuki-rs)
[![docs.rs](https://img.shields.io/docsrs/nuki-rs)](https://docs.rs/nuki-rs/latest/nuki_rs/)
![Crates.io License](https://img.shields.io/crates/l/nuki-rs)
![Crates.io Total Downloads](https://img.shields.io/crates/d/nuki-rs)



Bluetooth API for Nuki Smartlock

# Usage

## Pair
```rust
let mut nuki = NukiSmartLock::discover_pairable().await.unwrap();
nuki.pair("TestUser").await.unwrap();

// Save the credentials to file.
// The file contains the MAC adresse and the private key. 
nuki.save(&String::from("nuki-credentials.json")).unwrap();
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

let nuki = NukiSmartLock::load(&String::from("nuki-credentials.json")).unwrap();
nuki.perform_lock_action(LockAction::Unlock, "TestUser").unwrap();
```
# Example

see ```/example```.
