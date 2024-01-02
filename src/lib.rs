pub mod nuki_command;

use btleplug::api::{CentralEvent, Characteristic};
use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter, WriteType};
use btleplug::platform::{Manager, Peripheral};
use uuid::{Uuid, uuid};

use std::fs::File;
use std::path::Path;

use futures::stream::StreamExt;  // for steam::next()
use machine_uid;
use anyhow::{Result, anyhow};

#[allow(unused_imports)]
use log::{info, warn, error, debug};

use hex;
use std::time::{Duration, Instant};

use sodiumoxide::{crypto::box_, base64};
use crc::{Crc, CRC_32_ISCSI};

use serde::{Deserialize, Serialize};
use serde_json;

use crate::nuki_command::*;

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct NukiSmartLock {
    address: [u8;6],
    key: String,
    authorization_id: u32,
    app_id: u32,
}

const UUID_CHAR_PAIRING: Uuid = uuid!("a92ee101-5501-11e4-916c-0800200c9a66");
const UUID_CHAR_GDIO: Uuid =    uuid!("a92ee201-5501-11e4-916c-0800200c9a66");
const UUID_CHAR_USDIO: Uuid =   uuid!("a92ee202-5501-11e4-916c-0800200c9a66");
const UUID_SVC_PAIR: Uuid =     uuid!("a92ee100-5501-11e4-916c-0800200c9a66");

/// Operation Nuki device with BLE API from Nuki:
/// https://developer.nuki.io/page/nuki-smart-lock-api-2/2
impl NukiSmartLock {
    pub async fn pair(&mut self, name: &str) -> Result<()> {
        let p = self.connect().await?;

        // Request public key from nuki device
        let msg_req_pk = CmdRequestData0x0001::from(0x3);
        let resp_pk = self.request(&p, &UUID_CHAR_PAIRING, &msg_req_pk.encode()?).await?;
        let msg_pk = CmdPublicKey0x0003::from_raw(&resp_pk)?;
        let sl_pk = msg_pk.public_key;
        info!("Received public key of Nuki device: {}", base64::encode(&sl_pk, base64::Variant::OriginalNoPadding));

        // Generate own key pair, calculate shared key (precomputed key)
        let (pk, sk) = box_::gen_keypair();
        info!("Generated own public key: {}", base64::encode(&pk.0, base64::Variant::OriginalNoPadding));
        info!("Generated own secret key: [*** HIDE ***]");
        let pre = box_::precompute(&box_::PublicKey::from_slice(&sl_pk).ok_or(anyhow!("Invalid public key received."))?, &sk);
        self.key = base64::encode(&pre, base64::Variant::OriginalNoPadding);
        info!("Precomputed key for this Nuki device: [*** HIDE ***]");

        // Send own public key on Nuki and get a challenge back from Nuki
        let msg_pk = CmdPublicKey0x0003::from(&pk.0);
        let resp = self.request(&p, &UUID_CHAR_PAIRING, &msg_pk.encode()?).await?;
        let resp_challenge = CmdChallenge0x0004::from_raw(&resp)?;

        // Send Authorization Authenticator back to Nuki
        let msg_auth_auth = CmdAuthorizationAuthenticator0x0005::from(&pk.0, &sl_pk, &resp_challenge.nonce);
        let resp = self.request(&p, &UUID_CHAR_PAIRING, &msg_auth_auth.encode(&pre.0)?).await?;
        let resp_challenge = CmdChallenge0x0004::from_raw(&resp)?;

        // Send Authorization Data to Nuki
        let msg_auth_data = CmdAuthorizationData0x0006::from(
                    0, generate_app_id()?, name, &resp_challenge.nonce);
        let resp = self.request(&p, &UUID_CHAR_PAIRING, &msg_auth_data.encode(&pre.0)?).await?;
        let resp_auth_id = CmdAuthorizationID0x0007::from_raw(&resp, &pre.0, &msg_auth_data.nonce_abf)?;

        self.authorization_id = resp_auth_id.authorization_id;

        let msg_confirm_auth_id = CmdAuthorizationIdConfirmation0x001e::from(self.authorization_id, &resp_auth_id.nonce_k);
        let resp = self.request(&p, &UUID_CHAR_PAIRING, &msg_confirm_auth_id.encode(&pre.0)?).await?;

        // Status complete!
        let msg_status = CmdStatus0x000e::from_raw(&resp)?;

        p.disconnect().await?;

        if msg_status.status == 0 {
            Ok(())
        } else {
            Err(anyhow!("Pairing failed. Status code: {}.", msg_status.status))?
        }
    }

    pub fn new_with_address(addr: &[u8]) -> Self {
        let mut sl = Self { ..Default::default()};
        sl.address.copy_from_slice(addr);
        sl
    }

    pub fn load<P: AsRef<Path>>(pathname: &P) -> Result<Self> {
        let obj = serde_json::from_reader(std::io::BufReader::new(File::open(pathname)?))?;
        Ok(obj)
    }

    pub fn save<P: AsRef<Path>>(&self, pathname: &P) -> Result<()> {
        serde_json::to_writer(&File::create(pathname)?, self)?;
        Ok(())
    }

    pub async fn perform_lock_action(&self, action: LockAction, log_suffix: &str) -> Result<()> {
         let p = self.connect().await?;
         
         // request a challenge
        let cmd_req = CmdRequestData0x0001::from(0x4);
        let resp = self.request(&p, &UUID_CHAR_USDIO, &cmd_req.encrypt(&self.get_key()?, self.authorization_id)?).await?;
        
        let cmd_challenge = CmdChallenge0x0004::from_raw(&resp)?;
        let cmd_req = CmdLockAction0x000d::from(action.into(), self.app_id, log_suffix);
        let body = cmd_req.encrypt(&self.get_key()?, self.authorization_id, &cmd_challenge.nonce)?;

        let resp = self.request(&p, &UUID_CHAR_USDIO, &body).await?;

        // First response: Status
        let resp_status = CmdStatus0x000e::from_raw(&resp)?;
        info!("Response: {}", if resp_status.status == 1 { "ACCEPTED"} else { "UNEXPECTED"} );

        p.disconnect().await?;
        Ok(())
    }

    pub async fn get_status(&self) -> Result<CmdKeyturnerState0x000c> {
        let cmd_req = CmdRequestData0x0001::from(0xc);
        let body = cmd_req.encrypt(&self.get_key()?, self.authorization_id)?;

        let p = self.connect().await?;
        let resp = self.request(&p, &UUID_CHAR_USDIO, &body).await?;
        info!("Response: {}", hex::encode(&resp));
        
        let status = CmdKeyturnerState0x000c::from_raw(&resp)?;

        p.disconnect().await?;
        Ok(status)
    }

    pub async fn get_battery_report(&self) -> Result<CmdBatteryReport0x0011> {
        let cmd_req = CmdRequestData0x0001::from(0x11);
        let body = cmd_req.encrypt(&self.get_key()?, self.authorization_id)?;

        let p = self.connect().await?;
        let resp = self.request(&p, &UUID_CHAR_USDIO, &body).await?;
        info!("Response: {}", hex::encode(&resp));

        let report = CmdBatteryReport0x0011::from_raw(&resp)?;

        p.disconnect().await?;
        Ok(report)
    }

    async fn request(&self, p: &Peripheral, char_request: &Uuid, data: &[u8]) -> Result<Vec<u8>> {
        let chars = p.characteristics();
        let mut noti_stream = p.notifications().await?;

        let mut cmd_char = Option::<Box<Characteristic>>::None;
        for char in chars {

            if char.uuid == UUID_CHAR_GDIO || char.uuid == UUID_CHAR_PAIRING || char.uuid == UUID_CHAR_USDIO {
                debug!("Subscribed to {}", &char.uuid);
                p.subscribe(&char).await?;
            }
            if char.uuid == *char_request {
                cmd_char = Some(Box::new(char));
            }
        }

        if let Some(char_wr) = cmd_char {
            debug!("Tx: {}", hex::encode(data));
            p.write(&char_wr, data, WriteType::WithResponse).await?;

            // wait for response
            
            if let Some(data) = noti_stream.next().await{
                debug!("Rx: {} - {}", &data.uuid, &hex::encode(&data.value));

                // Decrypt messages from USDIO
                if data.uuid == UUID_CHAR_USDIO {
                    let data = decrypt_message(&data.value, &self.get_key()?, self.authorization_id)?;
                    get_error(&data)?;
                    Ok(data)
                } else {
                    verify_crc(&data.value)?;
                    get_error(&data.value)?;
                    Ok(data.value)
                }
            } else {
                Err(anyhow!("Error by waiting notification."))?
            }
        } else {
            Err(anyhow!("Characteristic not found."))?
        }
      
    }

    fn get_key(&self) -> Result<Vec<u8>> {
        Ok(base64::decode(&self.key, base64::Variant::OriginalNoPadding).map_err(|_| anyhow!("Failed to decode key."))?)
    }

    async fn connect(&self) -> Result<Peripheral> {
        let manager = Manager::new().await.unwrap();
        let start_time = Instant::now();

        // get the first bluetooth adapter
        let adapters = manager.adapters().await?;
        let central = adapters.into_iter().nth(0).unwrap();
        let mut events = central.events().await?;   

        central.start_scan(ScanFilter::default()).await?;
        while let Some(event) = events.next().await {
            if start_time.elapsed() > Duration::from_secs(15) {
                warn!("Timeout. No peripherial found.");
                central.stop_scan().await?;
                break;
            }
            match event {
                CentralEvent::DeviceDiscovered(id) => {
                    let periph = central.peripheral(&id).await?;
                    if periph.address() == self.address.into() {
                        central.stop_scan().await?;
                        info!("Connecting to device {}...", &periph.address());
                        periph.connect().await?;
                        periph.discover_services().await?;   
                        return Ok(periph)
                    }      
                },
                _ => {},
            }
        }

        Err(anyhow!("Nuki smart lock not found."))?
    }

    pub fn address_as_string(&self) -> String{
        format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
                self.address[0], self.address[1], self.address[2], 
                self.address[3], self.address[4], self.address[5])
    }

    pub async fn discover_nuki_device() -> Result<Self>{
        let manager = Manager::new().await.unwrap();
    
        // get the first bluetooth adapter
        let adapters = manager.adapters().await?;
        let central = adapters.into_iter().nth(0).unwrap();
        let mut events = central.events().await?;
    
        // start scanning for devices
        central.start_scan(ScanFilter::default()).await?;
        while let Some(event) = events.next().await {
            match event {
                CentralEvent::ServiceDataAdvertisement { id, service_data } => {
                    for (sid, _)in &service_data {
                        info!("{}", sid);
                        if sid == &UUID_SVC_PAIR{
                            central.stop_scan().await?;
                            let p = central.peripheral(&id).await?;
                            let nuki = Self {
                                address: p.address().into_inner(),
                                ..Default::default()
                            };
                            return Ok(nuki);
                        }
                    }
                },
                _ => {},
            }
        }
        Err(anyhow!("No pairable peripherial found."))
    }

}



// In Nuki device, every pairing must have different App-ID.
// New pairing will replace the old pairing with the same App-ID.
// The App-ID will be generated from information of machine ID and user name.
// This ensures the same user on the samte machine will always have the same App-ID,
// with which, the user cannot have two different pairing in the Nuki device.
fn generate_app_id() -> Result<u32> {
    let uid = machine_uid::get().map_err(|e| anyhow!("Cannot get machine ID {}.", e))?;
    let uid = hex::decode(uid)?;
    let user = whoami::username();

    // Calculate CRC32 value for App-ID
    let crc = Crc::<u32>::new(&CRC_32_ISCSI);
    let mut digest = crc.digest();
    digest.update(&uid);
    digest.update(user.as_bytes());
    Ok(digest.finalize())
}

// fn generate_app_name() -> String {
//     let mut user = String::from("rs-");
//     user.push_str(&whoami::username());
//     user
// }

#[cfg(test)]
mod tests {
    use super::*;

    use hex::decode;
    
    fn create_lock_from_secret() -> NukiSmartLock {
        let pk = decode("4e6592661d9b0a3f48671da53d6ba81fe0633c5ef902686ddafe5a718d5ebf45").unwrap();
        let sk = decode("354978f80cdf80587641ef71c5049f6db51f83503a324d8ad100f5713860a903").unwrap();
        let pk_nuki = decode("be7ed31a433546510addca0f698a40d6fd9bfea5bfcb69e964b361d7f0bd596d").unwrap();
        let pre = box_::precompute(&box_::PublicKey::from_slice(&pk_nuki).unwrap(), 
                    &box_::SecretKey::from_slice(&sk).unwrap());
        let lock = NukiSmartLock{
            address: [0x54u8, 0xd2, 0x72, 0xfd, 0x60, 0x15],
            authorization_id: 770179075,
            key: base64::encode(&pre.0, base64::Variant::OriginalNoPadding),
            ..Default::default()
        };
        lock
    }

    fn load_lock() -> NukiSmartLock {
        // NukiSmartLock::load("test_pair.json").unwrap()
        unimplemented!()
    }

    #[test]
    fn aquire_lock() {
        create_lock_from_secret();
    }

    #[test]
    fn machine_id() {
        info!("App-ID: {}", generate_app_id().unwrap());
    }

    #[tokio::test]
    async fn get_status() {
        let lock = load_lock();
        let status = lock.get_status().await.unwrap();
        info!("Status: {}", status);
    }

    #[tokio::test]
    async fn pair() {
        // only for address
        // let mut lock = load_lock();
        // match lock.pair().await{
        //     Err(e) => {
        //         println!("Failed: {:?}", e);
        //     },
        //     _ => {
        //         lock.save("test_pair.json").unwrap();
        //     },
        // }
    }

    #[tokio::test]
    async fn unlock() {
        let lock = load_lock();
        lock.perform_lock_action(LockAction::Unlock, "Test").await.unwrap();
    }

    #[test]
    fn save_load() {
        // let lock1 = create_lock_from_secret();
        // lock1.save("test_lock.json").unwrap();
        // let lock2 = NukiSmartLock::load("test_lock.json").unwrap();
        // assert_eq!(lock1.address, lock2.address);
        // assert_eq!(lock1.authorization_id, lock2.authorization_id);
        // assert_eq!(lock1.key, lock2.key);
    }

}