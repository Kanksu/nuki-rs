use crc::{Crc, CRC_16_IBM_3740};
use sodiumoxide::{crypto::auth::hmacsha256, crypto::box_, randombytes};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::{prelude::*, FixedOffset, LocalResult, Utc};

use anyhow::{anyhow, Result};

#[derive(Default)]
pub struct CmdRequestData0x0001 {
    cmd_id: u16,
    additional: Vec<u8>,
}

impl CmdRequestData0x0001 {
    pub fn from(cmd_id: u16) -> Self {
        Self {
            cmd_id: cmd_id,
            ..Default::default()
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut msg = vec![1u8, 0];
        msg.write_u16::<LittleEndian>(self.cmd_id)?;
        msg.extend(&self.additional);
        append_crc(&mut msg);
        Ok(msg)
    }

    fn pdata(&self, auth_id: u32) -> Result<Vec<u8>> {
        let mut pdata = Vec::<u8>::new();
        pdata.write_u32::<LittleEndian>(auth_id)?;
        pdata.write_u16::<LittleEndian>(0x1)?;
        pdata.write_u16::<LittleEndian>(self.cmd_id)?;
        append_crc(&mut pdata);
        Ok(pdata)
    }

    pub fn encrypt(&self, key: &[u8], auth_id: u32) -> Result<Vec<u8>> {
        let pdata = self.pdata(auth_id);
        let nonce = box_::gen_nonce();
        let cipher = box_::seal_precomputed(
            &pdata?,
            &nonce,
            &box_::PrecomputedKey::from_slice(key).ok_or(anyhow!("Key not valid."))?,
        );

        let mut body = Vec::<u8>::new();
        body.extend(&nonce.0);
        body.write_u32::<LittleEndian>(auth_id)?;
        body.write_u16::<LittleEndian>(cipher.len() as u16)?;
        body.extend(&cipher);
        Ok(body)
    }
}

pub struct CmdPublicKey0x0003 {
    pub public_key: Vec<u8>,
}

impl CmdPublicKey0x0003 {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        assert_command_length(raw, 32 + 4)?;
        assert_command_id(raw, 0x03)?;
        Ok(Self {
            public_key: raw[2..raw.len() - 2].to_vec(),
        })
    }

    pub fn from(pk: &[u8]) -> Self {
        Self {
            public_key: pk.to_vec(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut data = vec![3, 0];
        data.extend(&self.public_key);
        append_crc(&mut data);
        Ok(data)
    }
}

pub struct CmdChallenge0x0004 {
    pub nonce: Vec<u8>,
}

impl CmdChallenge0x0004 {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        assert_command_length(raw, 32 + 4)?;
        assert_command_id(raw, 0x04)?;
        Ok(Self {
            nonce: raw[2..raw.len() - 2].to_vec(),
        })
    }
}

pub struct CmdAuthorizationAuthenticator0x0005 {
    public_key_abf: Vec<u8>,
    public_key_k: Vec<u8>,
    nonce_k: Vec<u8>,
}

impl CmdAuthorizationAuthenticator0x0005 {
    pub fn from(pk_abf: &[u8], pk_k: &[u8], nonce_k: &[u8]) -> Self {
        CmdAuthorizationAuthenticator0x0005 {
            public_key_abf: pk_abf.to_vec(),
            public_key_k: pk_k.to_vec(),
            nonce_k: nonce_k.to_vec(),
        }
    }

    pub fn encode(&self, key: &[u8]) -> Result<Vec<u8>> {
        // CL concatenates its own public key with SL’s public key and the challenge to value r
        let mut r = Vec::<u8>::new();
        r.extend(&self.public_key_abf);
        r.extend(&self.public_key_k);
        r.extend(&self.nonce_k);

        // CL calculates the authenticator a of r using function h1 (HMAC-SHA256)
        let auth = hmacsha256::authenticate(
            &r,
            &hmacsha256::Key::from_slice(&key).ok_or(anyhow!("Key not valid."))?,
        );
        assert_eq!(auth.0.len(), 32);

        let mut data = vec![5, 0];
        data.extend(&auth.0);
        append_crc(&mut data);
        Ok(data)
    }
}

#[derive(Default)]
pub struct CmdAuthorizationData0x0006 {
    id_type: u8,
    id: u32,
    name: Vec<u8>,
    nonce_k: Vec<u8>,
    pub nonce_abf: Vec<u8>,
}

impl CmdAuthorizationData0x0006 {
    pub fn from(id_type: u8, id: u32, name: &str, nonce_k: &[u8]) -> Self {
        // TODO: wide characters must be handled here?
        // Do Nuki devices unterstand UTF-8?
        let mut name_vec = vec![0u8; 32];
        copy_from_str(&mut name_vec, name);
        Self {
            id_type: id_type,
            id,
            name: name_vec,
            nonce_k: nonce_k.to_vec(),
            nonce_abf: randombytes::randombytes(32),
        }
    }

    pub fn encode(&self, key: &[u8]) -> Result<Vec<u8>> {
        let mut r = Vec::new();
        r.push(self.id_type);
        r.write_u32::<LittleEndian>(self.id)?;
        assert_eq!(self.name.len(), 32);
        r.extend(&self.name);
        r.extend(&self.nonce_abf);
        r.extend(&self.nonce_k);

        let auth = hmacsha256::authenticate(
            &r,
            &hmacsha256::Key::from_slice(&key).ok_or(anyhow!("Key not valid."))?,
        );
        assert_eq!(auth.0.len(), 32);

        let mut data = vec![6, 0];
        data.extend(auth.0);
        data.push(self.id_type);
        data.write_u32::<LittleEndian>(self.id)?;
        data.extend(&self.name);
        data.extend(&self.nonce_abf);

        append_crc(&mut data);

        Ok(data)
    }
}

pub struct CmdAuthorizationID0x0007 {
    pub authorization_id: u32,
    pub uuid: Vec<u8>,
    pub nonce_k: Vec<u8>,
}

impl CmdAuthorizationID0x0007 {
    pub fn from_raw(raw: &[u8], key: &[u8], nonce_abf: &[u8]) -> Result<Self> {
        assert_command_length(raw, 88)?;
        assert_command_id(raw, 7)?;

        let body = &raw[2..(raw.len() - 2)];
        let auth = &body[0..32];
        let msg = &body[32..];
        let mut msg_plus_nonce = msg.to_vec();
        msg_plus_nonce.extend(nonce_abf);
        if hmacsha256::verify(
            &hmacsha256::Tag::from_slice(auth).ok_or(anyhow!("Send not trusted."))?,
            &msg_plus_nonce,
            &hmacsha256::Key::from_slice(key).ok_or(anyhow!("Send not trusted."))?,
        ) {
            let mut c = std::io::Cursor::new(&msg[0..4]);
            Ok(Self {
                authorization_id: c.read_u32::<LittleEndian>()?,
                uuid: msg[4..20].to_vec(),
                nonce_k: msg[20..52].to_vec(),
            })
        } else {
            Err(anyhow!("Send not trusted."))
        }
    }
}

pub struct CmdAuthorizationIdConfirmation0x001e {
    authorization_id: u32,
    nonce_k: Vec<u8>,
}

impl CmdAuthorizationIdConfirmation0x001e {
    pub fn from(id: u32, nonce_k: &[u8]) -> Self {
        Self {
            authorization_id: id,
            nonce_k: nonce_k.to_vec(),
        }
    }

    pub fn encode(&self, key: &[u8]) -> Result<Vec<u8>> {
        let mut tmp = Vec::new();
        tmp.write_u32::<LittleEndian>(self.authorization_id)?;
        let mut msg_to_verify = tmp.clone();
        msg_to_verify.extend(&self.nonce_k);
        let auth = hmacsha256::authenticate(
            &msg_to_verify,
            &hmacsha256::Key::from_slice(key).ok_or(anyhow!("Key not valid."))?,
        );
        let mut msg = vec![0x1e, 0];
        msg.extend(auth.0);
        msg.extend(&tmp);
        append_crc(&mut msg);
        Ok(msg)
    }
}

#[derive(Default, Debug)]
pub struct CmdKeyturnerState0x000c {
    pub nuki_state: u8,
    pub lock_state: u8,
    pub trigger: u8,
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub timezone_offset: i16,
    pub critical_battery_state: u8,
    pub config_update_count: u8,
    pub lock_n_go_timer: u8,
    pub last_lock_action: u8,
    pub last_lock_action_trigger: u8,
    pub last_lock_action_completion_status: u8,
    pub door_sensor_state: u8,
    pub nightmode_active: u16,
    pub accessory_battery_state: u8,
}

impl std::fmt::Display for CmdKeyturnerState0x000c {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Keyturner Status:\n\
            Nuki State: {}\n\
            Lock State: {}\n\
            Battery:    {}% ({})\n\
            Time:       {}",
            self.interp_nuki_state(),
            self.interp_lock_state(),
            self.interp_battery_level(),
            self.interp_battery_state(),
            self.interp_time()
        )
    }
}

impl CmdKeyturnerState0x000c {
    fn interp_nuki_state(&self) -> &'static str {
        match self.nuki_state {
            0x00 => "Uninitialized",
            0x01 => "Pairing Mode",
            0x02 => "Door Mode",
            0x04 => "Maintenance Mode",
            _ => "Undefined",
        }
    }

    fn interp_lock_state(&self) -> &'static str {
        match self.lock_state {
            0x00 => "uncalibrated",
            0x01 => "locked",
            0x02 => "unlocking",
            0x03 => "unlocked",
            0x04 => "locking",
            0x05 => "unlatched",
            0x06 => "unlocked (lock ‘n’ go active)",
            0x07 => "unlatching",
            0xFC => "calibration",
            0xFD => "boot run",
            0xFE => "motor blocked",
            _ => "Undefined",
        }
    }

    fn interp_battery_level(&self) -> u8 {
        (self.critical_battery_state >> 2) * 2
    }

    fn interp_battery_state(&self) -> &'static str {
        if self.critical_battery_state & 0x2 != 0 {
            "Charging"
        } else if self.critical_battery_state & 0x1 != 0 {
            "Critical"
        } else {
            "OK"
        }
    }

    fn interp_time(&self) -> String {
        if let LocalResult::Single(dt) = Utc.with_ymd_and_hms(
            self.year.into(),
            self.month.into(),
            self.day.into(),
            self.hour.into(),
            self.minute.into(),
            self.second.into(),
        ) {
            if let Some(offset) = FixedOffset::east_opt((self.timezone_offset as i32) * 60) {
                return format!("{}", dt.with_timezone(&offset)).to_string();
            }
        }
        "Failed to interprete".to_string()
    }

    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        assert_command_length(&raw, std::mem::size_of::<CmdKeyturnerState0x000c>() + 2)?;
        assert_command_id(raw, 0xc)?;
        let status = CmdKeyturnerState0x000c {
            nuki_state: raw[2],
            lock_state: raw[3],
            trigger: raw[4],
            year: std::io::Cursor::new(&raw[5..7]).read_u16::<LittleEndian>()?,
            month: raw[7],
            day: raw[8],
            hour: raw[9],
            minute: raw[10],
            second: raw[11],
            timezone_offset: std::io::Cursor::new(&raw[12..14]).read_i16::<LittleEndian>()?,
            critical_battery_state: raw[14],
            config_update_count: raw[15],
            lock_n_go_timer: raw[16],
            last_lock_action: raw[17],
            last_lock_action_trigger: raw[18],
            last_lock_action_completion_status: raw[19],
            door_sensor_state: raw[20],
            nightmode_active: std::io::Cursor::new(&raw[21..23]).read_u16::<LittleEndian>()?,
            accessory_battery_state: raw[23],
        };
        Ok(status)
    }
}

pub struct CmdStatus0x000e {
    pub status: u8,
}

impl CmdStatus0x000e {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        assert_command_length(raw, 5)?;
        assert_command_id(raw, 0x0e)?;

        Ok(Self { status: raw[2] })
    }
}

pub struct CmdLockAction0x000d {
    lock_action: u8,
    app_id: u32,
    flags: u8,
    log_suffix: Vec<u8>,
}

impl CmdLockAction0x000d {
    pub fn from(lock_action: u8, app_id: u32, log_suffix: &str) -> Self {
        let mut suffix = vec![0u8; 20];
        copy_from_str(&mut suffix, log_suffix);
        CmdLockAction0x000d {
            lock_action,
            app_id,
            flags: 0,
            log_suffix: suffix,
        }
    }

    fn pdata(&self, auth_id: u32, nonce_k: &[u8]) -> Result<Vec<u8>> {
        let mut data = Vec::<u8>::new();
        data.write_u32::<LittleEndian>(auth_id)?;
        data.write_u16::<LittleEndian>(0xd)?;
        data.push(self.lock_action);
        data.write_u32::<LittleEndian>(self.app_id)?;
        data.push(self.flags);
        assert_eq!(self.log_suffix.len(), 20);
        data.extend(&self.log_suffix);
        data.extend(nonce_k);
        append_crc(&mut data);
        Ok(data)
    }

    pub fn encrypt(&self, key: &[u8], auth_id: u32, nonce_k: &[u8]) -> Result<Vec<u8>> {
        let pdata = self.pdata(auth_id, nonce_k);
        let nonce = box_::gen_nonce();
        let cipher = box_::seal_precomputed(
            &pdata?,
            &nonce,
            &box_::PrecomputedKey::from_slice(key).ok_or(anyhow!("Key not valid."))?,
        );

        let mut body = Vec::<u8>::new();
        body.extend(&nonce.0);
        body.write_u32::<LittleEndian>(auth_id)?;
        body.write_u16::<LittleEndian>(cipher.len() as u16)?;
        body.extend(&cipher);
        Ok(body)
    }
}

pub struct CmdBatteryReport0x0011 {
    pub battery_drain: u16,
    pub battery_voltage: u16,
    pub critical_state: u8,
    pub lock_action: u8,
    pub start_voltage: u16,
    pub lowest_voltage: u16,
    pub lock_distance: u16,
    pub start_temperature: i8,
    pub max_turn_current: u16,
    pub battery_resistance: u16,
}

impl std::fmt::Display for CmdBatteryReport0x0011 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Battery Report:\n\
            Battery drain:      {}mWs\n\
            Battery voltage:    {}mV\n\
            Critical State:     {}\n\
            Lock action::       {}\n\
            Start voltage:      {}mV\n\
            Lowest voltage:     {}mV\n\
            Lock distance:      {}°\n\
            Start temperature:  {}°C\n\
            Max turn current:   {}mA\n\
            Battery resistance: {}mOhm\n",
            self.battery_drain,
            self.battery_voltage,
            self.critical_state,
            self.lock_action,
            self.start_voltage,
            self.lowest_voltage,
            self.lock_distance,
            self.start_temperature,
            self.max_turn_current,
            self.battery_resistance
        )
    }
}

impl CmdBatteryReport0x0011 {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        assert_command_length(raw, std::mem::size_of::<CmdBatteryReport0x0011>() + 2)?;
        assert_command_id(raw, 0x11)?;
        let s = Self {
            battery_drain: std::io::Cursor::new(&raw[2..4]).read_u16::<LittleEndian>()?,
            battery_voltage: std::io::Cursor::new(&raw[4..6]).read_u16::<LittleEndian>()?,
            critical_state: raw[6],
            lock_action: raw[7],
            start_voltage: std::io::Cursor::new(&raw[8..10]).read_u16::<LittleEndian>()?,
            lowest_voltage: std::io::Cursor::new(&raw[10..12]).read_u16::<LittleEndian>()?,
            lock_distance: std::io::Cursor::new(&raw[12..14]).read_u16::<LittleEndian>()?,
            start_temperature: raw[14] as i8,
            max_turn_current: std::io::Cursor::new(&raw[15..17]).read_u16::<LittleEndian>()?,
            battery_resistance: std::io::Cursor::new(&raw[17..19]).read_u16::<LittleEndian>()?,
        };

        Ok(s)
    }
}

pub struct CmdErrorReport0x0012 {
    err_code: u8,
    #[allow(dead_code)]
    command_id: u16,
}

impl CmdErrorReport0x0012 {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        assert_command_length(raw, 5)?;
        assert_command_id(raw, 0x12)?;
        let s = Self {
            err_code: raw[2],
            command_id: std::io::Cursor::new(&raw[3..5]).read_u16::<LittleEndian>()?,
        };

        Ok(s)
    }
}

pub fn get_error(msg: &[u8]) -> Result<()> {
    if get_command_id(msg)? == 0x12 {
        let d = CmdErrorReport0x0012::from_raw(msg)?;
        Err(anyhow!("Error from Nuki Smartlock (Code: {}).", d.err_code))
    } else {
        Ok(())
    }
}

fn assert_command_length(raw: &[u8], len: usize) -> Result<()> {
    if raw.len() < len {
        Err(anyhow!("Message has wrong length."))
    } else {
        Ok(())
    }
}

fn assert_command_id(raw: &[u8], id: u16) -> Result<()> {
    if (id & 0xff == raw[0] as u16) && (id >> 8 == raw[1] as u16) {
        Ok(())
    } else {
        Err(anyhow!("Unexpected command ID."))
    }
}

fn calc_crc(data: &[u8]) -> u16 {
    let crc = Crc::<u16>::new(&CRC_16_IBM_3740);
    let mut digest = crc.digest();
    digest.update(data);
    digest.finalize()
}

fn append_crc(data: &mut Vec<u8>) {
    let digest = calc_crc(data);
    data.push((digest & 0xff) as u8);
    data.push((digest >> 8) as u8);
}

pub fn verify_crc(raw: &[u8]) -> Result<()> {
    if raw.len() >= 4 {
        let digest = calc_crc(&raw[0..(raw.len() - 2)]);
        let digest_msg = (raw[raw.len() - 1] as u16) << 8 | (raw[raw.len() - 2] as u16);
        if digest == digest_msg {
            Ok(())
        } else {
            Err(anyhow!("Checksum error."))
        }
    } else {
        Err(anyhow!("Message too short."))
    }
}

fn copy_from_str(dest: &mut [u8], src: &str) {
    if dest.len() == src.len() {
        dest.copy_from_slice(src.as_bytes());
    } else if dest.len() > src.len() {
        dest[..src.len()].copy_from_slice(src.as_bytes());
    } else {
        dest.copy_from_slice(&src.as_bytes()[..dest.len()]);
    }
}

pub fn get_command_id(msg: &[u8]) -> Result<u16> {
    if msg.len() > 2 {
        Ok(std::io::Cursor::new(&msg[0..2]).read_u16::<LittleEndian>()?)
    } else {
        Err(anyhow!("Message too short."))
    }
}

pub fn decrypt_message(msg: &[u8], key: &[u8], _auth_id: u32) -> Result<Vec<u8>> {
    let nonce = &msg[0..24];
    let auth_id = std::io::Cursor::new(&msg[24..28]).read_u32::<LittleEndian>()?;
    let length = std::io::Cursor::new(&msg[28..30]).read_u16::<LittleEndian>()?;
    let cipher = &msg[30..];
    if (length as usize) == cipher.len() {
        match box_::open_precomputed(
            cipher,
            &box_::Nonce::from_slice(nonce).ok_or(anyhow!("Not supported."))?,
            &box_::PrecomputedKey::from_slice(key).ok_or(anyhow!("Invalid key."))?,
        ) {
            Ok(plain) => {
                verify_crc(&plain)?;
                if std::io::Cursor::new(&plain[0..4]).read_u32::<LittleEndian>()? == auth_id {
                    Ok(plain[4..].to_vec())
                } else {
                    Err(anyhow!("Sender not trusted."))
                }
            }
            Err(_) => Err(anyhow!("Sender not trusted.")),
        }
    } else {
        Err(anyhow!("Wrong message length."))
    }
}

#[cfg(test)]
mod test {
    // https://developer.nuki.io/page/nuki-smart-lock-api-2/2
    use super::*;

    #[test]
    fn crc_verify() {
        let data =
            hex::decode("03002FE57DA347CD62431528DAAC5FBB290730FFF684AFC4CFC2ED90995F58CB3B749DB9")
                .unwrap();
        verify_crc(&data).unwrap();
    }

    #[test]
    fn command_request_data_0x0001() {
        // unencrypted command
        let cmd = CmdRequestData0x0001::from(3);
        let body = cmd.encode().unwrap();
        let body_exp = hex::decode("0100030027A7").unwrap();
        assert_eq!(body, body_exp);

        // encrypted command
        let _key = hex::decode("217FCB0F18CAF284E9BDEA0B94B83B8D10867ED706BFDEDBD2381F4CB3B8F730")
            .unwrap();
        let auth_id = 2u32;

        let cmd = CmdRequestData0x0001::from(0xc);
        let body = cmd.pdata(auth_id).unwrap();
        let body_exp = hex::decode("0200000001000C00418D").unwrap();
        assert_eq!(body, body_exp);

        // let body = cmd.encrypt(&key, auth_id).unwrap();
        // let body_exp = hex::decode("37917F1AF31EC5940705F34D1E5550607D5B2F9FE7D496B6020000001A00670D124926004366532E8D927A33FE84E782A9594D39157D065E").unwrap();
        // assert_eq!(body, body_exp);
    }

    #[test]
    fn command_battery_report_0x0011() {
        let resp = hex::decode("1100c13a7c1364047b139f11ce041f9c059601b112").unwrap();
        let msg = CmdBatteryReport0x0011::from_raw(&resp).unwrap();
        println!("{}", msg);
    }

    #[test]
    fn command_public_key_0x0003() {
        let pk_out =
            hex::decode("2FE57DA347CD62431528DAAC5FBB290730FFF684AFC4CFC2ED90995F58CB3B74")
                .unwrap();
        let data =
            hex::decode("03002FE57DA347CD62431528DAAC5FBB290730FFF684AFC4CFC2ED90995F58CB3B749DB9")
                .unwrap();
        let msg = CmdPublicKey0x0003::from_raw(&data).unwrap();
        assert_eq!(pk_out, msg.public_key.as_slice());

        let pk = hex::decode("F88127CCF48023B5CBE9101D24BAA8A368DA94E8C2E3CDE2DED29CE96AB50C15")
            .unwrap();
        let body_exp =
            hex::decode("0300F88127CCF48023B5CBE9101D24BAA8A368DA94E8C2E3CDE2DED29CE96AB50C159241")
                .unwrap();
        let msg = CmdPublicKey0x0003::from(&pk);
        let body = msg.encode().unwrap();

        assert_eq!(body, body_exp);
    }

    #[test]
    fn command_challenge_0x0004() {
        let nonce_out =
            hex::decode("6CD4163D159050C798553EAA57E278A579AFFCBC56F09FC57FE879E51C42DF17")
                .unwrap();
        let data =
            hex::decode("04006CD4163D159050C798553EAA57E278A579AFFCBC56F09FC57FE879E51C42DF17C3DF")
                .unwrap();
        let msg = CmdChallenge0x0004::from_raw(&data).unwrap();
        assert_eq!(nonce_out, msg.nonce.as_slice());
    }

    #[test]
    fn command_authorization_authentificator_0x0005() {
        let challenge = CmdChallenge0x0004::from_raw(
            &hex::decode(
                "04006CD4163D159050C798553EAA57E278A579AFFCBC56F09FC57FE879E51C42DF17C3DF",
            )
            .unwrap(),
        )
        .unwrap();

        let pk_abf =
            hex::decode("F88127CCF48023B5CBE9101D24BAA8A368DA94E8C2E3CDE2DED29CE96AB50C15")
                .unwrap();
        let pk_k = hex::decode("2FE57DA347CD62431528DAAC5FBB290730FFF684AFC4CFC2ED90995F58CB3B74")
            .unwrap();
        let aa = CmdAuthorizationAuthenticator0x0005::from(&pk_abf, &pk_k, &challenge.nonce);
        let key = hex::decode("217FCB0F18CAF284E9BDEA0B94B83B8D10867ED706BFDEDBD2381F4CB3B8F730")
            .unwrap();
        let body = aa.encode(&key).unwrap();
        let body_exp =
            hex::decode("0500B09A0D3979A029E5FD027B519EAA200BC14AD3E163D3BE4563843E021073BCB1C357")
                .unwrap();
        assert_eq!(body, body_exp);
    }

    #[test]
    fn command_authorization_data_0x0006() {
        let challenge = CmdChallenge0x0004::from_raw(
            &hex::decode(
                "0400E0742CFEA39CB46109385BF91286A3C02F40EE86B0B62FC34033094DE41E2C0D7FE1",
            )
            .unwrap(),
        )
        .unwrap();
        let key = hex::decode("217FCB0F18CAF284E9BDEA0B94B83B8D10867ED706BFDEDBD2381F4CB3B8F730")
            .unwrap();

        let body_exp = hex::decode("0600CF1B9E7801E3196E6594E76D57908EE500AAD5C33F4B6E0BBEA0DDEF82967BFC00000000004D6172632028546573742900000000000000000000000000000000000000000052AFE0A664B4E9B56DC6BD4CB718A6C9FED6BE17A7411072AA0D31537814057769F2").unwrap();
        let msg = CmdAuthorizationData0x0006::from(0, 0, "Marc (Test)", &challenge.nonce);
        let body = msg.encode(&key).unwrap();

        // println!("Length: {} - exp: {}", body.len(), body_exp.len());

        // println!("Command ID    : {}", hex::encode(&body[0..2]));
        // println!("Command ID exp: {}", hex::encode(&body_exp[0..2]));

        // println!("Authenticator    : {}", hex::encode(&body[2..34]));
        // println!("Authenticator exp: {}", hex::encode(&body_exp[2..34]));

        // println!("ID Type    : {}", hex::encode(&body[34..35]));
        // println!("ID Type exp: {}", hex::encode(&body_exp[34..35]));

        // println!("App-ID    : {}", hex::encode(&body[35..39]));
        // println!("App-ID exp: {}", hex::encode(&body_exp[35..39]));

        // println!("Name    : {}", hex::encode(&body[39..71]));
        // println!("Name exp: {}", hex::encode(&body_exp[39..71]));

        // println!("Nonce n A/B/F    : {}", hex::encode(&body[71..103]));
        // println!("Nonce n A/B/F exp: {}", hex::encode(&body_exp[71..103]));

        // println!("CRC    : {}", hex::encode(&body[103..105]));
        // println!("CRC exp: {}", hex::encode(&body_exp[103..105]));

        assert_eq!(body_exp.len(), body.len());
    }

    #[test]
    fn command_authorization_id_0x0007() {
        let key = hex::decode("217FCB0F18CAF284E9BDEA0B94B83B8D10867ED706BFDEDBD2381F4CB3B8F730")
            .unwrap();
        let nonce_abf =
            hex::decode("52afe0a664b4e9b56dc6bd4cb718a6c9fed6be17a7411072aa0d315378140577")
                .unwrap();
        let raw = hex::decode(
            "07003A270A2E453443C3790E657CEBE634B03F01\
                                            02F45681B4067C661D46E6E15EDF0200000083B3\
                                            3643C6D97EF77ED51C02A277CBF7EA479915982F\
                                            13C61D997A56678AD77791BFA7E95229A3DD34F8\
                                            7132BF3E3C97DB9F",
        )
        .unwrap();

        let msg = CmdAuthorizationID0x0007::from_raw(&raw, &key, &nonce_abf).unwrap();
        assert_eq!(msg.authorization_id, 2);
        println!("Nonce_k: {}", hex::encode(&msg.nonce_k));
    }

    #[test]
    fn command_authorization_id_confirm_0x001e() {
        let nonce_k =
            hex::decode("ea479915982f13c61d997a56678ad77791bfa7e95229a3dd34f87132bf3e3c97")
                .unwrap();
        let key = hex::decode("217FCB0F18CAF284E9BDEA0B94B83B8D10867ED706BFDEDBD2381F4CB3B8F730")
            .unwrap();
        let msg = CmdAuthorizationIdConfirmation0x001e::from(2, &nonce_k);
        let msg_exp = hex::decode(
            "1E003A41B91A66FBC4D22EFEFBB7272140829695A3917433D5BEB981B76166D13F8A02000000CDF5",
        )
        .unwrap();
        assert_eq!(msg.encode(&key).unwrap(), msg_exp);
    }

    #[test]
    fn command_status_0x000e() {
        let msg = CmdStatus0x000e::from_raw(&hex::decode("0E00009DD7").unwrap()).unwrap();
        assert_eq!(msg.status, 0);
    }
}
