// Store keys associated with clients


use std::{io::BufReader, path::{Path, PathBuf}, str::FromStr};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use hashbrown::HashMap;

use crate::{ClientId, Config};

const DEFAULT_PATH: &str = "~/rumqttd/keystore/keyfile";


#[derive(Default)]
pub struct Keystore {
    pub map: HashMap<ClientId, [u8; 32]>,
    pub loc: Option<PathBuf>,
    pub timestamp: DateTime<Utc>
}
impl Keystore {
    pub fn get_client_key(&self, client_id: &str) -> Option<[u8; 32]> {
        self.map.get(client_id).cloned()
    }
}



pub fn load_keystore(config: &Config) -> Result<Keystore, KeystoreConstructionError> {
    let path = config.keystore_path.clone().unwrap_or(PathBuf::from_str(DEFAULT_PATH).or(Err(KeystoreConstructionError::InvalidPath))?);
    let file = std::fs::File::open(path.clone()).or(Err(KeystoreConstructionError::NoFile))?;
    let reader = BufReader::new(file);
    let key_vec: Vec<(String, [u8; 32])> = serde_json::from_reader(reader).or(Err(KeystoreConstructionError::ParseError))?;
    let mut store = Keystore {
        map: HashMap::new(),
        loc: Some(path),
        timestamp: Utc::now(),
    };
    for (cid, key) in key_vec {
        store.map.insert(cid, key);
    }
    return Ok(store);
}

pub enum KeystoreConstructionError {
    InvalidPath,
    NoFile,
    ParseError
}