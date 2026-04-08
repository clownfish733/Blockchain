use std::{collections::{HashMap, HashSet}, fmt::Debug};

use serde::{Serialize, Deserialize};
use postcard::to_allocvec;
use thiserror::Error;
use ed25519_dalek::{SigningKey,VerifyingKey};
use rand::Rng;
use sha2::{Sha256, Digest};

pub struct Hash([u8; 32]);

impl Hash{
    pub fn generate(msg: &[u8]) -> Self{
        Hash(Sha256::digest(msg).into())
    }

    pub fn get_bytes(&self) -> [u8; 32]{
        self.0
    }
}

impl Debug for Hash{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.get_bytes()))
    }
}

pub struct PrivateKey(SigningKey);

impl PrivateKey{
    pub fn new() -> Self{
        let mut key_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut key_bytes);
        Self(SigningKey::from_bytes(&key_bytes))
    }
    pub fn get_verifying_key(&self) -> VerifyingKey{
        return self.0.verifying_key();
    }
}


pub struct PublicKey(VerifyingKey);

impl PublicKey{
    pub fn new(sk: &PrivateKey) -> Self{
        Self(sk.get_verifying_key())
    }

    pub fn get_compressed_byes(&self) -> [u8; 32]{
        self.0.as_bytes().clone()
    }

    pub fn get_hash(&self) -> Hash{
        Hash::generate(&self.get_compressed_byes())
    }
}

impl Debug for PublicKey{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.get_compressed_byes()))
    }
}

pub fn generate_keys() -> (PrivateKey, PublicKey){
    let sk = PrivateKey::new();
    let pk = PublicKey::new(&sk);
    (sk, pk)
}

#[derive(Debug, Error)]
pub enum P2PError{
    #[error("Failed to serialize: {object:?}, cause: {source}")]
    SerializationError{
        object: String,
        source: postcard::Error
    }
}

fn serialize<T: Serialize+ std::fmt::Debug>(
    value: &T,
) -> Result<Vec<u8>, P2PError> {
    to_allocvec(value).map_err(|e| P2PError::SerializationError { 
        object: format!("{value:?}"), 
        source: e 
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Frame{
    pub header: FrameHeader,
    pub payload: Vec<u8>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FrameHeader{
    pub magic: Magic,
    pub version: Version,
    pub msg_type: MessageType,
    pub payload_len: PayloadLen,
    pub checksum: Checksum,
    pub nonce: Nonce,
    pub timestamp: Timestamp,
    pub sender_id: PeerId,
}

pub type Magic = [u8; 4];
pub type Version = u16;
pub type PayloadLen = u32;
pub type Checksum = [u8; 4];
pub type Nonce = u64;
pub type Timestamp = u64;
pub type PeerId = [u8; 32];

#[derive(Debug, Serialize, Deserialize)]
pub enum MessageType{

}

impl Frame{
    pub fn get_header_bytes(&self) -> Result<Vec<u8>, P2PError>{
        serialize(&self.header)
    }

    pub fn get_payload(&self) -> Result<Vec<u8>, P2PError>{
        serialize(&self.payload)
    }
}

pub struct P2PServer{
    pub config: P2PServerConfig,
    pub peer_db: PeerDB,            //database of all known peers
    pub peer_manager: PeerManager   //handles currently connected peers

}

pub struct P2PServerConfig{
    pub magic: Magic,
    pub version: Version,
    pub peer_id: PeerId,
    pub max_payload_len: PayloadLen,
    pub capabilites: HashSet<Capability>
}

pub struct PeerDB{
    pub peers: HashMap<PeerId, PeerRecord>
}

pub struct PeerRecord{

}

pub struct PeerManager(HashMap<PeerId, PeerStat>);


pub struct PeerStat{
    pub connection: ConnectionType,
    pub reputation: Reputation,
    pub capabilities: HashSet<Capability>
}

pub enum ConnectionType{
    Incoming,
    Outgoing,
    BiDrirectional
}

pub type Reputation = u32;

pub enum Capability{
    Sync,
    Validation,
}