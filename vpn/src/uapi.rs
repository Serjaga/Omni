
pub const GENL_VERSION: u8 = 2;

pub const DEV_A_IFINDEX: u16 = 1;
pub const DEV_A_IFNAME: u16 = 2;
pub const DEV_A_PRIVATE_KEY: u16 = 3;
pub const DEV_A_PUBLIC_KEY: u16 = 4;
pub const DEV_A_FLAGS: u16 = 5;
pub const DEV_A_LISTEN_PORT: u16 = 6;
pub const DEV_A_FWMARK: u16 = 7;
pub const DEV_A_PEERS: u16 = 8;
pub const DEV_A_JC: u16 = 9;
pub const DEV_A_JMIN: u16 = 10;
pub const DEV_A_JMAX: u16 = 11;
pub const DEV_A_S1: u16 = 12;
pub const DEV_A_S2: u16 = 13;
pub const DEV_A_H1: u16 = 14;
pub const DEV_A_H2: u16 = 15;
pub const DEV_A_H3: u16 = 16;
pub const DEV_A_H4: u16 = 17;
pub const DEV_A_PEER: u16 = 18;
pub const DEV_A_S3: u16 = 19;
pub const DEV_A_S4: u16 = 20;
pub const DEV_A_I1: u16 = 21;
pub const DEV_A_I2: u16 = 22;
pub const DEV_A_I3: u16 = 23;
pub const DEV_A_I4: u16 = 24;
pub const DEV_A_I5: u16 = 25;

pub const PEER_A_PUBLIC_KEY: u16 = 1;
pub const PEER_A_PRESHARED_KEY: u16 = 2;
pub const PEER_A_FLAGS: u16 = 3;
pub const PEER_A_ENDPOINT: u16 = 4;
pub const PEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
pub const PEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
pub const PEER_A_RX_BYTES: u16 = 7;
pub const PEER_A_TX_BYTES: u16 = 8;
pub const PEER_A_ALLOWEDIPS: u16 = 9;
pub const PEER_A_PROTOCOL_VERSION: u16 = 10;
pub const PEER_A_ADVANCED_SECURITY: u16 = 11;
pub const PEER_A_OBFS_PEER_FLAGS: u16 = 12;      

pub const AIP_A_FAMILY: u16 = 1;
pub const AIP_A_IPADDR: u16 = 2;
pub const AIP_A_CIDR_MASK: u16 = 3;
pub const AIP_A_FLAGS: u16 = 4;

pub const PEER_F_REMOVE_ME: u32 = 1 << 0;
pub const PEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;
pub const PEER_F_UPDATE_ONLY: u32 = 1 << 2;
pub const PEER_F_HAS_ADVANCED_SECURITY: u32 = 1 << 3;

pub const DEV_F_REPLACE_PEERS: u32 = 1 << 0;
pub const AIP_F_REMOVE_ME: u32 = 1 << 0;

pub const OBFS_PEER_F_FIXED_HEADERS: u32 = 1 << 0;
pub const OBFS_PEER_F_NO_S4: u32 = 1 << 1;
