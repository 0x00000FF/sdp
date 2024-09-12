use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream, UdpSocket};


/*
 *    STRUCT:
 *    SINGLE PACKET AUTORIZATION (SPA) MESSAGE
 *    
 *    PURPOSE:
 *    SPA IS RECEIVED FROM WHEN AH/IHs REQUEST THEIR AUTHORIZATION 
 *
 */

 #[derive(Debug, Serialize, Deserialize)]
pub struct SPAMessage {
    client_id      : String,
    nonce          : u16,
    timestamp      : u64,
    source         : String,   // Must be 4 bytes or 16 bytes
    
    message_type   : u8,        // SEE MessageType
    message_string : Option<String>,

    hotp           : String,
    hmac           : String
}

const SPA_PREAMBLE_TEXT_SIZE:usize = 8; // SPDSPA<NUL><NUL>
const SPA_PREAMBLE_MSG_SIZE:usize  = 8; // 8 bytes per each message

const SPA_PREAMBLE_SIZE:usize      = SPA_PREAMBLE_TEXT_SIZE + SPA_PREAMBLE_MSG_SIZE;

// const SPA_PREAMBLE_TEXT:u64        = 0x5350445350410000; // SPDSPA<NUL><NUL>
const SPA_PREAMBLE_TEXT_LE:u64     = 0x0000415053445053; // LITTLE-ENDIAN

const BUF_SIZE: usize              = 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let udp_listener = UdpSocket::bind("0.0.0.0:8000").await?;
    let tcp_listener = TcpListener::bind("0.0.0.0:8080").await?;

    tokio::spawn(wait_for_spa(udp_listener));
    
    println!("debug: spa accept thread start");
    println!("debug: starting tcp thread");

    loop {
        let (socket, _) = tcp_listener.accept().await?;
        tokio::spawn(accept_socket(socket));
    }
}

async fn handle_spa(peer: SocketAddr, buff: Vec<u8>) {
    let json_str = match String::from_utf8(buff) {
        Ok(str) => str,
        Err(_) => panic!("Invalid UTF-8 String")
    };
    let message: SPAMessage = serde_json::from_str(&json_str).unwrap();

    println!("{:?}", message);
}

async fn wait_for_spa(socket: UdpSocket) {
    let mut buff = [0x00 as u8; BUF_SIZE];
    let mut recv_info: Option<(usize, SocketAddr)> = None;

    loop {
        if let Some((size, peer)) = recv_info {
            // AT LEAST 16 BYTES
            if size < SPA_PREAMBLE_SIZE {
                println!("debug: received message does not even have preamble {} < {}", size, SPA_PREAMBLE_SIZE);

                recv_info = None;
                continue;
            }

            // CHECK MAGIC NUMBER (64bits) : SPDSPA 0x00 0x00
            let preamble_magic_bytes:[u8; 8] = buff[0..SPA_PREAMBLE_TEXT_SIZE].try_into().unwrap();

            if u64::from_le_bytes(preamble_magic_bytes) != SPA_PREAMBLE_TEXT_LE {
                println!("debug: signature failed!");

                recv_info = None;
                continue;
            }

            // GET SPA MESSAGE SIZE AND CHECK WITH TOTAL RECEIVED SIZE
            // ASSERT( TOTAL RECEIVED - PREAMBLE SIZE == SPA MESSAGE SIZE IN PREAMBLE )
            let msg_size_bytes: [u8; 8] = buff[SPA_PREAMBLE_TEXT_SIZE..SPA_PREAMBLE_SIZE].try_into().unwrap();
            let msg_size = usize::from_le_bytes(msg_size_bytes);

            println!("message received bytes: {}", msg_size);

            if msg_size != (size - SPA_PREAMBLE_SIZE) {
                println!("debug: total message size not valid (in packet: {}, actual: {})", msg_size, size - SPA_PREAMBLE_MSG_SIZE);

                recv_info = None;
                continue;
            }

            // GET SPA MESSAGE BUFFER
            let spa_body_end = SPA_PREAMBLE_SIZE + msg_size;
            let spa_body = buff[SPA_PREAMBLE_SIZE..spa_body_end].to_vec();

            // HANDLE SINGLE PACKET AUTHORIZATION
            tokio::spawn(handle_spa(peer, spa_body));
        }

        let recv_result = socket.recv_from(&mut buff).await.unwrap();
        recv_info = Some(recv_result);
    }
}

async fn accept_socket(mut socket: TcpStream) {
    let mut buff = [0x00 as u8; BUF_SIZE];
    
}