use std::net::{SocketAddr};
use tokio::net::{TcpListener, TcpStream, UdpSocket};


/*
 *    STRUCT:
 *    SINGLE PACKET AUTORIZATION (SPA) MESSAGE
 *    
 *    PURPOSE:
 *    SPA IS RECEIVED FROM WHEN AH/IHs REQUEST THEIR AUTHORIZATION 
 *
 */
pub struct SPAMessage {
    client_id      : [u8; 32],
    nonce          : u16,
    timestamp      : u64,
    source         : Vec<u8>,   // Must be 4 bytes or 16 bytes
    
    message_type   : u8,        // SEE MessageType
    message_string : Vec<u8>,

    hotp           : Vec<u8>,
    hmac           : Vec<u8>
}

const SPA_PREAMBLE_TEXT_SIZE:usize = 8; // SPDSPA<NUL><NUL>
const SPA_PREAMBLE_MSG_SIZE:usize  = 8; // 8 bytes per each message

const SPA_PREAMBLE_SIZE:usize      = SPA_PREAMBLE_TEXT_SIZE + SPA_PREAMBLE_MSG_SIZE;
const SPA_PREAMBLE_TEXT:u64        = 0x5350445350410000; // SPDSPA<NUL><NUL>

const SPA_MESSAGE_MIN_SIZE:usize   = size_of::<SPAMessage>();

const BUF_SIZE: usize              = 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let udp_listener = UdpSocket::bind("0.0.0.0:8000").await?;
    let tcp_listener = TcpListener::bind("0.0.0.0:8080").await?;

    tokio::spawn(wait_for_spa(udp_listener));
    
    println!("debug: spa accept thread start");
    println!("debug: starting tcp thread");

    loop {
        let (mut socket, _) = tcp_listener.accept().await?;
        tokio::spawn(accept_socket(socket));
    }
}

async fn handle_spa(peer: SocketAddr, buff: Vec<u8>) {

}

async fn wait_for_spa(mut socket: UdpSocket) {
    let mut buff = [0x00 as u8; BUF_SIZE];
    let mut recv_info: Option<(usize, SocketAddr)> = None;

    loop {
        if let Some((size, peer)) = recv_info {
            if size < SPA_PREAMBLE_SIZE {
                println!("debug: received message does not even have preamble {} < {}", size, SPA_PREAMBLE_SIZE);

                recv_info = None;
                continue;
            }

            let mut preamble_text = [0x00 as u8; SPA_PREAMBLE_TEXT_SIZE];
            preamble_text.copy_from_slice(&buff[0..SPA_PREAMBLE_TEXT_SIZE]);

            if u64::from_be_bytes(preamble_text) != SPA_PREAMBLE_TEXT {
                println!("debug: signature failed!");

                recv_info = None;
                continue;
            }

            let mut preamble_size = [0x00 as u8; SPA_PREAMBLE_MSG_SIZE];
            preamble_size.copy_from_slice(&buff[SPA_PREAMBLE_TEXT_SIZE..SPA_PREAMBLE_SIZE]);

            let msg_size = usize::from_le_bytes(preamble_size);

            if msg_size != (size - SPA_PREAMBLE_SIZE) {
                println!("debug: total message size not valid (in packet: {}, actual: {})", msg_size, size - SPA_PREAMBLE_MSG_SIZE);

                recv_info = None;
                continue;
            }

            let mut spa_body = Vec::new();
            spa_body.extend_from_slice(&buff[SPA_PREAMBLE_SIZE..]);

            tokio::spawn(handle_spa(peer, spa_body));
        }

        let recv_result = socket.recv_from(&mut buff).await.unwrap();
        recv_info = Some(recv_result);
    }
}

async fn accept_socket(mut socket: TcpStream) {
    let mut buff = [0x00 as u8; BUF_SIZE];
    
}