use insta::assert_json_snapshot;
use serde_json;
use zks_crypt::entropy_block::{DrandRound, EntropyBlock};
use zks_wire::entropy_swarm::EntropyGossipMessage;
use libp2p::PeerId;

#[test]
fn test_entropy_block_announcement_snapshot() {
    let mut block = EntropyBlock::new(1000);
    
    let round1 = DrandRound::new(
        1000,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
        vec![65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96],
        vec![97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128],
    );
    
    let round2 = DrandRound::new(
        1001,
        [33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64],
        vec![73, 74, 75, 76],
        vec![77, 78, 79, 80],
    );
    
    block.add_round(round1).unwrap();
    block.add_round(round2).unwrap();

    let message = EntropyGossipMessage::BlockAnnouncement {
        block_hash: block.block_hash,
        start_round: block.start_round,
        end_round: block.end_round,
        provider: "QmPeer1234567890abcdef".to_string(),
    };

    assert_json_snapshot!("block_announcement", serde_json::to_value(&message).unwrap());
}

#[test]
fn test_block_request_snapshot() {
    let message = EntropyGossipMessage::BlockRequest {
        start_round: 1000,
        end_round: 1099,
        requester: "QmRequester1234567890".to_string(),
    };

    assert_json_snapshot!("block_request", serde_json::to_value(&message).unwrap());
}

#[test]
fn test_block_response_snapshot() {
    let mut block = EntropyBlock::new(2000);
    block.add_round(DrandRound::new(
        2000,
        [65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96],
        vec![97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128],
        vec![129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160],
    ));

    let message = EntropyGossipMessage::BlockResponse {
        block: block.clone(),
        provider: "QmProvider1234567890".to_string(),
    };

    assert_json_snapshot!("block_response", serde_json::to_value(&message).unwrap());
}

#[test]
fn test_peer_announcement_snapshot() {
    let message = EntropyGossipMessage::PeerAnnouncement {
        peer_id: "QmNewPeer1234567890abcdef".to_string(),
        listen_addresses: vec![
            "/ip4/192.168.1.100/tcp/4001".to_string(),
            "/ip4/10.0.0.1/tcp/4001".to_string(),
        ],
        supported_protocols: vec!["/entropy-grid/1.0.0".to_string()],
    };

    assert_json_snapshot!("peer_announcement", serde_json::to_value(&message).unwrap());
}

#[test]
fn test_error_message_snapshot() {
    let message = EntropyGossipMessage::Error {
        error_code: "BLOCK_NOT_FOUND".to_string(),
        error_message: "Requested block range 1000-1099 not available".to_string(),
        request_id: "req_1234567890".to_string(),
    };

    assert_json_snapshot!("error_message", serde_json::to_value(&message).unwrap());
}

#[test]
fn test_empty_block_announcement_snapshot() {
    let message = EntropyGossipMessage::BlockAnnouncement {
        block_hash: [0u8; 32],
        start_round: 0,
        end_round: 0,
        provider: "QmEmptyPeer".to_string(),
    };

    assert_json_snapshot!("empty_block_announcement", serde_json::to_value(&message).unwrap());
}