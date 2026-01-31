use insta::assert_json_snapshot;
use serde_json;
use zks_crypt::entropy_block::{DrandRound, EntropyBlock};

#[test]
fn test_single_round_block_snapshot() {
    let mut block = EntropyBlock::new(1000);
    
    let round = DrandRound::new(
        1000,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
        vec![65, 66, 67, 68],
        vec![69, 70, 71, 72],
    );
    
    block.add_round(round).unwrap();

    assert_json_snapshot!("single_round_block", serde_json::to_value(&block).unwrap());
}

#[test]
fn test_multi_round_block_snapshot() {
    let mut block = EntropyBlock::new(2000);
    
    let round1 = DrandRound::new(
        2000,
        [65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96],
        vec![65, 66, 67, 68],
        vec![69, 70, 71, 72],
    );
    
    let round2 = DrandRound::new(
        2001,
        [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128],
        vec![73, 74, 75, 76],
        vec![77, 78, 79, 80],
    );
    
    let round3 = DrandRound::new(
        2002,
        [129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160],
        vec![81, 82, 83, 84],
        vec![85, 86, 87, 88],
    );
    
    block.add_round(round1).unwrap();
    block.add_round(round2).unwrap();
    block.add_round(round3).unwrap();

    assert_json_snapshot!("multi_round_block", serde_json::to_value(&block).unwrap());
}

#[test]
fn test_large_block_snapshot() {
    let mut block = EntropyBlock::new(3000);
    
    for i in 0..100 {
        let round = DrandRound::new(
            3000 + i,
            [
                (i * 32) as u8,
                (i * 32 + 1) as u8,
                (i * 32 + 2) as u8,
                (i * 32 + 3) as u8,
                (i * 32 + 4) as u8,
                (i * 32 + 5) as u8,
                (i * 32 + 6) as u8,
                (i * 32 + 7) as u8,
                (i * 32 + 8) as u8,
                (i * 32 + 9) as u8,
                (i * 32 + 10) as u8,
                (i * 32 + 11) as u8,
                (i * 32 + 12) as u8,
                (i * 32 + 13) as u8,
                (i * 32 + 14) as u8,
                (i * 32 + 15) as u8,
                (i * 32 + 16) as u8,
                (i * 32 + 17) as u8,
                (i * 32 + 18) as u8,
                (i * 32 + 19) as u8,
                (i * 32 + 20) as u8,
                (i * 32 + 21) as u8,
                (i * 32 + 22) as u8,
                (i * 32 + 23) as u8,
                (i * 32 + 24) as u8,
                (i * 32 + 25) as u8,
                (i * 32 + 26) as u8,
                (i * 32 + 27) as u8,
                (i * 32 + 28) as u8,
                (i * 32 + 29) as u8,
                (i * 32 + 30) as u8,
                (i * 32 + 31) as u8,
            ],
            vec![(i * 4) as u8, (i * 4 + 1) as u8, (i * 4 + 2) as u8, (i * 4 + 3) as u8],
            vec![(i * 4 + 100) as u8, (i * 4 + 101) as u8, (i * 4 + 102) as u8, (i * 4 + 103) as u8],
        );
        
        block.add_round(round).unwrap();
    }

    assert_json_snapshot!("large_block", serde_json::to_value(&block).unwrap());
}

#[test]
fn test_empty_block_snapshot() {
    let block = EntropyBlock::new(4000);

    assert_json_snapshot!("empty_block", serde_json::to_value(&block).unwrap());
}

#[test]
fn test_block_with_zero_entropy_snapshot() {
    let mut block = EntropyBlock::new(5000);
    
    let round = DrandRound::new(
        5000,
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![0, 0, 0, 0],
        vec![0, 0, 0, 0],
    );
    
    block.add_round(round).unwrap();

    assert_json_snapshot!("block_with_zero_entropy", serde_json::to_value(&block).unwrap());
}