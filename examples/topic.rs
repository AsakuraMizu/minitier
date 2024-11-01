use iroh::gossip::proto::TopicId;

fn main() {
    const TOPIC: &[u8] = b"DUMMY_TOPIC";
    println!("{}", TopicId::from(blake3::hash(TOPIC)));
}
