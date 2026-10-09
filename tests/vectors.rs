//! Wire-protocol compatibility tests against the shared spec vectors
//! from anomalyco/opentunnel (`spec/vectors`). If these pass, this server
//! speaks exactly the same protocol as the official clients.

use opentunnel_relay::proto::bridge::{self, ClientMessage, ServerMessage};
use opentunnel_relay::proto::names;

fn load(name: &str) -> serde_json::Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn route_name_validation() {
    let v = load("names.json");
    for case in v["route"].as_array().unwrap() {
        let value = case["value"].as_str().unwrap();
        let valid = case["valid"].as_bool().unwrap();
        assert_eq!(names::is_valid_route(value), valid, "route {value:?}");
    }
}

#[test]
fn profile_name_validation() {
    let v = load("names.json");
    for case in v["profile"].as_array().unwrap() {
        let value = case["value"].as_str().unwrap();
        let valid = case["valid"].as_bool().unwrap();
        assert_eq!(names::is_valid_profile(value), valid, "profile {value:?}");
    }
}

#[test]
fn target_parsing() {
    let v = load("names.json");
    for case in v["target"].as_array().unwrap() {
        let value = case["value"].as_str().unwrap();
        let valid = case["valid"].as_bool().unwrap();
        assert_eq!(
            names::parse_target(value).is_some(),
            valid,
            "target {value:?}"
        );
    }
}

#[test]
fn sni_routing() {
    let v = load("routes.json");
    for case in v.as_array().unwrap() {
        let hostname = case["hostname"].as_str().unwrap();
        let sni = case["sni"].as_str().unwrap();
        let expected = case["route"].as_str().map(|s| s.to_string());
        assert_eq!(
            names::route_for_sni(sni, hostname),
            expected,
            "sni {sni:?} on {hostname:?}"
        );
    }
}

#[test]
fn data_frames() {
    let v = load("frames.json");
    for case in v.as_array().unwrap() {
        let conn = case["conn"].as_u64().unwrap() as u32;
        let payload = hex(case["payload"].as_str().unwrap());
        let frame = hex(case["frame"].as_str().unwrap());
        assert_eq!(bridge::encode_data_frame(conn, &payload), frame);
        let (decoded_conn, decoded_payload) = bridge::decode_data_frame(&frame).unwrap();
        assert_eq!(decoded_conn, conn);
        assert_eq!(decoded_payload, payload.as_slice());
    }
}

#[test]
fn control_messages_round_trip() {
    let v = load("control.json");
    for case in v["client"].as_array().unwrap() {
        // Must parse as a client message and re-encode losslessly.
        let msg: ClientMessage = serde_json::from_value(case.clone()).unwrap();
        let text = serde_json::to_string(&msg).unwrap();
        let back: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(&back, case, "client message round-trip");
    }
    for case in v["server"].as_array().unwrap() {
        let msg: ServerMessage = serde_json::from_value(case.clone()).unwrap();
        let text = serde_json::to_string(&msg).unwrap();
        let back: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(&back, case, "server message round-trip");
    }
}

#[test]
fn unknown_message_types_are_ignored() {
    let v = load("control.json");
    for case in v["ignored"].as_array().unwrap() {
        let text = serde_json::to_string(case).unwrap();
        assert_eq!(
            ServerMessage::decode(&text).unwrap(),
            None,
            "should be ignored: {text}"
        );
    }
}

#[test]
fn invalid_messages_are_rejected() {
    let v = load("control.json");
    for case in v["invalid"].as_array().unwrap() {
        let text = serde_json::to_string(case).unwrap();
        // Either a hard decode error or an ignored unknown shape; what must
        // NOT happen is decoding into a valid message.
        if let Ok(Some(_)) = ServerMessage::decode(&text) {
            panic!("invalid message decoded as valid: {text}");
        }
    }
}
