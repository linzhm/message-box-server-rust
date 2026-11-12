use message_box_server_rust::auth_frame::{
    PreparedRequestFrame, encode_compact_size, encode_request_frame,
};
use serde_json::Value;
#[test]
fn compact_sizes_match_fixed_sdk_writer() {
    let f: Value = serde_json::from_str(include_str!("fixtures/http-frames-sdk4.json")).unwrap();
    for item in f["compactSizes"].as_array().unwrap() {
        let n = item["value"].as_i64().unwrap();
        let bytes = encode_compact_size(if n == -1 { None } else { Some(n as u64) });
        assert_eq!(hex::encode(bytes), item["hex"].as_str().unwrap());
    }
}
#[test]
fn request_frames_match_actual_fixed_middleware_helpers() {
    let f: Value = serde_json::from_str(include_str!("fixtures/http-frames-sdk4.json")).unwrap();
    for c in f["cases"].as_array().unwrap() {
        let mut id = [0u8; 32];
        for (i, v) in c["requestId"].as_array().unwrap().iter().enumerate() {
            id[i] = v.as_u64().unwrap() as u8;
        }
        let headers: Vec<(&str, &str)> = c["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p[0].as_str().unwrap(), p[1].as_str().unwrap()))
            .collect();
        let frame = PreparedRequestFrame {
            request_id: id,
            method: c["method"].as_str().unwrap(),
            path: c["path"].as_str(),
            query: c["query"].as_str(),
            headers: &headers,
            body: c["body"].as_str().map(str::as_bytes),
        };
        assert_eq!(
            hex::encode(encode_request_frame(&frame).unwrap()),
            c["frameHex"].as_str().unwrap()
        );
    }
}
#[test]
fn invalid_methods_are_not_encoded() {
    let id = [0u8; 32];
    for method in [
        "",
        "get",
        "G3T",
        "GET ",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let frame = PreparedRequestFrame {
            request_id: id,
            method,
            path: Some("/"),
            query: None,
            headers: &[],
            body: None,
        };
        assert!(encode_request_frame(&frame).is_err());
    }
}

#[test]
fn response_frames_match_source_derived_sdk_writer_sequence() {
    use message_box_server_rust::auth_frame::{PreparedResponseFrame, encode_response_frame};
    let f: Value = serde_json::from_str(include_str!("fixtures/http-frames-sdk4.json")).unwrap();
    for c in f["responseCases"].as_array().unwrap() {
        let mut id = [0u8; 32];
        for (i, v) in c["requestId"].as_array().unwrap().iter().enumerate() {
            id[i] = v.as_u64().unwrap() as u8;
        }
        let headers: Vec<(&str, &str)> = c["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p[0].as_str().unwrap(), p[1].as_str().unwrap()))
            .collect();
        let frame = PreparedResponseFrame {
            request_id: id,
            status: c["status"].as_u64().unwrap() as u16,
            headers: &headers,
            body: c["body"].as_str().map(str::as_bytes).unwrap_or(&[]),
        };
        assert_eq!(
            hex::encode(encode_response_frame(&frame)),
            c["frameHex"].as_str().unwrap()
        );
    }
}
