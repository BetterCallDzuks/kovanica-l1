//! Stratum V1 line-delimited JSON-RPC wire protocol definitions.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Inbound Stratum V1 request from miner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StratumRequest {
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl StratumRequest {
    /// Parse a single line-delimited JSON string into a [`StratumRequest`].
    pub fn parse_line(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line.trim())
    }
}

/// Outbound Stratum V1 response to miner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StratumResponse {
    pub id: Value,
    pub result: Value,
    pub error: Value,
}

impl StratumResponse {
    /// Build a successful response with `result`.
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            id,
            result,
            error: Value::Null,
        }
    }

    /// Build an error response with error code and description.
    pub fn error(id: Value, code: i64, message: &str) -> Self {
        Self {
            id,
            result: Value::Null,
            error: json!([code, message, Value::Null]),
        }
    }

    /// Stale or non-existent job submission (error code 21).
    pub fn job_not_found(id: Value) -> Self {
        Self::error(id, 21, "Job not found")
    }

    /// Duplicate share submission already accepted (error code 22).
    pub fn duplicate_share(id: Value) -> Self {
        Self::error(id, 22, "Duplicate share")
    }

    /// Share does not satisfy assigned target (error code 23).
    pub fn low_difficulty_share(id: Value) -> Self {
        Self::error(id, 23, "Low difficulty share")
    }

    /// Worker authorization failure (error code 24).
    pub fn unauthorized(id: Value, msg: &str) -> Self {
        Self::error(id, 24, msg)
    }

    /// Invalid parameters (error code 25).
    pub fn invalid_params(id: Value, msg: &str) -> Self {
        Self::error(id, 25, msg)
    }

    /// Serialize to a newline-terminated wire string.
    pub fn to_wire_line(&self) -> String {
        let mut s = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string());
        s.push('\n');
        s
    }
}

/// Outbound server push notification (e.g. `mining.set_difficulty`, `mining.notify`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StratumNotification {
    pub id: Value,
    pub method: String,
    pub params: Value,
}

impl StratumNotification {
    /// Create a new notification (Stratum notifications always have `id: null`).
    pub fn new(method: &str, params: Value) -> Self {
        Self {
            id: Value::Null,
            method: method.to_string(),
            params,
        }
    }

    /// Create `mining.set_difficulty` notification.
    pub fn set_difficulty(difficulty: f64) -> Self {
        Self::new("mining.set_difficulty", json!([difficulty]))
    }

    /// Create `mining.notify` notification matching the 9-parameter Stratum V1 format.
    #[allow(clippy::too_many_arguments)]
    pub fn notify(
        job_id: &str,
        prevhash: &str,
        coinb1: &str,
        coinb2: &str,
        merkle_branch: &[String],
        version: &str,
        nbits: &str,
        ntime: &str,
        clean_jobs: bool,
    ) -> Self {
        Self::new(
            "mining.notify",
            json!([
                job_id,
                prevhash,
                coinb1,
                coinb2,
                merkle_branch,
                version,
                nbits,
                ntime,
                clean_jobs
            ]),
        )
    }

    /// Serialize to a newline-terminated wire string.
    pub fn to_wire_line(&self) -> String {
        let mut s = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string());
        s.push('\n');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subscribe_request() {
        let raw = r#"{"id": 1, "method": "mining.subscribe", "params": ["kovanica-miner/1.0.0"]}"#;
        let req = StratumRequest::parse_line(raw).expect("parse request");
        assert_eq!(req.id, json!(1));
        assert_eq!(req.method, "mining.subscribe");
        assert_eq!(req.params, json!(["kovanica-miner/1.0.0"]));
    }

    #[test]
    fn test_parse_authorize_request() {
        let raw =
            r#"{"id": 2, "method": "mining.authorize", "params": ["kvnc1...dag.worker1", "x"]}"#;
        let req = StratumRequest::parse_line(raw).expect("parse request");
        assert_eq!(req.id, json!(2));
        assert_eq!(req.method, "mining.authorize");
    }

    #[test]
    fn test_serialize_subscribe_response() {
        let sub_resp = StratumResponse::ok(
            json!(1),
            json!([
                [
                    ["mining.set_difficulty", "sub_diff"],
                    ["mining.notify", "sub_notify"]
                ],
                "01a4b8",
                4
            ]),
        );
        let wire = sub_resp.to_wire_line();
        assert!(wire.contains(r#""id":1"#));
        assert!(wire.contains(r#""01a4b8""#));
        assert!(wire.ends_with('\n'));
    }

    #[test]
    fn test_serialize_notify_notification() {
        let notif = StratumNotification::notify(
            "job_1",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000050000002a",
            "",
            &[],
            "00000002",
            "207fffff",
            "673a5f20",
            true,
        );
        let wire = notif.to_wire_line();
        assert!(wire.contains(r#""method":"mining.notify""#));
        assert!(wire.contains(r#""job_1""#));
        assert!(wire.ends_with('\n'));
    }
}
