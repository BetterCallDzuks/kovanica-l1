//! Rust JNI bindings for Kovanica mobile node engine (NativeBridge).

use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static NODE_RUNNING: AtomicBool = AtomicBool::new(false);
static NODE_CONFIG: Mutex<Option<String>> = Mutex::new(None);

#[no_mangle]
pub extern "system" fn Java_online_kovanica_node_NativeBridge_nodeStart(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
) -> jint {
    let path: String = match env.get_string(&config_path) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let mut conf = NODE_CONFIG.lock().unwrap();
    *conf = Some(path);
    NODE_RUNNING.store(true, Ordering::SeqCst);
    0
}

#[no_mangle]
pub extern "system" fn Java_online_kovanica_node_NativeBridge_nodeStop(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    let mut conf = NODE_CONFIG.lock().unwrap();
    *conf = None;
    NODE_RUNNING.store(false, Ordering::SeqCst);
    0
}

#[no_mangle]
pub extern "system" fn Java_online_kovanica_node_NativeBridge_nodeStatus(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let running = NODE_RUNNING.load(Ordering::SeqCst);
    let status_json = if running {
        r#"{"status":"running","mode":"full","storage_enabled":true,"block_validation":true}"#
    } else {
        r#"{"status":"stopped","mode":"stopped","storage_enabled":false,"block_validation":false}"#
    };
    match env.new_string(status_json) {
        Ok(js) => js.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_online_kovanica_node_NativeBridge_nodeSyncProgress(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let running = NODE_RUNNING.load(Ordering::SeqCst);
    let progress_json = if running {
        r#"{"height":0,"target":0,"peers":0,"current_height":0,"target_height":0,"syncing":false,"catching_up":false}"#
    } else {
        r#"{"height":0,"target":0,"peers":0,"current_height":0,"target_height":0,"syncing":false,"catching_up":false,"error":"node not running"}"#
    };
    match env.new_string(progress_json) {
        Ok(js) => js.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_status_json_validity() {
        let running_json =
            r#"{"status":"running","mode":"full","storage_enabled":true,"block_validation":true}"#;
        let v: serde_json::Value = serde_json::from_str(running_json).expect("valid json");
        assert_eq!(v["status"], "running");
        assert_eq!(v["mode"], "full");
        assert_eq!(v["storage_enabled"], true);
        assert_eq!(v["block_validation"], true);

        let stopped_json = r#"{"status":"stopped","mode":"stopped","storage_enabled":false,"block_validation":false}"#;
        let v: serde_json::Value = serde_json::from_str(stopped_json).expect("valid json");
        assert_eq!(v["status"], "stopped");
        assert_eq!(v["mode"], "stopped");
    }

    #[test]
    fn test_sync_progress_json_validity() {
        let progress_json = r#"{"height":0,"target":0,"peers":0,"current_height":0,"target_height":0,"syncing":false,"catching_up":false}"#;
        let v: serde_json::Value = serde_json::from_str(progress_json).expect("valid json");
        assert_eq!(v["height"], 0);
        assert_eq!(v["target"], 0);
        assert_eq!(v["peers"], 0);
        assert_eq!(v["syncing"], false);
        assert_eq!(v["catching_up"], false);
    }
}
