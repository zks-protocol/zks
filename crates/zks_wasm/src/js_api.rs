use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use crate::transport::{WebSocketTransport, TransportConfig, TransportState};
use zks_sdk::{SecurityLevel, ConnectionConfig};

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct JsConfig {
    pub url: String,
    pub security_level: String,
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: u32,
}

#[wasm_bindgen]
impl JsConfig {
    #[wasm_bindgen(constructor)]
    pub fn new(url: String) -> Self {
        Self {
            url,
            security_level: "postquantum".to_string(),
            auto_reconnect: true,
            max_reconnect_attempts: 3,
        }
    }

    #[wasm_bindgen]
    pub fn with_security(mut self, level: &str) -> Result<Self, JsValue> {
        match level {
            "standard" | "enhanced" | "postquantum" => {
                self.security_level = level.to_string();
                Ok(self)
            }
            _ => Err(JsValue::from_str("Invalid security level")),
        }
    }

    #[wasm_bindgen]
    pub fn with_auto_reconnect(mut self, enabled: bool) -> Self {
        self.auto_reconnect = enabled;
        self
    }

    #[wasm_bindgen]
    pub fn with_max_reconnect_attempts(mut self, attempts: u32) -> Self {
        self.max_reconnect_attempts = attempts;
        self
    }
}

#[wasm_bindgen]
pub struct ZksProtocol {
    transport: WebSocketTransport,
    config: JsConfig,
}

#[wasm_bindgen]
impl ZksProtocol {
    #[wasm_bindgen(constructor)]
    pub fn new(config: JsConfig) -> Self {
        let transport_config = TransportConfig::new(config.url.clone())
            .with_reconnect_attempts(config.max_reconnect_attempts);
        
        let transport = WebSocketTransport::new(transport_config);
        
        Self { transport, config }
    }

    #[wasm_bindgen]
    pub async fn connect(&mut self) -> Result<(), JsValue> {
        console_log!("Connecting to ZKS Protocol at: {}", self.config.url);
        self.transport.connect().await
    }

    #[wasm_bindgen]
    pub fn disconnect(&mut self) {
        console_log!("Disconnecting from ZKS Protocol");
        self.transport.disconnect();
    }

    #[wasm_bindgen]
    pub fn send(&mut self, data: &[u8]) -> Result<(), JsValue> {
        self.transport.send(data)
    }

    #[wasm_bindgen]
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        self.transport.receive()
    }

    #[wasm_bindgen]
    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }

    #[wasm_bindgen]
    pub fn get_state(&self) -> String {
        format!("{:?}", self.transport.get_state())
    }

    #[wasm_bindgen]
    pub fn get_pending_message_count(&self) -> usize {
        self.transport.get_pending_message_count()
    }

    #[wasm_bindgen]
    pub fn get_config(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.config)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))
    }
}

// Utility functions for JavaScript developers
#[wasm_bindgen]
pub struct ZksUtils;

#[wasm_bindgen]
impl ZksUtils {
    #[wasm_bindgen]
    pub fn create_config(url: &str) -> JsConfig {
        JsConfig::new(url.to_string())
    }

    #[wasm_bindgen]
    pub fn validate_url(url: &str) -> bool {
        url.starts_with("zk://") || url.starts_with("zks://") || 
        url.starts_with("ws://") || url.starts_with("wss://")
    }

    #[wasm_bindgen]
    pub fn convert_to_websocket_url(url: &str) -> String {
        crate::transport::convert_zk_url(url)
    }

    #[wasm_bindgen]
    pub fn get_version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    #[wasm_bindgen]
    pub fn get_supported_security_levels() -> Vec<JsValue> {
        vec![
            JsValue::from_str("standard"),
            JsValue::from_str("enhanced"),
            JsValue::from_str("postquantum"),
        ]
    }
}

// Quick-start functions for common use cases
#[wasm_bindgen]
pub async fn quick_connect(url: &str) -> Result<ZksProtocol, JsValue> {
    let config = JsConfig::new(url.to_string());
    let mut client = ZksProtocol::new(config);
    client.connect().await?;
    Ok(client)
}

#[wasm_bindgen]
pub fn quick_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, JsValue> {
    crate::encrypt_data(data, key)
}

#[wasm_bindgen]
pub fn quick_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, JsValue> {
    crate::decrypt_data(data, key)
}

// Event handling for JavaScript
#[wasm_bindgen]
pub struct ZksEventHandler {
    on_connect: Option<js_sys::Function>,
    on_disconnect: Option<js_sys::Function>,
    on_message: Option<js_sys::Function>,
    on_error: Option<js_sys::Function>,
}

#[wasm_bindgen]
impl ZksEventHandler {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            on_connect: None,
            on_disconnect: None,
            on_message: None,
            on_error: None,
        }
    }

    #[wasm_bindgen]
    pub fn on_connect(mut self, callback: js_sys::Function) -> Self {
        self.on_connect = Some(callback);
        self
    }

    #[wasm_bindgen]
    pub fn on_disconnect(mut self, callback: js_sys::Function) -> Self {
        self.on_disconnect = Some(callback);
        self
    }

    #[wasm_bindgen]
    pub fn on_message(mut self, callback: js_sys::Function) -> Self {
        self.on_message = Some(callback);
        self
    }

    #[wasm_bindgen]
    pub fn on_error(mut self, callback: js_sys::Function) -> Self {
        self.on_error = Some(callback);
        self
    }
}

// Helper macro for console logging
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}