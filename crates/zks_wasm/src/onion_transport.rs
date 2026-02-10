//! Browser-specific WebSocket transport for onion routing
//!
//! This module provides WebSocket-based transport for browsers (WASM targets)
//! that enables onion routing through relay servers, since browsers cannot
//! establish direct TCP/UDP connections.

use crate::TransportState;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use uuid;
use wasm_bindgen::prelude::*;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

/// Circuit information for onion routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionCircuit {
    pub circuit_id: String,
    pub hops: Vec<OnionHop>,
    pub encryption_keys: Vec<Vec<u8>>,
}

/// Individual hop in the onion circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionHop {
    pub relay_url: String,
    pub peer_id: String,
    pub public_key: Vec<u8>,
}

/// Messages for onion routing protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum OnionMessage {
    /// Build a new circuit
    BuildCircuit {
        circuit_id: String,
        hops: Vec<OnionHop>,
    },
    /// Circuit built successfully
    CircuitBuilt { circuit_id: String },
    /// Forward data through circuit
    ForwardData { circuit_id: String, data: Vec<u8> },
    /// Data received from circuit
    DataReceived { circuit_id: String, data: Vec<u8> },
    /// Tear down circuit
    TearDownCircuit { circuit_id: String },
    /// Circuit torn down
    CircuitTornDown { circuit_id: String },
    /// Error message
    Error {
        circuit_id: Option<String>,
        code: String,
        message: String,
    },
}

/// Browser WebSocket transport for onion routing
#[wasm_bindgen]
pub struct BrowserOnionTransport {
    websocket: Option<WebSocket>,
    circuits: Arc<Mutex<std::collections::HashMap<String, OnionCircuit>>>,
    message_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    state: Arc<Mutex<TransportState>>,
    config: BrowserTransportConfig,
}

/// Configuration for browser transport
#[derive(Clone)]
pub struct BrowserTransportConfig {
    pub relay_url: String,
    pub max_circuit_hops: u8,
    pub circuit_timeout_ms: u32,
    pub max_reconnect_attempts: u32,
    pub reconnect_delay_ms: u32,
}

impl BrowserTransportConfig {
    pub fn new(relay_url: String) -> Self {
        Self {
            relay_url,
            max_circuit_hops: 3,
            circuit_timeout_ms: 30000,
            max_reconnect_attempts: 3,
            reconnect_delay_ms: 1000,
        }
    }

    pub fn with_max_hops(mut self, hops: u8) -> Self {
        self.max_circuit_hops = hops;
        self
    }

    pub fn with_circuit_timeout(mut self, timeout_ms: u32) -> Self {
        self.circuit_timeout_ms = timeout_ms;
        self
    }

    pub fn with_reconnect_attempts(mut self, attempts: u32) -> Self {
        self.max_reconnect_attempts = attempts;
        self
    }

    pub fn with_reconnect_delay(mut self, delay_ms: u32) -> Self {
        self.reconnect_delay_ms = delay_ms;
        self
    }
}

#[wasm_bindgen]
impl BrowserOnionTransport {
    #[wasm_bindgen(constructor)]
    pub fn new(relay_url: String, max_reconnect_attempts: u32) -> Self {
        Self {
            websocket: None,
            circuits: Arc::new(Mutex::new(std::collections::HashMap::new())),
            message_queue: Arc::new(Mutex::new(VecDeque::new())),
            state: Arc::new(Mutex::new(TransportState::Disconnected)),
            config: BrowserTransportConfig {
                relay_url,
                max_circuit_hops: 3,
                circuit_timeout_ms: 30000,
                max_reconnect_attempts,
                reconnect_delay_ms: 1000,
            },
        }
    }

    /// Connect to the relay server
    #[wasm_bindgen]
    pub async fn connect(&mut self) -> Result<(), JsValue> {
        console_log!("Connecting to onion relay at {}", self.config.relay_url);

        // Convert URL to WebSocket format
        let ws_url = convert_relay_url(&self.config.relay_url);

        let websocket = WebSocket::new(&ws_url)?;
        websocket.set_binary_type(web_sys::BinaryType::Arraybuffer);

        // Setup event handlers
        self.setup_event_handlers(&websocket)?;

        *self.state.lock().unwrap() = TransportState::Connecting;
        self.websocket = Some(websocket);

        Ok(())
    }

    /// Build an onion circuit for anonymous routing
    #[wasm_bindgen]
    pub async fn build_circuit(&mut self, hops: Vec<JsValue>) -> Result<String, JsValue> {
        let circuit_id = uuid::Uuid::new_v4().to_string();

        let mut onion_hops = Vec::new();
        for (_i, hop_js) in hops.iter().enumerate() {
            let hop_str = hop_js.as_string().ok_or("Invalid hop format")?;
            let parts: Vec<&str> = hop_str.split(',').collect();

            if parts.len() != 3 {
                return Err(JsValue::from_str(
                    "Each hop must be in format: relay_url,peer_id,public_key",
                ));
            }

            onion_hops.push(OnionHop {
                relay_url: parts[0].to_string(),
                peer_id: parts[1].to_string(),
                public_key: general_purpose::STANDARD
                    .decode(parts[2])
                    .map_err(|e| format!("Invalid public key: {}", e))?,
            });
        }

        let circuit = OnionCircuit {
            circuit_id: circuit_id.clone(),
            hops: onion_hops.clone(),
            encryption_keys: Vec::new(), // Will be populated during build
        };

        // Store circuit
        self.circuits
            .lock()
            .unwrap()
            .insert(circuit_id.clone(), circuit);

        // Send build circuit message
        let message = OnionMessage::BuildCircuit {
            circuit_id: circuit_id.clone(),
            hops: onion_hops,
        };

        self.send_onion_message(message).await?;

        Ok(circuit_id)
    }

    /// Send data through an established circuit
    #[wasm_bindgen]
    pub async fn send_through_circuit(
        &mut self,
        circuit_id: &str,
        data: &[u8],
    ) -> Result<(), JsValue> {
        // Verify circuit exists
        if !self.circuits.lock().unwrap().contains_key(circuit_id) {
            return Err(JsValue::from_str("Circuit not found"));
        }

        let message = OnionMessage::ForwardData {
            circuit_id: circuit_id.to_string(),
            data: data.to_vec(),
        };

        self.send_onion_message(message).await
    }

    /// Receive data from any circuit
    #[wasm_bindgen]
    pub fn receive_from_circuit(&self, _circuit_id: &str) -> Option<Vec<u8>> {
        // For now, just return any received data
        // In a full implementation, this would filter by circuit_id
        self.message_queue.lock().unwrap().pop_front()
    }

    /// Tear down a circuit
    #[wasm_bindgen]
    pub async fn teardown_circuit(&mut self, circuit_id: &str) -> Result<(), JsValue> {
        // Remove circuit from storage
        self.circuits.lock().unwrap().remove(circuit_id);

        let message = OnionMessage::TearDownCircuit {
            circuit_id: circuit_id.to_string(),
        };

        self.send_onion_message(message).await
    }

    /// Disconnect from relay
    #[wasm_bindgen]
    pub fn disconnect(&mut self) {
        if let Some(websocket) = &self.websocket {
            let _ = websocket.close();
        }

        *self.state.lock().unwrap() = TransportState::Disconnected;
        self.websocket = None;
        self.circuits.lock().unwrap().clear();
        self.message_queue.lock().unwrap().clear();
    }

    /// Get connection state
    #[wasm_bindgen]
    pub fn get_state(&self) -> TransportState {
        *self.state.lock().unwrap()
    }

    /// Check if connected
    #[wasm_bindgen]
    pub fn is_connected(&self) -> bool {
        *self.state.lock().unwrap() == TransportState::Connected
    }

    /// Send an onion routing message
    async fn send_onion_message(&mut self, message: OnionMessage) -> Result<(), JsValue> {
        let json = serde_json::to_string(&message)
            .map_err(|e| format!("Failed to serialize message: {}", e))?;

        if let Some(websocket) = &self.websocket {
            websocket.send_with_str(&json)?;
            Ok(())
        } else {
            Err(JsValue::from_str("Not connected to relay"))
        }
    }

    /// Setup WebSocket event handlers
    fn setup_event_handlers(&self, websocket: &WebSocket) -> Result<(), JsValue> {
        let _websocket_clone = websocket.clone();
        let state: Arc<Mutex<TransportState>> = Arc::clone(&self.state);
        let message_queue = Arc::clone(&self.message_queue);
        let circuits = Arc::clone(&self.circuits);

        // On open
        let onopen = Closure::wrap(Box::new(move || {
            console_log!("Onion transport connected to relay");
            *state.lock().unwrap() = TransportState::Connected;
        }) as Box<dyn FnMut()>);
        websocket.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        onopen.forget();

        // On message
        let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
            if let Ok(text) = event.data().dyn_into::<js_sys::JsString>() {
                let text_str = text.as_string().unwrap_or_default();

                match serde_json::from_str::<OnionMessage>(&text_str) {
                    Ok(OnionMessage::DataReceived { circuit_id, data }) => {
                        console_log!("Received {} bytes from circuit {}", data.len(), circuit_id);
                        message_queue.lock().unwrap().push_back(data);
                    }
                    Ok(OnionMessage::CircuitBuilt { circuit_id }) => {
                        console_log!("Circuit {} built successfully", circuit_id);
                    }
                    Ok(OnionMessage::CircuitTornDown { circuit_id }) => {
                        console_log!("Circuit {} torn down", circuit_id);
                        circuits.lock().unwrap().remove(&circuit_id);
                    }
                    Ok(OnionMessage::Error {
                        circuit_id,
                        code,
                        message,
                    }) => {
                        console_log!("Error in circuit {:?}: {} - {}", circuit_id, code, message);
                    }
                    Ok(OnionMessage::BuildCircuit { circuit_id, hops }) => {
                        console_log!(
                            "Build circuit request for {} with {} hops",
                            circuit_id,
                            hops.len()
                        );
                    }
                    Ok(OnionMessage::ForwardData { circuit_id, data }) => {
                        console_log!(
                            "Forward data request for circuit {}: {} bytes",
                            circuit_id,
                            data.len()
                        );
                    }
                    Ok(OnionMessage::TearDownCircuit { circuit_id }) => {
                        console_log!("Tear down circuit request for {}", circuit_id);
                        circuits.lock().unwrap().remove(&circuit_id);
                    }
                    Err(e) => {
                        console_log!("Failed to parse onion message: {}", e);
                    }
                }
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        websocket.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        onmessage.forget();

        // On error
        let state: Arc<Mutex<TransportState>> = Arc::clone(&self.state);
        let onerror = Closure::wrap(Box::new(move |error: ErrorEvent| {
            console_log!("Onion transport error: {:?}", error.message());
            *state.lock().unwrap() = TransportState::Error;
        }) as Box<dyn FnMut(ErrorEvent)>);
        websocket.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        onerror.forget();

        // On close
        let state: Arc<Mutex<TransportState>> = Arc::clone(&self.state);
        let onclose = Closure::wrap(Box::new(move |event: CloseEvent| {
            console_log!(
                "Onion transport closed: code={}, reason={}",
                event.code(),
                event.reason()
            );
            *state.lock().unwrap() = TransportState::Disconnected;
        }) as Box<dyn FnMut(CloseEvent)>);
        websocket.set_onclose(Some(onclose.as_ref().unchecked_ref()));
        onclose.forget();

        Ok(())
    }
}

/// Convert relay URL to WebSocket format
fn convert_relay_url(url: &str) -> String {
    if url.starts_with("ws://") || url.starts_with("wss://") {
        url.to_string()
    } else if url.starts_with("http://") {
        url.replace("http://", "ws://")
    } else if url.starts_with("https://") {
        url.replace("https://", "wss://")
    } else {
        format!("wss://{}/onion", url.trim_end_matches('/'))
    }
}
