//! WebAssembly bindings for ZKS onion routing
//! 
//! This module provides JavaScript bindings for browser-based onion routing
//! using WebSocket transport and the unified SwarmController.

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use js_sys::{Promise, Array, Uint8Array};
use web_sys::console;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

// Import our transport modules
use crate::{
    BrowserOnionTransport,
};

/// JavaScript-compatible wrapper for onion routing transport
#[wasm_bindgen]
pub struct ZksOnionTransport {
    inner: Arc<Mutex<BrowserOnionTransport>>,
    #[allow(dead_code)]
    message_queue: Arc<VecDeque<Vec<u8>>>,
}

#[wasm_bindgen]
impl ZksOnionTransport {
    /// Create a new onion transport instance
    #[wasm_bindgen(constructor)]
    pub fn new(relay_url: String) -> Self {
        console::log_1(&format!("Creating ZKS onion transport for relay: {}", relay_url).into());
        
        let transport = BrowserOnionTransport::new(relay_url, 3);
        
        Self {
            inner: Arc::new(Mutex::new(transport)),
            message_queue: Arc::new(VecDeque::new()),
        }
    }
    
    /// Connect to the relay server
    #[wasm_bindgen]
    pub fn connect(&self) -> Promise {
        let inner = Arc::clone(&self.inner);
        
        future_to_promise(async move {
            let mut transport = inner.lock().unwrap();
            (*transport).connect().await
                .map_err(|e| JsValue::from_str(&format!("Connection failed: {:?}", e)))?;
            
            console::log_1(&"ZKS onion transport connected successfully".into());
            Ok(JsValue::UNDEFINED)
        })
    }
    
    /// Build an onion circuit for anonymous routing
    #[wasm_bindgen]
    pub fn build_circuit(&self, hops: Array) -> Promise {
        let inner = Arc::clone(&self.inner);
        
        future_to_promise(async move {
            // Convert JavaScript array to Vec<JsValue>
            let hops_vec: Vec<JsValue> = hops.iter().collect();
            
            let mut transport = inner.lock().unwrap();
            let circuit_id = (*transport).build_circuit(hops_vec).await
                .map_err(|e| JsValue::from_str(&format!("Circuit build failed: {:?}", e)))?;
            
            console::log_1(&format!("Onion circuit {} built successfully", circuit_id).into());
            Ok(JsValue::from_str(&circuit_id))
        })
    }
    
    /// Send data through an established circuit
    #[wasm_bindgen]
    pub fn send_through_circuit(&self, circuit_id: &str, data: &[u8]) -> Promise {
        let inner = Arc::clone(&self.inner);
        let circuit_id = circuit_id.to_string();
        let data = data.to_vec(); // Clone the data to fix lifetime issues
        
        future_to_promise(async move {
            let mut transport = inner.lock().unwrap();
            (*transport).send_through_circuit(&circuit_id, &data).await
                .map_err(|e| JsValue::from_str(&format!("Send failed: {:?}", e)))?;
            
            console::log_1(&format!("Sent {} bytes through circuit {}", data.len(), circuit_id).into());
            Ok(JsValue::UNDEFINED)
        })
    }
    
    /// Receive data from any circuit
    #[wasm_bindgen]
    pub fn receive_from_circuit(&self, circuit_id: &str) -> Option<Uint8Array> {
        let transport = self.inner.lock().unwrap();
        match (*transport).receive_from_circuit(circuit_id) {
            Some(data) => Some(Uint8Array::from(&data[..])),
            None => None,
        }
    }
    
    /// Tear down a circuit
    #[wasm_bindgen]
    pub fn teardown_circuit(&self, circuit_id: &str) -> Promise {
        let inner = Arc::clone(&self.inner);
        let circuit_id = circuit_id.to_string();
        
        future_to_promise(async move {
            let mut transport = inner.lock().unwrap();
            (*transport).teardown_circuit(&circuit_id).await
                .map_err(|e| JsValue::from_str(&format!("Teardown failed: {:?}", e)))?;
            
            Ok(JsValue::UNDEFINED)
        })
    }
    
    /// Get current transport state
    #[wasm_bindgen]
    pub fn get_state(&self) -> JsValue {
        let transport = self.inner.lock().unwrap();
        let state = (*transport).get_state();
        JsValue::from_str(&format!("{:?}", state))
    }
}

/// High-level connection manager for browser environments
#[wasm_bindgen]
pub struct ZksConnectionManager {
    onion_transport: Option<Arc<Mutex<BrowserOnionTransport>>>,
    current_circuit: Option<String>,
}

#[wasm_bindgen]
impl ZksConnectionManager {
    /// Create a new connection manager
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console::log_1(&"Creating ZKS connection manager".into());
        
        Self {
            onion_transport: None,
            current_circuit: None,
        }
    }
    
    /// Initialize onion routing with a relay URL
    #[wasm_bindgen]
    pub fn initialize_onion(&mut self, relay_url: String) -> Promise {
        console::log_1(&format!("Initializing onion routing with relay: {}", relay_url).into());
        
        let transport = Arc::new(Mutex::new(BrowserOnionTransport::new(relay_url, 3)));
        
        let transport_clone = Arc::clone(&transport);
        
        future_to_promise(async move {
            let mut transport = transport_clone.lock().unwrap();
            (*transport).connect().await
                .map_err(|e| JsValue::from_str(&format!("Onion routing init failed: {:?}", e)))?;
            
            console::log_1(&"Onion routing initialized successfully".into());
            Ok(JsValue::UNDEFINED)
        })
    }
    
    /// Connect to a zks:// endpoint through onion routing
    #[wasm_bindgen]
    pub fn connect_onion(&mut self, target: String, hops: Array) -> Promise {
        if let Some(transport) = &self.onion_transport {
            let transport_clone = Arc::clone(transport);
            let hops_vec: Vec<JsValue> = hops.iter().collect();
            
            future_to_promise(async move {
                let mut transport = transport_clone.lock().unwrap();
                let circuit_id = (*transport).build_circuit(hops_vec).await
                    .map_err(|e| JsValue::from_str(&format!("Circuit build failed: {:?}", e)))?;
                
                console::log_1(&format!("Connected to {} via circuit {}", target, circuit_id).into());
                Ok(JsValue::from_str(&circuit_id))
            })
        } else {
            Promise::reject(&JsValue::from_str("Error"))
        }
    }
    
    /// Send data through the current onion circuit
    #[wasm_bindgen]
    pub fn send_onion_data(&self, data: &[u8]) -> Promise {
        if let (Some(transport), Some(circuit_id)) = (&self.onion_transport, &self.current_circuit) {
            let transport_clone = Arc::clone(transport);
            let circuit_id = circuit_id.clone();
            let data = data.to_vec();
            
            future_to_promise(async move {
                let mut transport = transport_clone.lock().unwrap();
                (*transport).send_through_circuit(&circuit_id, &data).await
                    .map_err(|e| JsValue::from_str(&format!("Send failed: {:?}", e)))?;
                
                Ok(JsValue::UNDEFINED)
            })
        } else {
            Promise::reject(&JsValue::from_str("Missing"))
        }
    }
    
    /// Receive data from the current onion circuit
    #[wasm_bindgen]
    pub fn receive_onion_data(&self) -> Option<Uint8Array> {
        if let (Some(transport), Some(circuit_id)) = (&self.onion_transport, &self.current_circuit) {
            let transport = transport.lock().unwrap();
            match (*transport).receive_from_circuit(circuit_id) {
                Some(data) => Some(Uint8Array::from(&data[..])),
                None => None,
            }
        } else {
            None
        }
    }
    
    /// Disconnect and tear down the current onion circuit
    #[wasm_bindgen]
    pub fn disconnect_onion(&mut self) -> Promise {
        if let (Some(transport), Some(circuit_id)) = (&self.onion_transport, &self.current_circuit.clone()) {
            let transport_clone = Arc::clone(transport);
            let circuit_id = circuit_id.clone();
            
            future_to_promise(async move {
                let mut transport = transport_clone.lock().unwrap();
                (*transport).teardown_circuit(&circuit_id).await
                    .map_err(|e| JsValue::from_str(&format!("Onion disconnect failed: {:?}", e)))?;
                
                console::log_1(&format!("Circuit {}", circuit_id).into());
                Ok(JsValue::UNDEFINED)
            })
        } else {
            Promise::resolve(&JsValue::UNDEFINED)
        }
    }
    
    /// Get connection state
    #[wasm_bindgen]
    pub fn get_connection_state(&self) -> JsValue {
        if let Some(transport) = &self.onion_transport {
            let transport = transport.lock().unwrap();
            let state = (*transport).get_state();
            JsValue::from_str(&format!("{:?}", state))
        } else {
            JsValue::from_str("0")
        }
    }
}