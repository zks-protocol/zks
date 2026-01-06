use wasm_bindgen::prelude::*;
use web_sys::{WebSocket, MessageEvent, CloseEvent, ErrorEvent};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransportState {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

#[wasm_bindgen]
pub struct TransportConfig {
    pub url: String,
    pub max_reconnect_attempts: u32,
    pub reconnect_delay_ms: u32,
}

#[wasm_bindgen]
impl TransportConfig {
    #[wasm_bindgen(constructor)]
    pub fn new(url: String) -> Self {
        Self {
            url,
            max_reconnect_attempts: 3,
            reconnect_delay_ms: 1000,
        }
    }

    #[wasm_bindgen]
    pub fn with_reconnect_attempts(mut self, attempts: u32) -> Self {
        self.max_reconnect_attempts = attempts;
        self
    }

    #[wasm_bindgen]
    pub fn with_reconnect_delay(mut self, delay_ms: u32) -> Self {
        self.reconnect_delay_ms = delay_ms;
        self
    }
}

#[wasm_bindgen]
pub struct WebSocketTransport {
    websocket: Option<WebSocket>,
    message_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    state: Arc<Mutex<TransportState>>,
    config: TransportConfig,
    reconnect_attempts: Arc<Mutex<u32>>,
}

#[wasm_bindgen]
impl WebSocketTransport {
    #[wasm_bindgen(constructor)]
    pub fn new(config: TransportConfig) -> Self {
        Self {
            websocket: None,
            message_queue: Arc::new(Mutex::new(VecDeque::new())),
            state: Arc::new(Mutex::new(TransportState::Disconnected)),
            config,
            reconnect_attempts: Arc::new(Mutex::new(0)),
        }
    }

    #[wasm_bindgen]
    pub async fn connect(&mut self) -> Result<(), JsValue> {
        console_log!("Connecting to: {}", self.config.url);
        
        // Convert zk:// to ws:// for WebSocket compatibility
        let ws_url = convert_zk_url(&self.config.url);
        
        let websocket = WebSocket::new(&ws_url)?;
        websocket.set_binary_type(web_sys::BinaryType::Arraybuffer);
        
        // Setup event handlers
        self.setup_event_handlers(&websocket)?;
        
        *self.state.lock().unwrap() = TransportState::Connecting;
        self.websocket = Some(websocket);
        
        Ok(())
    }

    #[wasm_bindgen]
    pub fn disconnect(&mut self) {
        if let Some(websocket) = &self.websocket {
            let _ = websocket.close();
        }
        *self.state.lock().unwrap() = TransportState::Disconnected;
        self.websocket = None;
        self.message_queue.lock().unwrap().clear();
        *self.reconnect_attempts.lock().unwrap() = 0;
    }

    #[wasm_bindgen]
    pub fn send(&mut self, data: &[u8]) -> Result<(), JsValue> {
        if let Some(websocket) = &self.websocket {
            websocket.send_with_u8_array(data)?;
            Ok(())
        } else {
            Err(JsValue::from_str("Not connected"))
        }
    }

    #[wasm_bindgen]
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        self.message_queue.lock().unwrap().pop_front()
    }

    #[wasm_bindgen]
    pub fn get_state(&self) -> TransportState {
        *self.state.lock().unwrap()
    }

    #[wasm_bindgen]
    pub fn is_connected(&self) -> bool {
        *self.state.lock().unwrap() == TransportState::Connected
    }

    #[wasm_bindgen]
    pub fn get_pending_message_count(&self) -> usize {
        self.message_queue.lock().unwrap().len()
    }

    fn setup_event_handlers(&self, websocket: &WebSocket) -> Result<(), JsValue> {
        let websocket_clone = websocket.clone();
        let state = Arc::clone(&self.state);
        let message_queue = Arc::clone(&self.message_queue);
        let reconnect_attempts = Arc::clone(&self.reconnect_attempts);
        let config = self.config.clone();

        // On open
        let onopen = Closure::wrap(Box::new(move || {
            console_log!("WebSocket connected");
            *state.lock().unwrap() = TransportState::Connected;
            *reconnect_attempts.lock().unwrap() = 0;
        }) as Box<dyn FnMut()>);
        websocket.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        onopen.forget();

        // On message
        let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
            if let Ok(array_buffer) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                let uint8_array = js_sys::Uint8Array::new(&array_buffer);
                let mut data = vec![0u8; uint8_array.length() as usize];
                uint8_array.copy_to(&mut data);
                
                console_log!("Received {} bytes", data.len());
                message_queue.lock().unwrap().push_back(data);
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        websocket.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        onmessage.forget();

        // On error
        let state = Arc::clone(&self.state);
        let onerror = Closure::wrap(Box::new(move |error: ErrorEvent| {
            console_log!("WebSocket error: {:?}", error.message());
            *state.lock().unwrap() = TransportState::Error;
        }) as Box<dyn FnMut(ErrorEvent)>);
        websocket.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        onerror.forget();

        // On close
        let state = Arc::clone(&self.state);
        let onclose = Closure::wrap(Box::new(move |event: CloseEvent| {
            console_log!("WebSocket closed: code={}, reason={}", event.code(), event.reason());
            *state.lock().unwrap() = TransportState::Disconnected;
            
            // Attempt reconnection if configured
            let attempts = *reconnect_attempts.lock().unwrap();
            if attempts < config.max_reconnect_attempts {
                *reconnect_attempts.lock().unwrap() += 1;
                console_log!("Attempting reconnection {} of {}", attempts + 1, config.max_reconnect_attempts);
                
                // Schedule reconnection attempt
                let state = Arc::clone(&state);
                let delay = config.reconnect_delay_ms;
                spawn_local(async move {
                    let _ = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
                        let window = web_sys::window().unwrap();
                        let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                            &resolve,
                            delay as i32,
                        );
                    })).await;
                    
                    // Note: In a real implementation, we would attempt reconnection here
                    console_log!("Reconnection would be attempted here");
                });
            }
        }) as Box<dyn FnMut(CloseEvent)>);
        websocket.set_onclose(Some(onclose.as_ref().unchecked_ref()));
        onclose.forget();

        Ok(())
    }
}

#[wasm_bindgen]
pub fn convert_zk_url(url: &str) -> String {
    url.replace("zk://", "ws://")
       .replace("zks://", "wss://")
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