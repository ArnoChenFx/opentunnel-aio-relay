//! Bridge session management: one WebSocket per client session.
//!
//! This replaces the per-tunnel Durable Object of the Cloudflare deployment.
//! Each [`Session`] owns the attached bridges (each with its claimed routes)
//! and the active proxied TCP channels. The wire protocol is unchanged, so
//! existing clients work without modification.

use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex, RwLock};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::proto::bridge::{
    self, decode_data_frame, encode_data_frame, ClientMessage, ConnId, ServerMessage, Transport,
};
use crate::proto::names;
use crate::state::{now_rfc3339, AppState};

const MAX_INBOUND_WS_BINARY_SIZE: usize = bridge::CONN_ID_SIZE + bridge::MAX_PAYLOAD_SIZE;

/// Queued messages per proxied connection, matching the official client's
/// inbound queue. A visitor that falls this far behind is reset.
const CHANNEL_QUEUE: usize = 64;

/// Outgoing frames queued for one bridge WebSocket.
#[derive(Debug)]
pub enum OutMsg {
    Text(String),
    Binary(Vec<u8>),
}

/// Incoming traffic for one proxied TCP connection, delivered in order to the
/// task that owns the public socket. Aborts travel on the channel's `cancel`
/// watch instead, so they never wait behind queued data.
#[derive(Debug)]
pub enum ChannelMsg {
    Data(Vec<u8>),
    End,
}

pub struct BridgeHandle {
    pub id: String,
    pub routes: Vec<String>,
    pub tx: mpsc::Sender<OutMsg>,
}

pub struct Session {
    pub id: String,
    pub hostname: String,
    pub token_hash: String,
    pub cert_ready: AtomicBool,
    bridges: AsyncMutex<Vec<BridgeHandle>>,
    channels: AsyncMutex<HashMap<ConnId, ChannelHandle>>,
    next_conn: AtomicU32,
    closed: AtomicBool,
    shutdown: watch::Sender<bool>,
}

struct ChannelHandle {
    bridge_id: String,
    tx: mpsc::Sender<ChannelMsg>,
    cancel: watch::Sender<Option<String>>,
}

#[derive(Default)]
pub struct SessionManager {
    inner: RwLock<HashMap<String, Arc<Session>>>,
}

impl SessionManager {
    /// Returns the in-memory session, loading it from the DB on first use.
    pub async fn get_or_load(&self, db: &Db, id: &str) -> Result<Option<Arc<Session>>> {
        let existing = { self.inner.read().await.get(id).cloned() };
        if let Some(session) = existing {
            if session.is_closed() {
                return Ok(None);
            }
            match db.get_tunnel(id)? {
                Some(record) if record.deleted_at.is_none() => return Ok(Some(session)),
                _ => {
                    session.signal_shutdown();
                    return Ok(None);
                }
            }
        }
        let mut sessions = self.inner.write().await;
        if let Some(session) = sessions.get(id) {
            return Ok((!session.is_closed()).then(|| session.clone()));
        }
        // Recheck under the insertion lock: deletion persists its tombstone
        // before SessionManager::remove takes this lock.
        let record = match db.get_tunnel(id)? {
            Some(record) if record.deleted_at.is_none() => record,
            _ => return Ok(None),
        };
        let (shutdown, _) = watch::channel(false);
        let session = Arc::new(Session {
            id: record.id.clone(),
            hostname: record.hostname.clone(),
            token_hash: record.token_hash.clone(),
            cert_ready: AtomicBool::new(record.cert_pem.is_some()),
            bridges: AsyncMutex::new(Vec::new()),
            channels: AsyncMutex::new(HashMap::new()),
            next_conn: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            shutdown,
        });
        sessions.insert(id.to_string(), session.clone());
        Ok(Some(session))
    }

    pub async fn insert(&self, session: Arc<Session>) {
        self.inner.write().await.insert(session.id.clone(), session);
    }

    pub async fn remove(&self, id: &str) {
        let session = self.inner.write().await.remove(id);
        if let Some(session) = session {
            session.signal_shutdown();
            session.shutdown_live_connections().await;
        }
    }
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Checks a presented token against its stored hash. The comparison touches
/// every byte, so response timing does not reveal how much of the hash matched.
pub fn token_matches(token: &str, stored_hash: &str) -> bool {
    use subtle::ConstantTimeEq;
    hash_token(token)
        .as_bytes()
        .ct_eq(stored_hash.as_bytes())
        .into()
}

const TUNNEL_ID_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn random_tunnel_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| TUNNEL_ID_ALPHABET[(b & 31) as usize] as char)
        .collect()
}

pub fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!(
        "rly_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

use base64::Engine as _;

/// Runs one bridge WebSocket: attach handshake, then bidirectional relay.
/// Called from the axum `/connect` handler after the HTTP upgrade.
pub async fn run_bridge(state: Arc<AppState>, tunnel_id: String, mut socket: WebSocket) {
    if let Err(e) = bridge_loop(state, &tunnel_id, &mut socket).await {
        tracing::debug!(tunnel = %tunnel_id, error = %e, "bridge ended");
    }
}

async fn bridge_loop(state: Arc<AppState>, tunnel_id: &str, socket: &mut WebSocket) -> Result<()> {
    let stall = state.config.timeouts.bridge_stall;
    // The client must send `attach` within 10 seconds (protocol spec).
    let first = tokio::time::timeout(std::time::Duration::from_secs(10), socket.next())
        .await
        .map_err(|_| Error::Internal("attach timeout".into()))?
        .ok_or_else(|| Error::Internal("bridge closed before attach".into()))?;
    let first = first.map_err(|e| Error::Internal(format!("websocket error: {e}")))?;

    let attach = match first {
        Message::Text(text) => parse_client_message(&text),
        _ => None,
    };
    let (token, routes, _client) = match attach {
        Some(ClientMessage::Attach {
            token,
            transport: Transport::Ws,
            routes,
            client,
        }) => (token, routes, client),
        _ => {
            let _ = socket.close().await;
            return Err(Error::Internal("attach required".into()));
        }
    };

    let session = match state.sessions.get_or_load(&state.db, tunnel_id).await? {
        Some(s) => s,
        None => {
            send_text(
                socket,
                &ServerMessage::AttachError {
                    code: bridge::codes::BAD_TOKEN.to_string(),
                },
            )
            .await?;
            let _ = socket.close().await;
            return Ok(());
        }
    };
    let mut shutdown_rx = session.shutdown.subscribe();
    if session.is_closed() {
        let _ = socket.close().await;
        return Ok(());
    }

    if !token_matches(&token, &session.token_hash) {
        send_text(
            socket,
            &ServerMessage::AttachError {
                code: bridge::codes::BAD_TOKEN.to_string(),
            },
        )
        .await?;
        let _ = socket.close().await;
        return Ok(());
    }
    if !session.cert_ready.load(Ordering::SeqCst) {
        send_text(
            socket,
            &ServerMessage::AttachError {
                code: bridge::codes::CERT_NOT_READY.to_string(),
            },
        )
        .await?;
        let _ = socket.close().await;
        return Ok(());
    }

    // Legacy clients attach the base hostname.
    let mut routes: Vec<String> = {
        let mut seen = HashSet::new();
        routes
            .into_iter()
            .filter(|r| seen.insert(r.clone()))
            .collect()
    };
    if routes.is_empty() {
        routes.push(names::ROOT_ROUTE.to_string());
    }
    if routes.iter().any(|r| !names::is_valid_route(r)) {
        send_text(
            socket,
            &ServerMessage::AttachError {
                code: "invalid_route".to_string(),
            },
        )
        .await?;
        let _ = socket.close().await;
        return Ok(());
    }
    let bridge_id = format!("sess_{}", random_session_id());
    let (tx, mut rx) = mpsc::channel::<OutMsg>(512);
    let conflict = !register_bridge(
        &state.db,
        &session,
        BridgeHandle {
            id: bridge_id.clone(),
            routes: routes.clone(),
            tx,
        },
    )
    .await?;
    if conflict {
        send_text(
            socket,
            &ServerMessage::AttachError {
                code: "route_conflict".to_string(),
            },
        )
        .await?;
        let _ = socket.close().await;
        return Ok(());
    }
    tracing::info!(tunnel = %tunnel_id, bridge = %bridge_id, routes = ?routes, "bridge attached");

    if let Err(error) = send_text(
        socket,
        &ServerMessage::Attached {
            session: bridge_id.clone(),
            routes: routes.clone(),
            heartbeat_ms: bridge::HEARTBEAT_MS,
            idle_timeout_ms: bridge::IDLE_TIMEOUT_MS,
        },
    )
    .await
    {
        // Registration happened before the reply so route ownership is
        // consistent; if the peer has already gone, release it immediately.
        detach_bridge(&state.db, &session, &bridge_id).await;
        return Err(error);
    }

    // Renew now if the certificate is close to expiry (covers idle tunnels
    // coming back). Runs in the background; the current cert keeps serving.
    crate::acme::maybe_renew_on_attach(state.clone(), tunnel_id).await;

    let idle = tokio::time::sleep(std::time::Duration::from_millis(bridge::IDLE_TIMEOUT_MS));
    tokio::pin!(idle);

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    tracing::debug!(tunnel = %tunnel_id, "bridge closed because tunnel was deleted");
                    break;
                }
            }
            _ = &mut idle => {
                tracing::debug!(tunnel = %tunnel_id, "bridge idle timeout");
                break;
            }
            out = rx.recv() => {
                let Some(out) = out else { break };
                let msg = match out {
                    OutMsg::Text(t) => Message::Text(t.into()),
                    OutMsg::Binary(b) => Message::Binary(b.into()),
                };
                if socket.send(msg).await.is_err() { break; }
            }
            incoming = socket.next() => {
                let Some(incoming) = incoming else { break };
                let msg = match incoming {
                    Ok(m) => m,
                    Err(_) => break,
                };
                idle.as_mut().reset(tokio::time::Instant::now() + std::time::Duration::from_millis(bridge::IDLE_TIMEOUT_MS));
                match msg {
                    Message::Text(text) => {
                        if let Some(control) = parse_client_message(&text) {
                            if let Some(reply) = handle_control(&session, &bridge_id, control, stall).await {
                                if send_text(socket, &reply).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Message::Binary(data) => {
                        if data.len() > MAX_INBOUND_WS_BINARY_SIZE {
                            tracing::debug!(tunnel = %tunnel_id, bridge = %bridge_id, size = data.len(), "oversized bridge frame");
                            break;
                        }
                        if let Some((conn, payload)) = decode_data_frame(&data) {
                            if let Some(tx) = channel_sender_for_bridge(&session, &bridge_id, conn).await {
                                let queued = tx.send(ChannelMsg::Data(payload.to_vec()));
                                if tokio::time::timeout(stall, queued).await.is_err() {
                                    // The visitor stopped reading for the whole stall
                                    // budget. Abort this connection only, and tell the
                                    // client at once so it stops forwarding to it.
                                    session.abort_channel(&bridge_id, conn, bridge::codes::BACKPRESSURE).await;
                                    let reset = ServerMessage::Reset {
                                        conn,
                                        code: bridge::codes::BACKPRESSURE.into(),
                                    };
                                    if send_text(socket, &reset).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Message::Ping(data) => {
                        let _ = socket.send(Message::Pong(data)).await;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    detach_bridge(&state.db, &session, &bridge_id).await;
    let _ = socket.close().await;
    Ok(())
}

async fn register_bridge(db: &Db, session: &Session, bridge: BridgeHandle) -> Result<bool> {
    let mut bridges = session.bridges.lock().await;
    if session.is_closed() {
        return Err(Error::Internal("tunnel was deleted".into()));
    }
    let conflict = bridges.iter().any(|b| {
        b.routes
            .iter()
            .any(|r| bridge.routes.iter().any(|want| want == r))
    });
    if conflict {
        return Ok(false);
    }

    // Persist membership transitions while holding the same lock used by
    // detach, so a delayed offline write cannot overwrite a newer attach.
    db.set_online(&session.id, true, &now_rfc3339())?;
    bridges.push(bridge);
    Ok(true)
}

async fn detach_bridge(db: &Db, session: &Session, bridge_id: &str) {
    let owned_channels = {
        let mut bridges = session.bridges.lock().await;
        bridges.retain(|b| b.id != bridge_id);
        if bridges.is_empty() {
            // Serialize the persisted online state with later bridge attaches.
            let _ = db.set_online(&session.id, false, &now_rfc3339());
        }

        // Route removal and channel cleanup are ordered against
        // open_channel_for_route, which takes these locks in the same order.
        let mut channels = session.channels.lock().await;
        let owned: Vec<ConnId> = channels
            .iter()
            .filter_map(|(conn, channel)| (channel.bridge_id == bridge_id).then_some(*conn))
            .collect();
        owned
            .into_iter()
            .filter_map(|conn| channels.remove(&conn))
            .collect::<Vec<_>>()
    };
    for channel in owned_channels {
        cancel_channel(channel, "bridge_disconnected");
    }
    tracing::info!(tunnel = %session.id, bridge = %bridge_id, "bridge detached");
}

fn cancel_channel(channel: ChannelHandle, reason: &str) {
    channel.cancel.send_replace(Some(reason.to_string()));
}

/// Handles an incoming control message. Returns a reply to send, if any.
async fn handle_control(
    session: &Arc<Session>,
    bridge_id: &str,
    control: ClientMessage,
    stall: Duration,
) -> Option<ServerMessage> {
    match control {
        ClientMessage::Ping { time_sent } => Some(ServerMessage::Pong { time_sent }),
        ClientMessage::Pong { .. } => None,
        ClientMessage::End { conn } => {
            let tx = channel_sender_for_bridge(session, bridge_id, conn).await?;
            // End ends the visitor's read side and must not be dropped. If the
            // queue stays full past the stall budget, reset the connection instead.
            match tokio::time::timeout(stall, tx.send(ChannelMsg::End)).await {
                Ok(_) => None,
                Err(_) => {
                    session
                        .abort_channel(bridge_id, conn, bridge::codes::BACKPRESSURE)
                        .await;
                    Some(ServerMessage::Reset {
                        conn,
                        code: bridge::codes::BACKPRESSURE.into(),
                    })
                }
            }
        }
        ClientMessage::Reset { conn, code } => {
            session.abort_channel(bridge_id, conn, &code).await;
            None
        }
        ClientMessage::Attach { .. } => None,
    }
}

async fn channel_sender_for_bridge(
    session: &Session,
    bridge_id: &str,
    conn: ConnId,
) -> Option<mpsc::Sender<ChannelMsg>> {
    session
        .channels
        .lock()
        .await
        .get(&conn)
        .filter(|channel| channel.bridge_id == bridge_id)
        .map(|channel| channel.tx.clone())
}

/// Lenient decode: unknown message types are ignored per the protocol spec.
fn parse_client_message(text: &str) -> Option<ClientMessage> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let kind = value.get("type")?.as_str()?;
    match kind {
        "attach" | "ping" | "pong" | "end" | "reset" => serde_json::from_value(value).ok(),
        _ => None,
    }
}

async fn send_text(socket: &mut WebSocket, msg: &ServerMessage) -> Result<()> {
    let text = serde_json::to_string(msg)?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|e| Error::Internal(format!("websocket send error: {e}")))?;
    Ok(())
}

pub fn random_session_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

impl Session {
    /// Finds the bridge currently holding `route`, if any.
    pub async fn bridge_for_route(&self, route: &str) -> Option<(String, mpsc::Sender<OutMsg>)> {
        let bridges = self.bridges.lock().await;
        bridges
            .iter()
            .find(|b| b.routes.iter().any(|r| r == route))
            .map(|b| (b.id.clone(), b.tx.clone()))
    }

    /// Atomically resolves a route and registers its channel. Bridge removal
    /// uses the same lock order, so it either sees this channel and cancels it
    /// or the route lookup fails after the bridge is gone.
    pub async fn open_channel_for_route(
        &self,
        route: &str,
    ) -> Option<(
        ConnId,
        mpsc::Receiver<ChannelMsg>,
        watch::Receiver<Option<String>>,
        mpsc::Sender<OutMsg>,
    )> {
        let _bridges = self.bridges.lock().await;
        if self.is_closed() {
            return None;
        }
        let (bridge_id, bridge_tx) = _bridges
            .iter()
            .find(|bridge| bridge.routes.iter().any(|candidate| candidate == route))
            .map(|bridge| (bridge.id.clone(), bridge.tx.clone()))?;

        let mut channels = self.channels.lock().await;
        let mut conn = self.next_conn.fetch_add(1, Ordering::SeqCst);
        while conn == 0 || channels.contains_key(&conn) {
            conn = self.next_conn.fetch_add(1, Ordering::SeqCst);
        }
        let (tx, rx) = mpsc::channel::<ChannelMsg>(CHANNEL_QUEUE);
        let (cancel, cancel_rx) = watch::channel(None);
        channels.insert(
            conn,
            ChannelHandle {
                bridge_id: bridge_id.clone(),
                tx,
                cancel,
            },
        );
        Some((conn, rx, cancel_rx, bridge_tx))
    }

    pub async fn channel_sender(&self, conn: ConnId) -> Option<mpsc::Sender<ChannelMsg>> {
        self.channels
            .lock()
            .await
            .get(&conn)
            .map(|channel| channel.tx.clone())
    }

    pub async fn close_channel(&self, conn: ConnId) {
        if let Some(channel) = self.channels.lock().await.remove(&conn) {
            channel.cancel.send_replace(Some("channel_closed".into()));
        }
    }

    /// Cancels one connection owned by `bridge_id` and detaches it. Returns
    /// false if it was already gone or belongs to another bridge.
    async fn abort_channel(&self, bridge_id: &str, conn: ConnId, reason: &str) -> bool {
        let channel = {
            let mut channels = self.channels.lock().await;
            if channels
                .get(&conn)
                .is_some_and(|channel| channel.bridge_id == bridge_id)
            {
                channels.remove(&conn)
            } else {
                None
            }
        };
        match channel {
            Some(channel) => {
                cancel_channel(channel, reason);
                true
            }
            None => false,
        }
    }

    pub async fn send_data(
        &self,
        bridge_tx: &mpsc::Sender<OutMsg>,
        conn: ConnId,
        payload: &[u8],
    ) -> bool {
        if self.is_closed() {
            return false;
        }
        for chunk in payload.chunks(bridge::MAX_PAYLOAD_SIZE) {
            let frame = encode_data_frame(conn, chunk);
            if bridge_tx.send(OutMsg::Binary(frame)).await.is_err() {
                return false;
            }
        }
        true
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub(crate) fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    fn signal_shutdown(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.shutdown.send_replace(true);
        }
    }

    async fn shutdown_live_connections(&self) {
        self.bridges.lock().await.clear();
        let channels = {
            let mut channels = self.channels.lock().await;
            channels
                .drain()
                .map(|(_, channel)| channel)
                .collect::<Vec<_>>()
        };
        for channel in channels {
            cancel_channel(channel, "tunnel_deleted");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(id: &str) -> Arc<Session> {
        let (shutdown, _) = watch::channel(false);
        Arc::new(Session {
            id: id.to_string(),
            hostname: format!("{id}.relay.test"),
            token_hash: "hash".into(),
            cert_ready: AtomicBool::new(true),
            bridges: AsyncMutex::new(Vec::new()),
            channels: AsyncMutex::new(HashMap::new()),
            next_conn: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            shutdown,
        })
    }

    fn test_db() -> (Arc<Db>, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "ot-relay-bridge-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = Arc::new(Db::open(&path).unwrap());
        db.create_tunnel("test", "test.relay.test", "hash", "now")
            .unwrap();
        (db, path)
    }

    fn bridge(id: &str, route: &str) -> BridgeHandle {
        let (tx, _rx) = mpsc::channel(8);
        BridgeHandle {
            id: id.into(),
            routes: vec![route.into()],
            tx,
        }
    }

    #[tokio::test]
    async fn attach_detach_race_keeps_online_state_in_sync_with_membership() {
        let (db, path) = test_db();
        let session = test_session("test");
        assert!(register_bridge(&db, &session, bridge("old", "@"))
            .await
            .unwrap());

        let db_detach = db.clone();
        let session_detach = session.clone();
        let db_attach = db.clone();
        let session_attach = session.clone();
        let ((), attached) = tokio::join!(
            detach_bridge(&db_detach, &session_detach, "old"),
            register_bridge(&db_attach, &session_attach, bridge("new", "api")),
        );
        assert!(attached.unwrap());
        assert_eq!(session.bridges.lock().await.len(), 1);
        assert_eq!(db.get_tunnel("test").unwrap().unwrap().state, "online");

        detach_bridge(&db, &session, "new").await;
        assert_eq!(db.get_tunnel("test").unwrap().unwrap().state, "offline");
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[tokio::test]
    async fn route_open_racing_bridge_detach_cannot_leave_an_orphan_channel() {
        let (db, path) = test_db();
        let session = test_session("test");
        assert!(register_bridge(&db, &session, bridge("only", "@"))
            .await
            .unwrap());

        let (opened, ()) = tokio::join!(
            session.open_channel_for_route("@"),
            detach_bridge(&db, &session, "only"),
        );
        drop(opened);
        assert!(session.channels.lock().await.is_empty());
        assert!(session.open_channel_for_route("@").await.is_none());
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[tokio::test]
    async fn tunnel_shutdown_does_not_wait_for_a_full_channel_queue() {
        let session = test_session("test");
        let (tx, _rx) = mpsc::channel(256);
        for _ in 0..256 {
            tx.try_send(ChannelMsg::Data(vec![1])).unwrap();
        }
        let (cancel, mut cancel_rx) = watch::channel(None);
        session.channels.lock().await.insert(
            1,
            ChannelHandle {
                bridge_id: "bridge".into(),
                tx,
                cancel,
            },
        );

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            session.shutdown_live_connections(),
        )
        .await
        .expect("shutdown blocked on a full per-channel queue");
        assert_eq!(
            cancel_rx.borrow_and_update().as_deref(),
            Some("tunnel_deleted")
        );
        assert!(session.channels.lock().await.is_empty());
    }

    #[tokio::test]
    async fn bridge_detach_does_not_wait_for_a_full_channel_queue() {
        let (db, path) = test_db();
        let session = test_session("test");
        assert!(register_bridge(&db, &session, bridge("bridge", "@"))
            .await
            .unwrap());
        let (tx, _rx) = mpsc::channel(256);
        for _ in 0..256 {
            tx.try_send(ChannelMsg::Data(vec![1])).unwrap();
        }
        let (cancel, mut cancel_rx) = watch::channel(None);
        session.channels.lock().await.insert(
            1,
            ChannelHandle {
                bridge_id: "bridge".into(),
                tx,
                cancel,
            },
        );

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            detach_bridge(&db, &session, "bridge"),
        )
        .await
        .expect("bridge detach blocked on a full per-channel queue");
        assert_eq!(
            cancel_rx.borrow_and_update().as_deref(),
            Some("bridge_disconnected")
        );
        assert!(session.channels.lock().await.is_empty());
        assert_eq!(db.get_tunnel("test").unwrap().unwrap().state, "offline");
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}
