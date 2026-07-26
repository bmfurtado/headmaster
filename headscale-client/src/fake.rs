use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hyper_util::rt::TokioIo;
use tonic::transport::{Endpoint, Server, Uri};
use tonic::{Request, Response, Status};
use tower::service_fn;

use crate::headscale::v1::headscale_service_client::HeadscaleServiceClient;
use crate::headscale::v1::headscale_service_server::{HeadscaleService, HeadscaleServiceServer};
use crate::headscale::v1::*;
use crate::{AuthInterceptor, AuthenticatedClient, Channel, HeadscaleConnector, TransportError};

fn not_needed<T>() -> Result<Response<T>, Status> {
    Err(Status::unimplemented("not needed"))
}

/// Shared mutable state for the fake server. Consolidated into a single
/// Mutex so user lookup and key insertion in create_pre_auth_key are atomic,
/// closing the TOCTOU window where delete_user could interleave between them.
#[derive(Default)]
pub struct FakeState {
    pub users: Vec<User>,
    pub pre_auth_keys: Vec<PreAuthKey>,
    pub nodes: Vec<Node>,
    /// Tracks the most recent tags set on each node via set_tags, keyed by node_id.
    pub node_tags: HashMap<u64, Vec<String>>,
}

pub struct FakeHeadscaleServer {
    pub state: Arc<Mutex<FakeState>>,
    pub policy: Arc<Mutex<String>>,
    /// When true, GetPolicy returns NOT_FOUND (simulates a fresh headscale
    /// instance that has never had a policy set).
    pub policy_not_found: bool,
    /// When set to true, SetPolicy returns INTERNAL (simulates a headscale write
    /// failure). Stored as an Arc<AtomicBool> so tests can flip it mid-run.
    pub set_policy_fails: Arc<AtomicBool>,
    /// When set to true, DeleteUser returns INTERNAL (simulates a headscale delete
    /// failure). Stored as an Arc<AtomicBool> so tests can flip it mid-run.
    pub delete_user_fails: Arc<AtomicBool>,
    /// When set to true, ExpireNode returns INTERNAL (simulates a headscale node
    /// expiry failure). Stored as an Arc<AtomicBool> so tests can flip it mid-run.
    pub expire_node_fails: Arc<AtomicBool>,
    next_id: Arc<AtomicU64>,
}

impl Default for FakeHeadscaleServer {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeState::default())),
            policy: Arc::new(Mutex::new(String::new())),
            policy_not_found: false,
            set_policy_fails: Arc::new(AtomicBool::new(false)),
            delete_user_fails: Arc::new(AtomicBool::new(false)),
            expire_node_fails: Arc::new(AtomicBool::new(false)),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }
}

impl FakeHeadscaleServer {
    pub fn with_policy_not_found() -> Self {
        Self {
            policy_not_found: true,
            ..Self::default()
        }
    }

    pub fn with_set_policy_fails() -> Self {
        Self {
            set_policy_fails: Arc::new(AtomicBool::new(true)),
            ..Self::default()
        }
    }

    /// Creates a node owned by `user` in the fake state and returns its ID.
    /// Used by tests to pre-populate nodes for deactivation/expiry scenarios.
    pub fn create_node_for_user(&self, user: User) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let node = Node {
            id,
            user: Some(user),
            ..Default::default()
        };
        self.state.lock().unwrap().nodes.push(node);
        id
    }
}

/// Wires `server` to an in-process duplex pipe and returns a raw `Channel`.
/// No network socket is bound; the server is unreachable from outside this process.
pub async fn spawn_fake_channel(server: FakeHeadscaleServer) -> Channel {
    let (client_io, server_io) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        Server::builder()
            .add_service(HeadscaleServiceServer::new(server))
            .serve_with_incoming(tokio_stream::once(Ok::<_, std::io::Error>(server_io)))
            .await
            .unwrap();
    });

    let mut client_io = Some(client_io);
    Endpoint::try_from("http://[::]:0")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let io = client_io.take();
            async move {
                match io {
                    Some(io) => Ok(TokioIo::new(io)),
                    None => Err(std::io::Error::other("duplex already consumed")),
                }
            }
        }))
        .await
        .unwrap()
}

/// Wires `server` to an in-process duplex pipe and returns a plain client (no auth).
/// Used directly in unit tests that exercise the fake server.
pub async fn spawn_fake_server(server: FakeHeadscaleServer) -> HeadscaleServiceClient<Channel> {
    HeadscaleServiceClient::new(spawn_fake_channel(server).await)
}

#[tonic::async_trait]
impl HeadscaleService for FakeHeadscaleServer {
    async fn list_users(
        &self,
        req: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        let req = req.into_inner();
        let state = self.state.lock().unwrap();
        let result: Vec<User> = if req.id != 0 {
            state
                .users
                .iter()
                .filter(|u| u.id == req.id)
                .cloned()
                .collect()
        } else if !req.name.is_empty() {
            state
                .users
                .iter()
                .filter(|u| u.name == req.name)
                .cloned()
                .collect()
        } else if !req.email.is_empty() {
            state
                .users
                .iter()
                .filter(|u| u.email == req.email)
                .cloned()
                .collect()
        } else {
            state.users.clone()
        };
        Ok(Response::new(ListUsersResponse { users: result }))
    }

    async fn create_user(
        &self,
        req: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let req = req.into_inner();
        let mut state = self.state.lock().unwrap();
        if state.users.iter().any(|u| u.name == req.name) {
            return Err(Status::already_exists(format!(
                "user '{}' already exists",
                req.name
            )));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let user = User {
            id,
            name: req.name,
            display_name: req.display_name,
            email: req.email,
            profile_pic_url: req.picture_url,
            ..Default::default()
        };
        state.users.push(user.clone());
        Ok(Response::new(CreateUserResponse { user: Some(user) }))
    }

    async fn delete_user(
        &self,
        req: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        if self.delete_user_fails.load(Ordering::Relaxed) {
            return Err(Status::internal("delete_user deliberately fails"));
        }
        let id = req.into_inner().id;
        let mut state = self.state.lock().unwrap();
        let before = state.users.len();
        state.users.retain(|u| u.id != id);
        if state.users.len() == before {
            return Err(Status::not_found(format!("user {id} not found")));
        }
        Ok(Response::new(DeleteUserResponse {}))
    }

    async fn create_pre_auth_key(
        &self,
        req: Request<CreatePreAuthKeyRequest>,
    ) -> Result<Response<CreatePreAuthKeyResponse>, Status> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let r = req.into_inner();
        // Single lock covers both the user lookup and key insertion, closing the
        // TOCTOU window where delete_user could remove the user between the two.
        let mut state = self.state.lock().unwrap();
        let user = state.users.iter().find(|u| u.id == r.user).cloned();
        let key = PreAuthKey {
            id,
            key: format!("fake-key-{id}"),
            user,
            reusable: r.reusable,
            ephemeral: r.ephemeral,
            acl_tags: r.acl_tags,
            ..Default::default()
        };
        state.pre_auth_keys.push(key.clone());
        Ok(Response::new(CreatePreAuthKeyResponse {
            pre_auth_key: Some(key),
        }))
    }

    async fn delete_pre_auth_key(
        &self,
        req: Request<DeletePreAuthKeyRequest>,
    ) -> Result<Response<DeletePreAuthKeyResponse>, Status> {
        let id = req.into_inner().id;
        let mut state = self.state.lock().unwrap();
        let before = state.pre_auth_keys.len();
        state.pre_auth_keys.retain(|k| k.id != id);
        if state.pre_auth_keys.len() == before {
            return Err(Status::not_found(format!("pre_auth_key {id} not found")));
        }
        Ok(Response::new(DeletePreAuthKeyResponse {}))
    }

    async fn list_nodes(
        &self,
        _: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        let nodes = self.state.lock().unwrap().nodes.clone();
        Ok(Response::new(ListNodesResponse { nodes }))
    }

    async fn delete_node(
        &self,
        req: Request<DeleteNodeRequest>,
    ) -> Result<Response<DeleteNodeResponse>, Status> {
        let id = req.into_inner().node_id;
        let mut state = self.state.lock().unwrap();
        let before = state.nodes.len();
        state.nodes.retain(|n| n.id != id);
        if state.nodes.len() == before {
            return Err(Status::not_found(format!("node {id} not found")));
        }
        Ok(Response::new(DeleteNodeResponse {}))
    }

    async fn rename_user(
        &self,
        req: Request<RenameUserRequest>,
    ) -> Result<Response<RenameUserResponse>, Status> {
        let req = req.into_inner();
        let mut state = self.state.lock().unwrap();
        let user = state
            .users
            .iter_mut()
            .find(|u| u.id == req.old_id)
            .ok_or_else(|| Status::not_found("user not found"))?;
        user.name = req.new_name;
        Ok(Response::new(RenameUserResponse {
            user: Some(user.clone()),
        }))
    }
    async fn expire_pre_auth_key(
        &self,
        _: Request<ExpirePreAuthKeyRequest>,
    ) -> Result<Response<ExpirePreAuthKeyResponse>, Status> {
        not_needed()
    }
    async fn list_pre_auth_keys(
        &self,
        _: Request<ListPreAuthKeysRequest>,
    ) -> Result<Response<ListPreAuthKeysResponse>, Status> {
        let keys = self.state.lock().unwrap().pre_auth_keys.clone();
        Ok(Response::new(ListPreAuthKeysResponse {
            pre_auth_keys: keys,
        }))
    }
    async fn debug_create_node(
        &self,
        _: Request<DebugCreateNodeRequest>,
    ) -> Result<Response<DebugCreateNodeResponse>, Status> {
        not_needed()
    }
    async fn get_node(
        &self,
        req: Request<GetNodeRequest>,
    ) -> Result<Response<GetNodeResponse>, Status> {
        let id = req.into_inner().node_id;
        let node = self
            .state
            .lock()
            .unwrap()
            .nodes
            .iter()
            .find(|n| n.id == id)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("node {id} not found")))?;
        Ok(Response::new(GetNodeResponse { node: Some(node) }))
    }
    async fn set_tags(
        &self,
        req: Request<SetTagsRequest>,
    ) -> Result<Response<SetTagsResponse>, Status> {
        let req = req.into_inner();
        self.state
            .lock()
            .unwrap()
            .node_tags
            .insert(req.node_id, req.tags);
        Ok(Response::new(SetTagsResponse { node: None }))
    }
    async fn set_approved_routes(
        &self,
        _: Request<SetApprovedRoutesRequest>,
    ) -> Result<Response<SetApprovedRoutesResponse>, Status> {
        not_needed()
    }
    async fn register_node(
        &self,
        _: Request<RegisterNodeRequest>,
    ) -> Result<Response<RegisterNodeResponse>, Status> {
        not_needed()
    }
    async fn expire_node(
        &self,
        req: Request<ExpireNodeRequest>,
    ) -> Result<Response<ExpireNodeResponse>, Status> {
        if self.expire_node_fails.load(Ordering::Relaxed) {
            return Err(Status::internal("expire_node deliberately fails"));
        }
        let req = req.into_inner();
        let mut state = self.state.lock().unwrap();
        let node = state
            .nodes
            .iter_mut()
            .find(|n| n.id == req.node_id)
            .ok_or_else(|| Status::not_found(format!("node {} not found", req.node_id)))?;
        node.expiry = req.expiry;
        let node = node.clone();
        Ok(Response::new(ExpireNodeResponse { node: Some(node) }))
    }
    async fn rename_node(
        &self,
        _: Request<RenameNodeRequest>,
    ) -> Result<Response<RenameNodeResponse>, Status> {
        not_needed()
    }
    async fn backfill_node_i_ps(
        &self,
        _: Request<BackfillNodeIPsRequest>,
    ) -> Result<Response<BackfillNodeIPsResponse>, Status> {
        not_needed()
    }
    async fn auth_register(
        &self,
        _: Request<AuthRegisterRequest>,
    ) -> Result<Response<AuthRegisterResponse>, Status> {
        not_needed()
    }
    async fn auth_approve(
        &self,
        _: Request<AuthApproveRequest>,
    ) -> Result<Response<AuthApproveResponse>, Status> {
        not_needed()
    }
    async fn auth_reject(
        &self,
        _: Request<AuthRejectRequest>,
    ) -> Result<Response<AuthRejectResponse>, Status> {
        not_needed()
    }
    async fn create_api_key(
        &self,
        _: Request<CreateApiKeyRequest>,
    ) -> Result<Response<CreateApiKeyResponse>, Status> {
        not_needed()
    }
    async fn expire_api_key(
        &self,
        _: Request<ExpireApiKeyRequest>,
    ) -> Result<Response<ExpireApiKeyResponse>, Status> {
        not_needed()
    }
    async fn list_api_keys(
        &self,
        _: Request<ListApiKeysRequest>,
    ) -> Result<Response<ListApiKeysResponse>, Status> {
        not_needed()
    }
    async fn delete_api_key(
        &self,
        _: Request<DeleteApiKeyRequest>,
    ) -> Result<Response<DeleteApiKeyResponse>, Status> {
        not_needed()
    }
    async fn get_policy(
        &self,
        _: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        if self.policy_not_found {
            // Real headscale wraps ErrPolicyNotFound in fmt.Errorf which Go's
            // gRPC framework maps to codes.Unknown, not codes.NotFound.
            return Err(Status::unknown(
                "loading ACL from database: acl policy not found",
            ));
        }
        let policy = self.policy.lock().unwrap().clone();
        Ok(Response::new(GetPolicyResponse {
            policy,
            ..Default::default()
        }))
    }
    async fn set_policy(
        &self,
        req: Request<SetPolicyRequest>,
    ) -> Result<Response<SetPolicyResponse>, Status> {
        if self.set_policy_fails.load(Ordering::Relaxed) {
            return Err(Status::internal("set_policy deliberately fails"));
        }
        let policy = req.into_inner().policy;
        *self.policy.lock().unwrap() = policy.clone();
        Ok(Response::new(SetPolicyResponse {
            policy,
            ..Default::default()
        }))
    }
    async fn check_policy(
        &self,
        _: Request<CheckPolicyRequest>,
    ) -> Result<Response<CheckPolicyResponse>, Status> {
        not_needed()
    }
    async fn health(&self, _: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        not_needed()
    }
}

/// A test connector that returns clones of a single pre-built gRPC client.
///
/// `spawn_fake_server` consumes the server into a duplex channel; this wrapper
/// lets the controller call `connect` multiple times while all calls share the
/// same in-process fake.
pub struct FakeConnector(Channel);

impl FakeConnector {
    pub async fn new(server: FakeHeadscaleServer) -> Self {
        Self(spawn_fake_channel(server).await)
    }
}

#[async_trait::async_trait]
impl HeadscaleConnector for FakeConnector {
    async fn connect(
        &self,
        _endpoint: &str,
        _api_key: &str,
    ) -> Result<AuthenticatedClient, TransportError> {
        Ok(HeadscaleServiceClient::with_interceptor(
            self.0.clone(),
            AuthInterceptor::bearer("fake"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── tests ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_empty_then_create_then_list_again() {
        let server = FakeHeadscaleServer::default();
        let mut conn = spawn_fake_server(server).await;

        let resp = conn.list_users(ListUsersRequest::default()).await.unwrap();
        assert!(resp.into_inner().users.is_empty());

        let created = conn
            .create_user(CreateUserRequest {
                name: "alice".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .user
            .unwrap();
        assert_eq!(created.name, "alice");
        assert_ne!(created.id, 0);

        let resp = conn.list_users(ListUsersRequest::default()).await.unwrap();
        let users = resp.into_inner().users;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].name, "alice");
    }
}
