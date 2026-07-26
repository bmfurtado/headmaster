use std::sync::Arc;
use std::time::Duration;

use headscale_client::fake::{FakeConnector, FakeHeadscaleServer};
use headscale_client::headscale::v1::{Node, User};
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::Event;
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Api;
use kube::api::{DeleteParams, ListParams, Patch, PatchParams, PostParams};
use operator::controllers::{headscale_instance, ingress};
use operator::types::{HeadscaleInstance, HeadscaleInstanceSpec, StorageSpec};

use super::support::{
    create_ready_instance, make_ctx, make_ingress, make_ingress_with_access,
    make_ingress_with_annotations, populate_state_secret,
};
use super::{client, unique_ns};

// ── tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ingress_creates_key_and_statefulset_and_registers() {
    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let fake_server = FakeHeadscaleServer::default();
    fake_server.state.lock().unwrap().users.push(User {
        id: 1,
        name: "my-ingress".to_string(),
        ..Default::default()
    });
    // The state secret below claims device_id 77; the node must exist in
    // headscale, or rotate_stale_auth_key treats the registration as lost
    // and wipes the proxy Secrets — device data included.
    fake_server.state.lock().unwrap().nodes.push(Node {
        id: 77,
        name: "my-ingress".to_string(),
        given_name: "my-ingress".to_string(),
        ip_addresses: vec!["100.64.0.5".to_string()],
        ..Default::default()
    });
    let keys = Arc::clone(&fake_server.state);
    let connector = Arc::new(FakeConnector::new(fake_server).await);

    create_ready_instance(&kube_client, &ns, "headscale").await;

    let ctx = make_ctx(&kube_client, &ns, connector);

    let handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress("my-ingress", &ns, "headscale"),
        )
        .await
        .expect("create Ingress");

    // Wait for the operator to pre-create the state Secret (in operator namespace = ns),
    // then simulate containerboot writing device_id and device_ips after registration.
    // Proxy resources are named {ingress_ns}-{ingress_name}, so the base is "{ns}-my-ingress".
    populate_state_secret(&kube_client, &ns, &ns, "my-ingress", "77", &["100.64.0.5"]).await;

    // Poll until the Ingress has a tailnet IP in its loadBalancer status.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let tailnet_ip = loop {
        let ing = ingress_api.get("my-ingress").await.expect("get Ingress");
        if let Some(ip) = ing
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
            .and_then(|i| i.first())
            .and_then(|e| e.ip.as_ref())
        {
            break ip.clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: Ingress my-ingress did not get a tailnet IP within 30s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    assert_eq!(tailnet_ip, "100.64.0.5");

    assert_eq!(
        keys.lock().unwrap().pre_auth_keys.len(),
        1,
        "exactly one pre-auth key should have been created"
    );

    Api::<StatefulSet>::namespaced(kube_client.clone(), &ns)
        .get(&ingress::proxy_sts_name(&ns, "my-ingress"))
        .await
        .expect("proxy StatefulSet must exist in operator namespace");

    handle.abort();
}

#[tokio::test]
async fn ingress_pending_when_headscale_instance_not_ready() {
    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let fake_server = FakeHeadscaleServer::default();
    let keys = Arc::clone(&fake_server.state);
    let connector = Arc::new(FakeConnector::new(fake_server).await);

    // Create HeadscaleInstance but do NOT patch its status — it stays not-Ready.
    Api::<HeadscaleInstance>::namespaced(kube_client.clone(), &ns)
        .create(
            &PostParams::default(),
            &HeadscaleInstance {
                metadata: ObjectMeta {
                    name: Some("headscale".to_string()),
                    namespace: Some(ns.clone()),
                    ..Default::default()
                },
                spec: HeadscaleInstanceSpec {
                    server_url: "https://headscale.example.com".to_string(),
                    dns_base_domain: "ts.example.com".to_string(),
                    storage: StorageSpec {
                        size: "1Gi".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                status: None,
            },
        )
        .await
        .expect("create HeadscaleInstance");

    let ctx = make_ctx(&kube_client, &ns, connector);

    let handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress("my-ingress", &ns, "headscale"),
        )
        .await
        .expect("create Ingress");

    // Poll until a "Pending" warning event appears on the Ingress.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let events = Api::<Event>::namespaced(kube_client.clone(), &ns)
            .list(&ListParams::default())
            .await
            .expect("list events");
        let has_pending = events.items.iter().any(|e| {
            e.reason.as_deref() == Some("Pending")
                && e.involved_object.name.as_deref() == Some("my-ingress")
        });
        if has_pending {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: Ingress my-ingress did not emit a Pending event within 10s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    assert!(
        keys.lock().unwrap().pre_auth_keys.is_empty(),
        "no pre-auth keys should be created while HeadscaleInstance is not Ready"
    );

    handle.abort();
}

#[tokio::test]
async fn ingress_cleanup_deletes_node_from_headscale() {
    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let fake_server = FakeHeadscaleServer::default();
    fake_server.state.lock().unwrap().users.push(User {
        id: 1,
        name: "cleanup-ingress".to_string(),
        ..Default::default()
    });
    fake_server.state.lock().unwrap().nodes.push(Node {
        id: 88,
        name: "cleanup-ingress".to_string(),
        given_name: "cleanup-ingress".to_string(),
        ip_addresses: vec!["100.64.0.8".to_string()],
        ..Default::default()
    });
    let nodes = Arc::clone(&fake_server.state);
    let connector = Arc::new(FakeConnector::new(fake_server).await);

    create_ready_instance(&kube_client, &ns, "headscale").await;

    let ctx = make_ctx(&kube_client, &ns, connector);

    let handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress("cleanup-ingress", &ns, "headscale"),
        )
        .await
        .expect("create Ingress");

    // Simulate containerboot: write device_id=88 so cleanup can delete from headscale.
    populate_state_secret(
        &kube_client,
        &ns,
        &ns,
        "cleanup-ingress",
        "88",
        &["100.64.0.8"],
    )
    .await;

    // Wait until the Ingress has been programmed (IP populated).
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let ing = ingress_api
            .get("cleanup-ingress")
            .await
            .expect("get Ingress");
        let has_ip = ing
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
            .is_some_and(|i| !i.is_empty());
        if has_ip {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: Ingress cleanup-ingress did not become programmed"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    ingress_api
        .delete("cleanup-ingress", &DeleteParams::default())
        .await
        .expect("delete Ingress");

    // Wait until the CR is fully gone (finalizer must run first).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match ingress_api.get("cleanup-ingress").await {
            Ok(_) => {}
            Err(kube::Error::Api(e)) if e.code == 404 => break,
            Err(e) => panic!("unexpected error waiting for Ingress deletion: {e}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: Ingress cleanup-ingress was not deleted within 10s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    assert!(
        nodes.lock().unwrap().nodes.is_empty(),
        "node must be deleted from headscale after Ingress CR deletion"
    );

    handle.abort();
}

#[tokio::test]
async fn ingress_orphaned_when_namespace_excluded() {
    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let connector = Arc::new(FakeConnector::new(FakeHeadscaleServer::default()).await);
    let ctx = make_ctx(&kube_client, &ns, connector);

    let hi_handle = tokio::spawn(headscale_instance::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));
    let ingress_handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    // Create a HeadscaleInstance that only watches "other-namespace", excluding our test namespace.
    let hi_api: Api<HeadscaleInstance> = Api::namespaced(kube_client.clone(), &ns);
    hi_api
        .create(
            &PostParams::default(),
            &HeadscaleInstance {
                metadata: ObjectMeta {
                    name: Some("hs".to_string()),
                    namespace: Some(ns.clone()),
                    ..Default::default()
                },
                spec: HeadscaleInstanceSpec {
                    server_url: "https://headscale.example.com".to_string(),
                    dns_base_domain: "ts.example.com".to_string(),
                    storage: StorageSpec {
                        size: "1Gi".to_string(),
                        ..Default::default()
                    },
                    watched_namespaces: vec!["other-namespace".to_string()],
                    ..Default::default()
                },
                status: None,
            },
        )
        .await
        .expect("create HeadscaleInstance");

    // Wait for the HI controller to add its finalizer.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let hi = hi_api.get("hs").await.expect("get HeadscaleInstance");
        if hi
            .metadata
            .finalizers
            .as_ref()
            .is_some_and(|f| !f.is_empty())
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for HeadscaleInstance finalizer"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress("test-ingress", &ns, "hs"),
        )
        .await
        .expect("create Ingress");

    // Give the ingress controller time to reconcile. It must NOT adopt this
    // Ingress: the namespace is excluded from watchedNamespaces, so no finalizer
    // should be stamped and no resources provisioned.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let ing = ingress_api.get("test-ingress").await.expect("get Ingress");
    assert!(
        ing.metadata
            .finalizers
            .as_ref()
            .is_none_or(|f| f.is_empty()),
        "operator must not stamp its finalizer on an Ingress from an excluded namespace"
    );

    // No proxy StatefulSet should exist — the namespace is excluded.
    let sts_api = Api::<StatefulSet>::namespaced(kube_client.clone(), &ns);
    assert!(
        sts_api
            .get(&ingress::proxy_sts_name(&ns, "test-ingress"))
            .await
            .is_err(),
        "proxy StatefulSet must not be created for an excluded namespace"
    );

    // Ingress must still exist — the controller must not delete it.
    ingress_api
        .get("test-ingress")
        .await
        .expect("Ingress must still exist when its namespace is excluded");

    hi_handle.abort();
    ingress_handle.abort();
}

#[tokio::test]
async fn ingress_namespace_exclusion_cleans_up_proxy_resources() {
    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let fake_server = FakeHeadscaleServer::default();
    fake_server.state.lock().unwrap().users.push(User {
        id: 1,
        name: "exc-ingress".to_string(),
        ..Default::default()
    });
    let connector = Arc::new(FakeConnector::new(fake_server).await);

    let hi_api = create_ready_instance(&kube_client, &ns, "headscale").await;
    let ctx = make_ctx(&kube_client, &ns, connector);

    let handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress("exc-ingress", &ns, "headscale"),
        )
        .await
        .expect("create Ingress");

    // Wait until the operator has created the proxy StatefulSet.
    let proxy_name = ingress::proxy_sts_name(&ns, "exc-ingress");
    let sts_api = Api::<StatefulSet>::namespaced(kube_client.clone(), &ns);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if sts_api.get(&proxy_name).await.is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: proxy StatefulSet {proxy_name} was not created within 30s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Exclude the test namespace by adding it to watchedNamespaces (which acts as an allowlist).
    hi_api
        .patch(
            "headscale",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "spec": { "watchedNamespaces": ["other-namespace"] }
            })),
        )
        .await
        .expect("patch HeadscaleInstance watchedNamespaces");

    // Wait for the proxy StatefulSet to be cleaned up.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        match sts_api.get(&proxy_name).await {
            Err(kube::Error::Api(e)) if e.code == 404 => break,
            Ok(_) => {}
            Err(e) => panic!("unexpected error polling for StatefulSet deletion: {e}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: proxy StatefulSet {proxy_name} was not cleaned up after namespace exclusion"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    handle.abort();
}

#[tokio::test]
async fn ingress_tags_only_creates_key_and_statefulset() {
    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let fake_server = FakeHeadscaleServer::default();
    // No users pre-populated — the tags-only path must not look up a user.
    let keys = Arc::clone(&fake_server.state);
    let connector = Arc::new(FakeConnector::new(fake_server).await);

    create_ready_instance(&kube_client, &ns, "headscale").await;
    let ctx = make_ctx(&kube_client, &ns, connector);

    let handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress_with_annotations("tags-ingress", &ns, "headscale", None, &["tag:server"]),
        )
        .await
        .expect("create tags-only Ingress");

    // Wait for the proxy StatefulSet to be created.
    let proxy_name = ingress::proxy_sts_name(&ns, "tags-ingress");
    let sts_api = Api::<StatefulSet>::namespaced(kube_client.clone(), &ns);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if sts_api.get(&proxy_name).await.is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: proxy StatefulSet {proxy_name} was not created within 30s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let created_keys_guard = keys.lock().unwrap();
    let created_keys = &created_keys_guard.pre_auth_keys;
    assert_eq!(
        created_keys.len(),
        1,
        "exactly one pre-auth key must be created"
    );
    let key = &created_keys[0];
    assert_eq!(
        key.acl_tags,
        vec!["tag:server"],
        "key must carry the requested tags"
    );
    assert!(
        key.user.is_none() || key.user.as_ref().map(|u| u.id) == Some(0),
        "tags-only key must not be associated with a named user"
    );

    handle.abort();
}

#[tokio::test]
async fn ingress_user_not_found_emits_warning_and_skips_key() {
    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let fake_server = FakeHeadscaleServer::default();
    // "ghost-user" is intentionally absent from the fake server.
    let keys = Arc::clone(&fake_server.state);
    let connector = Arc::new(FakeConnector::new(fake_server).await);

    create_ready_instance(&kube_client, &ns, "headscale").await;
    let ctx = make_ctx(&kube_client, &ns, connector);

    let handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress_with_annotations(
                "ghost-ingress",
                &ns,
                "headscale",
                Some("ghost-user"),
                &[],
            ),
        )
        .await
        .expect("create Ingress with missing user");

    // Wait for a UserNotFound warning event on the Ingress.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let events = Api::<Event>::namespaced(kube_client.clone(), &ns)
            .list(&ListParams::default())
            .await
            .expect("list events");
        let has_warning = events.items.iter().any(|e| {
            e.reason.as_deref() == Some("UserNotFound")
                && e.involved_object.name.as_deref() == Some("ghost-ingress")
        });
        if has_warning {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: UserNotFound event was not published on ghost-ingress within 10s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    assert!(
        keys.lock().unwrap().pre_auth_keys.is_empty(),
        "no pre-auth key must be created when the headscale user does not exist"
    );
    assert!(
        Api::<StatefulSet>::namespaced(kube_client.clone(), &ns)
            .get(&ingress::proxy_sts_name(&ns, "ghost-ingress"))
            .await
            .is_err(),
        "no proxy StatefulSet must be created when the headscale user does not exist"
    );

    handle.abort();
}

#[tokio::test]
async fn ingress_creates_key_with_user_and_tags() {
    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let fake_server = FakeHeadscaleServer::default();
    fake_server.state.lock().unwrap().users.push(User {
        id: 1,
        name: "svc-account".to_string(),
        ..Default::default()
    });
    let keys = Arc::clone(&fake_server.state);
    let connector = Arc::new(FakeConnector::new(fake_server).await);

    create_ready_instance(&kube_client, &ns, "headscale").await;
    let ctx = make_ctx(&kube_client, &ns, connector);

    let handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress_with_annotations(
                "tagged-ingress",
                &ns,
                "headscale",
                Some("svc-account"),
                &["tag:server"],
            ),
        )
        .await
        .expect("create Ingress with user and tags");

    // Wait for the proxy StatefulSet to be created.
    let proxy_name = ingress::proxy_sts_name(&ns, "tagged-ingress");
    let sts_api = Api::<StatefulSet>::namespaced(kube_client.clone(), &ns);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if sts_api.get(&proxy_name).await.is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: proxy StatefulSet {proxy_name} was not created within 30s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let created_keys_guard = keys.lock().unwrap();
    let created_keys = &created_keys_guard.pre_auth_keys;
    assert_eq!(
        created_keys.len(),
        1,
        "exactly one pre-auth key must be created"
    );
    let key = &created_keys[0];
    assert_eq!(
        key.acl_tags,
        vec!["tag:server"],
        "key must carry the requested tags"
    );
    assert_eq!(
        key.user.as_ref().map(|u| u.id),
        Some(1),
        "key must be associated with the correct user"
    );

    handle.abort();
}

#[tokio::test]
async fn ingress_namespace_exclusion_deregisters_node() {
    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let fake_server = FakeHeadscaleServer::default();
    fake_server.state.lock().unwrap().users.push(User {
        id: 1,
        name: "exc-node-ingress".to_string(),
        ..Default::default()
    });
    fake_server.state.lock().unwrap().nodes.push(Node {
        id: 77,
        name: "exc-node-ingress".to_string(),
        given_name: "exc-node-ingress".to_string(),
        ip_addresses: vec!["100.64.0.77".to_string()],
        ..Default::default()
    });
    let nodes = Arc::clone(&fake_server.state);
    let connector = Arc::new(FakeConnector::new(fake_server).await);

    let hi_api = create_ready_instance(&kube_client, &ns, "headscale").await;
    let ctx = make_ctx(&kube_client, &ns, connector);

    let handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress("exc-node-ingress", &ns, "headscale"),
        )
        .await
        .expect("create Ingress");

    // Simulate containerboot writing device_id=77 after the proxy registers.
    populate_state_secret(
        &kube_client,
        &ns,
        &ns,
        "exc-node-ingress",
        "77",
        &["100.64.0.77"],
    )
    .await;

    // Wait until the Ingress has been programmed (confirms apply() completed with device info).
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let ing = ingress_api
            .get("exc-node-ingress")
            .await
            .expect("get Ingress");
        let has_ip = ing
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
            .is_some_and(|i| !i.is_empty());
        if has_ip {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: Ingress exc-node-ingress did not get a tailnet IP within 30s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Exclude the test namespace.
    hi_api
        .patch(
            "headscale",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "spec": { "watchedNamespaces": ["other-namespace"] }
            })),
        )
        .await
        .expect("patch HeadscaleInstance watchedNamespaces");

    // Wait for the headscale node to be deregistered.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if nodes.lock().unwrap().nodes.is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: headscale node was not deregistered after namespace exclusion"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Proxy StatefulSet must also be gone.
    let proxy_name = ingress::proxy_sts_name(&ns, "exc-node-ingress");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match Api::<StatefulSet>::namespaced(kube_client.clone(), &ns)
            .get(&proxy_name)
            .await
        {
            Err(kube::Error::Api(e)) if e.code == 404 => break,
            Ok(_) => {}
            Err(e) => panic!("unexpected error polling for StatefulSet deletion: {e}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: proxy StatefulSet {proxy_name} was not cleaned up after namespace exclusion"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    handle.abort();
}

/// Verifies that an Ingress with a non-empty `access` annotation causes the
/// operator to include the derived auto-tag (`tag:hm-<ns>-<name>`) in the
/// pre-auth key's `acl_tags` alongside any `managed-key-tags`.
#[tokio::test]
async fn ingress_access_grant_appends_auto_tag_to_acl_tags() {
    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let fake_server = FakeHeadscaleServer::default();
    fake_server
        .state
        .lock()
        .unwrap()
        .users
        .push(headscale_client::headscale::v1::User {
            id: 1,
            name: "alice".to_string(),
            ..Default::default()
        });
    let state = Arc::clone(&fake_server.state);
    let connector = Arc::new(FakeConnector::new(fake_server).await);

    create_ready_instance(&kube_client, &ns, "headscale").await;
    let ctx = make_ctx(&kube_client, &ns, connector);

    let handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress_with_access(
                "grant-ingress",
                &ns,
                "headscale",
                "alice",
                serde_json::json!([{"from": ["tag:server"]}]),
            ),
        )
        .await
        .expect("create access-grant Ingress");

    let proxy_name = ingress::proxy_sts_name(&ns, "grant-ingress");
    let sts_api = Api::<StatefulSet>::namespaced(kube_client.clone(), &ns);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if sts_api.get(&proxy_name).await.is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: proxy StatefulSet {proxy_name} was not created"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let keys = state.lock().unwrap().pre_auth_keys.clone();
    assert_eq!(keys.len(), 1);
    let expected_auto_tag = ingress::ingress_auto_tag(&ns, "grant-ingress");
    assert!(
        keys[0].acl_tags.contains(&expected_auto_tag),
        "auto-tag must be in acl_tags when access is set; got: {:?}",
        keys[0].acl_tags
    );

    handle.abort();
}

/// Regression: an Ingress without `access` must NOT have the auto-tag added to
/// its pre-auth key's `acl_tags`.
#[tokio::test]
async fn ingress_without_access_has_no_auto_tag() {
    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let fake_server = FakeHeadscaleServer::default();
    let state = Arc::clone(&fake_server.state);
    let connector = Arc::new(FakeConnector::new(fake_server).await);

    create_ready_instance(&kube_client, &ns, "headscale").await;
    let ctx = make_ctx(&kube_client, &ns, connector);

    let handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress_with_annotations(
                "no-access-ingress",
                &ns,
                "headscale",
                None,
                &["tag:server"],
            ),
        )
        .await
        .expect("create no-access Ingress");

    let proxy_name = ingress::proxy_sts_name(&ns, "no-access-ingress");
    let sts_api = Api::<StatefulSet>::namespaced(kube_client.clone(), &ns);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if sts_api.get(&proxy_name).await.is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: proxy StatefulSet {proxy_name} was not created"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let keys = state.lock().unwrap().pre_auth_keys.clone();
    assert_eq!(keys.len(), 1);
    assert!(
        !keys[0].acl_tags.iter().any(|t| t.starts_with("tag:hm-")),
        "no auto-tag must be added when access is not set; got: {:?}",
        keys[0].acl_tags
    );
    assert_eq!(
        keys[0].acl_tags,
        vec!["tag:server"],
        "acl_tags must be exactly the managed-key-tags when access is absent"
    );

    handle.abort();
}

/// Regression: adding an `access` grant to an already-provisioned Ingress must
/// update the headscale node's ACL tags via set_tags. Before this fix,
/// ensure_auth_key returned early when the config secret existed, and no
/// set_tags call was ever made, leaving the node without the auto-tag.
#[tokio::test]
async fn adding_access_to_existing_ingress_updates_node_tags() {
    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let fake_server = FakeHeadscaleServer::default();
    fake_server
        .state
        .lock()
        .unwrap()
        .users
        .push(headscale_client::headscale::v1::User {
            id: 1,
            name: "my-ingress".to_string(),
            ..Default::default()
        });
    // The state secret below claims device_id 42; the node must exist in
    // headscale, or rotate_stale_auth_key treats the registration as lost
    // and wipes the proxy Secrets before set_tags ever runs.
    fake_server.state.lock().unwrap().nodes.push(Node {
        id: 42,
        name: "my-ingress".to_string(),
        given_name: "my-ingress".to_string(),
        ip_addresses: vec!["100.64.0.5".to_string()],
        ..Default::default()
    });
    let state = Arc::clone(&fake_server.state);
    let connector = Arc::new(FakeConnector::new(fake_server).await);

    create_ready_instance(&kube_client, &ns, "headscale").await;
    let ctx = make_ctx(&kube_client, &ns, connector);

    let handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    // Create the Ingress without any access grants.
    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress("my-ingress", &ns, "headscale"),
        )
        .await
        .expect("create Ingress");

    // Wait for the proxy StatefulSet to appear (operator has provisioned resources).
    let proxy_name = ingress::proxy_sts_name(&ns, "my-ingress");
    let sts_api = Api::<StatefulSet>::namespaced(kube_client.clone(), &ns);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if sts_api.get(&proxy_name).await.is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for StatefulSet"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Simulate the proxy registering with headscale (device_id = 42). No
    // set_tags call is expected yet: this Ingress has no tags and no access
    // grants, and the operator skips SetTags for tag-less proxies (headscale
    // rejects an empty tag list). The reconcile triggered by the annotation
    // patch below reads this state secret, so no extra synchronisation is
    // needed here.
    populate_state_secret(&kube_client, &ns, &ns, "my-ingress", "42", &["100.64.0.5"]).await;

    // Now add an access grant — simulates the user patching the Ingress after
    // the proxy was already running.
    let new_config = serde_json::json!({
        "headscale-ref": "headscale",
        "user": "my-ingress",
        "access": [{"from": ["tag:server"]}],
    });
    ingress_api
        .patch(
            "my-ingress",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "metadata": {
                    "annotations": {
                        "headmaster.potatonode.github.io/config": new_config.to_string()
                    }
                }
            })),
        )
        .await
        .expect("patch Ingress to add access grant");

    let expected_auto_tag = ingress::ingress_auto_tag(&ns, "my-ingress");

    // Wait for set_tags to be called with the auto-tag on node 42.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let tags = state
            .lock()
            .unwrap()
            .node_tags
            .get(&42)
            .cloned()
            .unwrap_or_default();
        if tags.contains(&expected_auto_tag) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: set_tags was not called with auto-tag after access grant was added; \
             node 42 tags: {tags:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    handle.abort();
}

/// Verifies that an Ingress with `access.capabilities` causes the operator to
/// write `AcceptAppCaps` into the serve ConfigMap's handler entries, so the
/// proxy forwards the `Tailscale-App-Capabilities` header to the upstream app.
#[tokio::test]
async fn ingress_access_grant_serve_config_has_accept_app_caps() {
    use k8s_openapi::api::core::v1::ConfigMap;
    use operator::controllers::ingress::proxy_state_secret_name;

    let kube_client = client().await;
    let ns = unique_ns(&kube_client).await;

    let fake_server = FakeHeadscaleServer::default();
    fake_server
        .state
        .lock()
        .unwrap()
        .users
        .push(headscale_client::headscale::v1::User {
            id: 1,
            name: "alice".to_string(),
            ..Default::default()
        });
    let connector = Arc::new(FakeConnector::new(fake_server).await);

    create_ready_instance(&kube_client, &ns, "headscale").await;
    let ctx = make_ctx(&kube_client, &ns, connector);

    let handle = tokio::spawn(ingress::stream(
        Api::namespaced(kube_client.clone(), &ns),
        ctx.clone(),
        std::future::pending(),
    ));

    let ingress_api = Api::<Ingress>::namespaced(kube_client.clone(), &ns);
    ingress_api
        .create(
            &PostParams::default(),
            &make_ingress_with_access(
                "caps-ingress",
                &ns,
                "headscale",
                "alice",
                serde_json::json!([{
                    "from": ["tag:server"],
                    "capabilities": {
                        "example.com/cap/role": [{"role": "viewer"}]
                    }
                }]),
            ),
        )
        .await
        .expect("create capabilities Ingress");

    // Derive the serve ConfigMap name from the state secret name (same base).
    let serve_cm =
        proxy_state_secret_name(&ns, "caps-ingress").replacen("proxy-state-", "proxy-serve-", 1);

    let cm_api = Api::<ConfigMap>::namespaced(kube_client.clone(), &ns);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let serve_json = loop {
        if let Ok(cm) = cm_api.get(&serve_cm).await
            && let Some(data) = cm.data
            && let Some(json_str) = data.get("serve.json")
        {
            break serde_json::from_str::<serde_json::Value>(json_str)
                .expect("serve.json must be valid JSON");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: serve ConfigMap {serve_cm} was not created or populated"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    // serve.json: {"Web": {"<fqdn>:80": {"Handlers": {"<path>": {"AcceptAppCaps": [...]}}}}}
    let web = serve_json["Web"]
        .as_object()
        .expect("Web section must exist");
    let host_handlers = web
        .values()
        .next()
        .expect("Web must have at least one host");
    let handlers = host_handlers["Handlers"]
        .as_object()
        .expect("Handlers must be an object");
    assert!(
        !handlers.is_empty(),
        "serve config must have at least one handler"
    );

    for (path, handler) in handlers {
        let caps = handler["AcceptAppCaps"]
            .as_array()
            .unwrap_or_else(|| panic!("AcceptAppCaps must be in handler '{path}'"));
        assert!(
            caps.iter().any(|c| c == "example.com/cap/role"),
            "AcceptAppCaps must contain 'example.com/cap/role'; got: {caps:?}"
        );
    }

    handle.abort();
}
