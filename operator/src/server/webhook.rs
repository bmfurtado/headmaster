use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::post;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use k8s_ext::{
    ConfigMapExt, ConfigMapVolumeSourceExt, ContainerExt, JobExt, PodSpecExt, PodTemplateSpecExt,
    VolumeExt, VolumeMountExt,
};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, Pod, PodSecurityContext, PodSpec, PodTemplateSpec,
    SeccompProfile, Volume, VolumeMount,
};
use kube::api::{Api, DeleteParams, ListParams, LogParams, PostParams};
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use kube::core::dynamic::DynamicObject;
use kube::runtime::wait::await_condition;

use crate::context::Context;
use crate::controllers::headscale_instance::{
    build_config, check_reserved_keys, policy_has_groups_with_members,
};
use crate::labels;
use crate::types::HeadscaleInstance;

const PORT: u16 = 9443;

/// Loads TLS certificate and key from `tls_dir/{tls.crt,tls.key}`.
/// Call this in `main()` before spawning so a missing cert fails the process
/// immediately rather than silently disabling admission control.
pub async fn load_tls_config(tls_dir: &Path) -> Result<RustlsConfig, std::io::Error> {
    RustlsConfig::from_pem_file(tls_dir.join("tls.crt"), tls_dir.join("tls.key")).await
}

pub async fn serve(
    ctx: Arc<Context>,
    tls_config: RustlsConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/validate", post(validate_handler))
        .with_state(ctx);

    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
    });

    tracing::info!("webhook server listening on 0.0.0.0:{PORT}");
    axum_server::bind_rustls(SocketAddr::from(([0, 0, 0, 0], PORT)), tls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn validate_handler(
    State(ctx): State<Arc<Context>>,
    Json(review): Json<AdmissionReview<HeadscaleInstance>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let request: AdmissionRequest<HeadscaleInstance> = match review.try_into() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("invalid AdmissionReview: {e}");
            // Must return a valid AdmissionReview JSON — a bare HTTP error causes the
            // API server to apply failurePolicy: Fail and block all HeadscaleInstance
            // mutations. AdmissionResponse::invalid handles the no-request-uid case.
            return Json(
                AdmissionResponse::invalid(format!("malformed admission request: {e}"))
                    .into_review(),
            );
        }
    };

    let response = validate(&ctx, request).await;
    Json(response.into_review())
}

#[tracing::instrument(skip_all, fields(uid = %request.uid, name = %request.name))]
async fn validate(
    ctx: &Context,
    request: AdmissionRequest<HeadscaleInstance>,
) -> AdmissionResponse {
    let spec = match request.object.as_ref().map(|o| &o.spec) {
        Some(spec) => spec,
        None => return AdmissionResponse::from(&request),
    };

    // External instances have no operator-rendered config to test and no
    // operator-owned policy/SCIM: only the connection details are ours.
    if spec.external.is_some() {
        if spec.policy.is_some() || spec.scim.is_some() || !spec.extra_config.is_empty() {
            return AdmissionResponse::from(&request).deny(
                "spec.external is mutually exclusive with spec.policy, spec.scim, and \
                 spec.extraConfig; the external headscale's configuration and policy \
                 are managed outside the operator",
            );
        }
        return AdmissionResponse::from(&request);
    }

    if spec.scim.is_some() && policy_has_groups_with_members(spec.policy.as_ref()) {
        return AdmissionResponse::from(&request).deny(
            "spec.policy.inline contains groups with members while spec.scim is set; \
             SCIM owns the groups section — remove member entries from 'groups' in spec.policy.inline",
        );
    }

    if let Err(msg) = check_reserved_keys(&spec.extra_config) {
        return AdmissionResponse::from(&request).deny(msg);
    }

    let config_yaml = match build_config(
        &spec.server_url,
        &spec.dns_base_domain,
        spec.extra_config.clone(),
    ) {
        Ok(c) => c,
        Err(e) => {
            return AdmissionResponse::from(&request)
                .deny(format!("failed to generate config: {e}"));
        }
    };

    tracing::debug!("validating HeadscaleInstance config");

    match run_configtest(ctx, &config_yaml, &request.name, &request.uid).await {
        Ok(()) => {
            tracing::debug!("HeadscaleInstance config valid");
            AdmissionResponse::from(&request)
        }
        Err(msg) => {
            tracing::debug!(error = msg, "HeadscaleInstance config invalid");
            AdmissionResponse::from(&request).deny(msg)
        }
    }
}

// ── HeadscaleInstance configtest ──────────────────────────────────────────────

async fn run_configtest(
    ctx: &Context,
    config_yaml: &str,
    instance_name: &str,
    uid: &str,
) -> Result<(), String> {
    // "configtest-" (11) + instance_name + "-" (1) + UUID (36) must fit in 63 chars,
    // leaving 15 chars for instance_name. floor_char_boundary avoids a panic when a
    // multi-byte char straddles position 15.
    let truncated = &instance_name[..instance_name.floor_char_boundary(15)];
    let name = format!("configtest-{truncated}-{uid}");

    let cm_api: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), &ctx.operator_namespace);
    let job_api: Api<Job> = Api::namespaced(ctx.client.clone(), &ctx.operator_namespace);

    // ResourceBuilder's .namespace()/.labels()/.owner() share names with kube::ResourceExt
    // getters; scoped locally to avoid the module-level collision.
    use k8s_ext::ResourceBuilder;
    let cm = ConfigMap::new(&name)
        .namespace(&ctx.operator_namespace)
        .labels(configtest_labels(instance_name))
        .data([("config.yaml", config_yaml)]);
    cm_api
        .create(&PostParams::default(), &cm)
        .await
        .map_err(|e| format!("failed to create validation ConfigMap: {e}"))?;

    let job = configtest_job(
        &ctx.operator_namespace,
        &ctx.headscale_image,
        &name,
        instance_name,
    );
    if let Err(e) = job_api.create(&PostParams::default(), &job).await {
        let _ = cm_api.delete(&name, &DeleteParams::default()).await;
        return Err(format!("failed to create validation Job: {e}"));
    }

    let is_done = |job: Option<&Job>| -> bool {
        let status = job.and_then(|j| j.status.as_ref());
        status.and_then(|s| s.succeeded).unwrap_or(0) > 0
            || status.and_then(|s| s.failed).unwrap_or(0) > 0
    };
    let watch_result = tokio::time::timeout(
        Duration::from_secs(25),
        await_condition(job_api.clone(), &name, is_done),
    )
    .await;
    let result = match watch_result {
        Err(_) => Err("config validation timed out".to_string()),
        Ok(Err(e)) => Err(format!("configtest watch error: {e}")),
        Ok(Ok(None)) => Err("configtest job disappeared".to_string()),
        Ok(Ok(Some(job))) => {
            if job.status.as_ref().and_then(|s| s.succeeded).unwrap_or(0) > 0 {
                Ok(())
            } else {
                Err(fetch_pod_logs(ctx, &name)
                    .await
                    .unwrap_or_else(|_| "headscale configtest failed".to_string()))
            }
        }
    };

    let _ = cm_api.delete(&name, &DeleteParams::default()).await;
    let _ = job_api.delete(&name, &DeleteParams::background()).await;
    result
}

fn configtest_labels(instance_name: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (labels::APP_NAME.into(), "headscale".into()),
        (labels::APP_INSTANCE.into(), instance_name.into()),
        (
            labels::APP_MANAGED_BY.into(),
            labels::MANAGED_BY_VALUE.into(),
        ),
    ])
}

fn configtest_job(namespace: &str, image: &str, name: &str, instance_name: &str) -> Job {
    // ResourceBuilder's .namespace()/.labels()/.owner() share names with kube::ResourceExt
    // getters; scoped locally to avoid the module-level collision.
    use k8s_ext::ResourceBuilder;
    let config_volume = Volume::configmap("config", ConfigMapVolumeSource::new(name));
    let container = Container::new("configtest")
        .image(image)
        .args(["--config", "/etc/headscale/config.yaml", "configtest"])
        .allow_privilege_escalation(false)
        .read_only_root_filesystem(true)
        .drop_capabilities(["ALL"])
        .volume_mounts([VolumeMount::new("/etc/headscale", &config_volume).read_only()]);
    let pod_spec = PodSpec {
        security_context: Some(PodSecurityContext {
            run_as_non_root: Some(true),
            run_as_user: Some(65532),
            run_as_group: Some(65532),
            seccomp_profile: Some(SeccompProfile {
                type_: "RuntimeDefault".into(),
                localhost_profile: None,
            }),
            ..Default::default()
        }),
        ..PodSpec::container(container)
            .restart_policy("Never")
            .volumes([config_volume])
    };
    Job::new(name)
        .namespace(namespace)
        .labels(configtest_labels(instance_name))
        .backoff_limit(0)
        .ttl_seconds_after_finished(60)
        .template(PodTemplateSpec::new().pod_spec(pod_spec))
}

async fn fetch_pod_logs(ctx: &Context, job_name: &str) -> Result<String, String> {
    let pod_api: Api<Pod> = Api::namespaced(ctx.client.clone(), &ctx.operator_namespace);

    let pods = pod_api
        .list(&ListParams::default().labels(&format!("job-name={job_name}")))
        .await
        .map_err(|e| e.to_string())?;
    let pod = pods
        .items
        .into_iter()
        .next()
        .ok_or_else(|| "no pod found for job".to_string())?;
    let pod_name = pod
        .metadata
        .name
        .ok_or_else(|| "pod has no name".to_string())?;

    // Wait for the container to reach Terminated state so logs are fully flushed.
    let is_terminated = |pod: Option<&Pod>| {
        pod.and_then(|p| p.status.as_ref())
            .and_then(|s| s.container_statuses.as_ref())
            .and_then(|cs| cs.first())
            .and_then(|c| c.state.as_ref())
            .and_then(|s| s.terminated.as_ref())
            .is_some()
    };
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        await_condition(pod_api.clone(), &pod_name, is_terminated),
    )
    .await;

    let logs = pod_api
        .logs(
            &pod_name,
            &LogParams {
                container: Some("configtest".to_string()),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    let trimmed = logs.trim().to_string();
    if trimmed.is_empty() {
        Err("logs unavailable".to_string())
    } else {
        Ok(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = "headmaster-system";
    const IMAGE: &str = "ghcr.io/juanfont/headscale:v0.29.0";
    const INSTANCE: &str = "my-instance";
    const UID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn configtest_name(instance_name: &str, uid: &str) -> String {
        let truncated = &instance_name[..instance_name.floor_char_boundary(15)];
        format!("configtest-{truncated}-{uid}")
    }

    #[test]
    fn configtest_name_never_exceeds_63_chars() {
        // 63-char Kubernetes DNS-label limit must hold for any instance name length.
        for len in [1, 15, 16, 32, 63] {
            let long_name = "a".repeat(len);
            let name = configtest_name(&long_name, UID);
            assert!(
                name.len() <= 63,
                "configtest name is {} chars for instance name of length {len}: {name:?}",
                name.len()
            );
        }
    }

    #[test]
    fn configtest_name_short_instance_is_unchanged() {
        // Names ≤15 chars must appear verbatim (no truncation).
        let name = configtest_name(INSTANCE, UID); // "my-instance" = 11 chars
        assert!(
            name.starts_with("configtest-my-instance-"),
            "prefix must be intact: {name}"
        );
    }

    #[test]
    fn configtest_job_name_includes_instance_and_uid() {
        let name = configtest_name(INSTANCE, UID);
        let job = configtest_job(NS, IMAGE, &name, INSTANCE);
        assert_eq!(job.metadata.name.as_deref(), Some(name.as_str()));
    }

    #[test]
    fn configtest_job_namespace_matches() {
        let name = format!("configtest-{INSTANCE}-{UID}");
        let job = configtest_job(NS, IMAGE, &name, INSTANCE);
        assert_eq!(job.metadata.namespace.as_deref(), Some(NS));
    }

    #[test]
    fn configtest_job_labels() {
        let name = format!("configtest-{INSTANCE}-{UID}");
        let job = configtest_job(NS, IMAGE, &name, INSTANCE);
        let got = job.metadata.labels.as_ref().expect("labels present");
        assert_eq!(
            got.get(labels::APP_NAME).map(String::as_str),
            Some("headscale")
        );
        assert_eq!(
            got.get(labels::APP_INSTANCE).map(String::as_str),
            Some(INSTANCE)
        );
        assert_eq!(
            got.get(labels::APP_MANAGED_BY).map(String::as_str),
            Some(labels::MANAGED_BY_VALUE)
        );
    }

    #[test]
    fn configtest_job_security_hardening() {
        let name = format!("configtest-{INSTANCE}-{UID}");
        let job = configtest_job(NS, IMAGE, &name, INSTANCE);
        let spec = job.spec.as_ref().unwrap();
        assert_eq!(spec.backoff_limit, Some(0));
        assert_eq!(spec.ttl_seconds_after_finished, Some(60));

        let pod_spec = spec.template.spec.as_ref().unwrap();
        assert_eq!(pod_spec.restart_policy.as_deref(), Some("Never"));
        let sec = pod_spec.security_context.as_ref().unwrap();
        assert_eq!(sec.run_as_non_root, Some(true));

        let container = &pod_spec.containers[0];
        assert_eq!(container.image.as_deref(), Some(IMAGE));
        let csec = container.security_context.as_ref().unwrap();
        assert_eq!(csec.allow_privilege_escalation, Some(false));
        assert_eq!(csec.read_only_root_filesystem, Some(true));
    }

    #[test]
    fn configtest_job_mounts_config_volume() {
        let name = format!("configtest-{INSTANCE}-{UID}");
        let job = configtest_job(NS, IMAGE, &name, INSTANCE);
        let pod_spec = job.spec.unwrap().template.spec.unwrap();
        let vol = pod_spec
            .volumes
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.name == "config")
            .expect("config volume");
        assert_eq!(vol.config_map.as_ref().unwrap().name.as_str(), name,);
        let mount = pod_spec.containers[0]
            .volume_mounts
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.name == "config")
            .expect("config mount");
        assert_eq!(mount.mount_path, "/etc/headscale");
        assert_eq!(mount.read_only, Some(true));
    }

    // ── run_configtest fault-injection tests ──────────────────────────────────

    use std::sync::Arc;

    use headscale_client::LiveConnector;
    use kube::runtime::events::Reporter;

    use crate::context::Context;
    use crate::test_support::FaultService;

    fn test_ctx(client: kube::Client) -> Context {
        Context {
            client,
            operator_namespace: NS.to_string(),
            headscale: Arc::new(LiveConnector),
            reporter: Reporter {
                controller: "test".to_string(),
                instance: None,
            },
            headscale_image: IMAGE.to_string(),
            proxy_image: "test".to_string(),
            operator_image: "test".to_string(),
            claim_default: true,
        }
    }

    fn cm_ok_job_fails(m: &http::Method, path: &str) -> (u16, Vec<u8>) {
        if *m == http::Method::POST && path.contains("/jobs") {
            (500, br#"{"code":500}"#.to_vec())
        } else if *m == http::Method::POST && path.contains("/configmaps") {
            // Return a minimal valid ConfigMap so kube can deserialise the response.
            let body = serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "test-cm", "namespace": NS, "resourceVersion": "1"}
            });
            (201, serde_json::to_vec(&body).unwrap())
        } else {
            // DELETE requests (cleanup) — return 404; the caller uses let _ = so this is fine.
            (404, br#"{"code":404}"#.to_vec())
        }
    }

    #[tokio::test]
    async fn run_configtest_deletes_cm_when_job_creation_fails() {
        let (k8s, calls) = FaultService::tracked(cm_ok_job_fails);
        let ctx = test_ctx(k8s);

        let result = run_configtest(&ctx, "log_level: info\n", INSTANCE, UID).await;

        assert!(
            result.is_err(),
            "job creation failure must be surfaced as an error"
        );

        let recorded = calls.lock().unwrap();
        let has_cm_post = recorded
            .iter()
            .any(|(m, p)| m == "POST" && p.contains("/configmaps"));
        let has_cm_delete = recorded
            .iter()
            .any(|(m, p)| m == "DELETE" && p.contains("/configmaps/"));
        let has_job_delete = recorded
            .iter()
            .any(|(m, p)| m == "DELETE" && p.contains("/jobs/"));

        assert!(has_cm_post, "ConfigMap must be created before the Job");
        assert!(
            has_cm_delete,
            "ConfigMap must be deleted when Job creation fails: {recorded:?}"
        );
        assert!(
            !has_job_delete,
            "Job DELETE must not be issued when Job creation failed: {recorded:?}"
        );
    }
}
