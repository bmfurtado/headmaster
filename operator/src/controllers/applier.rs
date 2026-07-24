//! SSA helpers for applying child Kubernetes resources. `ChildApplier` stamps
//! namespace, owner references, and standard `app.kubernetes.io` labels on
//! every resource before sending the SSA patch.

use std::collections::BTreeMap;

use k8s_openapi::NamespaceResourceScope;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{DeleteParams, Patch, PatchParams};
use kube::error::Status;
use kube::{Api, Client, Resource, ResourceExt};
use serde::Serialize;

use crate::context::Context;
use crate::labels;
use crate::types::HeadscaleInstance;

/// SSA helper for patching the parent object's status subresource.
pub(crate) struct Applier<'a> {
    pub client: &'a Client,
    pub ssa: PatchParams,
}

impl<'a> Applier<'a> {
    pub fn from_ctx(ctx: &'a Context) -> Self {
        Self {
            client: &ctx.client,
            ssa: PatchParams::apply(&crate::field_manager(&ctx.operator_namespace)).force(),
        }
    }

    pub async fn apply_status<T, S>(&self, obj: &T, status: &S) -> Result<(), kube::Error>
    where
        T: Resource<DynamicType = (), Scope = NamespaceResourceScope> + serde::de::DeserializeOwned,
        S: Serialize,
    {
        let ns = obj.namespace().ok_or_else(|| {
            kube::Error::Api(Box::new(
                Status::failure(
                    "object has no namespace; Applier only supports namespaced objects",
                    "MissingNamespace",
                )
                .with_code(400),
            ))
        })?;
        let patch = serde_json::json!({
            "apiVersion": T::api_version(&()).as_ref(),
            "kind": T::kind(&()).as_ref(),
            "metadata": { "name": obj.name_any(), "namespace": ns },
            "status": status,
        });
        Api::<T>::namespaced(self.client.clone(), &ns)
            .patch_status(&obj.name_any(), &self.ssa, &Patch::Apply(patch))
            .await?;
        Ok(())
    }
}

/// SSA helper for child resources. Stamps namespace, owner reference, and standard
/// labels (`app.kubernetes.io/name`, `instance`, `managed-by`) on every resource it
/// applies. `component` sets `app.kubernetes.io/name` (`headscale`, `scim`, etc.).
/// Extra labels from `spec.labels` are merged first; operator labels always win.
pub(crate) struct ChildApplier<'a> {
    pub(super) client: &'a Client,
    ssa: PatchParams,
    pub namespace: String,
    pub instance: String,
    owner_ref: OwnerReference,
    extra_labels: BTreeMap<String, String>,
}

impl<'a> ChildApplier<'a> {
    pub fn from_parent(ctx: &'a Context, parent: &HeadscaleInstance) -> Self {
        Self {
            client: &ctx.client,
            ssa: PatchParams::apply(&crate::field_manager(&ctx.operator_namespace)).force(),
            namespace: parent
                .namespace()
                .expect("reconciled object must be namespaced"),
            instance: parent.name_any(),
            owner_ref: parent
                .controller_owner_ref(&())
                .expect("reconciled object must have a UID"),
            extra_labels: parent.spec.labels.clone(),
        }
    }

    /// Constructs a `ChildApplier` for proxy resources owned by `owner`.
    ///
    /// Sets `APP_INSTANCE` to `proxy_base` so the WireGuard Service selector
    /// targets only this proxy's pods (not all proxies for the same instance).
    /// Parent coordinates and kind are included in `extra_labels` so each
    /// controller's state-Secret watcher can map secrets back to its own
    /// parent objects.
    pub fn for_proxy(
        ctx: &'a Context,
        namespace: &str,
        proxy_base: &str,
        owner: &HeadscaleInstance,
        parent_kind: &str,
        parent_name: &str,
        parent_ns: &str,
    ) -> Self {
        let mut extra_labels = owner.spec.labels.clone();
        extra_labels.insert(labels::PARENT_KIND.to_string(), parent_kind.to_string());
        extra_labels.insert(labels::INGRESS_NAME.to_string(), parent_name.to_string());
        extra_labels.insert(labels::INGRESS_NAMESPACE.to_string(), parent_ns.to_string());
        Self {
            client: &ctx.client,
            ssa: PatchParams::apply(&crate::field_manager(&ctx.operator_namespace)).force(),
            namespace: namespace.to_string(),
            instance: proxy_base.to_string(),
            owner_ref: owner
                .controller_owner_ref(&())
                .expect("HeadscaleInstance must have a UID"),
            extra_labels,
        }
    }

    /// Stable label subset safe for use as StatefulSet `match_labels` and Service
    /// `selector` — excludes user-supplied labels which are immutable after creation.
    pub fn selector_labels(&self, component: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            (labels::APP_NAME.to_string(), component.to_string()),
            (labels::APP_INSTANCE.to_string(), self.instance.clone()),
            (
                labels::APP_MANAGED_BY.to_string(),
                labels::MANAGED_BY_VALUE.to_string(),
            ),
        ])
    }

    /// SSA-patches `resource` after stamping namespace, owner reference, and labels.
    /// `component` becomes the `app.kubernetes.io/name` label value; the resource's
    /// own `metadata.name` determines the API object being patched.
    pub async fn apply<T>(&self, component: &str, mut resource: T) -> Result<(), kube::Error>
    where
        T: Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Serialize
            + serde::de::DeserializeOwned
            + Clone
            + std::fmt::Debug,
    {
        {
            let meta = resource.meta_mut();
            meta.namespace = Some(self.namespace.clone());
            meta.owner_references
                .get_or_insert_default()
                .push(self.owner_ref.clone());
            let lbs = meta.labels.get_or_insert_default();
            // Extra labels first; operator labels below always win.
            lbs.extend(self.extra_labels.clone());
            lbs.insert(labels::APP_NAME.to_string(), component.to_string());
            lbs.insert(labels::APP_INSTANCE.to_string(), self.instance.clone());
            lbs.insert(
                labels::APP_MANAGED_BY.to_string(),
                labels::MANAGED_BY_VALUE.to_string(),
            );
        }
        let name = resource.name_any();
        Api::<T>::namespaced(self.client.clone(), &self.namespace)
            .patch(&name, &self.ssa, &Patch::Apply(&resource))
            .await?;
        Ok(())
    }

    /// Like `apply`, but also stamps `match_labels` on the StatefulSet spec and merges
    /// selector labels into the pod template so pods satisfy the selector.
    pub async fn apply_statefulset(
        &self,
        component: &str,
        mut sts: StatefulSet,
    ) -> Result<(), kube::Error> {
        let selector = self.selector_labels(component);
        let spec = sts
            .spec
            .as_mut()
            .expect("apply_statefulset: StatefulSet must have a spec");
        spec.selector
            .match_labels
            .get_or_insert_default()
            .extend(selector.clone());
        spec.template
            .metadata
            .get_or_insert_default()
            .labels
            .get_or_insert_default()
            .extend(selector);
        self.apply(component, sts).await
    }

    /// Like `apply`, but also stamps `selector` on the Service spec so the caller
    /// doesn't need to compute or pass selector labels manually.
    pub async fn apply_service(
        &self,
        component: &str,
        mut svc: Service,
    ) -> Result<(), kube::Error> {
        let selector = self.selector_labels(component);
        let spec = svc
            .spec
            .as_mut()
            .expect("apply_service: Service must have a spec");
        spec.selector.get_or_insert_default().extend(selector);
        self.apply(component, svc).await
    }

    #[cfg(test)]
    pub(super) fn for_test(client: &'a Client, namespace: &str, instance: &str) -> Self {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
        Self {
            client,
            ssa: PatchParams::apply("headmaster-test").force(),
            namespace: namespace.to_string(),
            instance: instance.to_string(),
            owner_ref: OwnerReference {
                api_version: "headmaster.potatonode.github.io/v1alpha1".to_string(),
                kind: "HeadscaleInstance".to_string(),
                name: "test-instance".to_string(),
                uid: "00000000-0000-0000-0000-000000000001".to_string(),
                ..Default::default()
            },
            extra_labels: Default::default(),
        }
    }
}

/// Deletes `name` from `api`, treating a 404 (already gone) as success.
/// All other errors are returned for the caller to handle.
pub(crate) async fn delete_ignoring_404<K>(api: Api<K>, name: &str) -> Result<(), kube::Error>
where
    K: Resource + serde::de::DeserializeOwned + Clone + std::fmt::Debug,
{
    match api.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(ref e)) if e.code == 404 => Ok(()),
        Err(e) => Err(e),
    }
}
