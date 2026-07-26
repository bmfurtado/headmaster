use super::*;

pub trait ContainerExt: Sized {
    fn new(name: impl ToString) -> Self;
    fn args(self, args: impl IntoIterator<Item = impl ToString>) -> Self;
    fn command(self, command: impl IntoIterator<Item = impl ToString>) -> Self;
    fn env(self, env: impl IntoIterator<Item = impl ToEnvVar>) -> Self;
    fn env_from(self, env: impl IntoIterator<Item = impl ToEnvFrom>) -> Self;
    fn image(self, image: impl ToString) -> Self;
    fn ports(self, ports: impl IntoIterator<Item = corev1::ContainerPort>) -> Self;
    fn liveness_probe(self, probe: corev1::Probe) -> Self;
    fn readiness_probe(self, probe: corev1::Probe) -> Self;
    fn resource_limits(
        self,
        limits: impl IntoIterator<
            Item = (
                String,
                k8s_openapi::apimachinery::pkg::api::resource::Quantity,
            ),
        >,
    ) -> Self;
    fn resource_requests(
        self,
        requests: impl IntoIterator<
            Item = (
                String,
                k8s_openapi::apimachinery::pkg::api::resource::Quantity,
            ),
        >,
    ) -> Self;
    fn volume_mounts(self, volume_mounts: impl IntoIterator<Item = corev1::VolumeMount>) -> Self;
    fn security_context_mut(&mut self) -> &mut corev1::SecurityContext;

    fn allow_privilege_escalation(mut self, yes: bool) -> Self {
        self.security_context_mut().allow_privilege_escalation = Some(yes);
        self
    }

    fn read_only_root_filesystem(mut self, yes: bool) -> Self {
        self.security_context_mut().read_only_root_filesystem = Some(yes);
        self
    }

    fn drop_capabilities(mut self, capabilities: impl IntoIterator<Item = impl ToString>) -> Self {
        let drop = capabilities.into_iter().map(|item| item.to_string());
        self.security_context_mut()
            .capabilities
            .get_or_insert_default()
            .drop
            .get_or_insert_default()
            .extend(drop);
        self
    }

    fn add_capabilities(mut self, capabilities: impl IntoIterator<Item = impl ToString>) -> Self {
        let add = capabilities.into_iter().map(|item| item.to_string());
        self.security_context_mut()
            .capabilities
            .get_or_insert_default()
            .add
            .get_or_insert_default()
            .extend(add);
        self
    }

    fn privileged(mut self, yes: bool) -> Self {
        self.security_context_mut().privileged = Some(yes);
        self
    }
}

impl ContainerExt for corev1::Container {
    fn new(name: impl ToString) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn args(mut self, args: impl IntoIterator<Item = impl ToString>) -> Self {
        let args = args.into_iter().map(|item| item.to_string());
        self.args.get_or_insert_default().extend(args);
        self
    }

    fn command(self, command: impl IntoIterator<Item = impl ToString>) -> Self {
        let command = command.into_iter().map(|item| item.to_string()).collect();
        Self {
            command: Some(command),
            ..self
        }
    }

    fn env(mut self, env: impl IntoIterator<Item = impl ToEnvVar>) -> Self {
        let env = env.into_iter().map(|envvar| ToEnvVar::to_envvar(&envvar));
        self.env.get_or_insert_default().extend(env);
        self
    }

    fn env_from(mut self, env: impl IntoIterator<Item = impl ToEnvFrom>) -> Self {
        let env = env.into_iter().map(ToEnvFrom::to_envfrom);
        self.env_from.get_or_insert_default().extend(env);
        self
    }

    fn image(self, image: impl ToString) -> Self {
        Self {
            image: Some(image.to_string()),
            ..self
        }
    }

    fn ports(mut self, ports: impl IntoIterator<Item = corev1::ContainerPort>) -> Self {
        self.ports.get_or_insert_default().extend(ports);
        self
    }

    fn liveness_probe(mut self, probe: corev1::Probe) -> Self {
        self.liveness_probe = Some(probe);
        self
    }

    fn readiness_probe(mut self, probe: corev1::Probe) -> Self {
        self.readiness_probe = Some(probe);
        self
    }

    fn resource_limits(
        mut self,
        limits: impl IntoIterator<
            Item = (
                String,
                k8s_openapi::apimachinery::pkg::api::resource::Quantity,
            ),
        >,
    ) -> Self {
        self.resources
            .get_or_insert_default()
            .limits
            .get_or_insert_default()
            .extend(limits);
        self
    }

    fn resource_requests(
        mut self,
        requests: impl IntoIterator<
            Item = (
                String,
                k8s_openapi::apimachinery::pkg::api::resource::Quantity,
            ),
        >,
    ) -> Self {
        self.resources
            .get_or_insert_default()
            .requests
            .get_or_insert_default()
            .extend(requests);
        self
    }

    fn volume_mounts(
        mut self,
        volume_mounts: impl IntoIterator<Item = corev1::VolumeMount>,
    ) -> Self {
        let volume_mounts = volume_mounts.into_iter().collect();
        self.volume_mounts = Some(volume_mounts);
        self
    }

    fn security_context_mut(&mut self) -> &mut corev1::SecurityContext {
        self.security_context.get_or_insert_default()
    }
}
