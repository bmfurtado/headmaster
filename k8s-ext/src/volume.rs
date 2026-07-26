use super::*;

pub trait VolumeExt: Sized {
    fn configmap(name: impl ToString, configmap: corev1::ConfigMapVolumeSource) -> Self;
    fn emptydir(name: impl ToString) -> Self;
    fn hostpath(name: impl ToString, path: impl ToString, type_: impl ToString) -> Self;
}

impl VolumeExt for corev1::Volume {
    fn configmap(name: impl ToString, configmap: corev1::ConfigMapVolumeSource) -> Self {
        Self {
            name: name.to_string(),
            config_map: Some(configmap),
            ..Default::default()
        }
    }

    fn emptydir(name: impl ToString) -> Self {
        Self {
            name: name.to_string(),
            empty_dir: Some(corev1::EmptyDirVolumeSource::default()),
            ..Default::default()
        }
    }

    fn hostpath(name: impl ToString, path: impl ToString, type_: impl ToString) -> Self {
        Self {
            name: name.to_string(),
            host_path: Some(corev1::HostPathVolumeSource {
                path: path.to_string(),
                type_: Some(type_.to_string()),
            }),
            ..Default::default()
        }
    }
}
