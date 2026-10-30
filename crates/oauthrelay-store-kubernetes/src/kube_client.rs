use crate::{
    mapping::RecordMapping, CreateOutcome, DeleteOutcome, KubernetesClient, NewRecord, Page,
    ReplaceOutcome, Stored,
};
use anyhow::Context;
use async_trait::async_trait;
use kube::{
    api::{DeleteParams, DynamicObject, ListParams, PostParams, Preconditions},
    Api, Client,
};

/// `kube`-backed client for one resource in one namespace.
pub struct KubeClient {
    api: Api<DynamicObject>,
    mapping: RecordMapping,
    namespace: String,
}

impl KubeClient {
    /// `namespace` must be a valid namespace name: it becomes part of every request path.
    pub fn new(client: Client, namespace: impl Into<String>, mapping: RecordMapping) -> Self {
        let namespace = namespace.into();
        Self {
            api: Api::namespaced_with(client, &namespace, &mapping.api_resource()),
            mapping,
            namespace,
        }
    }
}

fn status_code(error: &kube::Error) -> Option<u16> {
    match error {
        kube::Error::Api(status) => Some(status.code),
        _ => None,
    }
}

#[async_trait]
impl KubernetesClient for KubeClient {
    fn target(&self) -> String {
        format!(
            "{} in namespace {:?}",
            self.mapping.resource_name(),
            self.namespace
        )
    }

    async fn get(&self, name: &str) -> anyhow::Result<Option<Stored>> {
        // No resourceVersion parameter: the API server answers from a quorum read.
        let object = self.api.get_opt(name).await.context("get object")?;
        object
            .map(|object| self.mapping.decode(&object))
            .transpose()
    }

    async fn create(&self, record: NewRecord<'_>) -> anyhow::Result<CreateOutcome> {
        let object = self.mapping.encode(&self.namespace, &record)?;
        match self.api.create(&PostParams::default(), &object).await {
            Ok(_) => Ok(CreateOutcome::Created),
            Err(error) if status_code(&error) == Some(409) => Ok(CreateOutcome::AlreadyExists),
            Err(error) => Err(error).context("create object"),
        }
    }

    async fn replace(
        &self,
        record: NewRecord<'_>,
        resource_version: &str,
    ) -> anyhow::Result<ReplaceOutcome> {
        let mut object = self.mapping.encode(&self.namespace, &record)?;
        object.metadata.resource_version = Some(resource_version.to_owned());
        match self
            .api
            .replace(record.name, &PostParams::default(), &object)
            .await
        {
            Ok(_) => Ok(ReplaceOutcome::Replaced),
            Err(error) if status_code(&error) == Some(409) => Ok(ReplaceOutcome::Conflict),
            Err(error) if status_code(&error) == Some(404) => Ok(ReplaceOutcome::NotFound),
            Err(error) => Err(error).context("replace object"),
        }
    }

    async fn delete(
        &self,
        name: &str,
        resource_version: Option<&str>,
    ) -> anyhow::Result<DeleteOutcome> {
        let mut params = DeleteParams::default();
        if let Some(resource_version) = resource_version {
            params = params.preconditions(Preconditions {
                resource_version: Some(resource_version.to_owned()),
                uid: None,
            });
        }
        match self.api.delete(name, &params).await {
            Ok(_) => Ok(DeleteOutcome::Deleted),
            Err(error) if status_code(&error) == Some(409) => Ok(DeleteOutcome::Conflict),
            Err(error) if status_code(&error) == Some(404) => Ok(DeleteOutcome::NotFound),
            Err(error) => Err(error).context("delete object"),
        }
    }

    async fn list(
        &self,
        label_selector: &str,
        limit: u32,
        continue_token: Option<&str>,
    ) -> anyhow::Result<Page> {
        let mut params = ListParams::default().labels(label_selector).limit(limit);
        if let Some(token) = continue_token {
            params = params.continue_token(token);
        }
        let list = self.api.list(&params).await.context("list objects")?;
        let mut page = Page {
            continue_token: list.metadata.continue_.filter(|token| !token.is_empty()),
            ..Page::default()
        };
        for object in list.items {
            match self.mapping.decode(&object) {
                Ok(stored) => page.items.push(stored),
                Err(_) => page
                    .undecodable
                    .push(object.metadata.name.unwrap_or_default()),
            }
        }
        Ok(page)
    }
}
