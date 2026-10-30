use crate::{
    mapping::RecordMapping, CreateOutcome, DeleteOutcome, KubernetesClient, NewRecord, Page,
    ReplaceOutcome, Stored,
};
use anyhow::Context;
use async_trait::async_trait;
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use kube::{
    api::{DeleteParams, DynamicObject, ListParams, PostParams, Preconditions},
    core::Status,
    Api, Client,
};

/// `kube`-backed client for one resource in one namespace.
pub struct KubeClient {
    client: Client,
    api: Api<DynamicObject>,
    mapping: RecordMapping,
    namespace: String,
}

impl KubeClient {
    /// `namespace` must be a valid namespace name: it becomes part of every request path.
    pub fn new(client: Client, namespace: impl Into<String>, mapping: RecordMapping) -> Self {
        let namespace = namespace.into();
        Self {
            api: Api::namespaced_with(client.clone(), &namespace, &mapping.api_resource()),
            client,
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

/// Whether `error` is the API server's answer that the object `name` does not exist.
///
/// A 404 has two causes. A missing object is reported as a `Status` with `reason: NotFound` and
/// `details.name` set to the object's name. A resource type that is not served at all (the CRD is
/// not installed, or was removed) is answered by the API server's generic not-found handler,
/// which has no `details.name`; a proxy in front of it may answer with a body that is not a
/// `Status` at all. Only the first is an absent record: the second says that every record is
/// unreachable, and must not read as "nothing there".
fn is_missing_object(error: &kube::Error, name: &str) -> bool {
    match error {
        kube::Error::Api(status) => is_object_not_found(status, name),
        _ => false,
    }
}

pub(crate) fn is_object_not_found(status: &Status, name: &str) -> bool {
    status.code == 404
        && status.reason == "NotFound"
        && status
            .details
            .as_ref()
            .is_some_and(|details| details.name == name)
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

    fn install_hint(&self) -> String {
        self.mapping.install_hint().to_owned()
    }

    fn object_name(&self, key: &str) -> String {
        self.mapping.object_name(key)
    }

    async fn permits(&self, verb: &str) -> anyhow::Result<bool> {
        let resource = self.mapping.api_resource();
        let review = SelfSubjectAccessReview {
            spec: SelfSubjectAccessReviewSpec {
                resource_attributes: Some(ResourceAttributes {
                    namespace: Some(self.namespace.clone()),
                    verb: Some(verb.to_owned()),
                    group: Some(resource.group),
                    resource: Some(resource.plural),
                    ..ResourceAttributes::default()
                }),
                ..SelfSubjectAccessReviewSpec::default()
            },
            ..SelfSubjectAccessReview::default()
        };
        let reviews: Api<SelfSubjectAccessReview> = Api::all(self.client.clone());
        let review = reviews
            .create(&PostParams::default(), &review)
            .await
            .context("create SelfSubjectAccessReview")?;
        Ok(review.status.is_some_and(|status| status.allowed))
    }

    async fn get(&self, name: &str) -> anyhow::Result<Option<Stored>> {
        // No resourceVersion parameter: the API server answers from a quorum read.
        let object = match self.api.get(name).await {
            Ok(object) => object,
            Err(error) if is_missing_object(&error, name) => return Ok(None),
            Err(error) => return Err(error).context("get object"),
        };
        self.mapping.decode(&object).map(Some)
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
            Err(error) if is_missing_object(&error, record.name) => Ok(ReplaceOutcome::NotFound),
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
            Err(error) if is_missing_object(&error, name) => Ok(DeleteOutcome::NotFound),
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
