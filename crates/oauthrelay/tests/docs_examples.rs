use async_trait::async_trait;
use oauthrelay_core::{
    compile_resources, ResourceDocument, SecretResolver, SecretSource, SecretString,
};
use serde::Deserialize;
use std::{fs, path::Path};

struct ExampleSecrets;

#[async_trait]
impl SecretResolver for ExampleSecrets {
    async fn resolve_value(&self, _: &str) -> anyhow::Result<SecretString> {
        Ok(SecretString::new("validated-example-secret"))
    }

    async fn resolve_source(&self, _: &SecretSource) -> anyhow::Result<SecretString> {
        Ok(SecretString::new("validated-example-secret"))
    }
}

struct Fence {
    info: String,
    body: String,
    line: usize,
}

fn collect_docs(path: &Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_docs(&path, files);
        } else if matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("md" | "mdx")
        ) {
            files.push(path);
        }
    }
}

fn fences(markdown: &str) -> Vec<Fence> {
    let mut result = Vec::new();
    let mut lines = markdown.lines().enumerate();
    while let Some((index, line)) = lines.next() {
        let Some(info) = line.strip_prefix("```") else {
            continue;
        };
        let mut body = String::new();
        for (_, line) in lines.by_ref() {
            if line == "```" {
                break;
            }
            body.push_str(line);
            body.push('\n');
        }
        result.push(Fence {
            info: info.trim().to_owned(),
            body,
            line: index + 1,
        });
    }
    result
}

#[tokio::test]
async fn documentation_yaml_and_json_examples_are_valid() {
    let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/src/content/docs");
    let mut files = Vec::new();
    collect_docs(&docs, &mut files);
    files.sort();

    let mut yaml_examples = 0;
    let mut json_examples = 0;
    let mut resource_examples = 0;
    for path in files {
        let markdown = fs::read_to_string(&path).unwrap();
        for fence in fences(&markdown) {
            let location = format!("{}:{}", path.display(), fence.line);
            let language = fence.info.split_whitespace().next().unwrap_or_default();
            match language {
                "yaml" => {
                    yaml_examples += 1;
                    for document in serde_yaml::Deserializer::from_str(&fence.body) {
                        serde_yaml::Value::deserialize(document)
                            .unwrap_or_else(|error| panic!("{location}: invalid YAML: {error}"));
                    }
                    if fence
                        .info
                        .split_whitespace()
                        .any(|tag| tag == "oauthrelay-config")
                    {
                        resource_examples += 1;
                        let documents = serde_yaml::Deserializer::from_str(&fence.body)
                            .map(|document| {
                                ResourceDocument::deserialize(document).unwrap_or_else(|error| {
                                    panic!("{location}: invalid oauthrelay resource: {error}")
                                })
                            })
                            .collect();
                        compile_resources(documents, &ExampleSecrets)
                            .await
                            .unwrap_or_else(|error| {
                                panic!("{location}: invalid oauthrelay resource graph: {error:#}")
                            });
                    }
                }
                "json" => {
                    json_examples += 1;
                    serde_json::from_str::<serde_json::Value>(&fence.body)
                        .unwrap_or_else(|error| panic!("{location}: invalid JSON: {error}"));
                }
                _ => {}
            }
        }
    }

    assert!(yaml_examples > 0, "no YAML documentation examples found");
    assert!(json_examples > 0, "no JSON documentation examples found");
    assert!(
        resource_examples >= 5,
        "expected complete oauthrelay resource examples across the documentation"
    );
}
