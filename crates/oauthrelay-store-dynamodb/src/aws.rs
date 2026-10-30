use crate::*;
use anyhow::Context;
use aws_sdk_dynamodb::{
    operation::put_item::PutItemError,
    primitives::Blob,
    types::{AttributeValue, ReturnValuesOnConditionCheckFailure},
};
use std::collections::HashMap;

/// SDK-backed client for one table.
pub struct AwsDynamoDbClient {
    client: aws_sdk_dynamodb::Client,
    table: String,
}

impl AwsDynamoDbClient {
    pub fn new(client: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }
}

fn number(value: u64) -> AttributeValue {
    AttributeValue::N(value.to_string())
}

/// A condition expression with the attribute-name and value placeholders it uses.
/// Placeholders stand in for every attribute name because `value` is a DynamoDB reserved word.
pub(super) struct ConditionParts {
    pub expression: &'static str,
    pub names: Vec<(&'static str, &'static str)>,
    pub values: Vec<(&'static str, AttributeValue)>,
}

pub(super) fn condition_parts(condition: &PutCondition) -> ConditionParts {
    match condition {
        PutCondition::AbsentOrExpired { now } => ConditionParts {
            expression: "attribute_not_exists(#pk) OR #exp <= :now",
            names: vec![("#pk", KEY_ATTRIBUTE), ("#exp", EXPIRES_ATTRIBUTE)],
            values: vec![(":now", number(*now))],
        },
        // A missing item has no `expires_at`, so the comparison is false and the put fails.
        PutCondition::LiveWithValue { now, expected } => ConditionParts {
            expression: "#exp > :now AND #val = :expected",
            names: vec![("#exp", EXPIRES_ATTRIBUTE), ("#val", VALUE_ATTRIBUTE)],
            values: vec![
                (":now", number(*now)),
                (":expected", AttributeValue::B(Blob::new(expected.clone()))),
            ],
        },
    }
}

fn decode_item(key: &str, item: &HashMap<String, AttributeValue>) -> anyhow::Result<Item> {
    let value = match item.get(VALUE_ATTRIBUTE) {
        Some(AttributeValue::B(blob)) => blob.as_ref().to_vec(),
        _ => anyhow::bail!("item {key:?} has no binary {VALUE_ATTRIBUTE} attribute"),
    };
    let expires_at = match item.get(EXPIRES_ATTRIBUTE) {
        Some(AttributeValue::N(number)) => number
            .parse()
            .with_context(|| format!("item {key:?} has an invalid {EXPIRES_ATTRIBUTE}"))?,
        _ => anyhow::bail!("item {key:?} has no numeric {EXPIRES_ATTRIBUTE} attribute"),
    };
    Ok(Item { value, expires_at })
}

fn key_attribute(key: &str) -> AttributeValue {
    AttributeValue::S(key.to_owned())
}

#[async_trait]
impl DynamoDbClient for AwsDynamoDbClient {
    async fn put_item(&self, request: PutRequest) -> anyhow::Result<PutOutcome> {
        let condition = condition_parts(&request.condition);
        let mut builder = self
            .client
            .put_item()
            .table_name(&self.table)
            .item(KEY_ATTRIBUTE, key_attribute(&request.key))
            .item(
                VALUE_ATTRIBUTE,
                AttributeValue::B(Blob::new(request.item.value)),
            )
            .item(EXPIRES_ATTRIBUTE, number(request.item.expires_at))
            .condition_expression(condition.expression)
            .return_values_on_condition_check_failure(ReturnValuesOnConditionCheckFailure::AllOld);
        for (placeholder, name) in condition.names {
            builder = builder.expression_attribute_names(placeholder, name);
        }
        for (placeholder, value) in condition.values {
            builder = builder.expression_attribute_values(placeholder, value);
        }
        match builder.send().await {
            Ok(_) => Ok(PutOutcome::Written),
            Err(error) => {
                if let Some(PutItemError::ConditionalCheckFailedException(failed)) =
                    error.as_service_error()
                {
                    // An item that cannot be decoded is reported as absent: the write then counts
                    // as failed, which is the safe reading.
                    let existing = failed
                        .item()
                        .and_then(|item| decode_item(&request.key, item).ok());
                    return Ok(PutOutcome::ConditionFailed { existing });
                }
                Err(error).context("PutItem")
            }
        }
    }

    async fn get_item(&self, key: &str) -> anyhow::Result<Option<Item>> {
        let output = self
            .client
            .get_item()
            .table_name(&self.table)
            .key(KEY_ATTRIBUTE, key_attribute(key))
            .consistent_read(true)
            .send()
            .await
            .context("GetItem")?;
        output.item().map(|item| decode_item(key, item)).transpose()
    }

    async fn delete_item(&self, key: &str) -> anyhow::Result<()> {
        self.client
            .delete_item()
            .table_name(&self.table)
            .key(KEY_ATTRIBUTE, key_attribute(key))
            .send()
            .await
            .context("DeleteItem")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
