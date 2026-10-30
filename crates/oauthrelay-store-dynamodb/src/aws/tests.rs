//! Drives the real SDK client against a stubbed HTTP layer to check the wire requests and the
//! mapping of DynamoDB's responses.

use super::*;
use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_smithy_http_client::test_util::infallible_client_fn;
use serde_json::{json, Value};
use std::sync::Mutex;

#[derive(Clone, Debug)]
struct Captured {
    target: String,
    body: Value,
}

type Responder = dyn Fn(&Captured) -> (u16, String) + Send + Sync;

fn stub(
    responder: impl Fn(&Captured) -> (u16, String) + Send + Sync + 'static,
) -> (AwsDynamoDbClient, Arc<Mutex<Vec<Captured>>>) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let log = captured.clone();
    let responder: Arc<Responder> = Arc::new(responder);
    let http = infallible_client_fn(move |request| {
        let call = Captured {
            target: request.headers()["x-amz-target"]
                .to_str()
                .unwrap()
                .to_owned(),
            body: serde_json::from_slice(request.body().bytes().unwrap()).unwrap(),
        };
        let (status, body) = responder(&call);
        log.lock().unwrap().push(call);
        http::Response::builder()
            .status(status)
            .header("content-type", "application/x-amz-json-1.0")
            .body(body)
            .unwrap()
    });
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("eu-west-1"))
        .credentials_provider(Credentials::new("AKID", "SECRET", None, None, "test"))
        .http_client(http)
        .build();
    (
        AwsDynamoDbClient::new(
            aws_sdk_dynamodb::Client::from_conf(config),
            "oauthrelay-store",
        ),
        captured,
    )
}

fn condition_failed() -> (u16, String) {
    (
        400,
        json!({
            "__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",
            "message": "The conditional request failed"
        })
        .to_string(),
    )
}

#[tokio::test]
async fn put_if_absent_condition_allows_absent_or_expired_items() {
    let (client, captured) = stub(|_| (200, "{}".into()));
    let written = client
        .put_item(PutRequest {
            key: "replay:code:abc".into(),
            item: Item {
                value: b"1".to_vec(),
                expires_at: 1_800_000_061,
            },
            condition: PutCondition::AbsentOrExpired { now: 1_800_000_000 },
        })
        .await
        .unwrap();
    assert!(written);
    let call = captured.lock().unwrap()[0].clone();
    assert_eq!(call.target, "DynamoDB_20120810.PutItem");
    assert_eq!(
        call.body,
        json!({
            "TableName": "oauthrelay-store",
            "Item": {
                "pk": {"S": "replay:code:abc"},
                // Base64 of the byte string "1".
                "value": {"B": "MQ=="},
                "expires_at": {"N": "1800000061"},
            },
            "ConditionExpression": "attribute_not_exists(#pk) OR #exp <= :now",
            "ExpressionAttributeNames": {"#pk": "pk", "#exp": "expires_at"},
            "ExpressionAttributeValues": {":now": {"N": "1800000000"}},
        })
    );
}

#[tokio::test]
async fn compare_and_swap_condition_requires_a_live_item_with_the_expected_value() {
    let (client, captured) = stub(|_| (200, "{}".into()));
    assert!(client
        .put_item(PutRequest {
            key: "refresh:used:h".into(),
            item: Item {
                value: b"new".to_vec(),
                expires_at: 1_800_000_061,
            },
            condition: PutCondition::LiveWithValue {
                now: 1_800_000_000,
                expected: b"old".to_vec(),
            },
        })
        .await
        .unwrap());
    let call = captured.lock().unwrap()[0].clone();
    assert_eq!(
        call.body["ConditionExpression"],
        "#exp > :now AND #val = :expected"
    );
    assert_eq!(
        call.body["ExpressionAttributeNames"],
        json!({"#exp": "expires_at", "#val": "value"})
    );
    assert_eq!(
        call.body["ExpressionAttributeValues"],
        // Base64 of the byte string "old".
        json!({":now": {"N": "1800000000"}, ":expected": {"B": "b2xk"}})
    );
    assert_eq!(call.body["Item"]["value"], json!({"B": "bmV3"}));
}

#[tokio::test]
async fn failed_conditions_report_not_written_and_other_errors_propagate() {
    let (client, _) = stub(|_| condition_failed());
    let request = || PutRequest {
        key: "k".into(),
        item: Item {
            value: b"v".to_vec(),
            expires_at: 10,
        },
        condition: PutCondition::AbsentOrExpired { now: 1 },
    };
    assert!(!client.put_item(request()).await.unwrap());

    let (client, _) = stub_with_error();
    let error = client.put_item(request()).await.unwrap_err();
    assert!(format!("{error:#}").contains("PutItem"), "{error:#}");
}

fn stub_with_error() -> (AwsDynamoDbClient, Arc<Mutex<Vec<Captured>>>) {
    stub(|_| {
        (
            400,
            json!({
                "__type": "com.amazon.coral.service#AccessDeniedException",
                "message": "not authorized"
            })
            .to_string(),
        )
    })
}

#[tokio::test]
async fn get_item_is_strongly_consistent_and_decodes_the_item() {
    let (client, captured) = stub(|_| {
        (
            200,
            json!({"Item": {
                "pk": {"S": "k"},
                "value": {"B": "MQ=="},
                "expires_at": {"N": "1800000061"},
            }})
            .to_string(),
        )
    });
    let item = client.get_item("k").await.unwrap().unwrap();
    assert_eq!(
        item,
        Item {
            value: b"1".to_vec(),
            expires_at: 1_800_000_061,
        }
    );
    let call = captured.lock().unwrap()[0].clone();
    assert_eq!(call.target, "DynamoDB_20120810.GetItem");
    assert_eq!(
        call.body,
        json!({"TableName": "oauthrelay-store", "Key": {"pk": {"S": "k"}}, "ConsistentRead": true})
    );
}

#[tokio::test]
async fn get_item_maps_absence_and_rejects_malformed_items() {
    let (client, _) = stub(|_| (200, "{}".into()));
    assert!(client.get_item("k").await.unwrap().is_none());
    let (client, _) = stub(|_| {
        (
            200,
            json!({"Item": {"pk": {"S": "k"}, "value": {"S": "text"}, "expires_at": {"N": "1"}}})
                .to_string(),
        )
    });
    assert!(client.get_item("k").await.is_err());
    let (client, _) = stub(|_| {
        (
            200,
            json!({"Item": {"pk": {"S": "k"}, "value": {"B": "MQ=="}}}).to_string(),
        )
    });
    assert!(client.get_item("k").await.is_err());
}

#[tokio::test]
async fn delete_item_removes_by_key() {
    let (client, captured) = stub(|_| (200, "{}".into()));
    client.delete_item("k").await.unwrap();
    let call = captured.lock().unwrap()[0].clone();
    assert_eq!(call.target, "DynamoDB_20120810.DeleteItem");
    assert_eq!(
        call.body,
        json!({"TableName": "oauthrelay-store", "Key": {"pk": {"S": "k"}}})
    );
    let (client, _) = stub_with_error();
    assert!(client.delete_item("k").await.is_err());
}
