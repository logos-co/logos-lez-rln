//! RLN JSON-RPC service.
//!
//! Exposes `rln_register`, `rln_getRoot`, and `rln_getMerkleProof` over HTTP.
//!
//! Usage:
//! ```bash
//! cargo run --bin rln_service [-- --payment-account <ACCOUNT_ID>] [--listen 127.0.0.1:3001]
//! ```
//!
//! If `--payment-account` is omitted, uses a previously saved account from local dev setup.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use logos_lez_rln::rln::client::{
    TREE_ID, init_wallet, load_programs, load_payment_account,
};
use logos_lez_rln::rln::service::RlnService;
use nssa::AccountId;

// ---- JSON-RPC types ----

#[derive(Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

fn success(id: serde_json::Value, result: serde_json::Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        result: Some(result),
        error: None,
        id,
    }
}

fn error(id: serde_json::Value, code: i32, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        result: None,
        error: Some(JsonRpcError { code, message }),
        id,
    }
}

// ---- Request param types ----

#[derive(Deserialize)]
struct RegisterParams {
    id_commitment: String,
    rate_limit: u64,
}

// ---- Handler ----

async fn handle_request(
    service: Arc<RlnService>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() != Method::POST {
        let body = serde_json::to_vec(&error(
            serde_json::Value::Null,
            -32600,
            "Only POST allowed".into(),
        ))
        .unwrap();
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap());
    }

    let body_bytes = req.collect().await?.to_bytes();
    let rpc_req: JsonRpcRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            let body = serde_json::to_vec(&error(
                serde_json::Value::Null,
                -32700,
                format!("Parse error: {e}"),
            ))
            .unwrap();
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap());
        }
    };

    if rpc_req.jsonrpc != "2.0" {
        let body = serde_json::to_vec(&error(
            rpc_req.id,
            -32600,
            "Invalid jsonrpc version".into(),
        ))
        .unwrap();
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap());
    }

    let method = rpc_req.method.clone();
    println!("<-- {} (id={})", method, rpc_req.id);
    let start = Instant::now();

    let response = match rpc_req.method.as_str() {
        "rln_register" => handle_register(&service, rpc_req.id, rpc_req.params).await,
        "rln_getRoot" => handle_get_root(&service, rpc_req.id).await,
        "rln_getMerkleProof" => {
            handle_get_merkle_proof(&service, rpc_req.id, rpc_req.params).await
        }
        _ => error(
            rpc_req.id,
            -32601,
            format!("Method not found: {}", rpc_req.method),
        ),
    };

    let elapsed = start.elapsed();
    if response.error.is_some() {
        let err = response.error.as_ref().unwrap();
        println!("--> {} error: {} ({:.1?})", method, err.message, elapsed);
    } else {
        println!("--> {} ok ({:.1?})", method, elapsed);
    }

    let body = serde_json::to_vec(&response).unwrap();
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

async fn handle_register(
    service: &RlnService,
    id: serde_json::Value,
    params: serde_json::Value,
) -> JsonRpcResponse {
    let params: RegisterParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            return error(id, -32602, format!("Invalid params: {e}"));
        }
    };

    // Parse hex id_commitment (strip optional 0x prefix)
    let hex_str = params.id_commitment.strip_prefix("0x").unwrap_or(&params.id_commitment);
    let bytes = match hex::decode(hex_str) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => {
            return error(
                id,
                -32602,
                format!("id_commitment must be 32 bytes, got {}", b.len()),
            );
        }
        Err(e) => {
            return error(id, -32602, format!("Invalid hex in id_commitment: {e}"));
        }
    };

    println!("    id_commitment=0x{:.16}... rate_limit={}", hex_str, params.rate_limit);
    match service.register(bytes, params.rate_limit).await {
        Ok(leaf_index) => {
            println!("    leaf_index={}", leaf_index);
            success(id, serde_json::json!({ "leaf_index": leaf_index }))
        }
        Err(e) => error(id, -32000, e),
    }
}

async fn handle_get_root(service: &RlnService, id: serde_json::Value) -> JsonRpcResponse {
    let root = service.get_root().await;
    println!("    root=0x{:.16}...", hex::encode(root));
    success(id, serde_json::Value::String(format!("0x{}", hex::encode(root))))
}

async fn handle_get_merkle_proof(
    service: &RlnService,
    id: serde_json::Value,
    params: serde_json::Value,
) -> JsonRpcResponse {
    // params is either [leaf_index] or {"leaf_index": N}
    let leaf_index: u64 = if let Some(arr) = params.as_array() {
        match arr.first().and_then(|v| v.as_u64()) {
            Some(idx) => idx,
            None => {
                return error(id, -32602, "Expected params: [leaf_index]".into());
            }
        }
    } else if let Some(obj) = params.as_object() {
        match obj.get("leaf_index").and_then(|v| v.as_u64()) {
            Some(idx) => idx,
            None => {
                return error(id, -32602, "Expected params: {\"leaf_index\": N}".into());
            }
        }
    } else {
        return error(id, -32602, "Invalid params".into());
    };

    println!("    leaf_index={}", leaf_index);
    let proof = service.get_merkle_proof(leaf_index).await;
    println!("    root=0x{:.16}... depth={}", hex::encode(proof.root), proof.path_elements.len());

    let path_elements: Vec<String> = proof
        .path_elements
        .iter()
        .map(|e| format!("0x{}", hex::encode(e)))
        .collect();

    let identity_path_index: Vec<u8> = proof.path_indices.clone();

    let result = serde_json::json!({
        "pathElements": path_elements,
        "identityPathIndex": identity_path_index,
        "root": format!("0x{}", hex::encode(proof.root)),
    });

    success(id, result)
}

// ---- CLI + main ----

fn parse_args() -> (SocketAddr, Option<AccountId>) {
    let args: Vec<String> = std::env::args().collect();
    let mut listen: SocketAddr = "127.0.0.1:3001".parse().unwrap();
    let mut payment_account: Option<AccountId> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                i += 1;
                listen = args[i]
                    .parse()
                    .unwrap_or_else(|e| panic!("Invalid listen address '{}': {}", args[i], e));
            }
            "--payment-account" => {
                i += 1;
                payment_account = Some(
                    args[i]
                        .parse()
                        .unwrap_or_else(|e| panic!("Invalid account ID '{}': {}", args[i], e)),
                );
            }
            other => {
                eprintln!("Unknown argument: {other}");
                eprintln!(
                    "Usage: rln_service [--payment-account <ACCOUNT_ID>] [--listen <ADDR:PORT>]"
                );
                std::process::exit(1);
            }
        }
        i += 1;
    }

    (listen, payment_account)
}

#[tokio::main]
async fn main() {
    let (listen_addr, payment_account_arg) = parse_args();
    let tree_id = TREE_ID;

    println!("Initializing wallet...");
    let wallet_core = init_wallet();

    println!("Loading programs...");
    let (registration_program, _merkle_program) = load_programs();

    // Resolve payment account: CLI arg > saved file > error
    let payment_account_id = if let Some(id) = payment_account_arg {
        println!("Using payment account from CLI: {id}");
        id
    } else if let Some(id) = load_payment_account(&tree_id) {
        println!("Using saved payment account: {id}");
        id
    } else {
        eprintln!("Error: No payment account available.");
        eprintln!("Run setup first:  cargo run --bin run_rln_proof");
        eprintln!("Or specify one:   cargo run --bin rln_service -- --payment-account <ID>");
        std::process::exit(1);
    };

    println!("Initializing service (payment account: {})...", payment_account_id);
    let service = Arc::new(
        RlnService::new(
            wallet_core,
            registration_program,
            tree_id,
            payment_account_id,
        )
        .await,
    );

    let listener = TcpListener::bind(listen_addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind to {listen_addr}: {e}"));

    println!("RLN service listening on http://{listen_addr}");
    println!("Methods: rln_register, rln_getRoot, rln_getMerkleProof");

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let service = service.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let service = service.clone();
                        async move { handle_request(service, req).await }
                    }),
                )
                .await
            {
                eprintln!("Connection error: {err}");
            }
        });
    }
}
