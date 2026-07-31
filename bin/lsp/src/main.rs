//! Composition root: an LSP server exposing yunq's analyzers to any
//! LSP-capable editor, in place of a per-IDE plugin.
//! `main` only wires transport + handlers; all analysis logic lives in
//! [`analysis`], reused unchanged from `yunq-cli`'s composition.

mod analysis;
mod connected;

use std::collections::HashMap;
use std::sync::Mutex;

use tower_lsp::jsonrpc::Result as RpcResult;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

struct Backend {
    client: Client,
    /// Full text of every currently open document, keyed by URI — LSP full
    /// document sync, the simplest correct choice for a first version.
    documents: Mutex<HashMap<Url, String>>,
}

impl Backend {
    async fn analyze_and_publish(&self, uri: Url, text: String) {
        let diagnostics = analysis::diagnose(&uri, &text).await;
        self.documents
            .lock()
            .expect("document map lock poisoned")
            .insert(uri.clone(), text);
        self.client
            .publish_diagnostics(uri, diagnostics, None)
            .await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> RpcResult<InitializeResult> {
        Ok(InitializeResult {
            server_info: Some(ServerInfo {
                name: "yunq-lsp".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                ..Default::default()
            },
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "yunq-lsp ready")
            .await;
    }

    async fn shutdown(&self) -> RpcResult<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.analyze_and_publish(params.text_document.uri, params.text_document.text)
            .await;
    }

    async fn did_change(&self, mut params: DidChangeTextDocumentParams) {
        // Full sync: the last content change carries the entire new text.
        let Some(change) = params.content_changes.pop() else {
            return;
        };
        self.analyze_and_publish(params.text_document.uri, change.text)
            .await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        self.documents
            .lock()
            .expect("document map lock poisoned")
            .remove(&uri);
        // Clear diagnostics rather than leaving stale ones in the editor.
        self.client.publish_diagnostics(uri, Vec::new(), None).await;
    }
}

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| Backend {
        client,
        documents: Mutex::new(HashMap::new()),
    });
    Server::new(stdin, stdout, socket).serve(service).await;
}
