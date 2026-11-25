// SPDX-License-Identifier: MIT
//! Calls to a program built on kernoid in the same native library (RFC 0011, 4; `crate::program`).

use crate::api::kernoid::{Kernoid, KernoidError};
use crate::frb_generated::StreamSink;
use crate::program::{self, Sink};

fn error(message: String) -> KernoidError {
    KernoidError { unauthorized: false, message }
}

/// Calls `method` of `program` without an account.
pub async fn program_call(program: String, method: String, input: Vec<u8>) -> Result<Vec<u8>, KernoidError> {
    let program = program::find(&program).map_err(error)?;
    program.call(None, &method, input).await.map_err(error)
}

/// Starts `method` of `program` sending to `sink`, without an account.
pub fn program_watch(
    program: String,
    method: String,
    input: Vec<u8>,
    sink: StreamSink<Vec<u8>>,
) -> Result<(), KernoidError> {
    let program = program::find(&program).map_err(error)?;
    program.watch(None, &method, input, Sink::new(sink)).map_err(error)
}

impl Kernoid {
    /// Calls `method` of `program` for this account.
    pub async fn program_call(&self, program: String, method: String, input: Vec<u8>) -> Result<Vec<u8>, KernoidError> {
        let program = program::find(&program).map_err(error)?;
        program.call(Some(self), &method, input).await.map_err(error)
    }

    /// Starts `method` of `program` sending to `sink`, for this account.
    pub fn program_watch(
        &self,
        program: String,
        method: String,
        input: Vec<u8>,
        sink: StreamSink<Vec<u8>>,
    ) -> Result<(), KernoidError> {
        let program = program::find(&program).map_err(error)?;
        program.watch(Some(self), &method, input, Sink::new(sink)).map_err(error)
    }
}
