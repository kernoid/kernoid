/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use crate::common::{Encoding, tokenizer::StopChar};
use encodify::{
    base64,
    qp::{self, QuotedPrintable},
};
use mail_parser::decoders::charsets::map::charset_decoder;
use std::borrow::Cow;

const QUOTED_PRINTABLE_CHARSET: &str = "iso-8859-1";
const QUOTED_PRINTABLE: QuotedPrintable = qp::BODY.strict();

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Decoded {
    Binary(Vec<u8>),
    Text(String),
    Undecodable,
}

pub(crate) struct ValueDecoder<'x> {
    pub(crate) encoding: Encoding,
    pub(crate) charset: Option<&'x str>,
    pub(crate) binary: bool,
}

impl ValueDecoder<'_> {
    #[inline(never)]
    pub(crate) fn decode(
        &self,
        input: &[u8],
        stop_char: StopChar,
        payload: Option<Vec<u8>>,
    ) -> Decoded {
        let Some(bytes) = payload
            .map(Cow::Owned)
            .or_else(|| self.encoding.decode_value(input, stop_char))
        else {
            return Decoded::Undecodable;
        };
        if self.binary {
            return Decoded::Binary(bytes.into_owned());
        }
        let default_charset = match self.encoding {
            Encoding::QuotedPrintable => Some(QUOTED_PRINTABLE_CHARSET),
            Encoding::Base64 => None,
        };
        // Changed for kernoid: the charset decoders of mail-parser 0.11 (Stalwart uses `Charset` of mail-parser 1.0).
        match self
            .charset
            .or(default_charset)
            .filter(|charset| {
                !charset.eq_ignore_ascii_case("utf-8") && !charset.eq_ignore_ascii_case("utf8")
            })
            .and_then(|charset| charset_decoder(charset.as_bytes()))
        {
            Some(decoder) => Decoded::Text(decoder(&bytes)),
            None => match String::from_utf8(bytes.into_owned()) {
                Ok(text) => Decoded::Text(text),
                Err(err) => Decoded::Binary(err.into_bytes()),
            },
        }
    }
}

impl Encoding {
    pub(crate) fn decode(self, input: &[u8]) -> Option<Cow<'_, [u8]>> {
        match self {
            Encoding::Base64 => base64::LENIENT.decode(input).ok().map(Cow::Owned),
            Encoding::QuotedPrintable => QUOTED_PRINTABLE.decode(input).ok(),
        }
    }

    fn decode_value(self, input: &[u8], stop_char: StopChar) -> Option<Cow<'_, [u8]>> {
        match (self, stop_char) {
            (Encoding::QuotedPrintable, StopChar::Lf) | (Encoding::Base64, _) => self.decode(input),
            (Encoding::QuotedPrintable, _) => Self::decode_quoted_printable_component(input),
        }
    }

    fn decode_quoted_printable_component(input: &[u8]) -> Option<Cow<'_, [u8]>> {
        let mut text = input;
        while let [head @ .., b' ' | b'\t'] = text {
            text = head;
        }
        match input.get(text.len()..) {
            Some(blanks @ [_, ..]) => {
                let mut bytes = Vec::new();
                QUOTED_PRINTABLE.decode_append(text, &mut bytes).ok()?;
                bytes.extend_from_slice(blanks);
                Some(Cow::Owned(bytes))
            }
            _ => QUOTED_PRINTABLE.decode(input).ok(),
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/calcard/src/common/decode/tests.rs"]
mod tests;
