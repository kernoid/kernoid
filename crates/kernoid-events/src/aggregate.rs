// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed aggregates on top of the event store: state is folded from its events, commands decide on new events
//! against that state, and the store makes sure no one else wrote in between.
//!
//! ```ignore
//! #[derive(Serialize, Deserialize)]
//! #[serde(tag = "type", content = "data")]
//! enum AccountEvent {
//!     #[serde(rename = "account.added")]
//!     Added { name: String },
//!     #[serde(rename = "account.disabled")]
//!     Disabled,
//! }
//! ```
//!
//! The serde tag is the stored `event_type`, the content the stored payload – one name for both. When the payload of
//! an event type changes, raise its [`DomainEvent::revision`] and teach [`DomainEvent::upcast`] the older form:
//! stored events are never rewritten.

use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{AggregateId, Error, Event, EventStore, Expected, InlineFuture, NewEvent};

/// How often a command is decided again when another writer changed the aggregate in between.
const ATTEMPTS: usize = 3;

/// The events of one kind of aggregate: a serde enum, adjacently tagged with `tag = "type", content = "data"`.
pub trait DomainEvent: Serialize + DeserializeOwned + Send + Sync {
    /// The current revision of the payload of `event_type`; 1 until it first changes.
    fn revision(_event_type: &str) -> i16 {
        1
    }

    /// Turns a stored payload of an older `revision` of `event_type` into the current form; called only for
    /// revisions older than [`revision`](Self::revision).
    fn upcast(_event_type: &str, revision: i16, _payload: Value) -> Result<Value, String> {
        Err(format!("no upcast from revision {revision}"))
    }

    /// The stored form: event type and payload.
    fn encode(&self) -> Result<(String, Value), Error> {
        let mut value = serde_json::to_value(self).map_err(|error| Error::Encode(error.to_string()))?;
        let event_type = match value.get("type") {
            Some(Value::String(event_type)) => event_type.clone(),
            _ => return Err(Error::Encode("not an adjacently tagged enum (tag \"type\", content \"data\")".into())),
        };
        let payload = value.get_mut("data").map(Value::take).unwrap_or(Value::Null);
        Ok((event_type, payload))
    }

    /// Reads a stored event, upcasting older revisions.
    fn decode(event_type: &str, revision: i16, payload: Value) -> Result<Self, Error> {
        let decode_error = |message: String| Error::Decode { event_type: event_type.to_owned(), revision, message };
        let current = Self::revision(event_type);
        let payload = match revision {
            r if r == current => payload,
            r if r < current => Self::upcast(event_type, revision, payload).map_err(decode_error)?,
            _ => return Err(decode_error(format!("newer than this version of kernoid knows ({current})"))),
        };
        let tagged = match payload {
            Value::Null => json!({ "type": event_type }),
            data => json!({ "type": event_type, "data": data }),
        };
        serde_json::from_value(tagged).map_err(|error| decode_error(error.to_string()))
    }
}

/// State derived from the events of one aggregate.
pub trait Aggregate: Default + Send + Sync {
    /// The stored `aggregate_type`, e.g. `account`.
    const TYPE: &'static str;
    type Event: DomainEvent;

    fn apply(&mut self, event: Self::Event);
}

/// An aggregate's state and the sequence of its last event (0: it has none yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded<A> {
    pub id: AggregateId,
    pub state: A,
    pub sequence: i64,
}

impl<A> Loaded<A> {
    pub fn exists(&self) -> bool {
        self.sequence > 0
    }
}

/// Why a command did not take effect.
#[derive(Debug, thiserror::Error)]
pub enum CommandError<E> {
    /// The command was refused for the state it found.
    #[error("refused: {0}")]
    Refused(E),
    #[error(transparent)]
    Store(#[from] Error),
}

impl EventStore {
    /// Folds the events of aggregate `id` in `instance` into its state.
    pub async fn load<A: Aggregate>(&self, instance: Uuid, id: &str) -> Result<Loaded<A>, Error> {
        let aggregate = AggregateId::new(instance, A::TYPE, id);
        let mut state = A::default();
        let mut sequence = 0;
        for event in self.events(&aggregate).await? {
            sequence = event.sequence;
            state.apply(A::Event::decode(&event.event_type, event.revision, event.payload)?);
        }
        Ok(Loaded { id: aggregate, state, sequence })
    }

    /// Loads the aggregate, lets `decide` turn its state into new events (or refuse) and appends them – unless
    /// another writer changed the aggregate in between, in which case it is loaded and decided again.
    /// `owner` is the tenant the aggregate belongs to (the instance for instance-wide aggregates).
    pub async fn execute<A: Aggregate, E>(
        &self,
        instance: Uuid,
        owner: Uuid,
        id: &str,
        creator: &str,
        decide: impl Fn(&A) -> Result<Vec<A::Event>, E>,
    ) -> Result<Vec<Event>, CommandError<E>> {
        self.execute_with(instance, owner, id, creator, decide, crate::no_inline).await
    }

    /// Like [`execute`](Self::execute), with inline projections run in the same transaction (see
    /// [`EventStore::append_with`]).
    pub async fn execute_with<A: Aggregate, E>(
        &self,
        instance: Uuid,
        owner: Uuid,
        id: &str,
        creator: &str,
        decide: impl Fn(&A) -> Result<Vec<A::Event>, E>,
        inline: impl for<'c> Fn(&'c mut PgConnection, &'c [Event]) -> InlineFuture<'c> + Send + Sync,
    ) -> Result<Vec<Event>, CommandError<E>> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let loaded = self.load::<A>(instance, id).await?;
            let events = decide(&loaded.state).map_err(CommandError::Refused)?;
            let new_events = events
                .iter()
                .map(|event| {
                    let (event_type, payload) = event.encode()?;
                    let revision = A::Event::revision(&event_type);
                    Ok(NewEvent { event_type, revision, payload, creator: creator.to_owned() })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let expected = if loaded.exists() { Expected::Sequence(loaded.sequence) } else { Expected::New };
            match self.append_with(&loaded.id, owner, expected, &new_events, |c, e| inline(c, e)).await {
                Err(Error::Conflict { .. }) if attempt < ATTEMPTS => continue,
                result => return Ok(result?),
            }
        }
    }
}
