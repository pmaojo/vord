// Fixture: a Rust domain entity that has given up its encapsulation.
// Fires, in order: architecture:framework-in-domain (sqlx),
// architecture:hexagonal-layer-violation (imports infrastructure),
// ddd:persistence-in-domain (Queryable), ddd:primitive-obsession
// (four interchangeable strings), ddd:anemic-domain-model (accessors only),
// ddd:public-entity-setter (set_status) and
// ddd:aggregate-exposes-internal-collection (get_items_mut).

use sqlx::PgPool;
use std::fs::File;
use crate::infrastructure::postgres_orders::postgres_save;

#[derive(Queryable)]
pub struct Order {
    pub id: String,
    pub status: String,
    pub currency: String,
    pub note: String,
    pub items: Vec<String>,
}

impl Order {
    pub fn new(id: String, status: String, currency: String, note: String) -> Self {
        Self {
            id,
            status,
            currency,
            note,
            items: Vec::new(),
        }
    }

    pub fn id(&self) -> &String {
        &self.id
    }

    pub fn status(&self) -> &String {
        &self.status
    }

    pub fn set_status(&mut self, status: String) {
        self.status = status;
    }

    pub fn get_items_mut(&mut self) -> &mut Vec<String> {
        &mut self.items
    }
}
