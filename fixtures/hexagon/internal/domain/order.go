// Fixture: a Go domain package that reaches outside the hexagon and models with
// primitives. Fires architecture:framework-in-domain (database/sql),
// architecture:hexagonal-layer-violation (imports internal/infra),
// ddd:persistence-in-domain (a gorm struct tag), ddd:public-entity-setter
// (SetStatus) and ddd:primitive-obsession (NewShipment's four strings).
package domain

import (
	"database/sql"

	"example.com/app/internal/infra"
)

type Shipment struct {
	ID     string `gorm:"primaryKey"`
	Status string
	Items  []string
}

func NewShipment(id string, customer string, currency string, note string) *Shipment {
	return &Shipment{ID: id, Status: "draft"}
}

func (o *Shipment) SetStatus(status string) {
	o.Status = status
}

func (o *Shipment) Ship(db *sql.DB) error {
	return infra.Save(db, o.ID)
}
