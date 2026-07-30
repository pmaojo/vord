// Fixture: the outer ring. An adapter talking to a database driver is what an
// adapter is for, so nothing here is a finding.
package infra

import "database/sql"

func Save(db *sql.DB, id string) error {
	_, err := db.Exec("UPDATE orders SET status = 'shipped' WHERE id = $1", id)
	return err
}
