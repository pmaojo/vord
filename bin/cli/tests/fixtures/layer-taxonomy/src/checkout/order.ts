// Fixture for the declarative layer taxonomy e2e test
// (bin/cli/tests/layer_taxonomy.rs): `checkout/` names no ring in the
// zero-config `HexLayer` vocabulary, so without a declared
// `[[architecture.layer]]` neither rule below should fire. With
// `checkout` -> `domain` declared, both should: the `@Entity` decorator
// (ddd:persistence-in-domain) and the import of `infrastructure`
// (architecture:hexagonal-layer-violation).
import { Entity } from 'typeorm';
import { pool } from '../infrastructure/db';

@Entity()
export class Order {
  private id: string = '';
}

export const connection = pool;
