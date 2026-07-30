// Fixture: a domain entity that has given up every property that made it one.
// Fires, in order: architecture:framework-in-domain (typeorm),
// architecture:hexagonal-layer-violation (imports infrastructure),
// ddd:persistence-in-domain (@Entity/@Column), ddd:primitive-obsession
// (four interchangeable strings), ddd:anemic-domain-model (accessors only),
// ddd:public-entity-setter (setStatus) and
// ddd:aggregate-exposes-internal-collection (getItems).
import { Column, Entity } from 'typeorm';
import { pool } from '../infrastructure/postgres_orders';

@Entity()
export class Order {
  @Column()
  private id: string = '';

  private status: string = '';

  private items: string[] = [];

  constructor(id: string, status: string, currency: string, note: string) {
    this.id = id;
    this.status = status;
  }

  getId(): string {
    return this.id;
  }

  getStatus(): string {
    return this.status;
  }

  setStatus(status: string): void {
    this.status = status;
  }

  getItems(): string[] {
    return this.items;
  }
}

export const connection = pool;
