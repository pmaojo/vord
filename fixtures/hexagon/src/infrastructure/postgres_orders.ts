// Fixture: the outer ring. Nothing here is a finding — an adapter importing a
// database driver is exactly what an adapter is for. It exists so the domain
// entity next door has a real infrastructure module to point at.
import { Pool } from 'pg';

export const pool = new Pool({ connectionString: process.env.DATABASE_URL });
