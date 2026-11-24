-- Demo data for the `shop` database. Idempotent: rerunning it changes nothing.
-- Loaded by examples/demo (target-db init) and by bin/seed (dev stack).
SET client_min_messages = warning;  -- rerun: no "already exists" notices

CREATE TABLE IF NOT EXISTS customers (
  id         integer PRIMARY KEY,
  name       text        NOT NULL,
  email      text        NOT NULL UNIQUE,
  country    text        NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
  id          integer PRIMARY KEY,
  sku         text           NOT NULL UNIQUE,
  name        text           NOT NULL,
  price_cents integer        NOT NULL CHECK (price_cents >= 0)
);

CREATE TABLE IF NOT EXISTS orders (
  id          integer PRIMARY KEY,
  customer_id integer     NOT NULL REFERENCES customers (id),
  product_id  integer     NOT NULL REFERENCES products (id),
  quantity    integer     NOT NULL CHECK (quantity > 0),
  status      text        NOT NULL,
  ordered_at  timestamptz NOT NULL
);

INSERT INTO customers (id, name, email, country, created_at) VALUES
  (1, 'Ada Lovelace',     'ada@example.com',     'GB', '2026-01-04 09:12:00+00'),
  (2, 'Grace Hopper',     'grace@example.com',   'US', '2026-01-19 14:40:00+00'),
  (3, 'Edsger Dijkstra',  'edsger@example.com',  'NL', '2026-02-02 08:05:00+00'),
  (4, 'Barbara Liskov',   'barbara@example.com', 'US', '2026-03-11 17:23:00+00'),
  (5, 'Donald Knuth',     'donald@example.com',  'US', '2026-04-27 11:58:00+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO products (id, sku, name, price_cents) VALUES
  (1, 'KB-001',  'Mechanical keyboard', 12900),
  (2, 'MS-002',  'Trackball mouse',      5900),
  (3, 'MN-003',  '27" monitor',         32900),
  (4, 'DK-004',  'USB-C dock',          18900)
ON CONFLICT (id) DO NOTHING;

INSERT INTO orders (id, customer_id, product_id, quantity, status, ordered_at) VALUES
  (1, 1, 1, 1, 'shipped',   '2026-05-02 10:00:00+00'),
  (2, 2, 3, 2, 'shipped',   '2026-05-03 12:30:00+00'),
  (3, 3, 2, 1, 'pending',   '2026-05-07 16:45:00+00'),
  (4, 4, 4, 1, 'cancelled', '2026-05-09 09:15:00+00'),
  (5, 5, 1, 3, 'shipped',   '2026-05-12 13:20:00+00'),
  (6, 1, 3, 1, 'pending',   '2026-05-14 18:05:00+00')
ON CONFLICT (id) DO NOTHING;
