# Live tests

Tests here use the network. They are excluded from a normal test run.

## The rule

**Only ever scan domains you own.** Passive checks read public records, but probe and active
checks contact the hosts, and doing that to someone else's systems without permission is
unlawful in most places.

`targets.toml` lists the domains these tests may touch. A test that names any other domain
stops before doing anything.

## Running them

1. Copy `targets.example.toml` to `targets.toml` and put in a domain you own.
   `targets.toml` is ignored by git.
2. Run the passive tests:

   ```sh
   uv run pytest -m live tests/integration
   ```

3. To run the probe test as well, set `probe = true` for that domain.

Active checks are not run from here. To try them, verify your domain and run
`pwatch scan YOUR-DOMAIN --active` yourself.
