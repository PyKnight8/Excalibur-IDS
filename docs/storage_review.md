# Excalibur Storage Friendliness Review

## Current Write Pattern

Traffic records are written once per captured IP packet through `Database.log_traffic()`. DNS queries, host discovery updates, and alerts add additional writes when those events occur.

SQLite commits currently happen per helper call because write helpers use `with self.connection:` transactions around individual inserts or updates. There is no batching yet.

Traffic retention is enforced after each traffic insert. When the traffic table exceeds `TRAFFIC_MAX_RECORDS`, the oldest rows are deleted until the table returns to the configured maximum.

## SQLite Mode and Indexes

The current SQLite journal mode is whatever SQLite reports for the active database, visible on `/system`. Unless changed externally, SQLite commonly uses `DELETE` mode by default.

Current indexes:

- `hosts.ip_address` has a unique index: `idx_hosts_ip_address`
- `domains.domain` is unique through the table constraint
- Primary keys exist on all tables through `INTEGER PRIMARY KEY AUTOINCREMENT`

There are no dedicated indexes yet for high-volume dashboard filters such as `traffic.timestamp`, `traffic.src_ip`, `traffic.dst_ip`, DNS query fields, or alert timestamps.

## Expected SSD/HDD Impact

The current design is simple and transparent, but it is write-heavy under high packet rates:

- Every captured packet can cause a traffic insert and commit.
- Host discovery can add or update host rows during packet processing.
- DNS queries add rows to `dns_queries` and update or insert `domains`.
- Retention checks happen per traffic insert.
- Per-packet commits increase write amplification compared with batched writes.

On SSDs, this is acceptable for low to moderate lab traffic, but sustained high packet rates will increase write amplification and database churn. On HDDs, per-packet commits can increase latency and reduce throughput because fsync-heavy workloads are expensive.

## Future Improvements

Recommended future optimizations:

- Batch traffic inserts instead of committing per packet.
- Introduce a writer queue so packet capture is decoupled from SQLite write latency.
- Enable and tune WAL mode for better concurrent dashboard reads and write behavior.
- Make retention limits configurable from Settings.
- Run retention periodically or after batches rather than after every packet.
- Add indexes for common dashboard filters and sort paths.
- Add an optional payload-free/minimal metadata mode if packet metadata expands in the future.
- Consider configurable DNS/domain logging if `domains.log` becomes high churn.

These changes should be benchmarked with `/system` before and after implementation to verify actual storage impact.
