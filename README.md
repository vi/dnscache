Dnscache
----

Simple DNS proxy supporting one upstream.
Designed for using slow and unreliable upstream DNS servers like Tor's DNS resolver.
Trades consistency for availability. Not for serious use.

License = MIT or Apache 2.0

There are some pre-built versions on Github releases. Versions further than 0.1.2 have no command-line-user-facing benefits yet.

DNSCache can also be used as a library (with your own database and network abstraction, but with DNS packets still as byte blobs).

---

```
dnscache 0.1.3
Vitaly _Vi Shukela <vi0oss@gmail.com>
Simple DNS cacher.

USAGE:
    dnscache [OPTIONS] <listen_addr> <upstream_addr> <db>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --max-ttl <max_ttl>    Maximum TTL of A or AAAA entry, seconds [default: 4294967295]
        --min-ttl <min_ttl>    Minimum TTL of A or AAAA entry, seconds [default: 0]
        --neg-ttl <neg_ttl>    Negative reply TTL, seconds [default: 30]

ARGS:
    <listen_addr>      Listen address and port
    <upstream_addr>    Upstream DNS server address and port
    <db>               Path to LevelDB database directory
```

-----

Features:

* IPv6 AAAA records
* Forwarding of trickier queries as is
* Multi-question queries
* Minimal protection from poisoning by filtering domain names in replies
* Always tries to immediately return some A or AAAA records for client to try, no waiting for refreshing.
* Clamping TTL betwen user-specified min and max (the cache contains unmodified value).

Notes:

* It does not construct DNS requests on its own, it reuses client-constructed packets
* Uncached queries (non-A, non-AAAA or non-IN) are forwarded based in ID
* TTL may be 0 in replies
* Single threaded, single UDP socket
* If all A or AAAA entries disappear in reply, cached ones retain instead. AAAA resolution sometimes works in Tor DNS resolver, sometimes not.
* CNAMEs are resolved recursively into A/AAAA entries and are not persisted
* Unsupported queries (MX, All) are forwarded as-is based on ID only

Concerns:

* Entries are never deleted from cache
* If data is stale, it first replies with TTL 0, then re-checks in upstream
* The used LevelDB implementation is not recommended for serious use yet.
* The same socket used both for client and for upstream communication. Can't listen only on 127.0.0.1, but rely on 8.8.8.8.

---

Database format: LevelDB database with domain names like `internals.rust-lang.org` as keys and [CBOR](https://cbor.io) as values. Sample value:

```
{"a4": {"t": 1513810855, "a": [{"ttl": 599, "ip": h'4047a8d3'}]}, "a6": {"t": 1513810855, "a": [{"ttl": 599, "ip": h'20010470000103a80000000000000211'}]}}

00000000  a2 62 61 34 a2 61 74 1a  5a 3a eb a7 61 61 81 a2  |.ba4.at.Z:..aa..|
00000010  63 74 74 6c 19 02 57 62  69 70 44 40 47 a8 d3 62  |cttl..WbipD@G..b|
00000020  61 36 a2 61 74 1a 5a 3a  eb a7 61 61 81 a2 63 74  |a6.at.Z:..aa..ct|
00000030  74 6c 19 02 57 62 69 70  50 20 01 04 70 00 01 03  |tl..WbipP ..p...|
00000040  a8 00 00 00 00 00 00 02  11                       |.........|
00000049
```

Simple description:

```
{"a4": {"t": timestamp_unix, "a":[IPv4/TTL pairs list]}, "a6": null (for never requested values)}
{"t": ..., "a":[(empty list)]} means negatively cached
```

The format is subject to change.

