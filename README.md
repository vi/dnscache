Dnscache
----

Simple DNS proxy supporting one upstream.
Designed for using slow and unreliable upstream DNS servers like Tor's DNS resolver.
Trades consistency for availability. Not for serious use.

License = MIT or Apache 2.0

There are some pre-built versions on Github releases.

---

```
dnscache 0.1.2
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
{"a4": [1513726378, [[[64, 71, 168, 211], 599]]], "a6": [1513726378, [[[32, 1, 4, 112, 0, 1, 3, 168, 0, 0, 0, 0, 0, 0, 2, 17], 599]]]}

00000000  a2 62 61 34 82 1a 5a 39  a1 aa 81 82 84 18 40 18  |.ba4..Z9......@.|
00000010  47 18 a8 18 d3 19 02 57  62 61 36 82 1a 5a 39 a1  |G......Wba6..Z9.|
00000020  aa 81 82 90 18 20 01 04  18 70 00 01 03 18 a8 00  |..... ...p......|
00000030  00 00 00 00 00 02 11 19  02 57                    |.........W|
0000003a
```

Simple description:

```
{"a4": [timestamp_unix, [IPv4/TTL pairs list]], "a6": null (for never requested value)}
```

The format is subject to change.

