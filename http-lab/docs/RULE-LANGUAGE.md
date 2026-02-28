# http-lab Rule Expression Language

**Status:** Implemented — live in detection pipeline
**Date:** February 28, 2026

## Overview

A composable Lisp-like expression language for L7 WAF rules. Rules are EDN (Extensible Data Notation) s-expressions with parameterized accessors, typed values, and multiple operators. The detection pipeline generates rules autonomously using this language, and the expression tree compiler evaluates them in sub-microsecond time.

## Matchable Field Inventory

Every field available on the Walkable structs (`TlsContext` and `RequestSample`) is a potential rule target. This section enumerates them all.

### TLS Fields (from `TlsContext` Walkable)

| Walkable Key | Type | Source | Description |
|---|---|---|---|
| `record_version` | Scalar(String) | `self.record_version` | Outer TLS record version, e.g. "TLS_1.0" |
| `version` | Scalar(String) | `self.handshake_version` | ClientHello version, e.g. "TLS_1.2" |
| `session_id_len` | Scalar(Int) | `self.session_id_len` | 0 or 32 (TLS 1.3 compat mode) |
| `ciphers` | **Set** | `self.cipher_suites` | Which cipher suites offered (order-independent) |
| `cipher_order` | **List** | `self.cipher_suites` | Exact cipher ordering (fingerprint gold) |
| `compression` | List | `self.compression_methods` | Compression methods (always [null] in TLS 1.3) |
| `ext_types` | **Set** | `self.extensions` | Which extension types present |
| `ext_order` | **List** | `self.extensions` | Exact extension ordering |
| `extensions` | **Map(name -> value)** | `self.extensions` | Per-extension parsed values (SNI, ALPN, versions, key_share, etc.) |
| `groups` | **Set** | `self.supported_groups` | Key exchange / elliptic curve groups |
| `sig_algs` | **Set** | `self.sig_algs` | Signature algorithms |
| `supported_versions` | List | `self.supported_versions` | TLS version negotiation list |
| `alpn` | List | `self.alpn` | ALPN protocols (h2, http/1.1, etc.) |
| `sni` | Scalar(String) | `self.sni` | Server Name Indication hostname |
| `ec_point_formats` | List | `self.ec_point_formats` | EC point format list |
| `psk_modes` | List | `self.psk_modes` | PSK key exchange modes |
| `key_shares` | **Set** | `self.key_share_groups` | Key share groups offered |
| `compress_certificate` | List | `self.compress_certificate` | Certificate compression algorithms |

### HTTP Fields (from `RequestSample` Walkable)

| Walkable Key | Type | Source | Description |
|---|---|---|---|
| `method` | Scalar(String) | `self.method` | HTTP method (GET, POST, etc.) |
| `path` | Scalar(String) | `self.path` | Full request path |
| `path_parts` | **List** | `self.path.split('/')` | Path segments (positional) |
| `version` | Scalar(String) | `self.version` | HTTP version (1.1, 2, etc.) |
| `query` | Scalar(String) | `self.query` | Raw query string |
| `query_parts` | **List(List\|Scalar)** | parsed query | Structured: pairs `["k","v"]`, flags `"k"`, empties `""` |
| `header_order` | **List** | `self.headers` | Header names in wire order |
| `headers` | **List of [name, value]** | `self.headers` | Full headers, ordered, dupes preserved |
| `header_count` | Scalar(numeric) | `self.headers.len()` | Number of headers |
| `cookies` | **List of [key, value]** | `self.cookies` | Parsed cookie pairs |
| `body_len` | Scalar(numeric) | `self.body_len` | Body size |
| `src_ip` | Scalar(String) | `self.src_ip` | Source IP address |
| `tls` | **nested Map** | `self.tls_ctx` | Entire TLS context (nested — accessible via tls-* accessors) |

### Implemented Dimension Coverage

The composable expression language (`expr.rs`) covers 26 field dimensions with full accessor chain support:

**HTTP Dimensions (11):**

| Dimension | Accessor | Notes |
|---|---|---|
| `src-ip` | scalar | Source IP address |
| `method` | scalar | HTTP method (GET, POST, etc.) |
| `path` | scalar | Full request path |
| `path-parts` | list, indexed via `(nth path-parts N)` | Path segments, positional |
| `host` | scalar | Host header |
| `user-agent` | scalar | User-Agent header |
| `content-type` | scalar | Content-Type header |
| `header-order` | list | Header names in wire order |
| `headers` | map, accessed via `(header "name")` | All headers, returns list of values |
| `cookies` | map, accessed via `(cookie "name")` | Cookie values, returns list |
| `query-params` | map, accessed via `(query "name")` | Query parameters, returns list of values |

**TLS Dimensions (15):**

| Dimension | Accessor | Notes |
|---|---|---|
| `tls-ciphers` | set | Cipher suites (order-independent) |
| `tls-cipher-order` | list | Cipher suites in wire order |
| `tls-ext-types` | set | Extension types present |
| `tls-ext-order` | list | Extension types in wire order |
| `tls-groups` | set | Key exchange groups |
| `tls-group-order` | list | Groups in wire order |
| `tls-sig-algs` | set | Signature algorithms |
| `tls-alpn` | list | ALPN protocols |
| `tls-sni` | scalar | SNI hostname |
| `tls-record-version` | scalar | Outer TLS record version |
| `tls-handshake-version` | scalar | ClientHello version |
| `tls-session-id-len` | scalar(numeric) | Session ID length |
| `tls-supported-versions` | list | Version negotiation list |
| `tls-psk-modes` | list | PSK key exchange modes |
| `tls-key-shares` | set | Key share groups |

**Shape dimensions** (`path_shape`, `query_shape`, `header_shapes`) are used internally by the VSA detection pipeline for shape-based anomaly attribution but are not yet exposed as directly matchable rule dimensions. The detection pipeline converts shape detections into `(= (count ...) N)` constraints using existing accessors.

**Not yet implemented**: `body_len`, `header_count`, per-extension values (`tls-extensions` map).

### Legacy FieldDim Coverage (superseded by expr.rs)

The legacy `FieldDim` enum provided 12 fixed dimensions with string equality only. These remain in the codebase for reference but are no longer used in the live detection/enforcement path:

| FieldDim | Maps to | Status |
|---|---|---|
| `SrcIp`, `Method`, `PathPrefix`, `Host`, `UserAgent`, `ContentType` | HTTP scalar fields | Superseded by `SimpleDim` |
| `TlsCipherHash`, `TlsExtOrderHash`, `TlsGroupHash` | TLS ordered fields | Superseded by `tls-cipher-order`, etc. |
| `TlsCipherSet`, `TlsExtSet`, `TlsGroupSet` | TLS set fields | Superseded by `tls-ciphers`, etc. |

### HTTP/2 Fields (from future `H2Context`)

HTTP/2 exposes connection-level metadata that is invisible after h2 demux — most WAFs discard it entirely. These fields are fingerprinting gold: the combination of SETTINGS values/order, WINDOW_UPDATE, PRIORITY topology, and pseudo-header order discriminates browsers from bots more reliably than TLS fingerprints in many cases.

| Field | Type | Description | Fingerprint Value |
|---|---|---|---|
| `h2-settings` | **Map(id -> value)** | SETTINGS frame key-value pairs | Chrome: `{0x1:65536, 0x2:0, 0x3:1000, 0x4:6291456, 0x6:262144}` |
| `h2-settings-order` | **List** | Order of setting IDs in SETTINGS frame | Chrome vs Firefox vs curl all differ |
| `h2-settings-keys` | **Set** | Which setting IDs are present | Some clients omit most settings |
| `h2-window-update` | Scalar(Number) | Initial connection-level WINDOW_UPDATE value | Chrome=15663105, unique per impl |
| `h2-priority-frames` | **List of tuples** | Stream dependency graph (stream, dep, weight, exclusive) | Browsers build characteristic trees; bots often omit entirely |
| `h2-has-priority` | Scalar(Bool) | Whether any PRIORITY frames were sent | Quick bot detection signal |
| `h2-priority-tree-depth` | Scalar(Number) | Depth of the stream dependency tree | Firefox=8 levels, Safari=flat |
| `h2-pseudo-order` | **List** | Order of pseudo-headers (`:method`, `:authority`, `:scheme`, `:path`) in first HEADERS frame | Chrome: `[:method :authority :scheme :path]`, Firefox: `[:method :path :authority :scheme]` |
| `h2-preface-frames` | **List** | Frame type sequence in connection preface | Chrome: `[SETTINGS WINDOW_UPDATE PRIORITY... HEADERS]`, curl: `[SETTINGS HEADERS]` |
| `h2-preface-frame-types` | **Set** | Which frame types appear in preface | `(exists h2-preface-frame-types "PRIORITY")` |
| `h2-huffman-encoding` | Scalar(Bool) | Whether client uses Huffman encoding for header values | HPACK implementation signal |
| `h2-dynamic-table-usage` | Scalar(Bool) | Whether client uses HPACK dynamic table | HPACK implementation signal |
| `h2-fingerprint` | Scalar(String) | Composite fingerprint: `settings_order:settings_values\|window_update\|priority_count\|pseudo_order` | Analogous to JA4 for TLS |

**Known per-implementation signatures:**

| Implementation | SETTINGS order | INITIAL_WINDOW_SIZE | WINDOW_UPDATE | Pseudo-header order | PRIORITY |
|---|---|---|---|---|---|
| Chrome/Edge | `0x1,0x2,0x3,0x4,0x6` | 6291456 | 15663105 | `:method :authority :scheme :path` | Yes (exclusive deps, weight 256) |
| Firefox | `0x1,0x4` | 131072 | none | `:method :path :authority :scheme` | Yes (8-level tree) |
| Safari | `0x3,0x4,0x1` | 4194304 | none | `:method :scheme :path :authority` | Yes (flat, weight 16) |
| curl | `0x1,0x3,0x4,0x5` | 16777215 | none | `:method :path :authority :scheme` | No |
| Python httpx | `0x1,0x3,0x4,0x5` | 16777215 | none | `:method :authority :scheme :path` | No |
| Go net/http | `0x1,0x4,0x5` | 4194304 | none | `:method :path :authority :scheme` | No |

**Capture strategy:** Intercept raw h2 frames before hyper's codec processes them, same approach as TLS ClientHello capture. Store in `H2Context` struct on `ConnectionContext`, shared via `Arc` across all requests on the connection.

### HTTP/3 Fields (from future `H3Context` / QUIC)

HTTP/3 runs over QUIC, which embeds TLS in its own framing. QUIC transport parameters are the L4 equivalent of both TLS extensions and HTTP/2 SETTINGS.

| Field | Type | Description |
|---|---|---|
| `quic-params` | **Map(name -> value)** | QUIC transport parameters (sent during handshake) |
| `quic-params-order` | **List** | Order of transport parameters |
| `quic-params-keys` | **Set** | Which transport parameters are present |
| `quic-initial-max-data` | Scalar(Number) | Connection-level flow control limit |
| `quic-initial-max-streams-bidi` | Scalar(Number) | Max concurrent bidirectional streams |
| `quic-initial-max-streams-uni` | Scalar(Number) | Max concurrent unidirectional streams |
| `quic-max-idle-timeout` | Scalar(Number) | Connection idle timeout (ms) |
| `quic-max-udp-payload-size` | Scalar(Number) | Max UDP datagram size |
| `quic-active-conn-id-limit` | Scalar(Number) | Max connection IDs |
| `h3-qpack-max-table-capacity` | Scalar(Number) | QPACK dynamic table capacity |
| `h3-qpack-blocked-streams` | Scalar(Number) | Max QPACK blocked streams |

### Derived / Composite Fields

| Field | Type | Description |
|---|---|---|
| `h2-fingerprint` | Scalar(String) | HTTP/2 fingerprint (settings + window + priority + pseudo order) |
| `protocol` | Scalar(String) | Negotiated protocol: `"h1"`, `"h2"`, `"h3"` |

Note: JA4 is intentionally excluded from the rule language. It's a lossy compression of TLS context — the full TLS fields (`tls-ciphers`, `tls-ext-types`, `tls-alpn`, etc.) are strictly more expressive. JA4 remains available on `TlsContext` for logging and external tool correlation, but rules should use the raw TLS accessors directly.

### The WAF Gap

Most WAFs — including commercial ones — operate on a post-demux HTTP/1.1-equivalent view:

```
What the client sends              What most WAFs see
──────────────────────              ──────────────────
TLS ClientHello                →   (maybe JA3/JA4)
H2 SETTINGS frame              →   *** discarded ***
H2 WINDOW_UPDATE                →   *** discarded ***
H2 PRIORITY frames              →   *** discarded ***
H2 pseudo-header order          →   *** discarded ***
H2 HPACK encoding choices       →   *** discarded ***
H2 frame sequence               →   *** discarded ***
QUIC transport parameters       →   *** discarded ***
HTTP headers                     →   headers (wire order lost in h2 demux)
HTTP body                        →   body
```

By capturing TLS, HTTP/2, and QUIC metadata before the respective codec processes it, the expression language can match on signals that are invisible to conventional WAFs. No additional expressive machinery is needed — the same `=`, `exists`, `prefix`, etc. operators work on h2/h3 fields identically to how they work on TLS and HTTP/1.1 fields.

## Proposed Expression Language

The language has three orthogonal concepts:

1. **Domain accessors** — raw data sources that know about protocol structure
2. **Generic functions** — composable transforms that work on any value type
3. **Operators** — test predicates that produce true/false

These compose naturally: `(= (first (header "host")) "example.com")` applies the operator `=` to the result of composing the generic function `first` with the domain accessor `(header "host")`.

No magic named shortcuts (no `host`, `user-agent`, `content-type`). Every field is accessed through the same uniform mechanisms. Adding a new protocol layer means adding new domain accessors — the generic functions and operators are reused unchanged.

### Grammar

```
Expr ::= (operator accessor value)
       | (operator accessor)

;; An accessor is either a bare field, a domain function, or a composition of generic functions:
Accessor ::= field                            ;; bare:      method, path, headers, tls-ciphers
           | (domain-fn arg)                  ;; domain:    (header "host"), (cookie "sid"), (query "page")
           | (generic-fn accessor)            ;; composed:  (first (header "host")), (count headers)
           | (generic-fn accessor arg)        ;; composed:  (nth path-parts 2), (get h2-settings "KEY")
```

### Domain Accessors

These are the raw data sources. Each knows how to extract data from the request/connection context. They are organized by protocol layer.

```
;; =====================================================================
;; HTTP layer — request line + headers + query + cookies + body
;; =====================================================================

;; Scalar fields (return a single value):
method                                ;; -> String       "GET", "POST", etc.
path                                  ;; -> String       full request path
src-ip                                ;; -> String       source IP address
body-len                              ;; -> Number       body size in bytes
protocol                              ;; -> String       "h1", "h2", "h3"

;; Pair-list fields (ordered list of [key, value] pairs — dupes preserved):
headers                               ;; -> List<[String, String]>   all headers, wire order
cookies                               ;; -> List<[String, String]>   parsed cookie pairs
query-params                          ;; -> List<[String, String]>   query key=value pairs

;; Collection fields:
header-order                          ;; -> List<String>  header names in wire order
path-parts                            ;; -> List<String>  path split by '/'
query-flags                           ;; -> List<String>  query params with no '=' (bare flags)
query-raw                             ;; -> String        raw query string

;; Parameterized accessors (filter pair-lists by key, return values):
(header "name")                       ;; -> List<String>  all values for this header
(cookie "name")                       ;; -> List<String>  all values for this cookie key
(query "name")                        ;; -> List<String>  all values for this query param

;; =====================================================================
;; TLS layer — from ClientHello (captured before rustls)
;; =====================================================================

;; Scalar:
tls-version                           ;; -> String       ClientHello version, e.g. "TLS_1.2"
tls-record-version                    ;; -> String       outer record version
tls-session-id-len                    ;; -> Number       0 or 32
sni                                   ;; -> String       Server Name Indication

;; Set (order-independent):
tls-ciphers                           ;; -> Set<String>   cipher suites offered
tls-ext-types                         ;; -> Set<String>   extension types present
tls-groups                            ;; -> Set<String>   key exchange groups
tls-sig-algs                          ;; -> Set<String>   signature algorithms
tls-key-shares                        ;; -> Set<String>   key share groups

;; List (order matters — fingerprint signal):
tls-cipher-order                      ;; -> List<String>  cipher suites, wire order
tls-ext-order                         ;; -> List<String>  extension types, wire order
tls-alpn                              ;; -> List<String>  ALPN protocols
tls-versions                          ;; -> List<String>  supported TLS versions
tls-psk-modes                         ;; -> List<String>  PSK modes
tls-compression                       ;; -> List<String>  compression methods

;; Map:
tls-extensions                        ;; -> Map<String, Value>  per-extension parsed values

  ;; =====================================================================
;; HTTP/2 layer (future — from H2Context, captured before h2 codec)
;; =====================================================================

;; Scalar:
h2-window-update                      ;; -> Number       initial connection WINDOW_UPDATE
h2-has-priority                       ;; -> Bool         any PRIORITY frames sent?
h2-priority-tree-depth                ;; -> Number       stream dependency tree depth
h2-huffman-encoding                   ;; -> Bool         client uses Huffman in HPACK?
h2-dynamic-table-usage                ;; -> Bool         client uses HPACK dynamic table?
h2-fingerprint                        ;; -> String       composite fingerprint

;; Map:
h2-settings                           ;; -> Map<String, Number>  SETTINGS frame key-value pairs

;; List:
h2-settings-order                     ;; -> List<String>  SETTINGS param IDs in wire order
h2-pseudo-order                       ;; -> List<String>  pseudo-header order in first HEADERS
h2-preface-frames                     ;; -> List<String>  frame type sequence in preface

;; Set:
h2-preface-frame-types                ;; -> Set<String>   which frame types in preface

;; =====================================================================
;; HTTP/3 / QUIC layer (future — from H3Context)
;; =====================================================================

;; Map:
quic-params                           ;; -> Map<String, Number>  QUIC transport parameters

;; List:
quic-params-order                     ;; -> List<String>  transport param order

;; Set:
quic-params-keys                      ;; -> Set<String>   which transport params present

;; Scalar:
h3-qpack-max-table-capacity           ;; -> Number
h3-qpack-blocked-streams              ;; -> Number
```

### Generic Functions

These compose with any accessor or with each other. They are the equivalent of Clojure's core sequence/collection functions — stable, generic, reusable across all protocol layers.

```
;; --- Element access ---
(first coll)                          ;; -> element      first element of list
(last coll)                           ;; -> element      last element of list
(nth coll n)                          ;; -> element      element at index (0-based, negative indexes from end)
(get map key)                         ;; -> value        map lookup by key

;; --- Pair decomposition (Clojure's key/val on map entries) ---
(key entry)                           ;; -> element      key of a pair (first element)
(val entry)                           ;; -> element      value of a pair (second element)

;; --- Info ---
(count coll)                          ;; -> Number       number of elements (List, Set, Map)
(count str)                           ;; -> Number       string length (character count)

;; --- Collection transformation ---
(keys coll)                           ;; -> List         all keys from a map or pair-list
(vals coll)                           ;; -> List         all values from a map or pair-list
(set list)                            ;; -> Set          list to set (dedupe, lose order)

;; --- String transformation ---
(lower str)                           ;; -> String       lowercase
```

### Value Literals

```
"string"                              ;; string literal
42                                    ;; integer literal
true / false                          ;; boolean literal
["a", "b", "c"]                       ;; ordered list
#{"a", "b", "c"}                      ;; set (unordered, unique)
```

### What Generic Functions Eliminate

No magic named shortcuts. Every "convenience" field is a composition:

| Old (magic shortcut) | New (composable) |
|---|---|
| `(= host "example.com")` | `(= (first (header "host")) "example.com")` |
| `(= user-agent "bot/1.0")` | `(= (first (header "user-agent")) "bot/1.0")` |
| `(= content-type "application/json")` | `(= (first (header "content-type")) "application/json")` |
| `(= (header-first "x-fwd") "1.2.3.4")` | `(= (first (header "x-forwarded-for")) "1.2.3.4")` |
| `(> header-count 50)` | `(> (count headers) 50)` |
| `(exists header-names "x-debug")` | `(exists (set header-order) "x-debug")` |
| `(exists cookie-names "session")` | `(exists (keys cookies) "session")` |
| `(exists query-keys "debug")` | `(exists (keys query-params) "debug")` |
| `(= (h2-setting "WINDOW") 6291456)` | `(= (get h2-settings "INITIAL_WINDOW_SIZE") 6291456)` |
| `(= (quic-param "max_bidi") 100)` | `(= (get quic-params "initial_max_streams_bidi") 100)` |

Note the singular/plural distinction (from Clojure's `key`/`val` on map entries):
- `(key entry)` / `(val entry)` — decompose **one pair** into its key or value
- `(keys coll)` / `(vals coll)` — extract **all keys or values** from a pair-list or map

### Expression Examples

```clojure
;; =====================================================================
;; HTTP request matching
;; =====================================================================

;; Simple scalar equality
(= method "POST")
(= src-ip "10.0.0.1")
(= path "/api/v1/login")

;; Header access via (first (header ...)) — replaces magic named headers
(= (first (header "host")) "example.com")
(= (first (header "user-agent")) "python-requests/2.31.0")
(= (first (header "content-type")) "application/json")

;; Multi-valued header — check if any value matches
(exists (header "x-forwarded-for") "10.0.0.1")

;; Header ordering (wire order fingerprint)
(= header-order ["host" "user-agent" "accept" "accept-encoding"])

;; Header existence
(exists (set header-order) "x-debug")

;; Query string access — same pattern as header and cookie
(= (first (query "page")) "1")
(exists (keys query-params) "debug")
(exists query-flags "verbose")

;; Cookie access
(= (first (cookie "session")) "abc123")
(exists (keys cookies) "tracking")

;; Path segment access
(= (nth path-parts 1) "api")
(exists path-parts "admin")

;; Numeric comparisons via generic functions
(> (count headers) 50)
(> body-len 10000)
(< (count query-params) 2)

;; =====================================================================
;; Query structure matching (compositional — no special "shape" accessor)
;; =====================================================================

;; Two access paths to query data — by name or by position:
;;
;; By name (key lookup, returns all values — like headers):
;;   (query "ary")  on ?x=1&ary=1&ary=2  -> ["1", "2"]
;;
;; By position (wire order, structural patterns):
;;   query-params   on ?x=1&ary=1&ary=2  -> [["x","1"], ["ary","1"], ["ary","2"]]
;;   (key (last query-params))            -> "ary"
;;   (val (last query-params))            -> "2"

;; ?user=admin&xyzabcdefg&abcdefghij  (1 param, 2 random-looking flags)
;; query-params -> [["user", "admin"]]
;; query-flags  -> ["xyzabcdefg", "abcdefghij"]
(= (count query-flags) 2)
(= (count (first query-flags)) 10)
(= (count (last query-flags)) 10)

;; ?user=admin&xyzabcdefg=abcdefghij  (last param has 10-char key AND 10-char value)
;; query-params -> [["user", "admin"], ["xyzabcdefg", "abcdefghij"]]
(= (count (key (last query-params))) 10)       ;; key length
(= (count (val (last query-params))) 10)       ;; value length

;; second-to-last flag is also 10 chars (negative indexing)
(= (count (nth query-flags -2)) 10)

;; key/val work on any pair-list entry (headers, cookies, query-params):
(= (key (last headers)) "x-custom")            ;; last header name
(> (count (val (first cookies))) 100)           ;; first cookie value > 100 chars

;; String functions
(prefix path "/api/v1")
(suffix path ".php")
(contains (lower (first (header "user-agent"))) "bot")

;; =====================================================================
;; TLS fingerprinting
;; =====================================================================

;; Set equality (proper set literal, not comma-joined string)
(= tls-ciphers #{"TLS_AES_128_GCM_SHA256" "TLS_AES_256_GCM_SHA384"})
(= tls-ext-types #{"server_name" "supported_groups" "ec_point_formats"})
(= tls-groups #{"x25519" "secp256r1"})

;; List equality (order matters)
(= tls-cipher-order ["TLS_AES_128_GCM_SHA256" "TLS_CHACHA20_POLY1305_SHA256"])

;; Membership
(exists tls-alpn "h2")
(exists tls-versions "TLS_1.3")
(exists tls-psk-modes "psk_dhe_ke")

;; TLS extension map access
(exists (get tls-extensions "alpn") "h2")

;; Convert ordered to set (ignore ordering)
(= (set tls-cipher-order) #{"TLS_AES_128_GCM_SHA256" "TLS_AES_256_GCM_SHA384"})

;; Set operations
(subset tls-ciphers #{"TLS_AES_128_GCM_SHA256" "TLS_AES_256_GCM_SHA384"})
(superset tls-ext-types #{"server_name" "supported_groups"})

;; =====================================================================
;; HTTP/2 fingerprinting (future)
;; =====================================================================

;; SETTINGS values via (get map key)
(= (get h2-settings "INITIAL_WINDOW_SIZE") 6291456)
(= (get h2-settings "HEADER_TABLE_SIZE") 65536)

;; SETTINGS ordering
(= h2-settings-order ["HEADER_TABLE_SIZE" "ENABLE_PUSH" "MAX_CONCURRENT_STREAMS"
                       "INITIAL_WINDOW_SIZE" "MAX_HEADER_LIST_SIZE"])

;; Connection-level signals
(= h2-window-update 15663105)
(= h2-has-priority false)

;; Pseudo-header order (browser fingerprint)
(= h2-pseudo-order [":method" ":authority" ":scheme" ":path"])

;; Frame sequence
(exists h2-preface-frame-types "PRIORITY")

;; Composite fingerprint
(= h2-fingerprint "1,2,3,4,6:65536,0,1000,6291456,262144|15663105|5|masp")

;; =====================================================================
;; HTTP/3 / QUIC (future)
;; =====================================================================

(= (get quic-params "initial_max_streams_bidi") 100)
(exists quic-params-keys "max_idle_timeout")

;; =====================================================================
;; Protocol-level rules
;; =====================================================================

(= protocol "h2")
(= protocol "h1")

;; =====================================================================
;; Advanced: regex, negation
;; =====================================================================

(regex (first (header "user-agent")) "python-requests/\\d+\\.\\d+")
(regex path "/api/v[0-9]+/users")
(not (= method "GET"))
```

## Operators

### Tier 1: Tree-Native (O(1) or bounded fan-out)

These operators map cleanly to the Rete-spirit DAG's HashMap branching model.

| Operator | Signature | Semantics | Tree Mapping |
|---|---|---|---|
| `=` | `(= accessor value)` | Exact equality. String=String, List=List (order matters), Set=Set (order-independent) | HashMap lookup on canonical value — O(1) |
| `exists` | `(exists collection value)` | Membership: is value in the collection? | Fan-out: check each element of runtime collection against children — O(n), n = collection size |

**`=` in the tree:** At the dimension's tree level, extract the value from the request, canonicalize it (sorted string for sets, bracket-joined for lists), look up in `children` HashMap. Same as today but with proper typed serialization.

**`exists` in the tree:** At the dimension's tree level, extract the collection, iterate elements, check each against `children` HashMap. Multiple children may match — the evaluator picks the best (highest `Specificity`). Collection sizes are bounded: typically 5-20 headers, 1-5 query params, 10-30 TLS extensions.

### Tier 2: Guard Predicates (linear work)

These cannot be HashMap edge keys. They require either linear-scan edges at their tree level, or post-match guard evaluation on terminal nodes.

| Operator | Signature | Semantics | Cost |
|---|---|---|---|
| `>` | `(> accessor number)` | Greater than (numeric) | Linear scan of range edges |
| `<` | `(< accessor number)` | Less than | Linear scan |
| `>=` | `(>= accessor number)` | Greater or equal | Linear scan |
| `<=` | `(<= accessor number)` | Less or equal | Linear scan |
| `prefix` | `(prefix accessor string)` | String starts with | Linear scan (or trie at that level) |
| `suffix` | `(suffix accessor string)` | String ends with | Linear scan |
| `contains` | `(contains accessor string)` | Substring / element contains | Linear scan |
| `regex` | `(regex accessor pattern)` | Regex match | Linear scan, pre-compiled regex |
| `not` | `(not expr)` | Negation | Cannot branch — filter on parent |
| `subset` | `(subset set-accessor set-value)` | Value set is subset of runtime set | Set comparison |
| `superset` | `(superset set-accessor set-value)` | Value set is superset of runtime set | Set comparison |
| `has-key` | `(has-key map-accessor key)` | Map contains key | Similar to `exists` |

### Implementation Strategy for Tier 2

Two options (not mutually exclusive):

**Option A: Range/filter edges on tree nodes.** Add a `filters: Vec<FilterEdge>` field to `TreeNode`. After the HashMap lookup for tier-1 predicates, iterate filters and check each. Similar to veth-lab's `MaskEq` range edges. Good for `>`, `<`, `prefix` where the number of filter edges per node is small.

**Option B: Post-match guards on terminals.** Match the tree using only tier-1 dimensions. Terminal nodes carry a `guards: Vec<Expr>` list. After tree traversal finds a candidate terminal, evaluate guards sequentially. If any guard fails, the match is rejected and the evaluator continues searching. Good for `regex`, `not`, complex predicates that don't benefit from tree structure.

## Dimension Identity and DIM_ORDER

### Current: Static

```rust
pub const DIM_ORDER: [FieldDim; 12] = [
    SrcIp, TlsGroupHash, TlsCipherHash, TlsExtOrderHash,
    TlsCipherSet, TlsExtSet, TlsGroupSet,
    Method, PathPrefix, Host, UserAgent, ContentType,
];
```

### Proposed: Dynamic, Discrimination-Optimized

With parameterized accessors like `(header "x-forwarded-for")`, the dimension set is open-ended. DIM_ORDER becomes computed at compile time from the active rule set.

**Ordering policy** (applied at each compilation):

1. Collect all unique `Dimension` values from all active rules
2. Rank by discrimination power:
   - **Primary**: number of rules that constrain this dimension (more rules = closer to root, higher branching factor)
   - **Secondary**: value cardinality at this dimension (more unique values across rules = better fan-out)
   - **Tertiary**: layer tiebreaker: TLS > H2 > HTTP request line > HTTP headers > HTTP query/cookies > body
3. Build tree with only the dimensions that appear

The goal is to prune non-matching branches as early as possible. A dimension that appears in 5 of 6 rules should be near the root — most requests will either match or miss early, avoiding deeper traversal.

This is orthogonal to the evaluation pipeline ordering (see below).

### Evaluation Pipeline Stages

The tree's DIM_ORDER optimizes for discrimination within a single evaluation. The pipeline controls **when** to evaluate — enabling early rejection before parsing later protocol layers:

```
Stage 1: TLS accept (connection start)
  -> evaluate_tls() against TLS-only rules
  -> Can reject before HTTP parsing (saves CPU)
  -> Data: TlsContext only

Stage 2: H2 connection preface (future)
  -> evaluate_h2() against TLS + H2 rules
  -> Can reject before first HTTP request
  -> Data: TlsContext + H2Context

Stage 3: Request line + headers received
  -> evaluate_req() against full rule tree
  -> Reject / rate-limit / pass
  -> Data: TlsContext + H2Context + RequestSample

Stage 4: Body complete (future, phase 2)
  -> evaluate_body() against body-inspection rules
  -> Final verdict after full inspection
  -> Data: all of the above + body bytes
```

Each stage calls the evaluator with the data available at that point. Rules that only constrain TLS fields are evaluated at stage 1 — no need to wait for HTTP parsing. Rules that mix TLS + HTTP are evaluated at stage 3. The Specificity ranking ensures the most surgical match wins across stages.

Currently implemented: stages 1 and 3 (`evaluate_tls` and `evaluate_req`). Stages 2 and 4 are future work (HTTP/2 support and body inspection respectively).

The `Dimension` type replaces `FieldDim`. It represents the **resolved accessor** — the full composition chain evaluated to a concrete extraction:

```rust
enum Dimension {
    // Simple (bare field name):
    Simple(SimpleDim),         // Method, Path, SrcIp, TlsCiphers, H2SettingsOrder, etc.

    // Parameterized (domain accessor + argument):
    Header(String),            // (header "name") -> List<String>
    Cookie(String),            // (cookie "name") -> List<String>
    Query(String),             // (query "name")  -> List<String>

    // Composed (generic function applied to another dimension):
    First(Box<Dimension>),     // (first (header "host")) -> String
    Last(Box<Dimension>),      // (last (header "host"))  -> String
    Nth(Box<Dimension>, i32),  // (nth path-parts 2), (nth query-flags -1)
    Get(Box<Dimension>, String),// (get h2-settings "KEY") -> Value
    Key(Box<Dimension>),       // (key (last query-params)) -> String
    Val(Box<Dimension>),       // (val (last query-params)) -> String
    Count(Box<Dimension>),     // (count headers)         -> Number
    Keys(Box<Dimension>),      // (keys cookies)          -> List
    Vals(Box<Dimension>),      // (vals cookies)          -> List
    SetOf(Box<Dimension>),     // (set header-order)      -> Set
    Lower(Box<Dimension>),     // (lower ...)             -> String
}
```

`Dimension` needs `Eq + Hash + Clone + Ord` for tree node identity. Two rules using `(first (header "host"))` resolve to the same `Dimension::First(Box::new(Dimension::Header("host".into())))` and share the same tree level.

### TreeNode Changes

```rust
pub struct TreeNode {
    dim: Dimension,              // was FieldDim — now supports composed accessors
    match_mode: MatchMode,       // how to branch at this level
    children: HashMap<String, usize>,
    wildcard: Option<usize>,
    action: Option<(RuleAction, u32, Specificity)>,
    guards: Vec<Expr>,           // tier-2 post-match predicates (terminal nodes only)
}

enum MatchMode {
    Exact,       // extract single value, children.get() — O(1)
    Membership,  // extract collection, check each element against children — O(n)
}
```

The `MatchMode` is determined by the accessor's return type:
- Scalar (String, Number, Bool) → `Exact`
- Collection (List, Set) with `exists` operator → `Membership`
- Collection with `=` operator → `Exact` (canonicalized to string for HashMap key)

## Detection Pipeline Bridge (Implemented)

The detection pipeline generates `RuleExpr` values directly using the composable expression language. It uses a controlled subset of the full language:

**Auto-generated constraints from FieldTracker concentration:**
- `(= path "/api/search")` — scalar equality on concentrated fields
- `(= method "POST")` — scalar equality
- `(= (first (header "user-agent")) "libwww-perl/6.72")` — parameterized header access
- `(= (first (header "content-type")) "application/json")` — accessor chain composition
- `(= tls-ext-types #{"0x0000" ...})` — TLS set equality

**Auto-generated constraints from VSA surprise probing:**
- `(= (nth path-parts 1) "api")` — positional path segment (Content detection)
- `(= (count (nth path-parts 2)) 5)` — segment length (Shape detection)
- `(= (first (header "user-agent")) "Scrapy/2.11.0 ...")` — header content from surprise

**Constraint merging:** When both FieldTracker and surprise probing detect the same field (e.g., user-agent), the FieldTracker result takes priority (more observations). Surprise probing fills in fields that FieldTracker doesn't cover (path segments, shape patterns, non-scalar-tracked headers).

The richer expressions (`exists`, `prefix`, `regex`, guards) are available for human-authored rules. The detection pipeline could be extended to use them — e.g., `(prefix path "/api/")` when multiple paths share a prefix — but the current approach of exact matches is more surgical.

## Extensibility Model

The language is designed for stability at the core with open-ended extension at the edges — the same philosophy as Clojure's core library.

### What is stable (the "core")

Three orthogonal concepts, each independently stable:

- **Value types**: String, Number, Bool, List, Set. Every accessor returns one, every operator consumes one. Adding HTTP/2 doesn't require new value types.
- **Operators**: `=`, `exists`, `>`, `<`, `prefix`, `contains`, `regex`, `not`, `subset`, `superset`. Generic over value types. Adding new protocol fields doesn't require new operators.
- **Generic functions**: `first`, `last`, `nth`, `get`, `count`, `keys`, `vals`, `set`, `lower`. Work on any value type. These replace all magic shortcuts and compose freely with any domain accessor.

These three sets are small, well-defined, and closed. They don't grow when new protocol layers are added.

### What extends (the "surface area")

New protocol support means adding new **domain accessors** — nothing else:

- **HTTP**: `method`, `path`, `headers`, `(header "name")`, `(cookie "name")`, `(query "name")`, ...
- **TLS**: `tls-ciphers`, `tls-ext-types`, `sni`, `tls-extensions`, ...
- **HTTP/2**: `h2-settings`, `h2-pseudo-order`, `h2-preface-frames`, ...
- **HTTP/3**: `quic-params`, `quic-params-keys`, ...
- **Future**: `body-entropy`, `geo-country`, `asn`, ...

Each new domain accessor is:
1. A name (kebab-case convention)
2. A return type (one of the existing value types)
3. An extraction function (how to pull the value from the request context)

No new syntax, no new operators, no new generic functions.

The three parameterized domain accessors — `(header "name")`, `(cookie "name")`, `(query "name")` — are the uniform pattern for filtering pair-lists by key. They all return `List<String>` (values for that key). Adding a new pair-list field in the future (e.g., form parameters from POST body) means adding `(form-param "name")` — same shape, same return type, same generic functions apply.

Generic functions compose with domain accessors to produce anything that used to require a special-case field:

```clojure
;; "host" is not a field — it's a composition:
(first (header "host"))

;; "header-count" is not a field — it's a composition:
(count headers)

;; "h2-setting WINDOW_SIZE" is not a field — it's a composition:
(get h2-settings "INITIAL_WINDOW_SIZE")

;; "query-keys" is not a field — it's a composition:
(keys query-params)
```

### What this means for the tree compiler

The tree compiler is generic over `Dimension` (the resolved accessor chain) and `MatchMode` (exact vs membership). Adding new domain accessors means:

1. Add extraction logic for the new raw field
2. Composed accessors (`first`, `get`, `nth`, etc.) are handled generically by the `Dimension` enum's `extract()` method — no per-accessor code needed

The tree compiler, DFS evaluator, specificity ranking, and serialization are all unchanged. A rule using `(= (first (header "x-custom")) "value")` compiles to a tree node with `Dimension::First(Header("x-custom"))` and `MatchMode::Exact` — no special handling required.

### What this means for the detection pipeline

The detection pipeline discovers anomalous fields and generates rules. Adding HTTP/2 support means:

1. Add `H2Context` to the Walkable encoding (new fields in the vector space)
2. Add h2 field names to the FieldTracker (concentration tracking)
3. Map surprised h2 fields to rule accessors (same as TLS field mapping today)

The CCIPCA scoring, concentration detection, engram library, and rule lifecycle are all unchanged.

## Open Questions

### Language design
- Should `prefix` be tier 1 (tree-native via trie) or tier 2 (guard)? Path prefix matching is extremely common in WAF rules.
- Do we need `and` / `or` combinators, or is the implicit conjunction (all constraints must match) sufficient?
- Should `nil`/absence be a value? E.g. `(= (first (header "x-custom")) nil)` to match "header not present". Or is `(not (exists (set header-order) "x-custom"))` sufficient?
- Do we need `(take n list)` / `(drop n list)` / `(slice list start end)` for subsequence matching? Could be useful for "first 3 headers match" rules.

### Tree compilation
- Composed dimensions like `(first (header "host"))` resolve at compile time. Should the tree cache extraction results per-request to avoid re-extracting the same raw data for multiple composed dimensions that share a base accessor?
- When multiple rules use `(header "x-forwarded-for")` with different generic functions applied (`first` vs `exists`), do they share a tree dimension or get separate levels?

### Protocol capture
- HTTP/2 frame capture: intercept before hyper's h2 codec, or hook into hyper's internal events? Pre-codec gives raw bytes (like TLS), post-codec is easier but may lose ordering info.
- HTTP/2 PRIORITY is deprecated (RFC 9113) in favor of Extensible Priorities (RFC 9218). Support both? The deprecation itself is a fingerprint signal — modern browsers still send PRIORITY frames.
- QUIC transport parameter capture requires a different TLS integration (parameters are embedded in the TLS handshake via extension 0x0039). How does this interact with the existing ClientHello parser?

### Composite fields
- Should `h2-fingerprint` be a single opaque string or structured fields matched independently? Opaque is simpler for quick matching, structured is more expressive. Leaning toward structured (individual h2 accessors already exist), with the composite string available for logging only — same decision as JA4.
- Should `(form-param "name")` be a domain accessor for POST body form parameters? Requires body inspection (phase 2).
