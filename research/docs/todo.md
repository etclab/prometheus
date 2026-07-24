- Done - how do I build and run a local copy of p8s?
- Done - how do I create a simple Go server as a scrape target?
- Done - how do i run the average over time range query against the locally built and deployed p8s?
- Done - a script that creates the required timecrypt keying material
    - Done - who creates the keys? a trusted authority for now
    - Done - what kind of keys are created? public, private keys, symmetric keys? 
- Done - does TimeCrypt only support encrypting integer data? - yes but floats can be converted to integer
- Does scrape target reads the keying material and encrypts (& computes) the values for the timeseries?
- Done - for plaintext eval
    - Done - disable alerting mechanism completely in Prometheus
    - Done - make trusted querier read the alerting rule, and then run the rule against Prometheus periodically
    - Done - send only the aggregate part of the rule to Prometheus and not the threshold comparison portion (all of this can be done without any of the TimeCrypt changes)
    - Done - YES - can I see alerts in my logs?

- Done - encrypt the (label,value) pairs too, not just the values
    - Done - Hermes (eprint 2025/701) ported to Go now lives in ../Hermes/hermes-go
    - Done - keytool generates the shared hermes.seed alongside the TimeCrypt seeds
    - Done - myapp is a Hermes *writer*: exposes enc_series{sid="..."} only, real
      labels go into the encrypted index. Two instances = two writer classes.
    - Done - the engine runs inside Prometheus (tsdb/hermes); a selector carries
      encrypted searches as `enc_series{__hermes__="q0,q1"}` + POSTed aggregate keys
    - Done - timecrypteval is the Hermes *reader*: it is the only party that can
      turn a label matcher into a search
- the encrypted index is in-memory only: no WAL, no replay. Restart myapp whenever
  Prometheus restarts. Should it be persisted, and what does that leak?
- all roles derive the authority from one seed, so Prometheus can derive keys it
  should not hold. Needs per-role key serialization in hermes-go.
- job/instance are still plaintext because *Prometheus* attaches them at scrape
  time. Does a push/remote-write path fix this, and what does it cost?
- epochs never advance. What does forward privacy actually buy here?
- only equality matchers can be searched. Is there anything sane to do for regex?

- Later - I need to run alert manager separately somehow.
- Later - how does Prometheus creates a new stream (stream ID) for a distinct combination of labels?

- how are keys (kdf trees) for different streams created?
- where are the keys (kdf trees) for the streams stored?
    - if streams owners only create these trees then the true master seeds must be only known by the scrape targets/data owner
- look into how the float to int conversion works?
    - what is transport.go doing in timecrypt-go?
- does the filtering, selection over 1m work as expected? is this even working?
- what is the chunk size here?
- there should be a running log of actual values being emitted by `myapp` and the decrypted values that I can correlate somehow
- how are the scrape configs/static configs (from prometheus.yaml file) added to Prometheus?
    - how is it read and how it gets added to the index?
    - are label=value pairs always fixed? what if a scrape target creates label=value pairs on the fly? is this even possible?
- what does Prometheus do with the rules defined in the alerts.yaml file?

- because of the companion timeID are we running two queries for one sample?
    - one to get the exact timeID and other for the sample values
- timeID is incremented per /metrics GET, so any extra reader (a browser refresh, a
  second scraper) steals ids and a myapp restart replays them onto fresh plaintext
  (HEAC blinds additively => key reuse leaks m1-m2). Should the target sample on its
  own clock, or derive timeID from wall time and drop the companion series?
- for missing values or resets who does the interpolation? Prometheus?
- Prometheus will auto add job(myapp), and instance (localhost:2112) labels when it receives samples from scrape target 
for the first time and creates the series. These are read from `scrape_configs`, okay.

- https://claude.ai/chat/d8890299-fc1e-457f-91c0-b32f3c69c525

- two different kinds of aggregation
    - functions like `rate, abs, ceil, etc` that are performed element-wise across time in a single series
        - we need to look into functions
    - aggregation operators like `sum, avg, min, max, count, etc.` that collapse across series
        - hmm TimeCrypt doesn't really handle this? because there's a separate KDF tree for each of the time series

- on sending (label,value) pairs encrypted as a single blob, can Prometheus still store values/indexes with its default compression/configs?
- how does exposing a writer-facing epoch/update endpoint change the threat model?
- how much storage needed for storing all keying material for Hermes, HICKAE for 2000-15000 targets (or labels or timeseries)