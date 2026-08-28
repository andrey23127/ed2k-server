# Running your own update service

The filter data files are what make Layers 1-5 useful, and they cannot live in a
public repository: the term lists describe how detection works, and the hash ban
list is a working index of known material. This document describes how to run a
service that distributes them to servers you trust, and how to point a server at
one.

If you only want to **receive** updates from an existing service, you need
[section 6](#6-configuring-a-server-to-receive-updates) alone.

---

## What the client does

Every update runs the same sequence. Nothing touches disk until all of it passes,
so a failed update leaves a working server rather than a disarmed one:

1. **Download**, with a completeness check against `Content-Length`. A dropped
   connection produces a prefix of a valid file, which parses cleanly and is
   simply shorter — this is the most common failure and the one most likely to go
   unnoticed.
2. **Verify the Ed25519 signature** over the bytes *as served*, before extraction.
   Signing the archive rather than its contents keeps the archive framing
   authenticated too; a decompressor should only ever see bytes somebody vouched
   for.
3. **Extract**, if the source is a ZIP.
4. **Validate with the runtime parser** — the same code that loads the file at
   startup, not a second copy of it. A private validator drifts from the real one
   and then passes files the loader rejects, leaving a layer running on nothing.
5. **Refuse a collapse.** A replacement whose entry count falls below
   `min_keep_ratio` of the current file is rejected.
6. **Rotate backups** to `<name>.1` … `<name>.N` and **install atomically**
   (temp file in the same directory, `fsync`, `rename`).
7. **Trip the reload flag**, so the new file is in force within about two
   seconds.

`Update & merge`, offered for the three hash lists, unions the download with the
file on disk **comparing hashes only** — one side is often a bare export and the
other your working copy with reasons written after each entry. Where both carry a
hash, the annotated line wins.

---

## 1. Prerequisites

* A domain name. Not cosmetic: without one there is no TLS certificate, and
  without TLS the access key travels in clear text on every request.
* A small VPS. Serving a handful of static files to a few dozen servers needs
  nothing.
* Ports 80 and 443 open. **Port 80 is not optional** — the ACME challenge lands
  there, and closing it after the first certificate breaks renewal about sixty
  days later, silently.

**Use a separate host from the eD2k server.** Two reasons. The update service
faces the internet with a web server, which is extra attack surface on a machine
holding a large index. And if both run on one box, taking that box yields both
the lists and the ability to replace them for everyone else — the signature only
protects the others if the private key is somewhere else entirely.

---

## 2. Signing key — generate it on your own machine

This is the step that must not happen on the VPS. With the private key on the
update host, taking that host is enough to push a signed empty vocabulary to
every server at once, which is exactly what the signature exists to prevent.

```bash
mkdir -p ~/.ed2k && cd ~/.ed2k
openssl genpkey -algorithm ed25519 -out ed2k-updates.key
chmod 600 ed2k-updates.key
openssl pkey -in ed2k-updates.key -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'; echo
```

The last command prints 64 hex characters. That is the public key; it goes into
`updates.public_key` in every server's config. Back the private key up offline —
losing it means every client must be reconfigured before you can publish again.

---

## 3. Layout on the service host

```bash
mkdir -p /srv/updates/public /srv/updates/private /srv/updates/state
useradd --system --home /srv/updates --shell /usr/sbin/nologin updauth || true

chown -R root:caddy /srv/updates/public /srv/updates/private
chmod 750 /srv/updates/public /srv/updates/private
chown -R updauth:updauth /srv/updates/state
chmod 700 /srv/updates/state
```

`public/` holds `guarding.p2p` and `ip-to-country.csv.zip` — public data, no
credentials. `private/` holds the six files that describe detection or index
material. Each file sits next to its `.sig`.

---

## 4. Web server

Any TLS-terminating server will do. Caddy needs no certificate management:

```
ed2k.example.org {
	encode zstd gzip
	log

	handle /pub/* {
		uri strip_prefix /pub
		root * /srv/updates/public
		file_server
	}

	handle /peers {
		reverse_proxy 127.0.0.1:8181
	}

	handle /files/* {
		forward_auth 127.0.0.1:8181 {
			uri /auth
			header_up X-Original-URI {uri}
		}
		uri strip_prefix /files
		root * /srv/updates/private
		file_server
	}

	handle {
		respond "" 404
	}
	header {
		-Server
		Strict-Transport-Security "max-age=31536000"
	}
}
```

On Debian 13, install Caddy without `gnupg`:

```bash
apt update && apt upgrade -y
mkdir -p /etc/apt/keyrings
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  -o /etc/apt/keyrings/caddy-stable.asc
chmod 644 /etc/apt/keyrings/caddy-stable.asc
cat > /etc/apt/sources.list.d/caddy-stable.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/caddy-stable.asc] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main
EOF
apt update && apt install -y caddy
```

The official instructions also install `debian-keyring` (34 MB of unrelated keys)
and pipe the key through `gpg --dearmor`; neither is needed, and the second is
what breaks if `gnupg` is not present.

---

## 5. Authorising servers

The access-controlled files sit behind a check on two things: the address the
request comes from, and a key the requesting server presents.

**The key is not a new secret.** It is
`IPObfuscate(that server's seckey, the reference server's IP)` — the number the
peer already computed and sent during the obfuscated server-to-server handshake.
Only those two parties have it, so no registration step is needed: a server that
has completed gossip already holds its credential.

Servers push their tables to `POST /peers`, authenticated with a bearer token you
issue. The authorisation service stores them and answers `GET /auth` for each
file request.

**⚠ A key proves "runs eD2k server software and completed a handshake", and
nothing more.** The software is public and the handshake is automatic, so an
address can appear in the table within an hour of somebody renting a VPS, with no
human involved. Treat the table as a list of **candidates** and keep an approval
step: a correct key should land the address in a queue, and only an explicit
entry in an allow list should grant the files. The ban list in particular is a
working index of known material and `OP_GLOBGETSOURCES` turns a hash into a
source list — approve people you have reason to trust, not addresses that showed
up.

A reference implementation of the authorisation service (about 250 lines of
Python, standard library only, listening on loopback) is available on request; it
is not shipped here because a service is an operational thing and every operator
will want their own approval policy.

---

## 6. Configuring a server to receive updates

```toml
[updates]
enabled = true
dest_dir = "/etc/ed2k-server"
public_key = "<64 hex characters from step 2>"
require_signature = true
key_reference_ip = "<the server whose exported table the service loaded>"
backups = 3
min_keep_ratio = 0.5
export_url = "https://ed2k.example.org/peers"
export_token = "<issued by the service operator>"
export_interval_secs = 3600

[updates.urls]
guarding_p2p     = "https://ed2k.example.org/pub/guarding.p2p"
ip_to_country    = "https://ed2k.example.org/pub/ip-to-country.csv.zip"
csam_jargon      = "https://ed2k.example.org/files/csam_jargon.txt"
csam_terms_extra = "https://ed2k.example.org/files/csam_terms_extra.txt"
layer2_terms     = "https://ed2k.example.org/files/layer2_terms.txt"
hash_banlist     = "https://ed2k.example.org/files/hash_banlist.txt"
hash_filter      = "https://ed2k.example.org/files/hash_filter.txt"
whitelist_hashes = "https://ed2k.example.org/files/whitelist_hashes.txt"
```

Two of these deserve care.

**`public_key`** is public by definition — it verifies a signature and cannot
create one, so it is safe in a shipped config and in a public repository. Ship
the key of whichever service you pull from.

**`export_token` is a secret.** Anyone holding it can push a peer table to the
service. It is issued per server by the service operator; never copy one out of a
repository, and never commit yours.

After a restart, the Health tab shows the derived access key next to the update
buttons. That is the number the service compares against, and seeing it is what
makes a `403` diagnosable.

**Your own server is a special case.** It never gossips with itself, so it never
appears in anybody's export and the service has no key on record for it. Grant it
by hand.

---

## 7. Publishing

Sign on your own machine and upload the signature **before** the file. Interrupted
halfway, clients then see a file whose signature is still the old one and refuse
it — which is the safe way round. The other order leaves a signature vouching for
a file that has not arrived.

```bash
openssl pkeyutl -sign -inkey ~/.ed2k/ed2k-updates.key -rawin -in FILE -out FILE.sig
openssl pkeyutl -verify -inkey ~/.ed2k/ed2k-updates.key -rawin -in FILE -sigfile FILE.sig
scp FILE.sig host:/srv/updates/private/
scp FILE     host:/srv/updates/private/
```

Verifying locally before uploading matters: a bad signature discovered on the
server means every client refuses that file until it is fixed.

---

## 8. Operational notes

**Signature failure is fail-closed.** A file that does not verify is not written,
not backed up and not applied; the server keeps filtering with what it has. When
rotating the signing key, publish new signatures for **every** file before
changing `public_key` on any client.

**Collapse guard.** A replace that would drop the entry count below half is
refused. If a list genuinely shrinks by more than that, lower `min_keep_ratio`
for the one operation or install by hand.

**Rolling back** is a file copy — `cp hash_banlist.txt.1 hash_banlist.txt` — then
`/api/reload`, or wait 30 s for the mtime watcher.

**Certificate renewal** needs port 80 to stay open. Check once a quarter.
