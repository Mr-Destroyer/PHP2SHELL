# Lab setup

Reproduce the environment the findings were measured in. Everything here is a
container you build yourself; nothing touches a third-party host.

## Requirements

- Docker with the ability to run `linux/amd64` images (or an amd64 host)
- ~2 GB disk
- `nm` (binutils) for offset derivation

## The image

`php:8.4.26-apache` — the last affected release before 8.4.27. It ships Apache
2.4.69 prefork with `mod_php`.

```bash
docker pull php:8.4.26-apache
```

## The lab container

The finding depends on a small `memory_limit`, because the OOM has to happen
during request parsing rather than in userland. Write an ini overlay:

```bash
mkdir -p /tmp/php2shell-lab
cat > /tmp/php2shell-lab/zz-lab.ini <<'INI'
memory_limit = 8M
max_input_vars = 1000
max_file_uploads = 20
post_max_size = 32M
upload_max_filesize = 32M
session.upload_progress.enabled = On
expose_php = On
INI
```

`post_max_size` and `upload_max_filesize` must be above the largest probe
(20 MiB), or PHP rejects the body before the vulnerable path runs — the scan then
returns `INCONCLUSIVE`, which is correct behaviour but useless as a lab.

```bash
docker run -d --name php2shell-lab \
  -p 8080:80 \
  -v /tmp/php2shell-lab/zz-lab.ini:/usr/local/etc/php/conf.d/zz-lab.ini:ro \
  -e APACHE_RUN_USER=www-data \
  php:8.4.26-apache

curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/
```

## Single worker, deterministic forks

Stage 0 needs a worker you can rotate predictably. Pin prefork to one child while
you work:

```bash
docker exec php2shell-lab bash -c \
  "sed -i 's/^StartServers.*/StartServers 1/; s/^MinSpareServers.*/MinSpareServers 1/; s/^MaxSpareServers.*/MaxSpareServers 1/; s/^MaxRequestWorkers.*/MaxRequestWorkers 1/' \
   /etc/apache2/apache2.conf 2>/dev/null || true"
docker restart php2shell-lab
```

`ps` inside the container should show a single `apache2 -k start` child besides
the parent.

## Derive the offsets for this image

The defaults in the exploit kit belong to this exact image, but derive them anyway
so you can see them come out the same — and so you can redo it for another build:

```bash
docker cp php2shell-lab:/usr/local/lib/libphp.so /tmp/php2shell-lab/
nm -D /tmp/php2shell-lab/libphp.so | grep -E ' zif_system$| zval_ptr_dtor$'
```

Expected:

```
0000000000465370 T zif_system
000000000065eb60 T zval_ptr_dtor
```

If your numbers differ, the image is not the one the findings were measured on.
Pass your own with `--zif-offset` / `--dtor-offset`.

## Verify the lab before believing anything

```bash
# 1. Scanner should say VULNERABLE / HIGH
./scanner/scan -u http://127.0.0.1:8080 -v

# 2. The worker should survive, then serve normally again
./scanner/scan -u http://127.0.0.1:8080
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/

# 3. Mechanism analysis: why stage 1 behaves as it does
./exploit-kit/exploit -u http://127.0.0.1:8080 --diagnose

# 4. The chain, expecting stages 0-2 and a stage 3 failure
./exploit-kit/exploit -u http://127.0.0.1:8080 -c id
```

Step 4 not reaching execution is the documented result, not a setup error. If your
stage 1 or 2 fails, your offsets or your worker count are wrong — go back to those
two sections.

## Patched control

A useful negative: the same lab on `php:8.4.27-apache` should scan clean.

```bash
docker run -d --name php2shell-fixed -p 8081:80 \
  -v /tmp/php2shell-lab/zz-lab.ini:/usr/local/etc/php/conf.d/zz-lab.ini:ro \
  php:8.4.27-apache

./scanner/scan -u http://127.0.0.1:8081    # NOT VULNERABLE
```

If the patched image also reports `VULNERABLE`, your scanner change is producing
false positives and the suite is missing a case. Fix that before anything else.

## Teardown

```bash
docker rm -f php2shell-lab php2shell-fixed
rm -rf /tmp/php2shell-lab
```

## Capturing traffic

If you want to read the probes on the wire, run the lab through mitmproxy and point
the scanner at the proxy with `-k`, or capture on the docker bridge. Captures are
git-ignored on purpose — a capture from a lab session contains target data.
