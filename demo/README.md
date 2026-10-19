# Interactive local demo

This runs Wagtail with **https://auth.resoauth.cloud** as its real identity provider. HTTPS uses a self-signed local certificate; accept the browser's local certificate warning. Modern browsers resolve `*.localhost` to loopback. RESOAuth's Dynamic CIMD service makes the public client metadata and public signing key reachable without publishing this local site. The browser returns directly to the local HTTPS callback.

From the repository root, build the test image if needed, create the persistent volume and start:

```sh
podman build -t wagtail-soca-test:0.0.1 -f Containerfile .
podman volume create wagtail-soca-demo-data
podman run -d --name wagtail-soca-demo \
  --workdir / \
  --publish 127.0.0.1:8443:8443 \
  --log-driver=k8s-file --log-opt max-size=10mb \
  --env PYTHONPATH=/:/app \
  --volume "$PWD/demo:/demo:ro" \
  --volume wagtail-soca-demo-data:/data:U \
  wagtail-soca-test:0.0.1 python -m demo.serve
```

Open **https://wagtail.localhost:8443/admin/**. Local username is `admin`; get the generated password with:

```sh
podman exec wagtail-soca-demo cat /data/admin-password
```

Open **Settings → SOCA** (https://wagtail.localhost:8443/admin/soca/). In **Access rules**, use **Edit your Wagtail account** to set your local account email to the address used at RESOAuth, then add that address to **Allowed email addresses** and save. You can also edit provider/metadata settings and run **Check connection** on this screen. Changes apply immediately without restarting.

An optional CLI shortcut configures the existing local administrator and allows its verified address:

```sh
podman exec wagtail-soca-demo python -m demo.account your-email@example.com
```

Select **Continue with SSO** to sign in at `auth.resoauth.cloud`. A verified provider email must match the configured address and local administrator email. Admission is denied until an email is configured. The local username/password continues to work independently. No provider is simulated or monkey-patched in this environment.

Logs and lifecycle:

```sh
podman logs --timestamps --tail 100 wagtail-soca-demo
podman logs --timestamps --follow wagtail-soca-demo
podman stop wagtail-soca-demo
podman start wagtail-soca-demo
podman exec wagtail-soca-demo python -m demo.smoke
```

Logs include request paths and redacted SOCA success/failure events; OAuth query strings and passwords are omitted. Podman retains and rotates the log file for this named container. The database, Django secret, signing key, certificate, configured email and generated password live in `wagtail-soca-demo-data` and survive restarts. The source mount lets you edit the local server harness; restart the container to apply changes. The live smoke check verifies HTTPS health/static files, local password login, the redirect to RESOAuth, public Dynamic CIMD metadata and removal of the old stub route. It does not authenticate a person or submit an OTP.

The host port is bound only to loopback. The standard HTTPS transport and signature/claim validation are used for all provider requests. Dynamic CIMD publishes only public application metadata and a public key, and its use changes the client ID when either changes. Keep the persistent signing key stable. Use the production configuration in the main README for a public deployment. The local WSGI server is intended for interactive development only.
