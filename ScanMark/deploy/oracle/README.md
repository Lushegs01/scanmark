# Running ScanMark on Oracle Cloud Always Free

One Ampere A1 VM runs everything Render, Neon and the Redis service host
today. The application code does not change: this directory is the server
setup around it.

| Today | On the VM |
|---|---|
| Render web service | gunicorn under systemd (`scanmark.service`), with the same `gunicorn.conf.py` |
| Neon | PostgreSQL on the VM, reached over its local socket with no password |
| Redis service | Redis on the VM |
| HTTPS on `*.onrender.com` | Your own domain, with HTTPS from Caddy (`Caddyfile`) |
| A deploy on every push | `update.sh`, run when you choose |
| Render restarts, Neon backups | systemd restarts on crash; `backup.sh` nightly, copied to Object Storage |

The VM has 2 CPUs and 12 GB of memory against Render free's 0.1 CPU and
512 MB. That is still not a measured 2,000-student capacity: rehearse it as
`DEPLOYMENT.md` describes.

## Before you start

- **Oracle may stop the VM.** Oracle reclaims Always Free VMs it considers
  idle: over 7 days, 95th-percentile CPU, network and memory use all below
  20% ([Always Free Resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)).
  ScanMark is likely to look idle by that measure, especially between terms.
  A reclaimed VM is stopped, not deleted, and its data survives, but ScanMark
  is down until someone starts it again. A 2023 Oracle notice said upgrading
  the account to Pay As You Go prevents this; the current documentation does
  not say either way. Upgrading needs a card; Always Free resources stay free
  after it, so set a budget alert. Either way, set up the uptime monitor in
  step 11.
- **You need a domain.** The camera and location only work over HTTPS, and
  HTTPS needs a hostname, not a bare IP address. If ScanMark already has its
  own domain on Render, point it at the VM and nobody notices the move. The
  `.onrender.com` address cannot move: if people use it today, everyone,
  CampOS included, moves to the new address, and home-screen installs of the
  app have to be redone from it.
- **Stay inside the free allowance.** Ampere A1 is free up to 2 OCPUs and
  12 GB in total. Oracle cut this from 4 OCPUs and 24 GB on 18 August 2026 and
  disables instances over it. A1 often reports "Out of capacity": try another
  availability domain, or again later. The free AMD VM (1 GB) is too small for
  the app, PostgreSQL and Redis together.
- **You are the administrator.** Updates, backups, restarts and disk space
  are yours. Ubuntu installs security updates by itself; nothing else
  happens unless you do it.

## Moving

1. **Find Neon's PostgreSQL version.** In Neon's SQL editor run
   `SHOW server_version;` and note the major version, e.g. `17`. The VM must
   run at least that version or `pg_dump` refuses.

2. **Create the VM.** Compute → Instances → Create instance, in your home
   region (Always Free resources exist only there).
   - Image: Canonical Ubuntu 24.04.
   - Shape: Ampere `VM.Standard.A1.Flex`, 2 OCPUs, 12 GB memory.
   - Networking: keep "Assign a public IPv4 address".
   - SSH keys: add your public key.

3. **Open ports 80 and 443.** On the instance page, open its subnet, then the
   subnet's security list, and add two ingress rules: source `0.0.0.0/0`,
   TCP, destination port `80`, and the same for `443`. Port 80 is how Let's
   Encrypt checks the domain and how plain-HTTP visitors get redirected.
   `setup.sh` opens the VM's own firewall.

4. **Point the domain at the VM.** Create an `A` record for the hostname with
   the instance's public IP. Caddy cannot get a certificate until this
   resolves.

5. **Install.**

   ```sh
   ssh ubuntu@<public-ip>
   sudo git clone https://github.com/Lushegs01/scanmark.git /opt/scanmark/src
   sudo DOMAIN=scanmark.example.edu.ng PG_VERSION=17 \
       /opt/scanmark/src/ScanMark/deploy/oracle/setup.sh
   ```

   This installs PostgreSQL, Redis, Caddy and the Python packages, creates
   the `scanmark` account and database, and installs the services. It does
   not start ScanMark.

6. **Copy the settings.** `sudo nano /etc/scanmark/scanmark.env`. The file
   says which variables to bring over from Render's Environment page and
   which to leave out. `SECRET_KEY` must be the same value as on Render:
   ScanMark will not start without it, and a new one logs everybody out and
   breaks emailed links already sent.

7. **Copy the data**, at a time no class is running.
   - Suspend the Render service, so no scan lands in Neon after the copy.
   - On the VM, with Neon's *direct* connection string (the host without
     `-pooler`):

     ```sh
     pg_dump --format=custom --no-owner --no-acl "<neon-direct-url>" --file /tmp/neon.dump
     sudo -u scanmark pg_restore --no-owner --no-acl --dbname scanmark /tmp/neon.dump
     rm /tmp/neon.dump
     ```

     Restore **before** the first start. Every boot creates any missing
     tables, so if ScanMark reaches the empty database first, the restore
     collides with them; add `--clean --if-exists` to `pg_restore` if that
     has happened. If anything failed, its last line reads
     `errors ignored on restore: N`.
   - Check the copy: `sudo -u scanmark psql scanmark -c 'SELECT count(*) FROM attendance'`
     against the same query on Neon.

8. **Start.**

   ```sh
   sudo systemctl enable --now scanmark
   curl -I https://scanmark.example.edu.ng/healthz    # 204 when healthy
   ```

   Then log in, start a class and scan it with a phone. If mail goes through
   Brevo it keeps working unchanged. Oracle blocks outbound port 25, so check
   SMTP with:

   ```sh
   sudo systemd-run --pty --uid=scanmark \
       -p EnvironmentFile=/etc/scanmark/scanmark.env \
       -p WorkingDirectory=/opt/scanmark/src/ScanMark \
       /opt/scanmark/venv/bin/python mail_selftest.py
   ```

9. **Tell everything else about a new address**, if it changed:
   - CampOS: ScanMark's address, whose SSO callback is now
     `https://<domain>/sso/callback`.
   - Google sign-in, if used: add `https://<domain>/authorize/google` to the
     OAuth client's authorised redirect URIs.
   - Students and lecturers: the new address, and to reinstall the
     home-screen app from it.

10. **Copy backups off the VM.** A backup kept only on the VM goes with it.
    - Storage → Buckets → Create bucket (private).
    - Profile menu → My profile → Customer secret keys → Generate secret key.
    - Fill in `/etc/scanmark/backup.env`. The bucket page shows the
      namespace, and the region is in the console's address bar.
    - Run one: `sudo systemctl start scanmark-backup && journalctl -u scanmark-backup -n 5`.
      The last line names the bucket it was copied to.
    - Add a lifecycle rule to the bucket that deletes objects after, say,
      30 days. Download one now and then, too: the bucket is in the same
      account as the VM.

11. **Watch it from outside.** Point a free uptime monitor (UptimeRobot, for
    example) at `https://<domain>/healthz`. If Oracle stops the VM, this is
    how you find out.

12. **Keep Render and Neon for a week**, suspended, in case you need to go
    back. Then delete them.

## Day to day

| Task | Command |
|---|---|
| Deploy the latest `main` (outside class hours) | `sudo /opt/scanmark/src/ScanMark/deploy/oracle/update.sh` |
| Apply a settings change | edit `/etc/scanmark/scanmark.env`, then `sudo systemctl restart scanmark` |
| Follow the logs | `journalctl -u scanmark -f` (Caddy: `journalctl -u caddy`) |
| List backups | `sudo ls -l /var/backups/scanmark` |
| Start a VM Oracle stopped | Console → the instance → Start; everything comes back on boot |

Kernel updates need a reboot. Do it outside class hours when
`/var/run/reboot-required` exists: `sudo reboot`.

To restore a backup:

```sh
sudo systemctl stop scanmark
sudo -u scanmark pg_restore --clean --if-exists --no-owner --no-acl \
    --dbname scanmark /var/backups/scanmark/scanmark-<timestamp>.dump
sudo systemctl start scanmark
```

If a file in this directory changes, `update.sh` reinstalls the systemd
units. For a changed `Caddyfile` or `setup.sh`, run `setup.sh` again with the
same `DOMAIN` and `PG_VERSION`. It keeps the settings files and the database
as they are.
