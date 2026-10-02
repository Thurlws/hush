# Running hush on a VPS

This is the setup for a small cloud server, e.g. an Oracle Cloud free VM. You get
`https://chat.example.com` with a real certificate, and hushd runs as a locked-down service.

1. **A domain name.** HTTPS needs one. Any domain works, or a free subdomain from e.g.
   [DuckDNS](https://www.duckdns.org). Point it at the VM's public IP.

2. **Open ports 80 and 443** (and 7777 if anyone uses the terminal client). On Oracle Cloud there are two firewalls:
   - In the web console: *Networking → Virtual cloud networks → your VCN → Security Lists → Add Ingress Rules*,
     source `0.0.0.0/0`, TCP, destination ports `80,443,7777`.
   - On the VM itself. The rules have to come before the image's catch-all REJECT rule, so insert them at the top:
     ```sh
     # Ubuntu images (iptables)
     for p in 80 443 7777; do sudo iptables -I INPUT 1 -p tcp --dport $p -m state --state NEW -j ACCEPT; done
     sudo netfilter-persistent save
     # Oracle Linux images (firewalld)
     for p in 80 443 7777; do sudo firewall-cmd --permanent --add-port=$p/tcp; done; sudo firewall-cmd --reload
     ```
   Keep 8080 closed: only the reverse proxy on the VM itself should talk to it.

3. **Install hushd** as a service with its own user:
   ```sh
   git clone https://github.com/Thurlws/hush && cd hush
   make && sudo make install PREFIX=/usr/local
   sudo useradd --system --home-dir /var/lib/hush --create-home --shell /usr/sbin/nologin hush
   sudo chmod 700 /var/lib/hush
   sudo cp contrib/hushd.service /etc/systemd/system/
   sudo systemctl enable --now hushd
   ```

4. **HTTPS with [Caddy](https://caddyserver.com/docs/install)**, which gets and renews the certificate itself.
   Put this in `/etc/caddy/Caddyfile`, with your own domain, and run `sudo systemctl reload caddy`:
   ```
   chat.example.com {
       reverse_proxy 127.0.0.1:8080
   }
   ```
   The service runs `hushd -x`, which makes it trust the `X-Forwarded-For` header from Caddy,
   so the rate limits apply to each visitor's real address.

5. **Create a chat key and make yourself admin.** Open your site. The login page shows your fingerprint.
   ```sh
   sudo -u hush hushd -C /var/lib/hush newkey friends
   sudo -u hush hushd -C /var/lib/hush admin "YOUR FINGERPRINT"
   ```
   Join with the key, then give it to your friends. Each of them waits until you approve them.

Logs: `journalctl -u hushd -f`. Everything the server keeps is in `/var/lib/hush`, so back that up.

For uptime monitoring, poll `https://chat.example.com/health`. It answers `ok` as long as hushd's
event loop is running. `hushd -V` prints the version.

To update: `git pull && make && sudo make install PREFIX=/usr/local && sudo systemctl restart hushd`.

## Upgrading from the version without history

Chat keys work differently now, so old keys stop working. After updating (install `libsqlite3-dev`
first), make each chat a new key and send it to your friends again:

```sh
sudo -u hush hushd -C /var/lib/hush keys             # old keys are marked as old
sudo -u hush hushd -C /var/lib/hush revoke friends
sudo -u hush hushd -C /var/lib/hush newkey friends
sudo -u hush hushd -C /var/lib/hush admin "YOUR FINGERPRINT"
```

Names and fingerprints stay the same. People who were already in a chat don't have to be approved again.
