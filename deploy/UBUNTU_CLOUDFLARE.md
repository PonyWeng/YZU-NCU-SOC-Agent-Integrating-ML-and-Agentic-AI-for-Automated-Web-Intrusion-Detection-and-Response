# ponyweng.tw on Ubuntu: Cloudflare → Nginx → WAF/SIEM

| Hostname | Purpose | Local upstream |
|---|---|---|
| siem.ponyweng.tw | SIEM dashboard | 127.0.0.1:8000 |
| shop.ponyweng.tw | TechMart / Apache target | 127.0.0.1:18080 |
| staff.ponyweng.tw | Flask target | 127.0.0.1:18081 |
| city.ponyweng.tw | Django target | 127.0.0.1:18082 |

All target upstreams are the OWASP CRS WAF ports, not the backend application ports.

1. In Cloudflare DNS, add four **proxied** A records (`siem`, `shop`, `staff`, `city`) pointing to the Ubuntu server's public IPv4 address. Add AAAA only when the server actually has public IPv6 and Nginx listens on it.
2. In Cloudflare SSL/TLS > Origin Server, create an Origin CA certificate covering `*.ponyweng.tw`; store the certificate at `/etc/ssl/cloudflare/ponyweng-origin.pem` and private key at `/etc/ssl/cloudflare/ponyweng-origin.key` (private key mode `600`). Set SSL/TLS mode to **Full (strict)** after Nginx is serving the certificate.
3. Copy `deploy/ubuntu-public.env.example` to the project `.env` (Compose port configuration). Copy the privately transferred `secrets.env` to the same directory (API, LINE and ngrok credentials). Run `docker compose up -d --build`.
4. Install Nginx, copy `deploy/ponyweng-siem.nginx.conf.example` to `/etc/nginx/sites-available/ponyweng-siem`, then symlink it into `/etc/nginx/sites-enabled/`. Remove the default site if it conflicts.
5. Create `/etc/nginx/conf.d/cloudflare-realip.conf` containing one `set_real_ip_from CIDR;` line for **each current Cloudflare IPv4 and IPv6 range** from `https://www.cloudflare.com/ips/`, followed by `real_ip_header CF-Connecting-IP;`. Update this file when Cloudflare's ranges change. Never trust `CF-Connecting-IP` from arbitrary source IPs.
6. Check with `sudo nginx -t && sudo systemctl reload nginx`; test each HTTPS hostname and the SIEM login flow. The upstream ports should listen only on `127.0.0.1` (`ss -lnt`). Open public `80/443` to Cloudflare; keep `8000/8002/18080/18081/18082` private. Restrict origin access to Cloudflare ranges where possible.
7. Add a Cloudflare Access self-hosted application for `siem.ponyweng.tw`, allowing only your accounts. Do not put Access on public demo targets if you want normal external traffic. For strongest protection against direct-origin bypass, use Cloudflare Tunnel with Access validation or enforce Cloudflare-only source ranges at the origin.

The Nginx sample clears `X-Demo-Source-IP` on public traffic and overwrites `X-Real-IP`; demo scripts can still send synthetic sources through localhost directly. The WAF remains in Detection Only mode, so these targets are demonstration services, not hardened production applications.

Do not proxy the LINE webhook through `siem.ponyweng.tw`; the existing ngrok tunnel targets the separate `8002` webhook service. Keep it enabled only if LINE integration is needed.
