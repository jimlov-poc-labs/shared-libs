# ssrf_fetch

SSRF-säker HTTP-hämtning med robots.txt (RFC 9309) och hastighetsgräns per värd.
Kontraktet är `vektorer.json`; Python (`py/ssrf_fetch`) och en framtida TS-port kör alla fall.
Allt som är osäkert, trasigt eller saknas nekas med en stabil felkod (fail closed).

## Avdelningar i vektorer.json

- `ip_spar`: `{ip, blockerad}`. Icke-sträng, `%`-zon eller ogiltig adress är alltid blockerad.
  IPv4-mappad IPv6 bedöms som sin IPv4.
- `url_validering`: `{url, dns, ut}`. `dns` är värd till adresslista (tom lista = `dns_empty`,
  värd som saknas = `dns_error`). `ut` är antingen `{ok:true, host, port, adresser, path_query}`
  eller `{ok:false, kod}`. Alla adresser måste vara tillåtna; en blockerad nekar hela värden.
  Hex/oktala/korta/heltals-IPv4 är `invalid_host` när de inte är kanoniska decimala a.b.c.d.
- `robots_tolkning`: `{text, agent, kontroller:[{path, tillaten}]}`. Längsta mönstret vinner
  (längden räknar `$`), lika längd ger Allow, namngiven grupp slår `*` även med tom Disallow,
  flera grupper slås ihop, `*` och `$` stöds, procentkodning normaliseras.
- `hamtning`: hela flödet mot en fejkad transport och DNS. Nycklar: `rutter`, `dns`, `config`,
  `robots`, `start` eller `anrop` (flera anrop med tid `t`), `dns_sekvens` (rebinding),
  `ip_fel`, `tid_per_forfragan`, `forvantat_antal`, och förväntat utfall i `ut`
  (`ok`, `kod`, `status`, `final_url`, `anslutna_ip`, `host_header`, `sni`, ...).
- `hastighetsgrans`: `{min_interval, max_wait, anrop:[{t, host, vantan}]}`; `vantan: null`
  betyder nekat (väntan över `max_wait`).

## Felkoder (stabila strängar)

invalid_url, scheme_not_allowed, credentials_in_url, no_host, invalid_host, port_not_allowed,
blocked_host, blocked_ip, dns_error, dns_empty, too_many_redirects, redirect_downgrade,
bad_redirect, http_status, timeout, connect_failed, network_error, too_large,
content_type_not_allowed, unsupported_encoding, robots_disallowed, robots_unavailable,
rate_limited, internal_error.

## Beteende som en port måste återge

- Bara http/https, inga användaruppgifter, `localhost` och `*.localhost` nekas.
- DNS slås upp en gång per hopp; anslutning sker mot den validerade IP:n med Host och SNI
  för ursprungsnamnet. Ingen återanvändning av anslutningar mellan namn.
- Omdirigeringar (301/302/303/307/308) följs manuellt, varje hopp valideras om, tak enligt
  config, https till http nekas.
- Storlekstak mot ström (Content-Length kontrolleras först); `truncate_oversize` är opt-in.
- Totaltid plus tid per steg; `Accept-Encoding: identity`, komprimerade svar nekas.
- robots: 404/410 tillåter, övriga 4xx tillåter om inte `strict_client_errors`, 429/5xx/
  nätverksfel/timeout nekar (`robots_unavailable`); fel cachas inte; regeltak ger nek-allt.
- `total_timeout` är en absolut deadline (monotonic klocka) för hela hämtningen: namnupplösning,
  anslutning, TLS, läsning av svarshuvud och body. Läsgränsen får aldrig nollställas per byte.
  Slut tid ger `timeout`. Namnupplösningen körs med tidsgräns (`timeout`); en hängd getaddrinfo
  överges i en daemon-tråd men blockerar aldrig anroparen.
- `Failed.url` är maskerad: bara schema, värd, port och sökväg (högst 200 tecken). Aldrig
  användaruppgifter, query eller fragment. Går URL:en inte att tolka är den den fasta texten
  `[url maskerad]`. Detsamma gäller varje felsträng och loggrad. `Fetched.url` är oförändrad.
- Content-Length måste vara strikt ASCII-siffror (`[0-9]+`); annat ger `network_error`, och
  tal med över 18 siffror räknas som över taket (`too_large`) utan att tolkas.
- Hastighetsgränsen (`HostLimiter`) är per normaliserat värdnamn, inte per IP-adress: två namn
  som pekar på samma server har var sin gräns. Vill man begränsa per server får anroparen
  lägga en egen gräns ovanpå.
