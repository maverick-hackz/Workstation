# cURL

> Command-line HTTP client used for probing endpoints, replaying requests, and quick auth/cookie tests during authorized testing only.

## TL;DR
- `-v` to inspect request/response; `-I` for headers only; `-i` to include response headers in body output.
- `-k` skips TLS verification (testing self-signed certs); never use as a production default.
- Auth: `-u user:pass` (Basic), `-H 'Authorization: …'` (Bearer / custom), `--cookie`/`-b` for sessions.
- Methods: `-X POST -d '…'`, `-X PUT`, `-X DELETE`. JSON: `-H 'Content-Type: application/json' -d '{…}'`.

## Detection / Discovery
| Command | Description |
| --- | --- |
| `curl -h` | cURL help menu |
| `curl inlanefreight.com -v` | Print full HTTP request/response details |
| `curl -I https://www.inlanefreight.com` | Send HEAD request (only prints response headers) |
| `curl -i https://www.inlanefreight.com` | Print response headers and response body |

## Exploitation
| Command | Description |
| --- | --- |
| `curl inlanefreight.com` | Basic GET request |
| `curl -s -O inlanefreight.com/index.html` | Download file |
| `curl -k https://inlanefreight.com` | Skip HTTPS (SSL) certificate validation |
| `curl https://www.inlanefreight.com -A 'Mozilla/5.0'` | Set User-Agent header |
| `curl -u admin:admin http://<SERVER_IP>:<PORT>/` | Set HTTP basic authorization credentials |
| `curl  http://admin:admin@<SERVER_IP>:<PORT>/` | Pass HTTP basic authorization credentials in the URL |
| `curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/` | Set request header |
| `curl 'http://<SERVER_IP>:<PORT>/search.php?search=le'` | Pass GET parameters |
| `curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/` | Send POST request with POST data |
| `curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/` | Set request cookies |
| `curl -X POST -d '{"search":"london"}' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php` | Send POST request with JSON data |

### APIs
| Command | Description |
| --- | --- |
| `curl http://<SERVER_IP>:<PORT>/api.php/city/london` | Read entry |
| `curl -s http://<SERVER_IP>:<PORT>/api.php/city/ \| jq` | Read all entries |
| `curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` | Create entry |
| `curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` | Update entry |
| `curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City` | Delete entry |

### Browser DevTools shortcuts
| Shortcut | Description |
| --- | --- |
| `CTRL+SHIFT+I` or `F12` | Show devtools |
| `CTRL+SHIFT+E` | Show Network tab |
| `CTRL+SHIFT+K` | Show Console tab |

## Defence / Remediation
Out of scope — `curl` is a generic client. For services it probes, see service-specific cheatsheets and OWASP WSTG.

## Sources
- curl man page: https://curl.se/docs/manpage.html
- everything curl: https://everything.curl.dev/
