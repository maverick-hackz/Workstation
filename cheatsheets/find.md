# Find all `SUID` binaries
> find / -perm /4000 -type f -exec ls -ld {} \; 2>/dev/null
> find / -perm -u=s -type f -exec ls -ld {} \; 2>/dev/null
> find / -perm -4000 2>/dev/null
> find / -perm -u=s -type f 2>/dev/null

# Find all files `by owner`
> find / -type f -user yash 2>/dev/null

# Find `writable directories`
> find / -type d -writable -print 2>/dev/null

# Find passwords
> grep -iR 'password' /etc/zabbix/ 2>/dev/null

# Find all modified files since time, popular folder to look for
> find /usr/ -type f -newermt '2022-01-01' -ls 2>/dev/null
> find /usr/ -type f -newermt '2022-02-01' -not -path "/usr/lib/*" -ls 2>/dev/null
