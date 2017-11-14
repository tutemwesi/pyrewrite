# pyrewrite
Simple Python/Scapy Script to re-write payload using NFQUEUE

sudo apt-get install python-nfqueue python-scapy

Server:
```
nc -l -p 1337
```

Client:

```
python rewrite.py
echo "triggera" | nc x.x.x.x 80
```
nc server side should then show the re-written data
