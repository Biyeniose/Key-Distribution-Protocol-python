## Hybrid Key Distribution Protocol implented with Python sockets

The KDC generates and shares a symmetric key with client A (Ka) and B (Kb) seperately.

Then the KDC generates and shares a session key shared between the 2 clients (Kab) that client A and client B use to communicate privately.

The folders `a_keys`, `b_keys` and `kdc_keys` contain the private and public keys generated by KDC client A and client B in .pem formart.

---

Run KDC and client files (with the same port numbers) in your Terminal with : `python3 KDC.py port_number`

`python3 KDC.py 3200`

`python3 clientA.py 3200`

`python3 clientB.py 3200`
