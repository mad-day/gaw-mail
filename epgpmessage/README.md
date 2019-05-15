# EPGP-Message
Encrypts and Decrypts mails using openpgp, Just like
[github.com/emersion/go-pgpmail/pgpmessage](https://godoc.org/github.com/emersion/go-pgpmail/pgpmessage)
but it implements some hacks, that allows the encryption of the entire message including
header (that includes _Subject_, _From_, _To_, _CC_ etc. pp. ...) and body alike.
This allows for stripping as much informations away as possible, thus thwarding eavesdroppers from obtaining
sensitive informations. __PLUS__ it hides the structure of a multipart message, obscuring informations
for eavesdroppers even more.

