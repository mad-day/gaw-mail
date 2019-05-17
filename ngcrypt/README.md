# NGCRYPT

Note: This Specification is still subject to Change.

#### Background

**The Problem:**

In traditional PGP encrypted E-Mails, only the Body is enrypted, leaving sensitive informations
like the Title (`Subject: `) unencrypted and unprotected. My first solution was to encrypt the
entire RFC822 into an OpenPGP-Armored block and to create a new, sufficient header. However, this
didn't work so well with an IMAP-server, since the Envelope was derived from the unencrypted
mail-header. And downloading and decrypting the entire message, when listing up the mailbox is
just too much of overhead. And it requires a special IMAP-Proxy, that decrypts the mails.

**The Answer**

Given the problem, and the fact, that either solution would require special software,
a new encryption format could be implemented from scratch, without having to care about
backward-compatibility with standard PGP.

The Requirements for a encrypted message format are:
1. The message format must be a valid E-Mail.
2. The message format must encrypt the RFC822 header of the original message.
3. The message format must be IMAP-friendly.

A the top-level, MIME multipart messages are choosen, because IMAP-servers can decompose
them, delivering each part individually.

Of the original message, the header and the body are OpenPGP-encrypted seperately and stored in
seperate parts of the MIME multipart message.

Each encrypted part is compressed prior to encryption, because the entropy is usually low. This is
the case especially for Base64-encoded binary-attachments.

### The encrypted Block.

1. The data is compressed using the DEFLATE algorithm.
2. The result is encrypted using [OpenPGP](https://godoc.org/golang.org/x/crypto/openpgp).
3. The result is encoded as ASCII Armor (see [RFC4880](http://tools.ietf.org/html/rfc4880)).

The block type is `NGCRYPT BLOCK` rather than `PGP MESSAGE`.

```
-----BEGIN NGCRYPT BLOCK-----
Headers

base64-encoded Bytes
'=' base64 encoded checksum
-----END NGCRYPT BLOCK-----
```

The key difference between a regular `PGP MESSAGE` and a `NGCRYPT BLOCK` is, that the data
is compressed prior to encryption.

### The message format.

The message is composed as a [**multipart**](https://en.wikipedia.org/wiki/MIME#Multipart_messages)-message.

* The whole, message. Is of type `multipart/*`.
	* Part 1, Contains The OpenPGP encrypted header of the original message.
	* Part 2, Contains the OpenPGP encrypted body of the original Message.

Also special Headers are attached to the message:
* `X-Ngcrypt-Pgp: enabled`
* `X-Ngcrypt-Size:` and the size of the original RFC822 message in bytes.

In ASCII Armor block in Part 1 has a header called `Rfc822-Size:` with the size of the original RFC822 message in bytes.

```
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=b_abc
Subject: ???
X-Ngcrypt-Pgp: enabled
X-Ngcrypt-Size: 2398

--b_abc
Content-Type: text/plain
Subject: ???

-----BEGIN NGCRYPT BLOCK-----
Rfc822-Size: 2398

PGh0bWw+CiAgPGhlYWQ+CiAgPC9oZWFkPgogIDxib2R5PgogICAgPHA+VGhpcyBpcyB0aGUg
Ym9keSBvZiB0aGUgbWVzc2FnZS48L3A+CiAgPC9ib2R5Pgo8L2h0bWw+Cg==
=PGh0bWw
-----END NGCRYPT BLOCK-----
--b_abc
Content-Type: text/plain
Subject: ???

-----BEGIN NGCRYPT BLOCK-----

PGh0bWw+CiAgPGhlYWQ+CiAgPC9oZWFkPgogIDxib2R5PgogICAgPHA+VGhpcyBpcyB0aGUg
Ym9keSBvZiB0aGUgbWVzc2FnZS48L3A+CiAgPC9ib2R5Pgo8L2h0bWw+Cg==
=PGh0bWw
-----END NGCRYPT BLOCK-----
--b_abc--
```


## Changes

1. Change:
	* Previously
		* The ASCII Armor block-type was `NGCRYPT MESSAGE`
		* Messages could consist either of 1 part or 2 parts
		* In 1-Part-Messages Header and Body is combined in one encrypted block.
		* In 2-Part-Messages, Part 1 contains the header, Part 2 the body.
	* Now
		* The ASCII Armor block-type is now `NGCRYPT BLOCK`
		* Messages must consist of 2 parts. 1-Part messages are disallowed.
