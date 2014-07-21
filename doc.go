package main

/*
secfileshare is an experimental tool to share files securely.

What is it?
The internet is rife with commercial and other insecure file sharing solutions.
secfileshare is trying to address this by implementing client side crypto while remaining easy to use.

It consists of two programs.
A client side program that encrypts and uploads the blob and a server that stores said blob.
Once a client finishes uploading the blob it'll receive a link from the server that can be used to retrieve the blob at a later time.

Note: The server side currently does not do any form of authentication and downloads blobs fully into memory first.
This obviously can be abused and crashed etc.
Do realize that at this time this software is considered experimental.

Why do we need this?
Hackers, social media, governments etc are increasingly infringing on our privacy and being able to safely and securely share information with others is vital in this day and age.
Closed source crypto solutions are bad since they can not be audited and verified by 3rd parties.
Commercial entities have proven to be unscrupulous and can not be trusted.


How does it work?
The tool leverages the ideas of the outstanding NaCl (http://nacl.cr.yp.to/) crypto suite.
It uses only free, not patented algorithms that were developed in academia that are seemingly untainted by government influence.
All messages are encrypted using NaCl boxes that use Curve25519, XSalsa20 and Poly1305 for encryption and public-key authenticators.
Additionally the mcrypt package (https://github.com/marcopeereboom/mcrypt) adds public-key signatures.

secfileshare builds on top of this and adds an ephemeral shared secret that encrypts the file that will be shared.
The ephemeral shared secret is then encrypted by the originator's private key and N recipients public keys.
The resulting blob does not contain any identifiable information regarding the originator or the recipients.

How do I start using it?
Install Go! http://golang.org/doc/install

Install secfileshare
go get github.com/marcopeereboom/secfileshare.git

Run secfileshare without any parameters.
This will create your keys.

Note that secfileshare uses HTTPS URLs to distinguish if it is dealing with files or servers.

The process of sharing files is simple.
1. Obtain the public key from the party you wish to share with.
2. Upload file to server using the recipient public key.
3. Share the link and your public-key with the recipient.

Examples

File to Server
Encrypt and upload a file to a single recipient
secfileshare -in filename -out https://a.b.c:12345 RecipientPublicKey

Encrypt and upload a file to a multiple recipients
secfileshare -in filename -out https://a.b.c:12345 Recipient1PublicKey Recipient2PublicKey Recipient3PublicKey

Encrypt and upload a file to a single recipient with an optional description
secfileshare -d "you wanted this" -in filename -out https://a.b.c:12345 RecipientPublicKey

Note that if you want to be able to decrypt the blob yourself that you must provide your public-key as well.

Server to File
Download and decrypt a single file
secfileshare https://a.b.c:12345/887123051

Download and decrypt multiple files
secfileshare https://a.b.c:12345/887123051 https://a.b.c:12345/887123052 https://a.b.c:12345/887123053

Download and decrypt a single file to a specific filename
secfileshare -out myfile https://a.b.c:12345/887123051

Do read the tool's help as well since it explains the -out parameter that is used to manipulate the out filenames.

File to File
secfileshare -in filename -out sharefilename -mode encrypt Recipient1PublicKey

To-Do:
	* Switch to binary protocol
	* Chunk data instead so that we don't have to do everything everything in memory
	* Add authentication to both sides
	* Add MIME handlers in client so that it can auto launch viewers for downloaded files
	* Add a client GUI
	* Add server management using HTTPS
	* Figure out auto-PKI
*/
