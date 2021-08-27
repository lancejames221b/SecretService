SecretService Decoy Encrypted Emailer
For use with gmail currently. Will add other mailers later. 

This system uses ECC/ECIES (Elliptic Curve Cryptography) to exchange keys with a user and enables them to send secret messages back and forth. When we say secret, it means there is a decoy message that sits in your normal gmail inbox, while the real message is accessible by the app and will decrypt your messages. 

How to operate:

Step 1: pip3 install -r requirements
(recommended to use a virtual env)

Step 2: python3 ./SecretService.py

Step 3: Register your gmail account (app password for now, will change later)

Step 4: Exchange Keys, Send a user your key, and have that user send theirs.

Step 4: Check Mail (to receive keys, will automate this later)

Step 5: Verify key by clicking List Public Keys

Step 6: Once key is in the keyring, then send a message to that person. 

Step 7: Have them check mail

Step 8: Optionally you have them send a message and you check mail. 

Have fun!

Proof of Concept - We are aware of major improvements we can do, but this was a project that took about 2.5 days just to get up and going. Stay tuned for updates!

-- Unit 221B, LLC