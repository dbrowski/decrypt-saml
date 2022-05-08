# Testing Instructions

## 1) Create Encryption Key

> **openssl req -x509 -sha256 -nodes -days 30 -newkey rsa:4096 -keyout
> decryptSAMLKey.pem -out decryptSAML.crt\***

</br>

## 2) If you want to confirm your inputs from the above commmand...

> **openssl x509 -in decryptSAML.crt -text -noout**

</br>

The above will print to std out the info containing what was entered earlier:

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3b:83:09:a4:17:b2:96:58:f8:d0:d2:57:46:a4:10:18:2b:64:4b:29
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, ST = TX, L = Austin, O = Ping Identity, OU = Doms_Product_Group, CN = anthony, emailAddress = anthonydombrowski@pingidentity.com
        Validity
            Not Before: May  7 23:33:59 2022 GMT
            Not After : Jun  6 23:33:59 2022 GMT
        Subject: C = US, ST = TX, L = Austin, O = Ping Identity, OU = Doms_Product_Group, CN = anthony, emailAddress = anthonydombrowski@pingidentity.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:a6:85:fa:21:ba:97:8a:65:5c:9d:04:de:c7:7a:
                    ...
                    Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                2C:6F:16:2F:55:6B:B4:92:4B:EB:B7:83:A4:E2:6F:39:47:6D:E3:C1
            X509v3 Authority Key Identifier:
                keyid:2C:6F:16:2F:55:6B:B4:92:4B:EB:B7:83:A4:E2:6F:39:47:6D:E3:C1

            X509v3 Basic Constraints: critical
                CA:TRUE
                Signature Algorithm: sha256WithRSAEncryption
                ...
```

</br>

## In the end, what we're looking for is the encryption key which can now be found in this file:

> **decryptSAML.crt**

</br>

## Create and configure a PingOne SSO SAML app connection.

After creating the connection, go to the config and use

> **decryptSAML.crt**

 to enable encryption.

</br>

## Generate an encrypted SAML response

#### *Here's how I did it...*

1. Open "init SSO url" in a browser (optionally, use an incognito window if you might be signed in already)
2. Sign in with a test user
3. Copy the SAML response
   - I pointed my app connection at httpbin.org so the SAML response just
     appears in the browser after authenticating
   - The example used is this file:
     > **encryptedEncodedSAMLResponse.txt**

</br>

## Decode the SAML response

- Can use the handy dandy
  [Ping Identity SAML Decoder](https://developer.pingidentity.com/en/tools/saml-decoder.html)
- I saved my example as

  > **encryptedSAMLResponse.txt**

</br>

## You're ready to test the tool!

Now, you have an encrypted but decoded SAML Request/Response and a private key.
That's all you need!
