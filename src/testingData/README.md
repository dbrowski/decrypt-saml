# Testing Instructions

### Encryption key found in this file:

> **c36a6653-25f6-4c00-a3d0-6570ef3632a8.crt**

### Create a PingOne SAML app connection.

After creating the connection, go to the config and use the above cert to enable encryption

### Genreate an encrypted SAML response

##### Here's how I did it...

1. Open "init SSO url" in a browser (optionally, use an incognito window)
2. Sign in with a test user
3. Copy the SAML response
   - I pointed my app connection at httpbin.org so the SAML response just appears in the browser after authenticating
   - The example used is this file:
     > **encryptedEncodedSAMLResponse.txt**

### Decode the SAML response

- Can use the handy dandy pingidentity [https://developer.pingidentity.com/en/tools/saml-decoder.html | SAML]
- I saved my example as

  > **encryptedSAMLResponse.txt**

### You're ready to test the tool!

Now, you have an encrypted but decoded SAML Request/Response and a private key. That's all you need!
