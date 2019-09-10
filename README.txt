A simple express middleware for authentication/authorization of requests. Uses Branca tokens instead of JWT.
Some of the advantages of branca over jwt - 
1. Amaller token size.
2. No restrictions on payload format. Payload can be any JSON object, plain text or binary data.
3. Tokens are always encrypted using XChaCha20-Poly1305 AEAD symmetric encryption. So, harder to shoot yourself in the foot.

For more information on Branca tokens - https://branca.io/.
