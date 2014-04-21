An implementation of OAuth 1.0a, as per RFC 5849. 

The client portion is designed for use with the http 
package. The server portion is designed to work with the dart:io
HttpServer class. 

Supports only HMAC-SHA1 signatures. In practice, RSA-SHA1 signatures are rare
and most users have switched to OAuth 2. PLAINTEXT signatures are also not 
supported, and hopefully less common.

Comes with a test suite. Please report any incompatibility issues.