library oauth.token;

/// Bundles together the public and secret portions of an OAuth token.
class Token {
  /// The token (public) key
  final String key;
  /// The token secret
  final String secret;
  
  /// Constructs a new token
  Token(this.key, this.secret);
}