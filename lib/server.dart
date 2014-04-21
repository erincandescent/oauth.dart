/** Server support for OAuth 1.0a with the dart:io [HttpServer] */
library oauth.server;
import 'dart:async';
import 'dart:io';
import 'dart:convert';
import 'package:oauth/src/token.dart';
import 'package:oauth/src/core.dart';
import 'package:oauth/src/utils.dart';
export 'package:oauth/src/token.dart' show Token;

final _paramRegex = new RegExp(r'^\s*(\w+)\s*=\s*"([^"]*)"\s*$');
class _NotAuthorized implements Exception {}
void _require(bool test) { if(!test) throw new _NotAuthorized(); }

/** A pair of OAuth tokens
 *  
 *  Groups together a pair of token credentials to be returned by a 
 *  [TokenFinder]
 */
class TokenPair {
  /// The consumer token
  final Token consumer;
  /// The (optional) user token
  final Token user;
  
  /// Returns a token pair with a consumer token and optionally a user token
  TokenPair(this.consumer, [this.user]);
}

/** Invoked by `isAuthorized` in order to look up the tokens for a request
 * 
 * If the `oauth_token` authorization header parameter was missing, the empty 
 * string will be passed as `userKey`. In this case, it is expected that 
 * `TokenPair.user` will be `null` in the returned `TokenPair`.  
 */
typedef Future<TokenPair> TokenFinder(String consumerKey, String userKey);

/** Invoked by `isAuthorized` in order to validate the non-reuse of the request
 *  nonce.
 *  
 *  Per the OAuth specification, the combination of nonce, consumer key, 
 *  user token key and nonce must be unique per distinct timestamp.
 *  
 *  Instead of the timestamp, this library passes the point in time at which
 *  the signature will expire, based upon the `timestampLeeway` parameter passed
 *  to `isAuthorized`. Therefore, there is a 1:1 mapping between request 
 *  timestamps and values passed to this function.
 *  
 *  The `expiry` value is computed as the timestamp passed in the request plus
 *  two times the `timestampLeeway` value, in order to avoid risk of attack due
 *  to server clock skew.
 *  
 *  The implementation should look up the combination of the parameters in a
 *  database to ensure they have not already been used. Following this, it 
 *  should insert the values of the passed parameters into a database to prevent 
 *  token reuse.
 *  
 *  The implementation should implement a process which periodically sweeps 
 *  expired nonce values from the database.
 */
typedef Future<bool> NonceQuery(String consumerToken, String userToken, 
    String nonce, DateTime expiry);

/** Validates that the request contains a valid OAuth signature.
 * 
 * The request parameters will be validated, and then [tokenFinder] will be
 * invoked in order to look up the secrets(s) associated with the request.
 * Finally, the signature will be computed and compared to the passed value
 * to ensure that the request is to be authorized.
 * 
 * [timestampLeeway] may be specified, which determines the maximum difference
 * permitted between the request timestamp and the present time. The default
 * value is 10 minutes. You should not vary this value across multiple requests
 * as doing so may permit request replay attacks.  
 * 
 * Returns whether the request should be permitted.
 */
Future<bool> isAuthorized(HttpRequest request, 
                          TokenFinder tokenFinder,
                          NonceQuery  nonceQuery,
                          {Duration timestampLeeway}) {  
  Map<String, String> params;
  String signature;
  TokenPair tokens;
  String consumerKey, tokenKey;
  
  timestampLeeway = timestampLeeway != null ? 
      timestampLeeway : new Duration(minutes: 10);
  
  return async.then((_) {
    List<String> authHeaders = request.headers['Authorization'];
    _require(authHeaders != null && authHeaders.length != 0);
    
    String authHeader = authHeaders.fold(null, 
        (l, r) => r.startsWith("OAuth ") ? r : l);
    _require(authHeader != null);
    
    authHeader = authHeader.substring(5);
    
    params = new Map<String, String>();
    for(var e in authHeader.split(",")) {
      Match res = _paramRegex.matchAsPrefix(e);
      _require(res != null);
      
      String key   = oauthDecode(res[1]);
      String value = oauthDecode(res[2]);
      params[key] = value;
    }
    
    if(params.containsKey("oauth_version"))
      _require(params["oauth_version"] == "1.0");
    
    _require(params["oauth_signature_method"] == "HMAC-SHA1");
    
    consumerKey   = params["oauth_consumer_key"];
    _require(consumerKey != null);
    
    tokenKey      = params["oauth_token"];
    if(tokenKey == null)
      tokenKey = "";
    
    signature = params.remove("oauth_signature");
    _require(signature != null);
    
    var strTimestamp = params["oauth_timestamp"];
    _require(strTimestamp != null);
    
    var timestamp = new DateTime.fromMillisecondsSinceEpoch(
        int.parse(strTimestamp, radix: 10) * 1000, isUtc: true);
    
    var now     = new DateTime.now();
    var diff    = now.difference(timestamp);
    _require(diff < timestampLeeway);
    
    return nonceQuery(consumerKey, tokenKey, params["oauth_nonce"], 
        timestamp.add(timestampLeeway * 2));
  }).then((res) {
    _require(res);
    
    return tokenFinder(consumerKey, tokenKey);
  }).then((TokenPair tokens_) {
    tokens = tokens_;
    
    List<Parameter> reqParams = new List<Parameter>.from(mapParameters(params));
    reqParams.addAll(mapParameters(request.uri.queryParameters));
    
    var contentType = request.headers.contentType;
    if(contentType != null 
        && contentType.mimeType == "application/x-www-form-urlencoded") {
      String encoding = contentType.parameters["charset"];
      if(encoding == null) encoding = "UTF-8";
      var codec = Encoding.getByName(encoding);
      return codec.decodeStream(request.asBroadcastStream()).then((String data) {
        reqParams.addAll(mapParameters(Uri.splitQueryString(data, encoding: codec)));
        return reqParams;
      });
    } else {
      return reqParams;
    }
  }).then((List<Parameter> reqParams) {   
    List<int> sigBase = computeSignatureBase(request.method, request.requestedUri, reqParams);
    List<int> sigKey  = computeKey(tokens.consumer, tokens.user);
    String    sig     = computeSignature(sigKey, sigBase);
    
    return sig == signature;
  }).catchError((_) => false, test: (e) => false);//e is _NotAuthorized);
}
