/** Client support for OAuth 1.0a with [http.BaseClient]
 */
library oauth.client;
import "dart:typed_data";
import 'dart:async';
import 'dart:io';
import 'package:oauth/src/utils.dart';
import 'package:oauth/src/core.dart';
import 'package:oauth/src/token.dart';
import 'package:http/http.dart' as http;
import 'package:crypto/crypto.dart' as crypto;
export 'package:oauth/src/token.dart' show Token;
import "package:cipher/cipher.dart" as cipher;
import 'package:asn1lib/asn1lib.dart' as asn1;


abstract class Signer {
  final String method;
  Signer(this.method);

  String compute(Token consumerToken, Token userToken, List<int> signatureBase);
}

class HmacSigner extends Signer {
  List<int> computeKey(Token consumer, Token user) {
    List<int> res = new List<int>();
    res.addAll(oauthEncode(consumer.secret));
    res.add($amp);
    if (user != null) res.addAll(oauthEncode(user.secret));
    return res;
  }

  static final HmacSigner _instance = new HmacSigner._internal();
  HmacSigner._internal() : super("HMAC-SHA1");
  factory HmacSigner() {
    return _instance;
  }
  String compute(Token consumerToken, Token userToken, List<int> signatureBase) {
    var sigKey = computeKey(consumerToken, userToken);
    var mac = new crypto.HMAC(new crypto.SHA1(), sigKey);
    mac.add(signatureBase);
    var bytes = mac.close();
    return crypto.CryptoUtils.bytesToBase64(bytes);
  }
}

class RsaSigner extends Signer {
  static cipher.Signer RSA_SHA1 = new cipher.Signer("SHA-1/RSA");
  RsaSigner(String privateKey) : super("RSA-SHA1") {
    var p = new asn1.ASN1Parser(new Uint8List.fromList(crypto.CryptoUtils.base64StringToBytes(privateKey)));
    asn1.ASN1Sequence seq = p.nextObject();
    var privk = new cipher.RSAPrivateKey((seq.elements[1] as asn1.ASN1Integer).intValue, (seq.elements[3] as asn1.ASN1Integer).intValue, (seq.elements[4] as asn1.ASN1Integer).intValue, (seq.elements[5] as asn1.ASN1Integer).intValue);
    RSA_SHA1.init(true, new cipher.ParametersWithRandom(new cipher.PrivateKeyParameter<cipher.RSAPrivateKey>(privk), new cipher.SecureRandom("AES/CTR/AUTO-SEED-PRNG")));
  }

  @override
  String compute(Token consumerToken, Token userToken, List<int> signatureBase) {
    RSA_SHA1.reset();
    cipher.RSASignature rsaSig = RSA_SHA1.generateSignature(new Uint8List.fromList(signatureBase));
    return crypto.CryptoUtils.bytesToBase64(rsaSig.bytes);
  }
}

/** Generate the parameters to be included in the `Authorization:` header of a
 *  request. Generally you should prefer use of [signRequest] or [Client] 
 */
Map<String, String> generateParameters(http.BaseRequest request, Token consumerToken, Token userToken, String nonce, int timestamp, Signer signer) {
  Map<String, String> params = new Map<String, String>();
  params["oauth_consumer_key"] = consumerToken.key;
  if (userToken != null) {
    params["oauth_token"] = userToken.key;
  }

  params["oauth_signature_method"] = signer.method;
  params["oauth_version"] = "1.0";
  params["oauth_nonce"] = nonce;
  params["oauth_timestamp"] = timestamp.toString();

  List<Parameter> requestParams = new List<Parameter>();
  requestParams.addAll(mapParameters(request.url.queryParameters));
  requestParams.addAll(mapParameters(params));

  if (request.contentLength != 0 && ContentType.parse(request.headers["Content-Type"]).mimeType == "application/x-www-form-urlencoded") {
    requestParams.addAll(mapParameters((request as http.Request).bodyFields));
  }

  var sigBase = computeSignatureBase(request.method, request.url, requestParams);
  params["oauth_signature"] = signer.compute(consumerToken, userToken, sigBase);

  return params;
}

/// Produces a correctly formatted Authorization header given a parameter map
String produceAuthorizationHeader(Map<String, String> parameters) {
  return "OAuth " + encodeAuthParameters(parameters);
}

/** Signs [request] using consumer token [consumerToken] and user authorization
 *  [userToken]
 *
 *  If the body of [request] has content type 
 *  `application/x-www-form-urlencoded`, then the request body cannot be 
 *  streaming as the body parameters are required as part of the signature.
 * 
 *  The combination of [consumerToken], [userToken], [nonce] and [timestamp]
 *  must be unique. [timestamp] must be specified in Unix time format (i.e. 
 *  seconds since 1970-01-01T00:00Z)
 */
void signRequest(http.BaseRequest request, Token consumerToken, Token userToken, String nonce, int timestamp, Signer signer) {

  var params = generateParameters(request, consumerToken, userToken, nonce, timestamp, signer);

  request.headers["Authorization"] = produceAuthorizationHeader(params);
}

/** An implementation of [http.BaseClient] which signs all requests with the
 * provided credentials.
 * 
 */
class Client extends http.BaseClient {
  final Signer signer;
  /// The OAuth consumer/client token. Required.
  Token consumerToken;

  /// The OAuth user/authorization token. Optional.
  Token userToken;
  http.BaseClient _client;

  /// The wrapped client
  http.BaseClient get client => _client;

  /** Constructs a new client, with tokens [consumerToken] and optionally 
   * [userToken]. If [client] is provided, it will be wrapped, else a new 
   * [http.Client] will be created.
   * 
   *  If the body of any request has content type 
   * `application/x-www-form-urlencoded`, then the request cannot be 
   *  streaming as the body parameters are required as part of the signature.
   */
  Client(this.consumerToken, {Signer signer, http.BaseClient client, Token this.userToken})
      : this.signer = (signer == null ? new HmacSigner() : signer),
        _client = client != null ? client : new http.Client();

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) => async.then((_) => getRandomBytes(8)).then((nonce) {
    String nonceStr = crypto.CryptoUtils.bytesToBase64(nonce, urlSafe: true);
    signRequest(request, consumerToken, userToken, nonceStr, new DateTime.now().millisecondsSinceEpoch ~/ 1000, signer);
    return _client.send(request);
  });
}
