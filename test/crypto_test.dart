import 'package:oauth/client.dart' as oauth;
import 'package:http/http.dart' as http;
import 'package:unittest/unittest.dart';

void main() {
  test("GET secret", () {
    var consumer = new oauth.Token("consumer", "remusnoc");
    var user     = new oauth.Token("user",     "resu");
    var nonce   = "1234";
    
    var req = new http.Request("GET", Uri.parse("http://example.com/?a=1&b=2"));
    var params = oauth.generateParameters(req, consumer, user, nonce, 1398030869);
    
    expect(params['oauth_signature'] == "SUmV0pnBNRvm57z69++0qAlg5Qk=", true);
  });
}