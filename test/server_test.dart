import 'dart:io';
import 'dart:async';
import 'package:oauth/oauth.dart' as oauth;
import 'package:http/http.dart' as http;
import 'package:unittest/unittest.dart';

simpleNonceQuery(String consumerToken, String userToken, 
    String nonce, DateTime expiry) {
  return new Future.value(true); 
}

simpleTokenFinder(String consumer, String user) {
  return new Future.value(new oauth.TokenPair(
      new oauth.Token(consumer, consumer.toUpperCase()), 
      new oauth.Token(user, user.toUpperCase())));
}

main() {
  HttpServer server;
  String authority;

  setUp(() {
    return HttpServer.bind(InternetAddress.LOOPBACK_IP_V6, 0).then((server_) {
      server = server_;
      authority = "localhost:" + server.port.toString();
      server.listen((HttpRequest request) {
        oauth.isAuthorized(request, simpleTokenFinder, simpleNonceQuery)
            .then((bool authorized) {
          request.response.statusCode = authorized ? HttpStatus.OK : HttpStatus.FORBIDDEN;
          return request.response.close();
        });
      });
    });
  });

  standardTests(oauth.Client goodClient) => () {
    test("Simple GET", () {
      var done = expectAsync((_) {});    
  
      goodClient.get(new Uri.http(authority, "/test/path", {"foo":"bar"})).then((response) {
        expect(response.statusCode, HttpStatus.OK);
      }).then(done);
    });
    
    test("Simple POST", () {
      var done = expectAsync((_) {});
      
      goodClient.post(new Uri.http(authority, "/test/path"), body: "Hello, World!").then((response) {
        expect(response.statusCode, HttpStatus.OK);      
      }).then(done);
    });
    
    test("Form Data POST", () {
      var done = expectAsync((_) {});
      
      goodClient.post(new Uri.http(authority, "/test/path", {"c":"4"}), 
          body: "a=1&b=2&c=3",
          headers: {"Content-Type": "application/x-www-form-urlencoded"}).then((response) {
        expect(response.statusCode, HttpStatus.OK);      
      }).then(done);    
    });
  };
  
  group("Consumer credentials only",
      standardTests(new oauth.Client(new oauth.Token("Hello", "HELLO"))));
  
  group("With user credentials",
      standardTests(new oauth.Client(new oauth.Token("Hello", "HELLO"), userToken: new oauth.Token("World", "WORLD"))));
  
  test("Bad GET", () {
    var done = expectAsync((_) {});
    
    var client = new oauth.Client(new oauth.Token("bad", "very very bad"));
    client.get(new Uri.http(authority,  "/")).then((response) {
      expect(response.statusCode, HttpStatus.FORBIDDEN);
    }).then(done);
  });
}
