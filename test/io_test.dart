import 'dart:async';
import 'dart:io';
import 'package:unittest/unittest.dart';
import 'package:oauth/oauth.dart' as oauth;
import 'package:oauth/server_io.dart';
import '_server_test.dart';

main() {
  HttpServer server;
  setUp(() {
    return HttpServer.bind(InternetAddress.LOOPBACK_IP_V6, 8989).then((server_) {
      server = server_;
      server.listen((HttpRequest request) {
        var reqAdapter = new HttpRequestAdapter(request);
        oauth.isAuthorized(reqAdapter, simpleTokenFinder, simpleNonceQuery)
            .then((bool authorized) {
          request.response.statusCode = authorized ? HttpStatus.OK : HttpStatus.FORBIDDEN;
          return request.response.close();
        });
      });
    });
  });
  tearDown(() {
    return server.close(force: true);
  });
  
  runAllTests("localhost:8989");
}