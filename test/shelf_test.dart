import 'dart:io';
import 'package:shelf/shelf.dart' as shelf;
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:unittest/unittest.dart';
import 'package:oauth/oauth.dart' as oauth;
import 'package:oauth/server_shelf.dart';
import '_server_test.dart';

main() {
  HttpServer server;
  setUp(() {
    print("Start server...");
    return shelf_io.serve((shelf.Request req) {
      var reqAdapter = new ShelfRequestAdapter(req);
      return oauth.isAuthorized(reqAdapter, simpleTokenFinder, simpleNonceQuery)
          .then((bool authorized) {
        print("Req ${authorized}");
        if(authorized) {
          return new shelf.Response.ok("OK");
        } else {
          return new shelf.Response.forbidden("Forbidden");
        }
      }).catchError((e) {
        print("Server error ${e}");
      });
    }, InternetAddress.LOOPBACK_IP_V6, 8989).then((server_) {
      server = server_;
    });
  });
  tearDown(() {
    print("Stop server...");
    return server.close(force: false);
  });
  
  runAllTests("localhost:8989");
}