///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS org.apache.wss4j:wss4j-ws-security-dom:3.0.4
//DEPS org.apache.santuario:xmlsec:3.0.4
//DEPS jakarta.mail:jakarta.mail-api:2.1.3
//DEPS org.eclipse.angus:angus-mail:2.0.3

// Independent WS-Security oracle: verifies a complete AS4 wire message —
// envelope signature AND SwA attachment digests — using Apache WSS4J, the
// stack phase4/production access points run. xmlsec1 can't check cid: refs;
// this can.
//
// Usage:
//   jbang Wss4jVerify.java <mime-dump-file> [trusted-cert.pem]
//
// When a PEM is given it is loaded as Merlin's trust store so self-signed
// fixture certs (and pinned peer certs) pass path validation. Without it
// Merlin has no roots and fails with "No trusted certs found".
//
// Exit 0 = every signature reference (incl. attachments) verified.
// Drive via `julia --project=. test/oracle_wss4j.jl` (skips if jbang is absent).

import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.util.ByteArrayDataSource;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class Wss4jVerify {
  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      System.err.println("usage: jbang Wss4jVerify.java <mime-dump> [trusted-cert.pem]");
      System.exit(2);
    }
    byte[] raw = Files.readAllBytes(Path.of(args[0]));
    String s = new String(raw, java.nio.charset.StandardCharsets.ISO_8859_1);
    int split = s.indexOf("\r\n\r\n");
    String head = s.substring(0, split);
    String ctype = head.lines().filter(l -> l.toLowerCase().startsWith("content-type:"))
        .findFirst().orElseThrow().substring(13).trim();
    byte[] body = s.substring(split + 4).getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);

    MimeMultipart mm = new MimeMultipart(new ByteArrayDataSource(body, ctype));
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document soap = dbf.newDocumentBuilder().parse(mm.getBodyPart(0).getInputStream());

    List<Attachment> atts = new ArrayList<>();
    for (int i = 1; i < mm.getCount(); i++) {
      Attachment a = new Attachment();
      String id = mm.getBodyPart(i).getHeader("Content-ID")[0].replaceAll("[<>]", "");
      a.setId(id);
      a.setSourceStream(mm.getBodyPart(i).getInputStream());
      atts.add(a);
    }
    CallbackHandler attachments = (Callback[] callbacks) -> {
      for (Callback cb : callbacks) {
        if (cb instanceof AttachmentRequestCallback arc) arc.setAttachments(atts);
        else if (cb instanceof AttachmentResultCallback) { /* verification output, ignore */ }
      }
    };

    Merlin crypto = new Merlin();
    if (args.length >= 2) {
      // Pin the signing cert (self-signed fixture or ATO leaf). Merlin's default
      // empty trust store would reject any path validation.
      KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
      trust.load(null, null);
      try (InputStream in = Files.newInputStream(Path.of(args[1]))) {
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(in);
        trust.setCertificateEntry("trusted", cert);
      }
      crypto.setTrustStore(trust);
    }

    RequestData data = new RequestData();
    data.setAttachmentCallbackHandler(attachments);
    data.setSigVerCrypto(crypto);
    org.w3c.dom.Element sec = (org.w3c.dom.Element) soap.getElementsByTagNameNS(
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security").item(0);
    new WSSecurityEngine().processSecurityHeader(sec, data);
    System.out.println("WSS4J: all signature references verified");
  }
}
