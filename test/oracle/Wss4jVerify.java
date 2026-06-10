///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS org.apache.wss4j:wss4j-ws-security-dom:3.0.4
//DEPS org.apache.santuario:xmlsec:3.0.4
//DEPS jakarta.mail:jakarta.mail-api:2.1.3
//DEPS org.eclipse.angus:angus-mail:2.0.3

// Independent WS-Security oracle: verifies a complete AS4 wire message —
// envelope signature AND SwA attachment digests — using Apache WSS4J, the
// stack phase4/production access points run. xmlsec1 can't check cid: refs;
// this can. Run: jbang Wss4jVerify.java <mime-dump-file>
//
// Exit 0 = every signature reference (incl. attachments) verified.
// UNRUN AS AT 2026-06-11: no JVM on the dev machine. First run pending; treat
// as a recipe that may need a tweak, not a proven artefact.

import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.util.ByteArrayDataSource;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class Wss4jVerify {
  public static void main(String[] args) throws Exception {
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

    RequestData data = new RequestData();
    data.setAttachmentCallbackHandler(attachments);
    data.setSigVerCrypto(new org.apache.wss4j.common.crypto.Merlin()); // BST cert from the message itself
    org.w3c.dom.Element sec = (org.w3c.dom.Element) soap.getElementsByTagNameNS(
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security").item(0);
    new WSSecurityEngine().processSecurityHeader(sec, data);
    System.out.println("WSS4J: all signature references verified");
  }
}
