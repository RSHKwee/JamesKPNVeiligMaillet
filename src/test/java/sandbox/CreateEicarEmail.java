package sandbox;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.apache.mailet.Mail;
import org.apache.mailet.base.test.FakeMail;

public class CreateEicarEmail {
  public static void main(String[] args) throws MessagingException, IOException {
    // 1. Stel e-mailproperties in (niet nodig voor alleen genereren, wel voor
    // verzenden)
    Properties props = new Properties();
    Session session = Session.getInstance(props);

    // 2. Maak een MimeMessage
    MimeMessage mimeMessage = new MimeMessage(session);

    // 3. Stel headers in
    mimeMessage.setHeader("Date", "Fri, 18 Jul 2025 14:14:03 +0200 (CEST)");
    mimeMessage.setHeader("Message-ID", "<1601756706.0.1752840843239>");
    mimeMessage.setSubject("Test: EICAR Virus Test File");
    mimeMessage.setFrom(new InternetAddress("sender@example.com"));
    mimeMessage.setRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"));
    mimeMessage.setHeader("MIME-Version", "1.0");

    // 4. Maak een multipart-bericht met boundary
    String boundary = "7d54f7c3_03a2_4215_9b6c_2439f0824d20";
    MimeMultipart multipart = new MimeMultipart("mixed");
    multipart.setSubType("mixed");
    mimeMessage.setContent(multipart);

    // 5. Voeg de EICAR-bijlage toe
    MimeBodyPart attachmentPart = new MimeBodyPart();
    String eicarContent = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    attachmentPart.setContent(eicarContent, "application/octet-stream");
    attachmentPart.setFileName("eicar.com");
    attachmentPart.setHeader("Content-ID", "<c6d1e995-d4ac-4ab9-8b50-7f4568b9c499>");
    multipart.addBodyPart(attachmentPart);

    // 6. Schrijf het bericht naar een bestand (of verstuur het)
    mimeMessage.writeTo(System.out); // Print naar console (of gebruik FileOutputStream)

    // 5. Maak het Mail object
    Mail mail;
    //@formatter:off
    mail = FakeMail.builder()
        .name("virus-test-mail")
        .mimeMessage(mimeMessage)
        .sender("sender@domain.com")
        .recipient("recipient@domain.com")
        .build();
    //@formatter:on

    Path tempPath = Paths.get(System.getProperty("java.io.tmpdir"));
    Path tempFile = Files.createTempFile(tempPath, "scan-", ".eml");
    try (OutputStream out = Files.newOutputStream(tempFile)) {
      mail.getMessage().writeTo(out);
    }
    System.out.println("File: " + tempFile.toAbsolutePath().toString());
  }
}