package org.apache.james.mailets.kwee;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;

import org.apache.james.core.builder.MimeMessageBuilder;
import org.apache.mailet.Mail;
import org.apache.mailet.MailetContext;
import org.apache.mailet.base.test.FakeMail;
import org.apache.mailet.base.test.FakeMailetConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import jakarta.mail.MessagingException;

public class KPNVeiligVirusScanTest {
  private static final Logger LOGGER = LoggerFactory.getLogger(KPNVeiligVirusScanTest.class);

  private KPNVeiligVirusScan mailet;
  private MailetContext mailetContext;
  private FakeMailetConfig mailetConfig;
  Path tempPath;

  @BeforeMethod
  public void setUp() throws Exception {
    tempPath = Paths.get(System.getProperty("java.io.tmpdir"));
    mailet = new KPNVeiligVirusScan();
    mailetContext = mock(MailetContext.class);
    //@formatter:off
    mailetConfig = FakeMailetConfig.builder()
        .mailetName("KPNVeiligScan")
        .mailetContext(mailetContext)
        .setProperty("kpnVeiligPath", "C:\\Program Files (x86)\\KPN Veilig\\fsscan.exe")
        .setProperty("tmpDir", tempPath.toAbsolutePath().toString())
        .setProperty("quarantineDir", "target/quarantine")
        .build();
    //@formatter:on
  }

  @Test
  public void testInitShouldCreateDirectories() throws Exception {
    LOGGER.info("testInitShouldCreateDirectories");
    mailet.init(mailetConfig);
    // Hier zou je kunnen verifiëren of directories zijn aangemaakt
    // (In echte implementatie zou je Files.exists checken)
  }

  @Test
  public void testCleanMailShouldContinueProcessing() throws Exception {
    LOGGER.info("testCleanMailShouldContinueProcessing");
    // Arrange
    mailet.init(mailetConfig);
    FakeMail mail = createTestMail();

    // Mock de scanner om false (schoon) terug te geven
    // KPNVeiligVirusScan spyMailet = spy(mailet);
    // spyMailet.service(mail);
    mailet.service(mail);

    // Assert
    assertNull(mail.getState(), "Mail state should not be changed");
  }

  @Test
  public void testInfectedMailShouldBeQuarantined() throws Exception {
    LOGGER.info("testInfectedMailShouldBeQuarantined");
    // Arrange
    mailet.init(mailetConfig);
    FakeMail mail = createInfectedMail();

    // Act
    mailet.service(mail);

    // Assert
    assertEquals(mail.getState(), Mail.GHOST, "Mail should be ghosted");
  }

  @Test
  public void testQuarantineDisabled() throws Exception {
    LOGGER.info("testQuarantineDisabled");

    //@formatter:off
    mailetConfig = FakeMailetConfig.builder()
        .mailetName("KPNVeiligVirusScan")
        .mailetContext(mailetContext)
        .setProperty("quarantine", "false")
        .setProperty("tmpDir", tempPath.toAbsolutePath().toString())
        .build();
    mailet.init(mailetConfig);
    //@formatter:on

    FakeMail mail = createInfectedMail();

    // Act
    mailet.service(mail);

    // Assert
    assertEquals(mail.getState(), Mail.GHOST, "Mail should be ghosted");
    // Verify no move to quarantine happened
    // (In echte implementatie zou je filesystem checks doen)

  }

  // Local routines
  //
  private FakeMail createTestMail() {
    javax.mail.internet.MimeMessage message;
    try {
      message = MimeMessageBuilder.mimeMessageBuilder().setSubject("Test mail").setText("Hello world!").build();
      return FakeMail.builder().name("mail1").mimeMessage(message).sender("sender@domain.com")
          .recipient("recipient@domain.com").build();
    } catch (Exception e) {
      // TODO Auto-generated catch block
      LOGGER.info(e.getMessage().toString());
      // e.printStackTrace();
    }
    return null;
  }

  // " *H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
  private FakeMail createInfectedMail() throws MessagingException, IOException {
    // 1. Maak een MimeMessage
    Properties props = new Properties();
    Session session = Session.getInstance(props);

    // 2. Maak een MimeMessage
    MimeMessage mimeMessage = new MimeMessage(session);
    try {
      String eicar = reverse("*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X");

      mimeMessage.setFrom("sender@example.com");
      mimeMessage.setRecipients(javax.mail.Message.RecipientType.TO, "recipient@example.com");
      mimeMessage.setSubject("Test: EICAR Virus Test File");

      // 3. Maak multipart bericht met tekst en bijlage
      MimeMultipart multipart = new MimeMultipart();

      // 3a. Tekstgedeelte
      MimeBodyPart textPart = new MimeBodyPart();
      textPart.setText("Dit is een testmail met een veilig testvirus als bijlage.");
      multipart.addBodyPart(textPart);

      // 3b. EICAR bijlage
      MimeBodyPart attachmentPart = new MimeBodyPart();

      // 3c. Maak datasource voor de bijlage
      ByteArrayDataSource ds = new ByteArrayDataSource(eicar.getBytes(), "application/octet-stream");
      attachmentPart.setDataHandler(new javax.activation.DataHandler(ds));
      attachmentPart.setFileName("eicar.com");
      multipart.addBodyPart(attachmentPart);

      // 4. Zet de content in het bericht
      mimeMessage.setContent(multipart);

      // 5. Maak het Mail object
      Mail mail;
      mail = FakeMail.builder().name("virus-test-mail").mimeMessage(mimeMessage).sender("sender@domain.com")
          .recipient("recipient@domain.com").build();

      return (FakeMail) mail;
    } catch (Exception e) {
      // TODO Auto-generated catch block
      // e.printStackTrace();
      LOGGER.info(e.getMessage().toString());
    }
    return null;
  }

  private String reverse(String str) {
    if (str.isEmpty()) {
      return str;
    }
    return reverse(str.substring(1)) + str.charAt(0);
  }

}