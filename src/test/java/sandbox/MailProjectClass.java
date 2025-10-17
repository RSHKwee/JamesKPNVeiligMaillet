package sandbox;

import java.util.Properties;

import jakarta.activation.DataHandler;
import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Multipart;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;

public class MailProjectClass {

  public static void main(String[] args) {

    final String username = "your.mail.id@gmail.com";
    final String password = "your.password";

    Properties props = new Properties();
    props.put("mail.smtp.auth", true);
    props.put("mail.smtp.starttls.enable", true);
    props.put("mail.smtp.host", "smtp.gmail.com");
    props.put("mail.smtp.port", "587");

    Session session = Session.getInstance(props, new Authenticator() {
      protected PasswordAuthentication getPasswordAuthentication() {
        return new PasswordAuthentication(username, password);
      }
    });

    try {

      Message message = new MimeMessage(session);
      message.setFrom(new InternetAddress("from.mail.id@gmail.com"));
      message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("to.mail.id@gmail.com"));
      message.setSubject("Testing Subject");
      message.setText("PFA");

      MimeBodyPart messageBodyPart = new MimeBodyPart();

      Multipart multipart = new MimeMultipart();

      String file = "path of file to be attached";
      String fileName = "attachmentName";
      DataSource source = new FileDataSource(file);
      messageBodyPart.setDataHandler(new DataHandler(source));
      messageBodyPart.setFileName(fileName);
      multipart.addBodyPart(messageBodyPart);

      message.setContent(multipart);

      System.out.println("Sending");

      Transport.send(message);

      System.out.println("Done");

    } catch (MessagingException e) {
      e.printStackTrace();
    }
  }
}
