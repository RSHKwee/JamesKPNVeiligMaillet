package sandbox;

import java.util.Properties;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.FileDataSource;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

public class MailProjectClass {

  public static void main(String[] args) {

    final String username = "your.mail.id@gmail.com";
    final String password = "your.password";

    Properties props = new Properties();
    props.put("mail.smtp.auth", true);
    props.put("mail.smtp.starttls.enable", true);
    props.put("mail.smtp.host", "smtp.gmail.com");
    props.put("mail.smtp.port", "587");

    Session session = Session.getInstance(props, new javax.mail.Authenticator() {
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
