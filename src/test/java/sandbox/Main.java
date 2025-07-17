package sandbox;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.mail.MessagingException;

import org.apache.mailet.MailetContext;
import org.apache.mailet.base.test.FakeMailetConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kwee.james.mailets.KPNVeiligVirusScan;

public class Main {
  private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);

  public static void main(String[] args) throws IOException {
    KPNVeiligVirusScan mailet;
    MailetContext mailetContext;
    FakeMailetConfig mailetConfig;

//    Path zipPath = Paths.get("F:\\dev\\James Mailets\\JamesKPNVeiligMaillet\\src\\test\\resources\\eicar_com.zip");
    Path zipPath = Paths.get("D:\\Dev\\Github\\James Maillets\\KPNVeilig\\src\\test\\resources\\eicar_com.zip");
    // Path sourcePath = Paths.get("bronbestand.txt");
    String gezipt = "Test.txt";
    Path destinationPath = Paths.get(gezipt);
    Path entryPath = null;

    try {
      mailetContext = mock(MailetContext.class);
      mailetConfig = FakeMailetConfig.builder()
          .mailetName("KPNVeiligScan")
          .mailetContext(mailetContext)
          .setProperty("kpnVeiligPath", "C:\\Program Files (x86)\\KPN Veilig\\fsscan.exe")
          .setProperty("tmpDir", "target\\tmp")
          .setProperty("quarantineDir", "target/quarantine")
          .build();

      mailet = new KPNVeiligVirusScan();
      mailet.init(mailetConfig);
      KPNVeiligVirusScan spyMailet = spy(mailet);

      boolean result = spyMailet.scanFileWithKPNVScan(destinationPath);
      LOGGER.info("Scanresult: " + result);
    } catch (MessagingException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

  }
}