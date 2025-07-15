package sandbox;

import org.slf4j.LoggerFactory;

public class LogTest {
  public static void main(String[] args) {
    System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
    LoggerFactory.getLogger(LogTest.class).info("TEST");
  }
}
