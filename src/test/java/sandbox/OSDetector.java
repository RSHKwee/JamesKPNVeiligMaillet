package sandbox;

public class OSDetector {
  public static void main(String[] args) {
      String os = System.getProperty("os.name").toLowerCase();
      
      if (os.contains("win")) {
          System.out.println("Dit is Windows");
      } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
          System.out.println("Dit is Linux/Unix");
      } else if (os.contains("mac")) {
          System.out.println("Dit is Mac OS");
      } else {
          System.out.println("Onbekend besturingssysteem: " + os);
      }
  }
}
