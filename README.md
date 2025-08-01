# JamesKPNVeiligMaillet

This module is for developing and delivering extensions to James for the [KPN Veilig virusscanner](https://www.kpn.com/service/internet/veilig-internetten/kpn-veilig/kpn-veilig-op-pc) (the antivirus engine) integration.

Currently, this module provides `KPN Veilig` mailet which runs the F-Secure engine on Windows to scan virus for every
incoming mail. Upon having virus, mail will be redirected to `virus` processor with configurable behavior for further processing.

```xml
<mailet match="All" class="org.apache.james.mailets.kwee.KPNVeiligVirusScan">
    <kpnVeiligPath>"C:\Program Files\F-Secure\Anti-Virus\fsscan.exe"</kpnVeiligPath>
    <tmpDir>C:\James\temp</tmpDir>
    <quarantine>true</quarantine>
    <quarantineDir>C:\James\quarantine</quarantineDir>
    <scanTimeout>60000</scanTimeout> <!-- 60 seconden timeout -->
    
    <!-- Optionele parameters -->
    <!-- <additionalParams>/VERBOSE /LOG=C:\James\logs\kpnveilig.log</additionalParams> -->
</mailet>
```

To run James with this KPN Veilig integration, please use James's jar extension mechanism.
