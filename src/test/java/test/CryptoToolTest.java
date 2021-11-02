package test;

import net.pdutta.cryptotool.CryptoTool;
import net.pdutta.cryptotool.KeyOnDiskSecretProvider;
import net.pdutta.cryptotool.Utils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CryptoToolTest {
    @Test
    void cryptoTool_test() throws IOException {
        String secretKey = tempDir("crypto_tool_test.key");
        writeKey(secretKey);
        KeyOnDiskSecretProvider secretProvider = new KeyOnDiskSecretProvider();
        secretProvider.setKeyFilename(secretKey);

        CryptoTool tool = new CryptoTool();
        tool.setSecretProvider(secretProvider);

        String[] sourceFiles = new String[]{"sample.txt", "earth.jpg"};
        for (String fname : sourceFiles) {
            tool.encrypt("src/test/resources/" + fname, tempDir(fname + ".enc"));
            tool.decrypt(tempDir(fname + ".enc"), tempDir(fname + ".dec"));
            String origDigest = Utils.sha256sum("src/test/resources/" + fname);
            String decryptedDigest = Utils.sha256sum(tempDir(fname + ".dec"));
            assertEquals(origDigest, decryptedDigest);
        }
    }

    private void writeKey(String secretKey) {
        String s = "an example set of credentials";
        Path path = Paths.get(secretKey);
        byte[] bytes = s.getBytes();
        try {
            Files.write(path, bytes);
        } catch (IOException e) {
            System.out.println("error: " + e.getMessage());
        }
    }

    private String tempDir(String fname) {
        String t = System.getProperty("java.io.tmpdir");
        if (fname == null) {
            return t;
        } else {
            return t + System.getProperty("file.separator") + fname;
        }
    }

}
