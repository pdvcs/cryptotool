package net.pdutta.cryptotool;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils {
    static String readSmallFile(String fname) {
        String result = null;
        try {
            final Path p = Paths.get(fname);
            result = Files.readString(p);
        } catch (IOException e) {
            log.error("error reading from file: {}", fname);
        }
        return result;
    }

    public static String byteArray(String arrayDesc, byte[] b) {
        StringBuilder sb = new StringBuilder(30);
        sb.append(arrayDesc).append(": [(").append(b.length).append(" items) ");
        if (b.length > 0) {
            sb.append(b[0]);
        }
        for (int i = 1; i < b.length; i++) {
            sb.append(", ").append(b[i]);
        }
        sb.append("]");
        return sb.toString();
    }

    public static String sha256sum(String inputFile) throws IOException {
        final String hashAlgorithm = "SHA-256";
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            log.error("error: could not find algorithm: {}", hashAlgorithm);
            return null;
        }
        InputStream fis = new BufferedInputStream(new FileInputStream(inputFile));
        byte[] byteArray = new byte[1024 * 1024]; // megabyte-sized chunks
        int bytesCount;

        while ((bytesCount = fis.read(byteArray)) != -1) {
            digest.update(byteArray, 0, bytesCount);
        }
        fis.close();

        byte[] bytes = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

    static Logger log = LoggerFactory.getLogger(CryptoTool.class);
}
