package net.pdutta.cryptotool;

import java.io.FileNotFoundException;

public class Demo {

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java CryptoTool.App <filename>");
        } else {
            try {
                boolean result = demo(args[0]);
                if (!result) {
                    System.out.println("error running demo().");
                }
            } catch (FileNotFoundException e) {
                System.out.println("error: " + e.getMessage());
            }
        }
    }

    private static boolean demo(String filename) throws FileNotFoundException
    {
        KeyOnDiskSecretProvider secretProvider = new KeyOnDiskSecretProvider();
        secretProvider.setKeyFilename("/tmp/demo/sec.key");

        CryptoTool tool = new CryptoTool();
        tool.setSecretProvider(secretProvider);

        System.out.println("encrypting...");
        boolean success = false;
        try {
            success = tool.encrypt(filename, filename + ".enc");
            if (!success) {
                System.out.println("error encrypting file!");
            }

            System.out.println("decrypting...");
            success = tool.decrypt(filename + ".enc", filename + ".dec");
            if (!success) {
                System.out.println("error decrypting file!");
            }

            System.out.println("computing sha256...");
            success = computeDigests(tool, filename);
        } catch (FileNotFoundException e) {
            System.out.println("error: " + e.getMessage() + ", cause: " + e.getCause());
        }

        return success;
    }

    private static boolean computeDigests(CryptoTool tool, String filename) {
        boolean result = false;
        String origFileDigest = tool.checksum(filename);
        String decryptedFileDigest = tool.checksum(filename + ".dec");
        if (origFileDigest.equals(decryptedFileDigest)) {
            System.out.println("sha256 matches");
            result = true;
        } else {
            System.out.println("error: sha256 mismatch!");
        }
        System.out.println(filename + ":     " + origFileDigest);
        System.out.println(filename + ".dec: " + decryptedFileDigest);
        return result;
    }

}
