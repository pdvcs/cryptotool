package net.pdutta.cryptotool;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.Optional;

public class CryptoTool {

    /**
     * Computes a SHA256 hash for the input file
     * @param filename the filename to hash
     * @return the hash using lowercase hex digits
     */
    public String checksum(String filename) {
        String digest = "";
        try {
            digest = Utils.sha256sum(filename);
        } catch (IOException e) {
            System.out.println("error: " + e.getMessage());
        }
        return digest;
    }

    /**
     * Encrypt a file
     * @param inputFile the file to encrypt
     * @param outputFile the encrypted file
     * @return 'true' if the operation is successful
     * @throws FileNotFoundException if the input file isn't found
     */
    public boolean encrypt(String inputFile, String outputFile) throws FileNotFoundException {
        InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile));
        OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
        boolean result = false;

        try {
            encryptStream(inputStream, outputStream);
            outputStream.flush();
            outputStream.close();
            result = true;
        } catch (IOException | NoSuchElementException e) {
            log.error("error: {}, {}", e.getCause(), e.getMessage());
        }
        return result;
    }

    /**
     * Decrypt a file
     * @param inputFile the file to decrypt
     * @param outputFile the decrypted file
     * @return 'true' if the operation is successful
     * @throws FileNotFoundException if the input file isn't found
     */
    public boolean decrypt(String inputFile, String outputFile) throws FileNotFoundException {
        InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile));
        OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
        boolean result = false;

        try {
            decryptStream(inputStream, outputStream);
            outputStream.flush();
            outputStream.close();
            result = true;
        } catch (IOException | NoSuchElementException e) {
            log.error("error: {}, {}", e.getCause(), e.getMessage());
        }
        return result;
    }

    @SuppressWarnings("ConstantConditions")
    public CryptoTool() {
        CryptoTool.setup();
        if (HEADER.length() != 20) {
            throw new RuntimeException("HEADER must be exactly 20 characters!");
        }
    }

    //region private methods

    private void encryptStream(InputStream istream, OutputStream ostream)
            throws IOException, NoSuchElementException {

        byte[] salt = generateSalt();
        if (!writeHeader(salt, ostream)) {
            throw new RuntimeException("error writing header");
        }
        byte[] ivData = new byte[AES_NIVBITS / 8];
        new SecureRandom().nextBytes(ivData);

        // encryption algo and padding: AES with CBC and PCKS7
        // encrypt input stream using key+iv
        KeyParameter keyParam = aesKey(salt).orElseThrow();
        CipherParameters params = new ParametersWithIV(keyParam, ivData);

        BlockCipherPadding padding = new PKCS7Padding();
        BufferedBlockCipher blockCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding);
        blockCipher.reset();
        blockCipher.init(true, params);

        ostream.write(ivData);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(ostream, blockCipher);
        IOUtils.copy(istream, cipherOutputStream);
        cipherOutputStream.close();
        istream.close();
        ostream.close();
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    private void decryptStream(InputStream encryptedInputStream, OutputStream decryptedOutputStream)
            throws IOException, NoSuchElementException {
        byte[] salt = readHeader(encryptedInputStream);

        // extract the IV, which is stored in the next N bytes at the start of fileStream
        int nIvBytes = AES_NIVBITS / 8;
        byte[] ivBytes = new byte[nIvBytes];
        encryptedInputStream.read(ivBytes, 0, nIvBytes);

        KeyParameter keyParam = aesKey(salt).orElseThrow();
        CipherParameters params = new ParametersWithIV(keyParam, ivBytes);
        BlockCipherPadding padding = new PKCS7Padding();
        BufferedBlockCipher blockCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding);
        blockCipher.reset();
        blockCipher.init(false, params);

        CipherInputStream cipherInputStream = new CipherInputStream(encryptedInputStream, blockCipher);
        IOUtils.copy(cipherInputStream, decryptedOutputStream);
        cipherInputStream.close();
        decryptedOutputStream.close();
    }

    private boolean writeHeader(byte[] salt, OutputStream ostream) {
        boolean result = false;
        try {
            byte[] header = HEADER.getBytes(StandardCharsets.UTF_8);
            assert (header.length == 20);
            assert (salt.length == 20);
            ostream.write(header);
            ostream.write(salt);
            result = true;
        } catch (IOException e) {
            log.error("writeHeader() failed: {}, {}", e.getMessage(), e.getCause());
        }
        return result;
    }

    private byte[] readHeader(InputStream istream) {
        byte[] salt = null;
        final int HEADER_BYTE_LENGTH = 40;
        try {
            byte[] header = istream.readNBytes(HEADER_BYTE_LENGTH);
            if (header == null || header.length != HEADER_BYTE_LENGTH) {
                log.error("error reading header");
            } else {
                log.trace(Utils.byteArray("header", header));
                byte[] marker = Arrays.copyOfRange(header, 0, 20);
                String markerText = new String(marker, StandardCharsets.UTF_8);
                if (!markerText.equals(HEADER)) {
                    throw new RuntimeException("Invalid header encountered!");
                }
                salt = Arrays.copyOfRange(header, 20, 40);
                assert (salt.length == 20);
                log.trace(Utils.byteArray("salt", salt));
            }
        } catch (IOException e) {
            log.error("readHeader() failed: {}, {}", e.getMessage(), e.getCause());
        }
        return salt;
    }

    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[20];
        random.nextBytes(salt);
        return salt;
    }

    private Optional<KeyParameter> aesKey(byte[] salt) {
        final String KEY_ALGORITHM = "PBEWITHSHA256AND256BITAES-CBC-BC";
        final int ITERATIONS = 4096;
        final int KEY_LENGTH = 256;

        byte[] rawKey = null;
        try {
            char[] secret = secretProvider.secret();
            PBEKeySpec keySpec = new PBEKeySpec(secret, salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
            rawKey = keyFactory.generateSecret(keySpec).getEncoded();
        } catch (Exception e) {
            log.error("keyFactory: init failed: {}, {}", e.getMessage(), e.getCause());
        }
        return rawKey != null ? Optional.of(new KeyParameter(rawKey)) : Optional.empty();
    }

    public void setSecretProvider(ISecretProvider secretProvider) {
        this.secretProvider = secretProvider;
    }

    private static void setup() {
        ensureModernCryptoPolicy();
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    private static void ensureModernCryptoPolicy() {
        if (!Security.getProperty("crypto.policy").equals("unlimited")) {
            System.out.println("Please configure the JVM's crypto.policy correctly! Exiting.");
            System.exit(1);
        }
    }

    //endregion

    private ISecretProvider secretProvider;
    private final String HEADER = "CRYPTOTOOL/000.01.00"; // must be 20 chars
    private final int AES_NIVBITS = 128;

    Logger log = LoggerFactory.getLogger(CryptoTool.class);
}
