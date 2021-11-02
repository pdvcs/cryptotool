package net.pdutta.cryptotool;

/**
 * This is a temporary, naive implmentation.
 * Eventually we'll get this from an HSM.
 */
public class KeyOnDiskSecretProvider implements ISecretProvider {
    @Override
    public char[] secret() {
        return Utils.readSmallFile(this.keyFilename).toCharArray();
    }

    @SuppressWarnings("unused")
    public String getKeyFilename() {
        return this.keyFilename;
    }

    public void setKeyFilename(String keyFilename) {
        this.keyFilename = keyFilename;
    }

    private String keyFilename;
}
