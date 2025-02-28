package DigitalSignature;
import librerias.Options;
public class SignatureOptions extends Options {
    protected String keyFilename = "practica4.key";

    protected char[] keyFilePasswd = new char[] { 'p', 'a', 'l', 'a', 'b', 'r', 'a' };

    public static String optionsFileName = "Practica4.cfg";

    protected String publicCipher;

    protected String signAlgorithm;

    public String getPublicCipher() {
        return this.publicCipher;
    }

    public void setPublicCipher(String paramString) {
        this.publicCipher = paramString;
    }

    public String getSignAlgorithm() {
        return this.signAlgorithm;
    }

    public void setSignAlgorithm(String paramString) {
        this.signAlgorithm = paramString;
    }

    public SignatureOptions() {
        setSignAlgorithm(Options.signAlgorithms[0]);
        setPublicCipher(Options.publicAlgorithms[0]);
    }

    public SignatureOptions(String paramString1, String paramString2, String paramString3, String paramString4, String paramString5, char[] paramArrayOfchar) {
//        setSymmetricalCipher(paramString1);
        setPublicCipher(paramString1);
        setAuthenticator(paramString2);
        setSignAlgorithm(paramString4);
        setPublicCipher(paramString3);
        this.keyFilename = paramString5;
        this.keyFilePasswd = paramArrayOfchar;
    }

    public String getKeyFilename() {
        return this.keyFilename;
    }

    public char[] getKeyFilePasswd() {
        return this.keyFilePasswd;
    }

    public void setKeyFilename(String paramString) {
        this.keyFilename = paramString;
    }

    public void setKeyFilePasswd(char[] paramArrayOfchar) {
        this.keyFilePasswd = paramArrayOfchar;
    }
}
