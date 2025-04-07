package DigitalSignature;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
/**
 * Clase para gestionar pares de claves RSA y su persistencia.
 * Proporciona funcionalidad para generar, cargar, guardar, y validar pares de claves.
 */
public class ParClaves {
    /**
     * Indica si el par de claves está inicializado.
     */
    protected boolean isInicialized = false;
    /**
     * Contiene el par de claves generado o cargado.
     */
    protected KeyPair generateKeyPair;
    /**
     * Sal por defecto utilizada en el cifrado basado en contraseña.
     */
    private static final byte[] DEFAULT_SALT = {-57, 115, 33, -116, 126, -56, -18, -103};
    /**
     * Constructor por defecto.
     * Inicializa la clase sin ningún par de claves generado.
     */
    public ParClaves() {
        this.isInicialized = false;
        this.generateKeyPair = null;
    }
    /**
     * Constructor que inicializa la clase con un par de claves proporcionado.
     *
     * @param parClaves El par de claves a utilizar.
     */
    public ParClaves(KeyPair parClaves ){
        this.isInicialized = true;
        this.generateKeyPair = parClaves;
    }
    /**
     * Devuelve si el par de claves está inicializado.
     *
     * @return true si el par de claves está inicializado, false en caso contrario.
     */
    public final boolean getIsInicialized() {
        return this.isInicialized;
    }
    /**
     * Devuelve la clave pública del par de claves.
     *
     * @return La clave pública.
     */
    public final PublicKey getPublicKey() {
        return this.generateKeyPair.getPublic();
    }
    /**
     * Devuelve la clave privada del par de claves.
     *
     * @return La clave privada.
     */
    public final PrivateKey getPrivateKey() {
        return this.generateKeyPair.getPrivate();
    }

    /**
     * Genera un nuevo par de claves RSA y lo valida.
     *
     * @return true si el par de claves se generó y validó correctamente.
     */
    public final boolean generateKeyPair() {
        boolean bool = false;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512);
            this.generateKeyPair = keyPairGenerator.generateKeyPair();
            bool = validateKeyPair(this.generateKeyPair);
        } catch (Exception exception) {
            exception.printStackTrace();
            this.generateKeyPair = null;
        }
        this.isInicialized = bool;
        return bool;
    }

    /**
     * Carga un par de claves desde un archivo, desencriptando la clave privada con la contraseña proporcionada.
     *
     * @param filename El nombre del archivo que contiene el par de claves.
     * @param password La contraseña para desencriptar la clave privada.
     * @return true si el par de claves se cargó correctamente, false en caso contrario.
     */
    public final boolean loadKeyPair(String filename, char[] password) {
        boolean bool = true;
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(filename));
            PublicKey publicKey = (PublicKey)objectInputStream.readObject();
            byte[] arrayOfByte = (byte[])objectInputStream.readObject();
            PrivateKey privateKey = generateKeyPair(password, arrayOfByte);
            this.generateKeyPair = new KeyPair(publicKey, privateKey);
            objectInputStream.close();
        } catch (Exception exception) {
            bool = false;
        }
        this.isInicialized = bool;
        return bool;
    }
    /**
     * Guarda el par de claves en un archivo, encriptando la clave privada con la contraseña proporcionada.
     *
     * @param filename El nombre del archivo donde se guardará el par de claves.
     * @param password La contraseña para encriptar la clave privada.
     * @return true si el par de claves se guardó correctamente, false en caso contrario.
     */
    public final boolean saveKeyPair(String filename, char[] password) {
        boolean bool = true;
        try {
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(filename));
            objectOutputStream.writeObject(this.generateKeyPair.getPublic());
            objectOutputStream.writeObject(wrapPrivateKey(password));
            objectOutputStream.close();
        } catch (Exception exception) {
            bool = false;
        }
        this.isInicialized = bool;
        return bool;
    }
    /**
     * Cifra la clave privada usando cifrado basado en contraseña.
     *
     * @param password Contraseña para cifrar la clave privada.
     * @return La clave privada cifrada como un array de bytes.
     */
    private byte[] wrapPrivateKey(char[] password) {
        byte[] arrayOfByte1 = null;
        byte[] arrayOfByte2 = { -57, 115, 33, -116, 126, -56, -18, -103 };
        byte b = 20;
        PBEParameterSpec pBEParameterSpec = new PBEParameterSpec(DEFAULT_SALT, b);
        try {
            PBEKeySpec pBEKeySpec = new PBEKeySpec(password);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey secretKey = secretKeyFactory.generateSecret(pBEKeySpec);
            Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init(Cipher.WRAP_MODE, secretKey, pBEParameterSpec);
            arrayOfByte1 = cipher.wrap(this.generateKeyPair.getPrivate());
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
        return arrayOfByte1;
    }

    /**
     * Desencripta la clave privada usando cifrado basado en contraseña.
     *
     * @param password Contraseña para desencriptar la clave privada.
     * @param wrappedKey Clave privada cifrada.
     * @return La clave privada desencriptada.
     */
    private PrivateKey generateKeyPair(char[] password, byte[] wrappedKey) {
        PrivateKey privateKey = null;
        byte b = 20;
        PBEParameterSpec pBEParameterSpec = new PBEParameterSpec(DEFAULT_SALT, b);
        try {
            PBEKeySpec pBEKeySpec = new PBEKeySpec(password);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey secretKey = secretKeyFactory.generateSecret(pBEKeySpec);
            Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init(Cipher.UNWRAP_MODE, secretKey, pBEParameterSpec);
            privateKey = (PrivateKey)cipher.unwrap(wrappedKey, "RSA", 2);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
        return privateKey;
    }

    /**
     * Valida un par de claves realizando una operación de firma y verificación.
     *
     * @param keyPair El par de claves a validar.
     * @return true si la validación fue exitosa, false en caso contrario.
     */
    public final boolean validateKeyPair(KeyPair keyPair) {
        boolean bool = false;
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            PrivateKey privateKey = keyPair.getPrivate();
            signature.initSign(privateKey);
            String str = "Texto de prueba para la firma";
            signature.update(str.getBytes());
            byte[] arrayOfByte = signature.sign();
            PublicKey publicKey = keyPair.getPublic();
            signature.initVerify(publicKey);
            signature.update(str.getBytes());
            boolean bool1 = signature.verify(arrayOfByte);
            bool = bool1;
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return bool;
    }
}



