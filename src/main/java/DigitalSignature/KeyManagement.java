package DigitalSignature;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.*;
import java.io.*;

public class KeyManagement {
    protected boolean close = false;

    protected KeyPair generatedKeyPair;

    /**
     * Genera un par de claves RSA y las guarda en los archivos especificados.
     *
     * @param algoritmo Nombre del algoritmo de cifrado (no se usa en este método, siempre usa "RSA").
     * @param publicKeyFile Ruta del archivo donde se almacenará la clave pública.
     * @param privateKeyFile Ruta del archivo donde se almacenará la clave privada.
     * @return boolean true si las claves se generaron y almacenaron correctamente.
     * @throws Exception Si ocurre un error durante la generación o almacenamiento de las claves.
     */
    public static boolean generateAndStoreKeys(String algoritmo, String publicKeyFile, String privateKeyFile) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048); // Tamaño de clave
        KeyPair keyPair = kpg.generateKeyPair();


        // Guardar clave pública
        try (ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKeyFile))) {
            publicKeyOS.writeObject(keyPair.getPublic());
        }

        // Guardar clave privada
        try (ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(privateKeyFile))) {
            privateKeyOS.writeObject(keyPair.getPrivate());
        }
        return true;
    }

    // Carga una clave pública desde un archivo
    /**
     * Carga una clave pública desde un archivo especificado.
     *
     * @param publicKeyFile Ruta del archivo que contiene la clave pública.
     * @return PublicKey Objeto que representa la clave pública cargada.
     * @throws Exception Si ocurre un error al leer o interpretar el archivo de clave pública.
     */
    public static PublicKey loadPublicKey(String publicKeyFile) throws Exception {
        try (ObjectInputStream publicKeyIS = new ObjectInputStream(new FileInputStream(publicKeyFile))) {
            return (PublicKey) publicKeyIS.readObject();
        }
    }

    /**
     * Carga una clave privada desde un archivo especificado.
     *
     * @param privateKeyFile Ruta del archivo que contiene la clave privada.
     * @return PrivateKey Objeto que representa la clave privada cargada.
     * @throws Exception Si ocurre un error al leer o interpretar el archivo de clave privada.
     */
    public static PrivateKey loadPrivateKey(String privateKeyFile) throws Exception {
        try (ObjectInputStream privateKeyIS = new ObjectInputStream(new FileInputStream(privateKeyFile))) {
            return (PrivateKey) privateKeyIS.readObject();
        }
    }

    private PrivateKey generateKeyPair(char[] paramArrayOfchar, byte[] paramArrayOfbyte) {
        PrivateKey privateKey = null;
        byte[] arrayOfByte = { -57, 115, 33, -116, 126, -56, -18, -103 };
        byte b = 20;
        PBEParameterSpec pBEParameterSpec = new PBEParameterSpec(arrayOfByte, b);
        try {
            PBEKeySpec pBEKeySpec = new PBEKeySpec(paramArrayOfchar);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey secretKey = secretKeyFactory.generateSecret(pBEKeySpec);
            Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init(4, secretKey, pBEParameterSpec);
            privateKey = (PrivateKey)cipher.unwrap(paramArrayOfbyte, "RSA", 2);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
        return privateKey;
    }

    public final boolean generateSecret(KeyPair paramKeyPair) {
        boolean bool = false;
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            PrivateKey privateKey = paramKeyPair.getPrivate();
            signature.initSign(privateKey);
            String str = "Texto de prueba para la firma";
            signature.update(str.getBytes());
            byte[] arrayOfByte = signature.sign();
            PublicKey publicKey = paramKeyPair.getPublic();
            signature.initVerify(publicKey);
            signature.update(str.getBytes());
            boolean bool1 = signature.verify(arrayOfByte);
            bool = bool1;
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return bool;
    }

    private byte[] close(char[] paramArrayOfchar) {
        byte[] arrayOfByte1 = null;
        byte[] arrayOfByte2 = { -57, 115, 33, -116, 126, -56, -18, -103 };
        byte b = 20;
        PBEParameterSpec pBEParameterSpec = new PBEParameterSpec(arrayOfByte2, b);
        try {
            PBEKeySpec pBEKeySpec = new PBEKeySpec(paramArrayOfchar);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey secretKey = secretKeyFactory.generateSecret(pBEKeySpec);
            Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init(3, secretKey, pBEParameterSpec);
            arrayOfByte1 = cipher.wrap(this.generatedKeyPair.getPrivate());
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
        return arrayOfByte1;
    }

    public final boolean saveKeyPairInFile(String paramString, char[] paramArrayOfchar) {
        boolean bool = true;
        try {
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(paramString));
            objectOutputStream.writeObject(this.generatedKeyPair.getPublic());
            objectOutputStream.writeObject(close(paramArrayOfchar));
            objectOutputStream.close();
        } catch (Exception exception) {
            bool = false;
        }
        this.close = bool;
        return bool;
    }

    public final boolean loadKeyPairFromFile(String paramString, char[] paramArrayOfchar) {
        boolean bool = true;
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(paramString));
            PublicKey publicKey = (PublicKey)objectInputStream.readObject();
            byte[] arrayOfByte = (byte[])objectInputStream.readObject();
            PrivateKey privateKey = generateKeyPair(paramArrayOfchar, arrayOfByte);
            this.generatedKeyPair = new KeyPair(publicKey, privateKey);
            objectInputStream.close();
        } catch (Exception exception) {
            bool = false;
        }
        this.close = bool;
        return bool;
    }
}
