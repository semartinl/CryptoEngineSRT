package DigitalSignature;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Encryption {


    /**
     * Encripta un archivo utilizando la clave pública proporcionada.
     *
     * @param inputFile Ruta del archivo que se desea encriptar.
     * @param encryptedFile Ruta del archivo donde se guardará el contenido encriptado.
     * @param publicKey Clave pública utilizada para encriptar el contenido del archivo.
     * @throws Exception Si ocurre un error al leer/escribir archivos o durante el proceso de encriptación.
     */
    public static void encryptFile(String inputFile, String encryptedFile, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(encryptedFile)) {

            byte[] buffer = new byte[53]; // Tamaño de bloque para RSA
            int len;
            while ((len = fis.read(buffer)) != -1) {
                byte[] encrypted = cipher.doFinal(buffer, 0, len);
                fos.write(encrypted);
            }
        }
    }

    /**
     * Desencripta un archivo utilizando la clave privada proporcionada.
     *
     * @param encryptedFile Ruta del archivo encriptado que se desea desencriptar.
     * @param outputFile Ruta del archivo donde se guardará el contenido desencriptado.
     * @param privateKey Clave privada utilizada para desencriptar el contenido del archivo.
     * @throws Exception Si ocurre un error al leer/escribir archivos o durante el proceso de desencriptación.
     */
    public static void decryptFile(String encryptedFile, String outputFile, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        try (FileInputStream fis = new FileInputStream(encryptedFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            byte[] buffer = new byte[256]; // Tamaño de bloque para RSA
            int len;
            while ((len = fis.read(buffer)) != -1) {
                byte[] decrypted = cipher.doFinal(buffer, 0, len);
                fos.write(decrypted);
            }
        }
    }
}

