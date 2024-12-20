package DigitalSignature;

import java.security.PrivateKey;
import java.security.PublicKey;

public class Main {

    public static void main(String[] args) {
        try {
            // Archivos de claves
            String publicKeyFile = "publicKey.key";
            String privateKeyFile = "privateKey.key";

            // Generar y guardar claves
            KeyManagement.generateAndStoreKeys("RSA",publicKeyFile, privateKeyFile);

            System.out.println("Generado el par de claves");
            // Cargar claves
            PublicKey publicKey = KeyManagement.loadPublicKey(publicKeyFile);
            PrivateKey privateKey = KeyManagement.loadPrivateKey(privateKeyFile);

            // Archivos de prueba
            String inputFile = "input.txt";
            String signatureFile = "signature.sig";
            String encryptedFile = "encrypted.enc";
            String decryptedFile = "decrypted.txt";

            // Firmar y verificar archivo
            DigitalSignature.signFile(inputFile, signatureFile, privateKey);
            boolean isVerified = DigitalSignature.verifyFile(inputFile, signatureFile, publicKey);
            System.out.println("Firma verificada: " + isVerified);

            // Encriptar y desencriptar archivo
            Encryption.encryptFile(inputFile, encryptedFile, publicKey);
            Encryption.decryptFile(encryptedFile, decryptedFile, privateKey);
            System.out.println("Archivo desencriptado con éxito.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
