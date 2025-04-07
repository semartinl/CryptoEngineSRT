package DigitalSignature;
import librerias.Header;
import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Encryption {

    /**
     * Función para cifrar un fichero utilizando cifrado asimétrico
     * @param inputFile Fichero de entrada a cifrar
     * @param ouputFile Fichero de salida con la información cifrada
     * @param paramPublicKey Clave pública a utilizar para el cifrado
     * @param algoritmoCifAsimetrico Algoritmo de cifrado asimétrico utilizado
     */
    public static final void cifrarBloques(String inputFile, String ouputFile, PublicKey paramPublicKey, String algoritmoCifAsimetrico) {
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(ouputFile);
            FileInputStream fileInputStream = new FileInputStream(inputFile);
            byte[] arrayOfByte1 = new byte[1];
            Header header = new Header((byte)20, algoritmoCifAsimetrico, "none", arrayOfByte1);
            header.save(fileOutputStream);
            Cipher cipher = Cipher.getInstance(algoritmoCifAsimetrico);
            cipher.init(1, paramPublicKey);
            byte b1 = 53;
            byte b2 = 0;
            int j = 0;
            int k = fileInputStream.available();
            byte[] arrayOfByte2 = new byte[b1];
            int i;
            while ((i = fileInputStream.read(arrayOfByte2)) != -1) {
                byte[] arrayOfByte = cipher.doFinal(arrayOfByte2, 0, i);
                fileOutputStream.write(arrayOfByte);
                b2++;
                j += i;
            }
            System.out.println("\nCifrados " + b2 + " bloques; " + j + " bytes.\n");
            fileOutputStream.close();
            fileInputStream.close();
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    /**
     * Función para descifrar un fichero utilizando cifrado asimétrico
     * @param inputFile Fichero a descifrar
     * @param outputFile Fichero donde se guardará el contenido del fichero descifrado
     * @param paramPrivateKey Clave privada a utilizar para descifrar el contenido del archivo
     */

    public static final void descifrarBloques(String inputFile, String outputFile, PrivateKey paramPrivateKey) {
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
            FileInputStream fileInputStream = new FileInputStream(inputFile);
            Header header = new Header();
            if (header.load(fileInputStream)) {
                Cipher cipher = Cipher.getInstance(header.getAlgorithm1());
                cipher.init(2, paramPrivateKey);
                byte b1 = 64;
                byte b2 = 0;
                int j = 0;
                int k = fileInputStream.available();
                byte[] buffer = new byte[b1];
                int i;
                while ((i = fileInputStream.read(buffer)) != -1) {
                    byte[] arrayOfByte1 = cipher.doFinal(buffer, 0, i);
                    fileOutputStream.write(arrayOfByte1);
                    b2++;
                    j += i;
                }
                System.out.println("\nDescifrados " + b2 + " bloques; " + j + " bytes.\n");
                fileOutputStream.close();
                fileInputStream.close();
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

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

