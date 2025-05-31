package DigitalSignature;
import librerias.Header;
import librerias.Options;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;

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
            // Se abre el archivo de salida y entrada
            FileOutputStream fileOutputStream = new FileOutputStream(ouputFile);
            FileInputStream fileInputStream = new FileInputStream(inputFile);

            // Se crea una cabecera con información del algoritmo usado
            byte[] arrayOfByte1 = new byte[1];
            Header header = new Header(Options.OP_PUBLIC_CIPHER, algoritmoCifAsimetrico, "none", arrayOfByte1);
            header.save(fileOutputStream); // Guardamos la cabecera en el archivo cifrado

            // Se inicializa el cifrador con la clave pública
            Cipher cipher = Cipher.getInstance(algoritmoCifAsimetrico);
            cipher.init(Cipher.ENCRYPT_MODE, paramPublicKey);

            // Se calcula el tamaño de bloque máximo permitido por la clave pública y el padding
            int keySizeBytes = ((RSAKey) paramPublicKey).getModulus().bitLength() / 8;
            int blockSize = keySizeBytes - 11; // PKCS1Padding reserva 11 bytes
            System.out.println("Tamaño de cifrado del algoritmo: " + cipher.getBlockSize());
            System.out.println("Tamaño del cifrado por bloque (blocksize): " + blockSize);

            byte b2 = 0; // contador de bloques
            int j = 0;   // contador de bytes totales
            byte[] arrayOfByte2 = new byte[blockSize];
            int i;

            // Se lee y cifra el archivo por bloques compatibles con el tamaño RSA
            while ((i = fileInputStream.read(arrayOfByte2)) != -1) {
                byte[] arrayOfByte = cipher.doFinal(arrayOfByte2, 0, i); // Se cifra el bloque
                fileOutputStream.write(arrayOfByte); // Se escribe en el archivo de salida
                b2++;
                j += i;
            }

            System.out.println("\nCifrados " + b2 + " bloques; " + j + " bytes.\n");

            // Se cierran los flujos
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

    public static final boolean descifrarBloques(String inputFile, String outputFile, PrivateKey paramPrivateKey) throws Exception {
        FileOutputStream fileOutputStream = null;
        FileInputStream fileInputStream = null;
        try {
            // Se abre el archivo de salida y el de entrada cifrado
            fileOutputStream = new FileOutputStream(outputFile);
            fileInputStream = new FileInputStream(inputFile);

            // Se carga la cabecera que contiene metadatos del algoritmo utilizado
            Header header = new Header();

            if (header.load(fileInputStream)) {
                if (header.getOperation() == Options.OP_PUBLIC_CIPHER) {
                    // Se inicializa el cifrador con la clave privada
                    Cipher cipher = Cipher.getInstance(header.getAlgorithm1());
                    cipher.init(Cipher.DECRYPT_MODE, paramPrivateKey);

                    // Se calcula el tamaño de bloque de entrada según la clave
                    int keySizeBytes = ((RSAKey) paramPrivateKey).getModulus().bitLength() / 8;
                    int blockSize = keySizeBytes;
                    System.out.println("Tamaño de cifrado del algoritmo: " + cipher.getBlockSize());
                    System.out.println("Tamaño del cifrado por bloque (blocksize): " + blockSize);

                    byte b2 = 0; // bloques procesados
                    int j = 0;   // total de bytes
                    byte[] buffer = new byte[blockSize];
                    int i;

                    // Se lee y descifra el archivo por bloques RSA
                    while ((i = fileInputStream.read(buffer)) != -1) {
                        byte[] arrayOfByte1 = cipher.doFinal(buffer, 0, i); // Se descifra
                        fileOutputStream.write(arrayOfByte1);               // Se escribe el bloque descifrado
                        b2++;
                        j += i;
                    }

                    System.out.println("\nDescifrados " + b2 + " bloques; " + j + " bytes.\n");


                }

            }
            else {
                throw new Exception("Error: El fichero no se encuentra cifrado");

            }

        }finally {
            // Se cierran los flujos
            if (fileInputStream != null) fileInputStream.close();
            if (fileOutputStream != null) fileOutputStream.close();
        }
        return true;
    }

}

