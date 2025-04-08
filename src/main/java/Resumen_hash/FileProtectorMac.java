package Resumen_hash;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Iterator;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import actividad2.CifradoOriginal;
import librerias.Header;
import librerias.Options;

public class FileProtectorMac extends CifradoOriginal {

    private static int BUFFER_SIZE = 32768;

    private static final byte[] SALT = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

    public FileProtectorMac() {}

    /**
     * Carga la cabecera de un archivo especificado.
     * @param inputFile Ruta del archivo a leer.
     * @param header Objeto Header donde se almacenará la información de la cabecera.
     * @return true si se carga correctamente, false en caso contrario.
     */

    public final boolean cargarCabeceraArchivo(String inputFile, Header header) {
        try {
            FileInputStream fileInputStream = new FileInputStream(inputFile);
            boolean bool = header.load(fileInputStream);
            fileInputStream.close();
            return bool;
        } catch (Exception exception) {
            System.out.println("Problemas al leer el fichero: " + inputFile + "\n");
            return false;
        }
    }

    /**
     * Aplica un hash a un archivo de entrada y escribe el resultado en un archivo de salida.
     * @param inputFile Archivo de entrada.
     * @param outputFile Archivo de salida.
     * @param secreto Contraseña o clave para el hash.
     * @param algoritmo Algoritmo de hashing a utilizar.
     */
    public final void applyHash(String inputFile, String outputFile, String secreto, String algoritmo) {
        System.out.println("Proceso de hashing de <" + inputFile + "> con Algoritmo: " + algoritmo + "\n");
        try (FileInputStream fileInputStream = new FileInputStream(inputFile);
             FileOutputStream fileOutputStream = new FileOutputStream(outputFile)) {

            MessageDigest messageDigest = MessageDigest.getInstance(algoritmo);
            messageDigest.update(secreto.getBytes(StandardCharsets.UTF_8));

            try (DigestInputStream digestInputStream = new DigestInputStream(fileInputStream, messageDigest)) {
                byte[] aux= new byte[BUFFER_SIZE];
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                int totalBytes = 0;

                while ((bytesRead = digestInputStream.read(buffer)) > -1) {
                    totalBytes += bytesRead;
                }

                aux = messageDigest.digest();
                System.out.println("Total bytes: " + totalBytes);

                Header header = new Header((byte) 10, "none", algoritmo, aux);
                header.save(fileOutputStream);

                fileInputStream.close();
                digestInputStream.close();
                // Escribir el contenido original del archivo después de la cabecera.
                try (FileInputStream originalFileInput = new FileInputStream(inputFile)) {


                    while ((bytesRead = originalFileInput.read(buffer)) > -1) {

                        fileOutputStream.write(buffer, 0, bytesRead);

                    }

                }

//        System.out.println("\nMD: " + srt.I.mostrarBytesComoString(aux));
                System.out.println("\nHecho (" + totalBytes + " bytes).\n");
            }



        } catch (FileNotFoundException fileNotFoundException) {
            System.out.println("Fichero no se encuentra: " + inputFile + "\n");
        } catch (IOException iOException) {
            System.out.println("Error de E/S en.\n");
        } catch (Exception exception) {
            System.out.println(String.valueOf(exception.getMessage()) + "\n");
        }
    }



    /**
     * Convierte bytes a hexadecimal
     * @param bytes Los bytes a convertir
     * @return String con el valor hexadcimal de los bytes pasado por parametro.
     */
    protected static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    /**
     * Verifica el hash de un archivo.
     * @param inputFile Archivo de entrada con el hash incorporado.
     * @param outputFile Archivo donde se almacenará el contenido sin la cabecera.
     * @param secreto Contraseña o clave para la verificación del hash.
     * @param algoritmo Algoritmo utilizado para generar el hash.
     */
    public final void verifyHash(String inputFile, String outputFile, String secreto, String algoritmo) {
        System.out.println("Proceso de verificación de <" + inputFile + "> con: " + algoritmo + "\n");
        try (FileInputStream fileInputStream = new FileInputStream(inputFile);
             FileOutputStream fileOutputStream = new FileOutputStream(outputFile)) {

            Header header = new Header();
            header.load(fileInputStream);

            MessageDigest messageDigest = MessageDigest.getInstance(header.getAlgorithm2());
            messageDigest.update(secreto.getBytes());

            try (DigestInputStream digestInputStream = new DigestInputStream(fileInputStream, messageDigest)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;

                while ((bytesRead = digestInputStream.read(buffer)) != -1) {
                    fileOutputStream.write(buffer, 0, bytesRead);
                }

                byte[] computedHash = digestInputStream.getMessageDigest().digest();
//        String storedHash = srt.I.mostrarBytesComoString(header.getData());
                String storedHash = bytesToHex(header.getData()); //Se pasa el HASH del archivo a hexadecimal
//        String calculatedHash = srt.I.mostrarBytesComoString(computedHash);
                String calculatedHash = bytesToHex(computedHash); //Se pasa el HASH calculado a hexadecimal

                System.out.println("\nMD almacenado: " + storedHash);
                System.out.println("\nMD calculado: " + calculatedHash);

                if (storedHash.contentEquals(calculatedHash)) {

                    System.out.println("\nHash idénticos, el fichero no ha sido modificado.\n");
                } else {
                    System.out.println("\nHash diferentes, el fichero ha sido modificado (o la contraseña no es correcta).\n");
                    new File(outputFile).deleteOnExit();
                }
            }

        } catch (Exception exception) {
            System.out.println(String.valueOf(exception.getMessage()) + "\n");
        }
    }

    /**
     * Muestra las distintas opciones de algoritmos de Hash y devuelve el elegido
     * @return String Algoritmo de Hash elegido
     */
    public static String solicitarAlgoritmoHash() {
        int alCifrado = -1;
        while (alCifrado < 0 || alCifrado >= Options.hashAlgorithms.length) {
            for (int i = 0; i < Options.hashAlgorithms.length; i++) {
                System.out.println("[" + i + "]" + Options.hashAlgorithms[i]);
            }
            alCifrado = leerIntegerTeclado("Elige un algoritmo de cifrado: ");
        }
        return Options.hashAlgorithms[alCifrado];
    }
    /**
     * Muestra las distintas opciones de algoritmos de MAC y devuelve el elegido
     * @return String Algoritmo de MAC elegido
     */
    static String solicitarAlgoritmoHMAC() {
        int alCifrado = -1;
        while (alCifrado < 0 || alCifrado >= Options.macAlgorithms.length) {
            for (int i = 0; i < Options.macAlgorithms.length; i++) {
                System.out.println("[" + i + "]" + Options.macAlgorithms[i]);
            }
            alCifrado = leerIntegerTeclado("Elige un algoritmo de cifrado: ");
        }
        return Options.macAlgorithms[alCifrado];
    }

    /**
     * Crea una nueva secret key
     * @param secret Una clave privada para guardar el secreto
     * @param datos Datos que se quieren guardar.
     * @param iterationCount Numero de iteraciones de la funcion de creación de la clave secreta
     * @param macLength Tamaño que va a tener el mac
     * @return SecretKey El valor de la clave secreta creada.
     */
    public static final SecretKey generateSecretKey(char[] secret, byte[] datos, int iterationCount, int macLength) {
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            PBEKeySpec pBEKeySpec = new PBEKeySpec(secret, datos, iterationCount, macLength);
            return secretKeyFactory.generateSecret(pBEKeySpec);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    /**
     * Aplica un HMAC a un archivo de entrada y escribe el resultado en un archivo de salida.
     * @param inputFile Archivo de entrada.
     * @param outputFile Archivo de salida.
     * @param secreto Contraseña o clave para el hash.
     * @param algoritmo Algoritmo de hashing a utilizar.
     */
    public final void applyHMAC(String inputFile, String outputFile, String secreto, String algoritmo) {
        System.out.println("Proceso de HMac de <" + inputFile + "> con Algoritmo: " + algoritmo + "\n");
        try {
            FileInputStream fileInputStream = new FileInputStream(inputFile);
            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
            Mac mac = Mac.getInstance(algoritmo);
            SecretKey secretKey = generateSecretKey(secreto.toCharArray(), SALT, this.num_bytes, mac.getMacLength());
            mac.init(secretKey);
            byte[] arrayOfByte = new byte[BUFFER_SIZE];
            while (true) {
                int i = fileInputStream.read(arrayOfByte, 0, BUFFER_SIZE);
                mac.update(arrayOfByte, 0, i);
                if (i != BUFFER_SIZE) {
                    byte[] macValue = mac.doFinal();
                    fileInputStream.close();
                    Header headerCifradoMAC = new Header((byte)10, "none", algoritmo, macValue);
                    headerCifradoMAC.save(fileOutputStream);
                    fileInputStream.close();
                    fileInputStream = new FileInputStream(inputFile);
                    while (true) {
                        i = fileInputStream.read(arrayOfByte, 0, BUFFER_SIZE);
                        fileOutputStream.write(arrayOfByte, 0, i);
                        if (i != BUFFER_SIZE) {
//              System.out.println("\nMD: " + srt.I.mostrarBytesComoString(arrayOfByte1));
                            System.out.println("\nMD: " + bytesToHex(macValue));
                            fileOutputStream.flush();
                            fileOutputStream.close();
                            fileInputStream.close();
                            return;
                        }
                    }
//          break;
                }
            }
        } catch (FileNotFoundException fileNotFoundException) {
            System.out.println("Fichero no se encuentra: " + inputFile + "\n");
        } catch (IOException iOException) {
            System.out.println("Error de E/S en.\n");
        } catch (Exception exception) {
            System.out.println(String.valueOf(exception.getMessage()) + "\n");
        }
    }
    /**
     * Verifica el HMAC de un archivo.
     * @param inputFile Archivo de entrada con el hash incorporado.
     * @param outputFile Archivo donde se almacenará el contenido sin la cabecera.
     * @param secreto Contraseña o clave para la verificación del HMAC.
     * @param algoritmo Algoritmo utilizado para generar el HMAC.
     */
    public final void verifyHMAC(String inputFile, String outputFile, String secreto, String algoritmo) {
        try {
            System.out.println("Proceso de verificación de <" + inputFile + "> con: " + algoritmo + "\n");
            FileInputStream fileInputStream = new FileInputStream(inputFile);
            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
            Header headerCifradoMAC = new Header();
            headerCifradoMAC.load(fileInputStream);

            Mac mac = Mac.getInstance(algoritmo);
            SecretKey secretKey = generateSecretKey(secreto.toCharArray(), SALT, this.num_bytes, mac.getMacLength());
            mac.init(secretKey);
            byte[] arrayOfByte = new byte[BUFFER_SIZE];
            while (true) {
                int i = fileInputStream.read(arrayOfByte, 0, BUFFER_SIZE);
                mac.update(arrayOfByte, 0, i);
                fileOutputStream.write(arrayOfByte, 0, i);
                if (i != BUFFER_SIZE) {
                    byte[] macValue = mac.doFinal();
                    System.out.println("\nHecho.\n");
                    String macCalculatedHex = bytesToHex(macValue);
                    String macStoragedFileHex = bytesToHex(headerCifradoMAC.getData());
                    System.out.println("\nMD almacenado: " + macStoragedFileHex);
                    System.out.println("\nMD  calculado: " + macCalculatedHex);
                    if (macCalculatedHex.contentEquals(macStoragedFileHex)) {
                        System.out.println("\nHMac idénticos, el fichero no ha sido modificado.\n");
                    } else {
                        System.out.println("\nHMac diferentes, el fichero ha sido modificado (o la contraseña no es correcta).\n");
                        (new File(outputFile)).deleteOnExit();
                    }
                    fileInputStream.close();
                    fileOutputStream.flush();
                    fileOutputStream.close();
                    return;
                }
            }
        } catch (Exception exception) {
            System.out.println(String.valueOf(exception.getMessage()) + "\n");
        }
    }

    /**
     * Muestra los algoritmos de cifrado disponibles para utilizar
     */
    final void MostrarInformacionAlgoritmosCifrado() {
        Set<String> set = Security.getAlgorithms("Cipher");
        System.out.println("\nInformación sobre la JCE:");
        System.out.println("\nAlgoritmos de cifrado disponibles: \n");
        Iterator<String> iterator = set.iterator();
        while (iterator.hasNext())
            System.out.println((new StringBuilder()).append(iterator.next()).append(", ").toString());
        System.out.println("\n");
    }

    /**
     * Muestra los algoritmos disponibles a utilizar que nos proporciona el servicio de MessageDigest
     */
    final void MostrarInformacionAlgoritmosResumen() {
        Set<String> set = Security.getAlgorithms("MessageDigest");
        System.out.println("\nInformación sobre la JCE:");
        System.out.println("Algoritmos de resumen disponibles: ");
        Iterator<String> iterator = set.iterator();
        while (iterator.hasNext())
            System.out.println((new StringBuilder()).append(iterator.next()).append(", ").toString());
        System.out.println("\n");
    }
}
