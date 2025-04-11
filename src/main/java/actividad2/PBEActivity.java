/**
 * Actividad 2 - JCA
 * Seguridad en Redes Telemáticas
 * Estudiantes:
 * Guillén Torrado, Sara
 * Martín Ledesma, Sergio
 */

package actividad2;

import librerias.Header;
import librerias.Options;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Clase que implementa funcionalidades de cifrado y descifrado de archivos
 * usando algoritmos PBE (Password-Based Encryption) del API JCA.
 *
 * <p>Esta clase permite:
 * <ul>
 *   <li>Cifrar un archivo con contraseña usando PBE</li>
 *   <li>Descifrar un archivo validando la contraseña mediante hash</li>
 *   <li>Leer y escribir archivos cifrados o descifrados</li>
 *   <li>Generar claves de sesión desde contraseñas</li>
 * </ul>
 *
 * <p>Usa cabeceras personalizadas mediante la clase {@code Header}.
 *
 * <p>Asignatura: Seguridad en Redes Telemáticas
 * <br>Autores: Guillén Torrado, Sara - Martín Ledesma, Sergio
 */
public class PBEActivity {
    /**
     * Cifra un archivo usando una contraseña simétrica, un algoritmo PBE
     * y un número determinado de iteraciones. Guarda el resultado en un archivo ".cif".
     *
     * @param filename         Ruta del archivo a cifrar.
     * @param password         Contraseña proporcionada por el usuario.
     * @param algoritmoCifrado Algoritmo PBE a utilizar (ej. PBEWithMD5AndDES).
     * @param numIteraciones   Número de iteraciones del algoritmo PBE.
     * @param hashPassword     Hash de la contraseña para posterior validación.
     * @throws Exception Si ocurre un error durante el proceso de cifrado.
     */
    public static void processingCipher(String filename, String password, String algoritmoCifrado, int numIteraciones, byte[] hashPassword) throws Exception {

        Options confAlgoritmo = new Options();
        confAlgoritmo.setCipherAlgorithm(algoritmoCifrado);
        Cipher c = Cipher.getInstance(algoritmoCifrado);

        SecretKey sKey = generateSessionKey(password, algoritmoCifrado);

        byte[] salt;
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
//        SecureRandom random = SecureRandom.getInstance("DEFAULT", "BC");
        salt = random.generateSeed(8);

        PBEParameterSpec pPS = new PBEParameterSpec(salt, numIteraciones);

        c.init(Cipher.ENCRYPT_MODE, sKey, pPS);

        Header h = new Header(Options.OP_SYMMETRIC_CIPHER, algoritmoCifrado,
                Options.authenticationAlgorithms[0],salt, hashPassword);

        if (!writeCipheredText(c, filename, h)) {
            System.out.println("Error al cifrar el fichero");
        } else {
            System.out.println("El fichero se cifrado correctamente");
        }

    }

    /**
     * Verifica si el hash de la contraseña proporcionada coincide con el almacenado en la cabecera del archivo cifrado.
     *
     * @param ruta_archivo Ruta del archivo cifrado.
     * @param hashPassword Hash calculado de la contraseña ingresada.
     * @return true si los hashes coinciden; false en caso contrario.
     * @throws Exception Si ocurre un error al leer la cabecera del archivo.
     */
    public static boolean verifyPasswordHash(String ruta_archivo, byte[] hashPassword) throws Exception {
        Header h = new Header();
        FileInputStream fis = new FileInputStream(ruta_archivo);

        boolean equal = false;
        if (h.load(fis)) {
//            String algoritmoCifrado = h.getAlgorithm1();
//            byte[] salt = h.getData();
//
//            Options confAlgoritmo = new Options();
//            confAlgoritmo.setCipherAlgorithm(algoritmoCifrado);
//            Cipher c = Cipher.getInstance(algoritmoCifrado);
//
//            SecretKey sKey = generateSessionKey(password, algoritmoCifrado);
//            PBEParameterSpec pPS = new PBEParameterSpec(salt, numIteraciones);
//
//            c.init(Cipher.DECRYPT_MODE, sKey, pPS);
            String algoritmoCifrado = h.getAlgorithm1();
            System.out.println(algoritmoCifrado);

            System.out.println("Hash guardado en la cabecera: " + Arrays.toString(h.getHashPassword()));
            System.out.println("Hash calculado: " + Arrays.toString(hashPassword));
            if(Arrays.equals(h.getHashPassword(), hashPassword)) {
                equal = true;
            }
        }
        return equal;
    }

    /**
     * Descifra un archivo previamente cifrado mediante PBE.
     * El archivo de salida tendrá extensión ".cla".
     *
     * @param fichero        Ruta del archivo cifrado (.cif).
     * @param password       Contraseña proporcionada por el usuario.
     * @param numIteraciones Número de iteraciones del algoritmo PBE.
     * @throws Exception Si ocurre un error durante el proceso de descifrado.
     */
    public static void processingDecipher(String fichero, String password, int numIteraciones) throws Exception {
        Header h = new Header();
        FileInputStream fis = new FileInputStream(fichero);
        if (h.load(fis)) {
            String algoritmoCifrado = h.getAlgorithm1();
            byte[] salt = h.getData();

            Options confAlgoritmo = new Options();
            confAlgoritmo.setCipherAlgorithm(algoritmoCifrado);
            Cipher c = Cipher.getInstance(algoritmoCifrado);

            SecretKey sKey = generateSessionKey(password, algoritmoCifrado);
            PBEParameterSpec pPS = new PBEParameterSpec(salt, numIteraciones);

            c.init(Cipher.DECRYPT_MODE, sKey, pPS);

            if (!writeDecipheredText(c, fichero, fis)) {
                System.out.println("Error al descifrar el fichero");
            } else {
                System.out.println("El fichero se ha descifrado correctamente");
            }
        }
    }

    /**
     * Lee el archivo original y genera su versión cifrada en un nuevo archivo ".cif",
     * escribiendo primero una cabecera personalizada.
     *
     * @param c        Objeto {@link Cipher} configurado para cifrar.
     * @param filename Ruta del archivo original a cifrar.
     * @param h        Objeto {@link Header} con información de metadatos.
     * @return true si el archivo fue cifrado correctamente; false si ocurrió algún error.
     * @throws Exception Si ocurre un error de escritura o cifrado.
     */
    public static boolean writeCipheredText(Cipher c, String filename, Header h) throws Exception {
        String outFile = filename + ".cif";

        FileOutputStream fos = new FileOutputStream(outFile); // Abre el flujo de outFile desde un fichero
        CipherOutputStream cos = new CipherOutputStream(fos, c); // Abre el flujo de outFile cifrado

        boolean success = false;

        if (!h.save(fos)) {
            System.out.println("Error al guardar la cabecera");
        }
        System.out.println("Llega despues de escribir el fichero");
        try {
            FileInputStream fis = new FileInputStream(filename);
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) > -1) {
                cos.write(buffer, 0, bytesRead);
            }

            fis.close();
            success = true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        cos.close();
        fos.close();

        return success;
    }

    /**
     * Descifra el contenido de un archivo cifrado utilizando un {@link Cipher} configurado
     * y lo guarda en un archivo con extensión ".cla".
     *
     * @param c        Objeto {@link Cipher} configurado para descifrar.
     * @param filename Ruta del archivo cifrado.
     * @param fis      Flujo de entrada ya posicionado después de la cabecera.
     * @return true si el archivo fue descifrado correctamente; false en caso contrario.
     * @throws Exception Si ocurre un error de lectura o descifrado.
     */
    public static boolean writeDecipheredText(Cipher c, String filename, FileInputStream fis) throws Exception {
        String outFile = filename + ".cla";

        FileOutputStream fos = new FileOutputStream(outFile); // Abre el flujo de outFile desde un fichero

        boolean success = false;
        try {
            CipherInputStream cis = new CipherInputStream(fis, c);

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) > -1) {
                fos.write(buffer, 0, bytesRead);
            }

            fis.close();
            success = true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        fos.close();

        return success;
    }

    /**
     * Genera una clave de sesión (clave simétrica) a partir de una contraseña
     * utilizando el algoritmo PBE especificado.
     *
     * @param password  Contraseña proporcionada por el usuario.
     * @param algorithm Algoritmo de cifrado (ej. PBEWithMD5AndDES).
     * @return {@link SecretKey} generado desde la contraseña.
     * @throws Exception Si el algoritmo no es válido o falla la generación.
     */
    public static SecretKey generateSessionKey(String password, String algorithm) throws Exception {
        System.out.println("GENERANDO CLAVE DE SESION");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());

        SecretKeyFactory kf = SecretKeyFactory.getInstance(algorithm);

        SecretKey sKey = kf.generateSecret(pbeKeySpec);
        return sKey;

    }

    /**
     * Evalúa si una contraseña cumple los requisitos mínimos de seguridad.
     *
     * @param password Contraseña introducida por el usuario.
     * @return true si la contraseña tiene al menos 8 caracteres; false en caso contrario.
     */
    public static boolean securePassword(String password) {
        return password.length() >= 8;
    }

}