/**
 * Actividad 2 - JCA
 * Seguridad en Redes Telemáticas
 * Estudiantes:
 * Guillén Torrado, Sara
 * Martín Ledesma, Sergio
 */

package algoritmos;

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

/**
 * Clase para cifrar y descifrar ficheros
 */
public class PBEActivity {
    /**
     * Configura el objeto de cifrado y cifra el fichero
     *
     * @param filename         El nombre del fichero a cifrar
     * @param password         La contraseña simétrica
     * @param algoritmoCifrado El algoritmo de cifrado elegido
     * @param numIteraciones   El número de iteraciones
     * @throws Exception
     */
    public static void processingCipher(String filename, String password, String algoritmoCifrado, int numIteraciones) throws Exception {

        Options confAlgoritmo = new Options();
        confAlgoritmo.setCipherAlgorithm(algoritmoCifrado);
        Cipher c = Cipher.getInstance(algoritmoCifrado);

        SecretKey sKey = generateSessionKey(password, algoritmoCifrado);
        byte[] salt;
        SecureRandom random = SecureRandom.getInstance("DEFAULT", "BC");
        salt = random.generateSeed(8);

        PBEParameterSpec pPS = new PBEParameterSpec(salt, numIteraciones);
        c.init(Cipher.ENCRYPT_MODE, sKey, pPS);


        Header h = new Header(Options.OP_SYMMETRIC_CIPHER, algoritmoCifrado,
                Options.authenticationAlgorithms[0], salt);

        if (!writeCipheredText(c, filename, h)) {
            System.out.println("Error al cifrar el fichero");
        } else {
            System.out.println("El fichero se cifrado correctamente");
        }

    }

    /**
     * Configura el objeto de descifrado y genera el fichero descifrado
     *
     * @param fichero        El nombre del fichero a descifrar
     * @param password       La contraseña simétrica
     * @param numIteraciones El número de iteraciones
     * @throws Exception
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
     * Lee un fichero y lo encripta
     *
     * @param c        Objeto de cifrado inicializado
     * @param filename Nombre del fichero a cifrar
     * @param h        Cabecera inicializada
     * @throws FileNotFoundException Si no se encuentra el fichero
     * @throws IOException           Si hay un error al leer el fichero
     * @throws Exception             Si hay un error al cifrar el fichero
     */
    public static boolean writeCipheredText(Cipher c, String filename, Header h) throws Exception {
        String outFile = filename + ".cif";

        FileOutputStream fos = new FileOutputStream(outFile); // Abre el flujo de outFile desde un fichero
        CipherOutputStream cos = new CipherOutputStream(fos, c); // Abre el flujo de outFile cifrado

        boolean success = false;
        if (!h.save(fos)) {
            System.out.println("Error al guardar la cabecera");
        }

        try {
            FileInputStream fis = new FileInputStream(filename);
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) > -1) {
                cos.write(buffer, 0, bytesRead);
            }
            cos.close();

            fis.close();
            success = true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        fos.close();

        return success;
    }

    /**
     * Descifra un fichero y guarda la salida en un fichero.cla
     *
     * @param c        Objeto de cifrado inicializado
     * @param filename El nombre del fichero a descifrar
     * @param fis      El flujo de entrada inicializado tras haber leído la cabecera
     * @return true si se ha descifrado correctamente, y false en caso contrario
     * @throws Exception
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
     * Genera una clave de sesión a partir de una contraseña y un algoritmo
     *
     * @param password  Contraseña a partir de la cual se generará la clave de sesión
     * @param algorithm Algoritmo con el que se generará la clave de sesión
     * @return SecretKey Clave de sesión generada
     * @throws Exception Si el algoritmo no existe o si la clave generada no es válida
     */
    public static SecretKey generateSessionKey(String password, String algorithm) throws Exception {
        System.out.println("GENERANDO CLAVE DE SESION");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());

        SecretKeyFactory kf = SecretKeyFactory.getInstance(algorithm);

        SecretKey sKey = kf.generateSecret(pbeKeySpec);
        return sKey;

    }

    /**
     * Comprueba si una contraseña es segura
     *
     * @param password Contraseña a comprobar
     * @return boolean True si la contraseña es segura, false en caso contrario
     */
    public static boolean securePassword(String password) {

        return password.length() >= 8;
    }

}