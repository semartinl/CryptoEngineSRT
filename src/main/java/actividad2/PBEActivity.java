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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
 * <br>Autores: Martín Ledesma, Sergio
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
        //Se comienza el proceso de cifrado
        Cipher c = Cipher.getInstance(algoritmoCifrado);

        //Se genera la clave de sesión para el proceso de cifrado
        SecretKey sKey = generateSessionKey(password, algoritmoCifrado);

        //Se genera y configura la cabecera a guardar en el fichero. Se genera el salt aleatorio.
        Header h = new Header(hashPassword, algoritmoCifrado, Options.OP_SYMMETRIC_CIPHER);

        PBEParameterSpec pPS = new PBEParameterSpec(h.getData(), numIteraciones);

        //Se inicia el proceso de cifrado con las variables anteriormente configuradas.
        c.init(Cipher.ENCRYPT_MODE, sKey, pPS);
        //Se escribe el fichero cifrado en el archivo de salida establecido. Si sale un error, se muestra por pantalla un error. Sino, se genera un mensaje de retroalimentación por pantalla.
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
        //Se carga la cabecera del archivo a verificar
        if (h.load(fis)) {
            //Se comprueba si son iguales. Si es así, se cambia la bandera a verdadero.
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
            //Guardamos el algoritmo de cifrado y el salt geneardo en el Header de forma aleatoria
            String algoritmoCifrado = h.getAlgorithm1();
            byte[] salt = h.getData();

            //Configuramos el cifrado con el algoritmo de cifrado elegido
            Cipher c = Cipher.getInstance(algoritmoCifrado);

            //Se genera una clave de sesión con la contraseña y algoritmo de cifrado elegido
            SecretKey sKey = generateSessionKey(password, algoritmoCifrado);
            PBEParameterSpec pPS = new PBEParameterSpec(salt, numIteraciones);

            //Se inicializa el proceso de cifrado
            c.init(Cipher.DECRYPT_MODE, sKey, pPS);

            //Se descifra el fichero. Si hay un error, salta por pantalla. Sino, se genera un texto de retroalimentación exitosa.
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
        // Se define el nombre del archivo de salida agregando la extensión ".cif"
        String outFile = filename + ".cif";

        // Se crea un flujo de salida para escribir en el archivo cifrado
        FileOutputStream fos = new FileOutputStream(outFile);

        // Se envuelve el flujo de salida en un CipherOutputStream, para que los datos se cifren al escribirlos
        CipherOutputStream cos = new CipherOutputStream(fos, c);

        // Bandera que indicará si el proceso fue exitoso
        boolean success = false;

        // Se escribe la cabecera personalizada al principio del archivo
        if (!h.save(fos)) {
            System.out.println("Error al guardar la cabecera");
        }

        try {
            // Se abre el flujo de lectura del archivo original
            FileInputStream fis = new FileInputStream(filename);

            // Búfer para leer los datos por bloques
            byte[] buffer = new byte[1024];
            int bytesRead;

            // Se leen bloques del archivo original y se escriben cifrados en el nuevo archivo
            while ((bytesRead = fis.read(buffer)) > -1) {
                cos.write(buffer, 0, bytesRead);
            }

            // Se cierra el flujo de entrada después de leer todo el archivo
            fis.close();

            // Se marca como exitoso
            success = true;

        } catch (FileNotFoundException e) {
            // Si no se encuentra el archivo original, se imprime el error
            e.printStackTrace();
        }

        // Se cierran los flujos de salida cifrada y normal
        cos.close();
        fos.close();

        // Se retorna true si el proceso fue exitoso, false en caso contrario
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
        // Se define el nombre del archivo de salida agregando la extensión ".cla"
        String outFile = filename + ".cla";

        // Se abre el flujo de salida donde se escribirá el archivo descifrado
        FileOutputStream fos = new FileOutputStream(outFile);

        // Bandera que indica si la operación fue exitosa
        boolean success = false;

        try {
            // Se envuelve el flujo de entrada con CipherInputStream para aplicar descifrado al vuelo
            CipherInputStream cis = new CipherInputStream(fis, c);

            // Búfer para leer los datos en bloques
            byte[] buffer = new byte[1024];
            int bytesRead;

            // Lectura del archivo cifrado y escritura directa del contenido descifrado
            while ((bytesRead = cis.read(buffer)) > -1) {
                fos.write(buffer, 0, bytesRead);
            }

            // Se cierra el flujo de entrada una vez finalizada la lectura
            fis.close();

            // Se marca la operación como exitosa
            success = true;

        } catch (FileNotFoundException e) {
            // En caso de que no se encuentre el archivo, se imprime el error
            e.printStackTrace();
        }

        // Se cierra el flujo de salida, asegurando que se escriban todos los datos
        fos.close();

        // Se devuelve true si todo salió bien, false en caso de error
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

        // Se convierte la contraseña a un arreglo de caracteres y se encapsula en un PBEKeySpec
        // Este objeto representa la especificación de clave que usará la factoría
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());

        // Se obtiene una factoría de claves basada en el algoritmo de cifrado especificado
        SecretKeyFactory kf = SecretKeyFactory.getInstance(algorithm);

        // A partir de la especificación (PBEKeySpec), se genera una clave secreta
        SecretKey sKey = kf.generateSecret(pbeKeySpec);

        // Se devuelve la clave generada
        return sKey;
    }


    /**
     * Calcula un hash SHA-256 a partir de la contraseña proporcionada y devuelve los primeros 8 bytes del resultado.
     *
     * Este método es útil, por ejemplo, para derivar claves o generar valores de comprobación simplificados a partir de contraseñas.
     *
     * @param contrasena Cadena de texto que representa la contraseña a hashear.
     * @return Un arreglo de 8 bytes que contiene los primeros bytes del hash SHA-256 calculado.
     * @throws RuntimeException Si ocurre un error al obtener el algoritmo de hash o al procesar la cadena.
     */
    public static byte[] calcularHash(String contrasena) {
        try {
            // Se obtiene una instancia del algoritmo de resumen SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Se convierte la contraseña a bytes (UTF-8) y se calcula el hash completo (32 bytes)
            byte[] hash = digest.digest(contrasena.getBytes(StandardCharsets.UTF_8));

            // Se retorna únicamente los primeros 8 bytes del hash (para usar como clave corta, IV, etc.)
            return Arrays.copyOf(hash, 8);

        } catch (Exception e) {
            // Si ocurre cualquier excepción durante el proceso, se lanza como RuntimeException
            throw new RuntimeException("Error al calcular hash de la contraseña", e);
        }
    }

}