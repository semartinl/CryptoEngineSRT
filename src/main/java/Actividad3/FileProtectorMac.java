package Actividad3;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


import librerias.Header;

/**
 * Clase que permite proteger archivos mediante funciones criptográficas de integridad:
 * <ul>
 *     <li>Aplicación y verificación de funciones Hash (MessageDigest)</li>
 *     <li>Aplicación y verificación de HMAC (Message Authentication Code)</li>
 *     <li>Consulta de algoritmos disponibles (Digest y Cifrado)</li>
 * </ul>
 *
 * <p>Hace uso de {@link Header}
 * para almacenar metadatos junto con los archivos protegidos.
 *
 * <p>Usa algoritmos como SHA-256, SHA-1, HmacSHA256, HmacSHA1, etc.
 */
public class FileProtectorMac {
    // Número de bytes por bloque usado en operaciones de lectura/escritura
    private int num_bytes = 1024;

    // Tamaño del búfer utilizado para operaciones con archivos grandes (32 KB)
    private static int BUFFER_SIZE = 32768;

    // Valor de sal estático utilizado para derivación de claves (PBE o MAC)
    private static final byte[] SALT = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

    // Constructor por defecto de la clase. No realiza ninguna inicialización adicional.
    public FileProtectorMac() {}

    /**
     * Carga la cabecera de un archivo que contiene metadatos con información
     * criptográfica (hash o HMAC).
     *
     * @param inputFile Ruta del archivo desde donde se desea leer la cabecera.
     * @param header Objeto {@link Header} que será rellenado con los metadatos.
     * @return true si se ha cargado correctamente la cabecera; false si ocurre un error.
     */
    public final boolean cargarCabeceraArchivo(String inputFile, Header header) {
        try {
            // Se abre un flujo de lectura hacia el archivo de entrada
            FileInputStream fileInputStream = new FileInputStream(inputFile);

            // Se intenta cargar la cabecera utilizando el método del objeto Header
            boolean bool = header.load(fileInputStream);

            // Se cierra el flujo de lectura tras haber leído la cabecera
            fileInputStream.close();

            // Se retorna el resultado de la carga
            return bool;
        } catch (Exception exception) {
            // En caso de error (archivo inexistente, formato incorrecto, etc.)
            System.out.println("Problemas al leer el fichero: " + inputFile + "\n");
            return false;
        }
    }

    /**
     * Aplica un resumen HASH al archivo de entrada y guarda el archivo con la cabecera
     * conteniendo dicho resumen. El resumen se calcula incluyendo la contraseña.
     *
     * @param inputFile Ruta del archivo original.
     * @param outputFile Ruta del archivo de salida con la cabecera HASH.
     * @param secreto Contraseña o clave para inicializar el hash.
     * @param algoritmo Algoritmo de MessageDigest (ej. SHA-256, SHA-1).
     */
    public final void applyHash(String inputFile, String outputFile, String secreto, String algoritmo) {
        System.out.println("Proceso de hashing de <" + inputFile + "> con Algoritmo: " + algoritmo + "\n");

        try (
                // Se abren los flujos para lectura del archivo original y escritura del nuevo
                FileInputStream fileInputStream = new FileInputStream(inputFile);
                FileOutputStream fileOutputStream = new FileOutputStream(outputFile)
        ) {
            // Se inicializa el objeto MessageDigest con el algoritmo especificado
            MessageDigest messageDigest = MessageDigest.getInstance(algoritmo);

            // Se actualiza el digest con la contraseña como paso inicial (semilla del resumen)
            messageDigest.update(secreto.getBytes(StandardCharsets.UTF_8));

            // Se crea un DigestInputStream que calculará el hash automáticamente al leer datos
            try (DigestInputStream digestInputStream = new DigestInputStream(fileInputStream, messageDigest)) {

                // Buffers para lectura de bloques de datos
                byte[] aux = new byte[BUFFER_SIZE];
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                int totalBytes = 0;

                // Se lee todo el archivo para que DigestInputStream actualice el hash internamente
                while ((bytesRead = digestInputStream.read(buffer)) > -1) {
                    totalBytes += bytesRead;
                }

                // Se obtiene el hash final tras leer todo el archivo
                aux = messageDigest.digest();

                System.out.println("Total bytes: " + totalBytes);

                // Se crea un objeto Header con el resumen y metadatos del proceso
                Header header = new Header((byte) 10, "none", algoritmo, aux);

                // Se escribe la cabecera al inicio del archivo de salida
                header.save(fileOutputStream);

                // Se vuelve a abrir el archivo original para escribir su contenido después de la cabecera
                fileInputStream.close();
                digestInputStream.close(); // Cierre explícito por seguridad (aunque el try-with-resources ya lo gestiona)

                try (FileInputStream originalFileInput = new FileInputStream(inputFile)) {
                    // Se copia el contenido original al archivo de salida, justo después de la cabecera
                    while ((bytesRead = originalFileInput.read(buffer)) > -1) {
                        fileOutputStream.write(buffer, 0, bytesRead);
                    }
                }

                System.out.println("\nHecho (" + totalBytes + " bytes).\n");
            }

        } catch (FileNotFoundException fileNotFoundException) {
            // Archivo de entrada no encontrado
            System.out.println("Fichero no se encuentra: " + inputFile + "\n");

        } catch (IOException iOException) {
            // Error de entrada/salida
            System.out.println("Error de E/S en.\n");

        } catch (Exception exception) {
            // Cualquier otro tipo de error general
            System.out.println(String.valueOf(exception.getMessage()) + "\n");
        }
    }


    /**
     * Convierte un array de bytes a una cadena en formato hexadecimal.
     *
     * @param bytes Array de bytes a convertir.
     * @return Cadena en formato hexadecimal.
     */
    protected static String bytesToHex(byte[] bytes) {
        // Se utiliza StringBuilder para construir eficientemente la cadena resultante
        StringBuilder sb = new StringBuilder();

        // Por cada byte, se convierte a su representación hexadecimal de dos dígitos
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }

        // Se devuelve la cadena hexadecimal completa
        return sb.toString();
    }
    /**
     * Verifica el hash de un archivo.
     * @param inputFile Archivo de entrada con el hash incorporado.
     * @param outputFile Archivo donde se almacenará el contenido sin la cabecera.
     * @param secreto Contraseña o clave para la verificación del hash.
     * @param algoritmo Algoritmo utilizado para generar el hash.
     */
    public final boolean verifyHash(String inputFile, String outputFile, String secreto, String algoritmo) throws Exception {

        // Bandera que indicará si el archivo fue verificado con éxito
        boolean verificado = false;

        try (
                // Se abre el archivo de entrada para leer la cabecera y los datos
                FileInputStream fileInputStream = new FileInputStream(inputFile);

                // Se prepara un archivo de salida para escribir el contenido limpio (sin cabecera)
                FileOutputStream fileOutputStream = new FileOutputStream(outputFile)
        ) {
            // Se carga la cabecera que contiene el hash original
            Header header = new Header();
            if(header.load(fileInputStream)){
                // Se prepara el algoritmo de hash según la información en la cabecera
                MessageDigest messageDigest = MessageDigest.getInstance(header.getAlgorithm2());

                // Se añade la contraseña como parte del hash
                messageDigest.update(secreto.getBytes());

                // DigestInputStream aplicará el cálculo del hash mientras se lee el archivo
                try (DigestInputStream digestInputStream = new DigestInputStream(fileInputStream, messageDigest)) {
                    byte[] buffer = new byte[BUFFER_SIZE];
                    int bytesRead;

                    // Se lee todo el contenido restante (tras la cabecera) y se escribe al archivo limpio
                    while ((bytesRead = digestInputStream.read(buffer)) != -1) {
                        fileOutputStream.write(buffer, 0, bytesRead);
                    }

                    // Al terminar la lectura, se obtiene el hash calculado
                    byte[] computedHash = digestInputStream.getMessageDigest().digest();

                    // Se convierte el hash guardado (en la cabecera) y el calculado a hexadecimal para comparar
                    String storedHash = bytesToHex(header.getData());
                    String calculatedHash = bytesToHex(computedHash);

                    // Comparación de hashes
                    if (storedHash.contentEquals(calculatedHash)) {
                        verificado = true;
                        System.out.println("\nHash idénticos, el fichero no ha sido modificado.\n");
                    } else {
                        System.out.println("\nHash diferentes, el fichero ha sido modificado (o la contraseña no es correcta).\n");

                        // Si el hash no coincide, el archivo de salida se marca para borrarse al cerrar la app
                        new File(outputFile).deleteOnExit();
                    }
                }catch (Exception exception) {
                    // Cualquier excepción (lectura, hash, etc.) se captura y se muestra
                    System.out.println(String.valueOf(exception.getMessage()) + "\n");
                }

            }
                //Exception que se da cuando da un error al leer la cabecera de un fichero.
                else throw new Exception("Error al leer la cabecera del fichero: " + inputFile + "\n");
            }catch (Exception exception) {
            // Cualquier excepción (lectura, hash, etc.) se captura y se muestra
            System.out.println(String.valueOf(exception.getMessage()) + "\n");
        }




        // Se devuelve el resultado de la verificación
        return verificado;
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
            // Se obtiene la fábrica de claves para el algoritmo PBKDF2 con HMAC-SHA1
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            // Se define la especificación de clave usando la contraseña, salt, número de iteraciones y tamaño final de clave
            PBEKeySpec pBEKeySpec = new PBEKeySpec(secret, datos, iterationCount, macLength);

            // A partir de la especificación, se genera la clave secreta final
            return secretKeyFactory.generateSecret(pBEKeySpec);

        } catch (Exception exception) {
            // Si ocurre algún error (algoritmo no disponible, parámetros inválidos, etc.), se imprime el error
            exception.printStackTrace();

            // Se devuelve null como indicador de fallo
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
    public final void applyHMAC(String inputFile, String outputFile, String secreto, String algoritmo) throws Exception {
        System.out.println("Proceso de HMac de <" + inputFile + "> con Algoritmo: " + algoritmo + "\n");
//        if(inputFile.contentEquals(outputFile)){
//            throw new Exception("No se pueden poner el nombre de entrada y salida iguales.");
//        }
        try {
            // Se abre el archivo de entrada
            FileInputStream fileInputStream = new FileInputStream(inputFile);

            // Se prepara el archivo de salida
            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);

            // Se obtiene una instancia del algoritmo MAC (ej. HmacSHA256)
            Mac mac = Mac.getInstance(algoritmo);

            // Cabecera provisional para extraer los datos necesarios como el salt
            Header header = new Header();

            // Se genera una clave secreta derivada de la contraseña usando PBKDF2
            SecretKey secretKey = generateSecretKey(
                    secreto.toCharArray(),                  // Contraseña
                    SALT,                       // Salt para derivación
                    this.num_bytes,                         // Número de iteraciones
                    mac.getMacLength() * 8                  // Tamaño del MAC en bits
            );

            // Se inicializa el objeto MAC con la clave derivada
            mac.init(secretKey);

            byte[] arrayOfByte = new byte[BUFFER_SIZE];

            while (true) {
                // Se lee un bloque del archivo de entrada
                int i = fileInputStream.read(arrayOfByte, 0, BUFFER_SIZE);

                // Se actualiza el MAC con el bloque leído
                mac.update(arrayOfByte, 0, i);

                // Si no se leyó un bloque completo, significa que estamos al final del archivo
                if (i != BUFFER_SIZE) {
                    // Se obtiene el valor final del HMAC
                    byte[] macValue = mac.doFinal();

                    // Cerramos la lectura del archivo (ya lo procesamos por completo)
                    fileInputStream.close();

                    // Creamos una nueva cabecera con el valor del HMAC y metadatos
                    Header headerCifradoMAC = new Header((byte) 10, "none", algoritmo, macValue);

                    // Se guarda la cabecera en el archivo de salida
                    headerCifradoMAC.save(fileOutputStream);

                    // Reabrimos el archivo original para copiarlo al nuevo archivo junto a la cabecera
                    fileInputStream = new FileInputStream(inputFile);

                    while (true) {
                        i = fileInputStream.read(arrayOfByte, 0, BUFFER_SIZE);
                        fileOutputStream.write(arrayOfByte, 0, i);

                        // Si alcanzamos el final, mostramos el MAC y cerramos todo
                        if (i != BUFFER_SIZE) {
                            System.out.println("\nMD: " + bytesToHex(macValue));
                            fileOutputStream.flush();
                            fileOutputStream.close();
                            fileInputStream.close();
                            return;
                        }
                    }
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
    public final boolean verifyHMAC(String inputFile, String outputFile, String secreto, String algoritmo) throws Exception {
//        if(inputFile.contentEquals(outputFile)){
//            throw new Exception("No se pueden poner el nombre de entrada y salida iguales.");
//        }
        try {

            // Se abre el archivo que contiene el contenido y la cabecera HMAC
            FileInputStream fileInputStream = new FileInputStream(inputFile);

            // Se crea el archivo de salida donde se almacenará el contenido sin cabecera
            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);

            // Se carga la cabecera que contiene el valor original del HMAC
            Header headerCifradoMAC = new Header();
            if(headerCifradoMAC.load(fileInputStream)){
                boolean verificado = false;

                // Se obtiene una instancia del algoritmo HMAC
                Mac mac = Mac.getInstance(algoritmo);

                // Se genera una clave secreta a partir de la contraseña, salt fijo, iteraciones y tamaño del MAC

                SecretKey secretKey = generateSecretKey(secreto.toCharArray(), SALT, this.num_bytes, mac.getMacLength() * 8);

                // Se inicializa el HMAC con la clave generada
                mac.init(secretKey);

                // Búfer para lectura por bloques
                byte[] arrayOfByte = new byte[BUFFER_SIZE];

                while (true) {
                    // Se lee un bloque del archivo (después de la cabecera)
                    int i = fileInputStream.read(arrayOfByte, 0, BUFFER_SIZE);

                    // Se actualiza el HMAC con el contenido leído
                    mac.update(arrayOfByte, 0, i);

                    // Se escribe el contenido leído al archivo limpio
                    fileOutputStream.write(arrayOfByte, 0, i);

                    // Si no se leyó un bloque completo, significa que es el final del archivo
                    if (i != BUFFER_SIZE) {
                        // Se finaliza el HMAC con el contenido total leído
                        byte[] macValue = mac.doFinal();

                        System.out.println("\nHecho.\n");

                        // Se convierten ambos valores (almacenado y calculado) a hexadecimal
                        String macCalculatedHex = bytesToHex(macValue);
                        String macStoragedFileHex = bytesToHex(headerCifradoMAC.getData());

                        // Se muestran ambos valores por consola
                        System.out.println("\nMD almacenado: " + macStoragedFileHex);
                        System.out.println("\nMD  calculado: " + macCalculatedHex);

                        // Se comparan los valores HMAC
                        if (macCalculatedHex.contentEquals(macStoragedFileHex)) {
                            System.out.println("\nHMac idénticos, el fichero no ha sido modificado.\n");
                            verificado = true;
                        } else {
                            System.out.println("\nHMac diferentes, el fichero ha sido modificado (o la contraseña no es correcta).\n");

                            // Si la verificación falla, el archivo limpio se elimina al cerrar la app
                            (new File(outputFile)).deleteOnExit();
                        }

                        // Se cierran los flujos
                        fileInputStream.close();
                        fileOutputStream.flush();
                        fileOutputStream.close();

                        // Se retorna el resultado de la verificación
                        return verificado;
                    }
                }
            }
            //Exception que se da cuando da un error al leer la cabecera de un fichero.
            else throw new Exception("Error al leer la cabecera del fichero: " + inputFile + "\n");




        } catch (Exception exception) {
            // En caso de cualquier error, se imprime el mensaje
            System.out.println(String.valueOf(exception.getMessage()) + "\n");
        }

        // Si ocurrió un error, se retorna false
        return false;
    }


}
