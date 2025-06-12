package Actividad4;

import librerias.Header;
import librerias.Options;

import java.io.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;


/**
 * Clase de utilidad para gestionar operaciones relacionadas con claves criptográficas
 * y firmas digitales. Proporciona métodos para guardar/cargar pares de claves y firmar archivos
 * mediante clave privada.
 *
 * @author Sergio Martín Ledesma
 */
public class DigitalSignature {
    /**
     * Guarda un par de claves (privada y pública) en un archivo utilizando serialización.
     *
     * @param keyPair Par de claves a guardar.
     * @param filename Nombre del archivo destino (sin extensión).
     * @throws IOException Si ocurre un error al escribir el archivo.
     */
    public static void saveKeyPairToFile(KeyPair keyPair, String filename) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(keyPair.getPrivate());
            oos.writeObject(keyPair.getPublic());
        }
    }
    /**
     * Carga un par de claves previamente almacenado desde un archivo.
     *
     * @param filename Ruta del archivo que contiene el par de claves serializado.
     * @return El objeto KeyPair reconstruido desde el archivo.
     * @throws Exception Si ocurre un error al leer el archivo o deserializar las claves.
     */
    public static KeyPair loadKeyPairFromFile(String filename) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            PrivateKey privateKey = (PrivateKey) ois.readObject();
            PublicKey publicKey = (PublicKey) ois.readObject();
            return new KeyPair(publicKey, privateKey);
        }
    }
    /**
     * Firma un archivo con la clave privada proporcionada utilizando el algoritmo especificado.
     *
     * El archivo firmado se guarda junto con una cabecera (`Header`) que contiene los metadatos
     * necesarios para la verificación, como el algoritmo de firma y la firma generada.
     *
     * @param inputFile Ruta del archivo que se desea firmar.
     * @param outputFile Ruta del archivo de salida que contendrá la firma y el contenido original.
     * @param paramPrivateKey Clave privada utilizada para firmar el archivo.
     * @param algoritmoClavePrivada Algoritmo de firma digital (por ejemplo, "SHA256withRSA").
     *
     * @throws Exception Si ocurre un error durante la lectura/escritura de archivos o el proceso de firma.
     */
    public static final void firmarFicheroClavePrivada(String inputFile, String outputFile, PrivateKey paramPrivateKey, String algoritmoClavePrivada) {
        try {
            // Se abre el archivo a firmar para leer su contenido
            FileInputStream fileInputStream = new FileInputStream(inputFile);

            // Inicializamos el objeto Signature con el algoritmo seleccionado
            Signature signature = Signature.getInstance(algoritmoClavePrivada);
            signature.initSign(paramPrivateKey);

            byte[] buffer = new byte[1024];
            int i;

            // Se procesa el archivo por bloques para actualizar la firma
            while ((i = fileInputStream.read(buffer)) > -1) {
                signature.update(buffer, 0, i);
            }

            // Se genera la firma final a partir del contenido leído
            byte[] firma = signature.sign();

            // Se prepara el archivo de salida
            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
            fileInputStream.close();

            // Se vuelve a abrir el archivo original para copiar su contenido después de la cabecera
            FileInputStream newFileInputStream = new FileInputStream(inputFile);

            // Se construye la cabecera con los datos de firma
            Header headerCifradoMAC = new Header(Options.OP_SIGNED, "none", algoritmoClavePrivada, firma);

            // Se guarda la cabecera al inicio del archivo firmado
            headerCifradoMAC.save(fileOutputStream);

            // Se copia el contenido original del archivo
            while ((i = newFileInputStream.read(buffer)) != -1) {
                fileOutputStream.write(buffer, 0, i);
            }

            // Se cierran los flujos
            fileOutputStream.close();
            newFileInputStream.close();

        } catch (Exception exception) {
            // Cualquier excepción se muestra por consola
            System.err.println(exception);
        }
    }

    /**
     * Realiza el proceso de verificacion de firma con la clave publica, creando un nuevo fichero
     * @param pathEntrada Fichero a verificar la firma
     * @param pathSalida Fichreo de salida con la firma verificada
     * @param paramPublicKey Clave publica utilizada para la verificacion de la firma
     * @return
     */
    public static final boolean verificarFicheroFirmado(String pathEntrada, String pathSalida, PublicKey paramPublicKey) {
        boolean bool = false;

        try {
            // Abrimos el archivo firmado
            FileInputStream fileInputStream = new FileInputStream(pathEntrada);
            FileOutputStream fileOutputStream = new FileOutputStream(pathSalida);

            // Se carga la cabecera que contiene los metadatos de la firma
            Header cabecera = new Header();
            if (cabecera.load(fileInputStream)) {

                // Se comprueba que la cabecera indica una operación de firma
                if (cabecera.getOperation() == Options.OP_SIGNED) {
                    System.out.println("La operación de la cabecera es de firma");

                    // Se prepara la instancia del algoritmo de firma para verificación
                    Signature signature = Signature.getInstance(cabecera.getAlgorithm2());
                    signature.initVerify(paramPublicKey);

                    byte[] buffer = new byte[1024];
                    int i;

                    // Se procesa el contenido original del archivo
                    while ((i = fileInputStream.read(buffer)) > -1) {
                        signature.update(buffer, 0, i);              // Se actualiza el objeto de verificación
                        fileOutputStream.write(buffer, 0, i);        // Se guarda una copia limpia del contenido
                    }

                    // Verificamos la firma comparando con la almacenada en la cabecera
                    if (signature.verify(cabecera.getData())) {
                        bool = true;
                    } else {
                        bool = false;
                    }

                    // Cerramos los flujos
                    fileOutputStream.close();
                    fileInputStream.close();

                } else {
                    // Si el archivo no fue generado con firma, se avisa y se cierran los flujos
                    System.out.println("\nArchivo no utilizado para firmas.\n");
                    fileOutputStream.close();
                    fileInputStream.close();
                }
            }

        } catch (Exception exception) {
            System.err.println(exception);
        }

        return bool;
    }

}

