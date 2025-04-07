package DigitalSignature;

import librerias.Header;
import librerias.Options;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Scanner;

import static actividad2.CifradoOriginal.leerIntegerTeclado;

public class DigitalSignature {
    /**
     * Firma un archivo con la clave privada proporcionada.
     *
     * @param inputFile Ruta del archivo que se desea firmar.
     * @param signatureFile Ruta del archivo donde se guardará la firma generada.
     * @param privateKey Clave privada utilizada para generar la firma digital.
     * @throws Exception Si ocurre un error al leer/escribir archivos o en el proceso de firma digital.
     */
    public static void signFile(String inputFile, String signatureFile, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);

        // Leer datos del archivo y firmar
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                signature.update(buffer, 0, len);
            }
        }

        // Guardar la firma en un archivo
        try (FileOutputStream fos = new FileOutputStream(signatureFile)) {
            fos.write(signature.sign());
        }
    }
    /**
     * Verifica la firma de un archivo utilizando la clave pública proporcionada.
     *
     * @param inputFile Ruta del archivo cuyo contenido se desea verificar.
     * @param signatureFile Ruta del archivo que contiene la firma digital.
     * @param publicKey Clave pública utilizada para verificar la firma.
     * @return boolean true si la firma es válida, false en caso contrario.
     * @throws Exception Si ocurre un error al leer archivos o en el proceso de verificación.
     */
    // Verifica la firma de un archivo con la clave pública
    public static boolean verifyFile(String inputFile, String signatureFile, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);

        // Leer datos del archivo y verificar
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                signature.update(buffer, 0, len);
            }
        }

        // Leer firma
        byte[] sigBytes = new byte[new FileInputStream(signatureFile).available()];
        try (FileInputStream sigFis = new FileInputStream(signatureFile)) {
            sigFis.read(sigBytes);
        }

        return signature.verify(sigBytes);
    }
    public static final void firmarFicheroClavePrivada(String inputFile, String outputFile, PrivateKey paramPrivateKey, String algoritmoClavePrivada) {
        try {
            FileInputStream fileInputStream = new FileInputStream(inputFile);
            int j = 0;
            int k = fileInputStream.available();
            Signature signature = Signature.getInstance(algoritmoClavePrivada);
            signature.initSign(paramPrivateKey);
            byte[] buffer = new byte[1024];
            int i;
            while ((i = fileInputStream.read(buffer)) > -1) {
                j += i;
                signature.update(buffer, 0, i);
            }

            byte[] firma = signature.sign();

            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
            fileInputStream.close();

            FileInputStream newFileInputStream = new FileInputStream(inputFile);
            Header headerCifradoMAC = new Header(Options.OP_SIGNED, "none", algoritmoClavePrivada, firma);
            headerCifradoMAC.save(fileOutputStream);

            while ((i = newFileInputStream.read(buffer)) != -1)
                fileOutputStream.write(buffer, 0, i);
            fileOutputStream.close();
            newFileInputStream.close();
        } catch (Exception exception) {
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
            FileOutputStream fileOutputStream = new FileOutputStream(pathSalida);
            FileInputStream fileInputStream = new FileInputStream(pathEntrada);
            Header cabecera = new Header();
            System.out.println("Llega hasta la creación de la cabecera y antes del if de carga de la cabecera");
            if (cabecera.load(fileInputStream)) {
                System.out.println("Se carga la cabecera: " + Arrays.toString(cabecera.getData()));
                if(cabecera.getOperation() == Options.OP_SIGNED) {
                    System.out.println("La operación de la cabecera es de firma");
                    int j = 0;
                    int k = fileInputStream.available();

                    Signature signature = Signature.getInstance(cabecera.getAlgorithm2());

                    signature.initVerify(paramPublicKey);
                    byte[] buffer = new byte[1024];
                    int i;
                    while ((i = fileInputStream.read(buffer)) > -1) {
                        j += i;
                        signature.update(buffer, 0, i);
                        fileOutputStream.write(buffer, 0, i);
                    }

                    if (signature.verify(cabecera.getData())) {

                        bool = true;
                    } else {

                        bool = false;
                    }
                    fileOutputStream.close();
                    fileInputStream.close();
                }
                else {
                    System.out.println("\nArchivo no utilizado para firmas.\n");
                }

            }
        } catch (Exception exception) {
            System.err.println(exception);
        }
        return bool;
    }

    /**
     * Muestra las distintas opciones de algoritmos de cifrado y devuelve el elegido
     * @return String Algoritmo de cifrado elegido
     */
    public static String solicitarAlgoritmoCifradoClavePublica(Scanner scanner) {
        int alCifrado = -1;
        while (alCifrado < 0 || alCifrado >= Options.signAlgorithms.length) {
            for (int i = 0; i < Options.signAlgorithms.length; i++) {
                System.out.println("[" + i + "]" + Options.signAlgorithms[i]);
            }
            alCifrado = leerIntegerTeclado("Elige un algoritmo de cifrado: ");
        }
        return Options.signAlgorithms[alCifrado];
    }

    /**
     * Funcion que nos permite cambiar o añadir una nueva extensión, si el fichero no la tiene.
     *
     * @param pathFichero Fichero que se va a cambiar o añadir una extension
     * @param extension Una extension del fichero que se quiere crear
     * @return La direccion del fichero con la nueva extensión
     */
    public static final String cambioExtensionFichero(String pathFichero, String extension) {
        int i;
        return ((i = pathFichero.lastIndexOf(".")) == -1) ? (String.valueOf(pathFichero) + "." + extension) : (String.valueOf(pathFichero.substring(0, i)) + "." + extension);
    }

    /**
     * Elimina la última extensión de un archivo en una ruta, si esta existe.
     *
     * @param path Ruta del archivo cuya última extensión se desea eliminar.
     * @return String Ruta sin la última extensión. Si no hay una extensión válida, devuelve la ruta original.
     */
    public static String eliminarUltimaExtension(String path) {
        if (path == null || path.isEmpty()) {
            return path; // Retornar tal cual si el path es nulo o vacío
        }

        // Encontrar la última posición del punto
        int lastDotIndex = path.lastIndexOf('.');
        int lastSeparatorIndex = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')); // Soporte para diferentes OS

        // Verificar si el punto está después del último separador (es una extensión válida)
        if (lastDotIndex > lastSeparatorIndex) {
            return path.substring(0, lastDotIndex);
        }

        // Si no hay extensión válida, retornar el path original
        return path;
    }
}

