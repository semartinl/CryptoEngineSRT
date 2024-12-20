package DigitalSignature;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

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

