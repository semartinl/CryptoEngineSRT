package Resumen_hash;

import librerias.Header;
import librerias.Options;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class FileProtector {


    public static byte[] getHash (String inputFile, Header h, MessageDigest md){

        byte[] hash = null;


        try {
            FileInputStream fis = new FileInputStream(inputFile);

             DigestInputStream dis = new DigestInputStream(fis, md);


//            byte[] buffer = new byte[4096];

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = dis.read(buffer)) > -1) {

            }

            // Recuperar el resumen
            md = dis.getMessageDigest();
            hash = md.digest();

            dis.close();
            fis.close();
        } catch (Exception e){
            e.printStackTrace();
        }
        return hash;
    }

    // Función para generar un Hash del contenido del archivo
    public static void applyHash(String inputFile, Header h, MessageDigest md, boolean toVerify) throws Exception {
        // Crear el MessageDigest con el algoritmo deseado


        // Escribir la cabecera al archivo de salida


        String outputFile = inputFile + ".hsh";

        byte[] hash = getHash(inputFile, h, md);

        try (FileInputStream fis = new FileInputStream(inputFile);
             DigestInputStream dis = new DigestInputStream(fis, md);
             FileOutputStream fos = new FileOutputStream(outputFile)) {



            System.out.println("HASH OBTENIDO" + hash);


            /*fos.write(("Algorithm: " + algorithm + "\n").getBytes(StandardCharsets.UTF_8));
            fos.write(("Hash: " + bytesToHex(hash) + "\n").getBytes(StandardCharsets.UTF_8));
            fos.write("----BEGIN FILE CONTENT----\n".getBytes(StandardCharsets.UTF_8));*/

            // Escribir el contenido original
//            fis.getChannel().position(0); // Resetear FileInputStream
//            byte[] buffer = new byte[4096];
            boolean success = false;
            h.setData(hash); //AÑADIMOS A LA CABECERA EL HASH OBTENIDO
            if (!h.save(fos)) { //Guardamos en el fichero de salida la cabecera con los datos correspondientes del algoritmo
                System.out.println("Error al guardar la cabecera");
            }

            /*while (fis.read(buffer) != -1) {
                fos.write(buffer);
            }*/
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = dis.read(buffer)) > -1) {
                fos.write(buffer, 0, bytesRead);
            }
            dis.close();
            fis.close();
            fos.close();
        }
    }

    // Función para generar un Hash del contenido del archivo
    public static boolean verifyHash(String inputFile, Header h, MessageDigest md) throws Exception {
        // Crear el MessageDigest con el algoritmo deseado


        // Escribir la cabecera al archivo de salida
        boolean success = false;
        String outputFile = inputFile + ".cla";

            byte[] hash = null;


        try {
            FileInputStream fis = new FileInputStream(inputFile);

             DigestInputStream dis = new DigestInputStream(fis, md);
             FileOutputStream fos = new FileOutputStream(outputFile);

            Header hFile = new Header();
            hFile.load(fis); //Se carga la cabecera del fichero.

//            byte[] hash = getHash(inputFile, h, md);
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = dis.read(buffer)) > -1) {
                fos.write(buffer, 0, bytesRead);
            }

            // Recuperar el resumen
            md = dis.getMessageDigest();
            hash = md.digest();

            if(bytesToHex(hash).equals(bytesToHex(hFile.getData()))){
                success = true;
            }
            dis.close();
            fis.close();
            fos.close();
        }
        catch (Exception e){
            e.printStackTrace();

        }
        return success;
    }


    // Función para generar un MAC del contenido del archivo
    public static void applyMac(String inputFile, String outputFile, String algorithm, String secret, byte[] salt, int iterationCount, int macLength) throws Exception {
        // Generar clave secreta usando PBKDF2
        PBEKeySpec spec = new PBEKeySpec(secret.toCharArray(), salt, iterationCount, macLength * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey secretKey = skf.generateSecret(spec);
        SecretKeySpec macKey = new SecretKeySpec(secretKey.getEncoded(), algorithm);

        // Crear el objeto Mac
        Mac mac = Mac.getInstance(algorithm);
        mac.init(macKey);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                mac.update(buffer, 0, bytesRead); // Actualizamos el MAC con el contenido
            }

            // Generar el MAC final
            byte[] macCode = mac.doFinal();

            // Escribir la cabecera al archivo de salida
            fos.write(("Algorithm: " + algorithm + "\n").getBytes(StandardCharsets.UTF_8));
            fos.write(("MAC: " + bytesToHex(macCode) + "\n").getBytes(StandardCharsets.UTF_8));
            fos.write("----BEGIN FILE CONTENT----\n".getBytes(StandardCharsets.UTF_8));

            // Escribir el contenido original
            fis.getChannel().position(0); // Resetear FileInputStream
            while ((bytesRead = fis.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }
            fis.close();
            fos.close();

        }
    }

    // Utilidad para convertir bytes a hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }


    public static void processingAuthentication(String filename, String algoritmoAutenticacion, String secreto){
        try {

//            String outputFileHash = "output_hash.txt";
//            String outputFileMac = "output_mac.txt";
            String secret = "shared_secret"; //Lo PONE EL USUARIO
            String hashAlgorithm = "SHA-256"; // Ejemplo: SHA-256
            String macAlgorithm = "HmacSHA256"; // Ejemplo: HmacSHA256
            byte[] salt = "12345678".getBytes(StandardCharsets.UTF_8); // Salt fijo
            int macLength = 256; // Longitud en bits para HmacSHA256

            int iterationCount = 10000; //fijas


            Header h = new Header(Options.OP_HASH_MAC,
                    Options.cipherAlgorithms[0],algoritmoAutenticacion, salt);

            // Aplicar Hash
            MessageDigest md = MessageDigest.getInstance(algoritmoAutenticacion);
            md.update(secret.getBytes(StandardCharsets.UTF_8)); // Actualizamos con el secreto
            applyHash(filename, h, md, true);
//            System.out.println("Archivo protegido con Hash generado: " + outputFileHash);

            MessageDigest md2 = MessageDigest.getInstance(algoritmoAutenticacion);
            md2.update(secret.getBytes(StandardCharsets.UTF_8)); // Actualizamos con el secreto
            if(verifyHash(filename+".hsh", h, md2)){
                System.out.println("ARCHIVOS CON EL MISMO HASH: NO HAN SIDO MODIFICADOS");
            }
            else {
                System.out.println("LOS ARCHIVOS NO TIENEN EL MISMO HASH");
            }

            // Aplicar MAC
//            applyMac(inputFile, outputFileMac, macAlgorithm, secret, salt, iterationCount, macLength / 8);
//            System.out.println("Archivo protegido con MAC generado: " + outputFileMac);
        }catch (Exception e) {
            e.printStackTrace();
        }


    }

    // Ejemplo de uso
    public static void main(String[] args) {
        String inputFile = "C:\\Users\\celia\\eclipse-workspace-pbd\\cryptoEngineSRT\\src\\Resumen_hash\\qq";
        try {
            processingAuthentication(inputFile,"MD2", "hola");


        }catch (Exception e) {
            e.printStackTrace();
        }
    }
}

