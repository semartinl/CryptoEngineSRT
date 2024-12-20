package Resumen_hash;

import librerias.Header;
import librerias.Options;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
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

    public static byte[] getMac (String inputFile, Header h, String algorithm, SecretKeySpec macKey, boolean toVerify) throws Exception {

        byte[] macCode = null;


        try {


            String outputFile;

            FileInputStream fis = new FileInputStream(inputFile);
            if(toVerify){

                h.load(fis);
                algorithm = h.getAlgorithm2();
            }
            // Crear el objeto Mac
            Mac mac = Mac.getInstance(algorithm);
            mac.init(macKey);

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                mac.update(buffer, 0, bytesRead); // Actualizamos el MAC con el contenido
            }
             macCode = mac.doFinal();
        } catch (Exception e){
            e.printStackTrace();
        }
        return macCode;
    }


    // Función para generar un MAC del contenido del archivo
    public static byte[] applyMac(String inputFile, String algorithm,Header h, String secret, int iterationCount, int macLength, boolean toVerify) throws Exception {
        // Generar clave secreta usando PBKDF2
        PBEKeySpec spec = new PBEKeySpec(secret.toCharArray(), h.getData(), iterationCount, macLength * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey secretKey = skf.generateSecret(spec);
        SecretKeySpec macKey = new SecretKeySpec(secretKey.getEncoded(), algorithm);

        String outputFile;

        FileInputStream fis = new FileInputStream(inputFile);
        if(toVerify){

            h.load(fis);

        }
        // Crear el objeto Mac
        Mac mac = Mac.getInstance(algorithm);
        mac.init(macKey);

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                mac.update(buffer, 0, bytesRead); // Actualizamos el MAC con el contenido
            }

        if(toVerify){
            outputFile = inputFile + ".cla";
            h.load(fis);
        }else {
            outputFile = inputFile + ".hsh";

        }
            // Generar el MAC final
            byte[] macCode = mac.doFinal();
            h.setData(macCode); //AÑADIMOS A LA CABECERA EL HMAC OBTENIDO
            FileOutputStream fos = new FileOutputStream(outputFile) ;
            if (!h.save(fos)) { //Guardamos en el fichero de salida la cabecera con los datos correspondientes del algoritmo
                System.out.println("Error al guardar la cabecera");
            }


            // Escribir el contenido original
            fis.getChannel().position(0); // Resetear FileInputStream

            while ((bytesRead = fis.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }

            fis.close();
            fos.close();

        return macCode;

    }

    public static boolean verifyMac(String inputFile, String secret, byte[] salt, int iterationCount, int macLength) throws Exception {
            FileInputStream fis = new FileInputStream(inputFile);
            FileOutputStream fos = new FileOutputStream(inputFile+ ".cla");
            // Leer y extraer la cabecera
            Header h = new Header();
            h.load(fis);
            String algorithm = h.getAlgorithm2();

            // Generar clave secreta usando PBKDF2
            PBEKeySpec spec = new PBEKeySpec(secret.toCharArray(), salt, iterationCount, macLength * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            SecretKey secretKey = skf.generateSecret(spec);
            SecretKeySpec macKey = new SecretKeySpec(secretKey.getEncoded(), algorithm);



            // Configurar Mac
            Mac mac = Mac.getInstance(algorithm);
            mac.init(macKey);


            // Leer el contenido original del archivo
        byte[] buffer = new byte[4096];
        int bytesRead;

        while ((bytesRead = fis.read(buffer)) != -1) {

            mac.update(buffer, 0, bytesRead);
        }

        // Calcular el MAC del contenido
        byte[] calculatedMac = mac.doFinal();

        fis.getChannel().position(0); // Resetear FileInputStream
        h.load(fis);
        while ((bytesRead = fis.read(buffer)) != -1) {
            fos.write(buffer, 0, bytesRead);
        }

        fis.close();
        fos.close();
            // Comparar el MAC calculado con el almacenado
            return bytesToHex(calculatedMac).equals(bytesToHex(h.getData()));

    }

    // Utilidad para convertir bytes a hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }


    public static void processingAuthentication(String filename, String algoritmoAutenticacion, String secreto, boolean isHashing){
        try {
            boolean result = false;
            byte[] salt = "12345678".getBytes(StandardCharsets.UTF_8); // Salt fijo
            int macLength = 256; // Longitud en bits para HmacSHA256

            int iterationCount = 10000; //fijas


            Header h = new Header(Options.OP_HASH_MAC,
                    Options.cipherAlgorithms[0],algoritmoAutenticacion, salt);

            // Aplicar Hash
                if(Arrays.asList(Options.hashmacAlgorithms).contains(algoritmoAutenticacion)){
                    if(isHashing){
                    applyMac(filename, algoritmoAutenticacion,h, secreto, iterationCount, macLength / 8, false);
                    result = true;

                }else{
                        if(verifyMac(filename,secreto,salt,iterationCount,macLength/8)){
                            System.out.println("ARCHIVOS CON EL MISMO HASH: NO HAN SIDO MODIFICADOS");
                            result = true;
                        }else{
                            System.out.println("LOS ARCHIVOS NO TIENEN EL MISMO HASH");
                        }
                    }

            }else{
                    if(isHashing){
                        MessageDigest md = MessageDigest.getInstance(algoritmoAutenticacion);
                        md.update(secreto.getBytes(StandardCharsets.UTF_8)); // Actualizamos con el secreto
                        applyHash(filename, h, md, true);
                        result= true;
                    }else{
                        MessageDigest md2 = MessageDigest.getInstance(algoritmoAutenticacion);
                        md2.update(secreto.getBytes(StandardCharsets.UTF_8)); // Actualizamos con el secreto
                        if(verifyHash(filename, h, md2)){
                            System.out.println("ARCHIVOS CON EL MISMO HASH: NO HAN SIDO MODIFICADOS");
                        }
                        else {
                            System.out.println("LOS ARCHIVOS NO TIENEN EL MISMO HASH");
                        }
                    }

            }

//            System.out.println("Archivo protegido con Hash generado: " + outputFileHash);



            // Aplicar MAC



        }catch (Exception e) {
            e.printStackTrace();
        }


    }

    // Ejemplo de uso
    public static void main(String[] args) {
        String inputFile = "C:\\Users\\celia\\eclipse-workspace-pbd\\cryptoEngineSRT\\src\\Resumen_hash\\qq";
        try {
//            processingAuthentication(inputFile,"HmacSHA256", "hola");


        }catch (Exception e) {
            e.printStackTrace();
        }
    }
}

