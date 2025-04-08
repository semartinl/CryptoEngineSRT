package Resumen_hash;


import librerias.Header;
import librerias.Options;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.PrintWriter;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.Scanner;

import static Resumen_hash.FileProtectorMac.*;
import static actividad2.Main.procesarCifrado;
import static actividad2.Main.procesarDescifrado;

public class Main {
    static FileProtectorMac mac = new FileProtectorMac();
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean continuar = true;

        while (continuar) {
            System.out.println("Seleccione una opción:");
            System.out.println("1. Cifrar un archivo");
            System.out.println("2. Descifrar un archivo");
            System.out.println("3. Calcular HASH");
            System.out.println("4. Calcular MAC");
            System.out.println("5. Verificar HASH");
            System.out.println("6. Verificar MAC");
            System.out.println("7. Salir");
            System.out.print("Opción: ");
            int subop = scanner.nextInt();
            scanner.nextLine();
            switch (subop) {
                case 1:
                    procesarCifrado(scanner);
                    break;
                case 2:
                    procesarDescifrado(scanner);
                    break;
                case 3:
                    logicaCalcularHash(scanner);
                    break;
                case 4:
                    logicaCalcularMAC(scanner);
                    break;
                case 5:
                    verificarHash(scanner);
                    break;
                case 6:
                    verificarMAC(scanner);
                    break;
                case 7:
                    scanner.close();
                    System.exit(0);
                default:
                    System.out.println("Opción inválida.");
            }
        }

    }

    public static void logicaCalcularHash(Scanner scanner) {
        try {
            System.out.print("Ingrese el nombre del archivo a resumir (hash): ");
            String filePath = scanner.nextLine();

            System.out.println("Seleccione algoritmo de hash (SHA-1, SHA-256, SHA-512): ");
            String algorithm = solicitarAlgoritmoHash();

            String tipoClave = "secreto";

            System.out.print("Ingrese " + tipoClave +" : ");
            String clave = scanner.nextLine();


            mac.applyHash(filePath,filePath+".hash",clave,algorithm);


        } catch (Exception e) {
            System.out.println("Error al calcular el hash: " + e.getMessage());
        }
    }


    public static void logicaCalcularMAC(Scanner scanner) {
        try {
            System.out.print("Ingrese el nombre del archivo a resumir (MAC): ");
            String filePath = scanner.nextLine();

            System.out.println("Seleccione algoritmo HMAC a utilizar: ");
            String algorithm = solicitarAlgoritmoHMAC();

            String tipoClave = "contraseña";

            System.out.print("Ingrese " + tipoClave +" : ");
            String clave = scanner.nextLine();

            mac.applyHMAC(filePath,filePath+".mac",clave,algorithm);

//            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
//            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
//            SecretKey tmp = skf.generateSecret(spec);
//            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), algorithm);
//
//            Mac mac2 = Mac.getInstance(algorithm);
//            mac2.init(secretKey);
//
//            try (FileInputStream fis = new FileInputStream(filePath)) {
//                byte[] buffer = new byte[1024];
//                int read;
//                while ((read = fis.read(buffer)) != -1) {
//                    mac2.update(buffer, 0, read);
//                }
//
//                byte[] macResult = mac2.doFinal();
//                String macHex = bytesToHex(macResult);
//
//                String macFile = filePath + "." + algorithm + ".mac";
//                try (PrintWriter out = new PrintWriter(macFile)) {
//                    out.println(algorithm);
//                    out.println(macHex);
//                }
//
//                System.out.println("Código MAC guardado en: " + macFile);
//            }

        } catch (Exception e) {
            System.out.println("Error al calcular el MAC: " + e.getMessage());
        }
    }


    public static void verificarHash(Scanner scanner) {
        try {
            System.out.print("Ingrese el archivo a verificar: ");
            String originalFile = scanner.nextLine();

            System.out.print("Ingrese el archivo de salida: ");
            String outputFile = scanner.nextLine();

            System.out.print("Ingrese la contraseña usada para HASH: ");
            String password = scanner.nextLine();

            Header header = new Header();
            if (mac.cargarCabeceraArchivo(originalFile, header)) {
                mac.verifyHash(originalFile,outputFile,password,header.getAlgorithm2());
            }




        } catch (Exception e) {
            System.out.println("Error al verificar el hash: " + e.getMessage());
        }
    }


    public static void verificarMAC(Scanner scanner) {
        try {
            System.out.print("Ingrese el archivo original a verificar: ");
            String originalFile = scanner.nextLine();

            System.out.print("Ingrese el archivo de MAC (.mac)(archivo de salida): ");
            String macFile = scanner.nextLine();

            System.out.print("Ingrese la contraseña usada para MAC: ");
            String password = scanner.nextLine();

            Header header = new Header();
            if (mac.cargarCabeceraArchivo(originalFile, header)) {
                String tipoClave;
                if (Options.isTypeAlgorithm(Options.hashAlgorithms, header.getAlgorithm2())) {
                    tipoClave = "Secreto";
                } else {
                    tipoClave = "Contraseña";
                }
            }

            mac.verifyHMAC(originalFile, macFile,password,header.getAlgorithm2());

    }
        catch (Exception e) {
        System.out.println("Error al verificar el hash: " + e.getMessage());}
    }




}
