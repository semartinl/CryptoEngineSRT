package DigitalSignature;

import java.util.Scanner;
import java.security.*;
import java.io.*;

import static Resumen_hash.Main.*;
import static actividad2.Main.*;

public class InterfazGraficaP4 {
    /**
     * Método principal que ejecuta la aplicación de criptografía en la consola.
     */
    public static void LogicaPrincipal(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        KeyPair keyPair;
        String keyPairDefault = "C:\\Users\\USUARIO\\Desktop\\Sergio\\Universidad\\4ºcurso\\SRT\\Practicas\\CryptoEngine\\CryptoEngineSRT\\claves.key";
        keyPair = loadKeyPairFromFile(keyPairDefault);
        if(keyPair == null) {
            System.out.print("Escribe el nombre del fichero donde se guarda el par de claves a utilizar:");

            String KeyPairPath = scanner.nextLine();
            keyPair = loadKeyPairFromFile(KeyPairPath);
        }

        while (true) {
            System.out.println("Aplicación de Criptografía");
            System.out.println("1. Generar Claves");
            System.out.println("2. Cargar Claves");
            System.out.println("3. Firmar Archivo");
            System.out.println("4. Verificar Firma");
            System.out.println("5. Cifrar Archivo con par de claves");
            System.out.println("6. Descifrar Archivo con un par de claves");
            System.out.println("7. Mostrar MENU DE OPCIONES ASIMETRICAS");
            System.out.println("8. Salir");
            System.out.print("Seleccione una opción: ");

            int option = scanner.nextInt();
            scanner.nextLine(); // Limpiar buffer

            switch (option) {
                case 1:
                    System.out.println("Generando claves...");
                    keyPair = logicaGenerarClaves(scanner);
                    break;
                case 2:
                    System.out.println("Cargando un par de claves desde un archivo...");
                    keyPair=logicaCargarClaves(scanner);
                    break;
                case 3:
                    System.out.println("Firmando archivo...");
                    logicaFirmarArchivo(scanner, keyPair);
                    break;
                case 4:
                    System.out.println("Verificando firma...");
                    logicaVerificarFirmaArchivo(scanner, keyPair);
                    break;
                case 5:
                    System.out.println("Cifrando archivo...");
                    logicaEncriptarFichero(scanner, keyPair);
                    break;
                case 6:
                    System.out.println("Descifrando archivo...");
                    logicaDescifrarArchivo(scanner, keyPair);
                    break;
                case 7:
                    mostrarSubmenuAsimetrico(scanner);
                    break;
                case 8:
                    System.out.println("Saliendo...");
                    scanner.close();
                    return;
                default:
                    System.out.println("Opción no válida. Intente nuevamente.");
            }
            System.out.println();
        }
    }

    public static void saveKeyPairToFile(KeyPair keyPair, String filename) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(keyPair.getPrivate());
            oos.writeObject(keyPair.getPublic());
        }
    }

    public static KeyPair loadKeyPairFromFile(String filename) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            PrivateKey privateKey = (PrivateKey) ois.readObject();
            PublicKey publicKey = (PublicKey) ois.readObject();
            return new KeyPair(publicKey, privateKey);
        }
    }


    /**
     * Genera un par de claves (privada y pública) y las almacena en archivos.
     * @param scanner Objeto Scanner para la entrada del usuario.
     */
    public static KeyPair logicaGenerarClaves(Scanner scanner) {
        try {
            System.out.println("Seleccione el tipo de clave (RSA o DSA): ");
            String keyType = scanner.nextLine().toUpperCase();
            if (!keyType.equals("RSA") && !keyType.equals("DSA")) {
                System.out.println("Tipo de clave no válido.");
                return null;
            }

            System.out.println("Seleccione la longitud de la clave (512, 768, 1024 bits): ");
            int keySize = scanner.nextInt();
            scanner.nextLine(); // Limpiar buffer
            if (keySize != 512 && keySize != 768 && keySize != 1024) {
                System.out.println("Longitud de clave no válida.");
                return null;
            }

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyType);
            keyGen.initialize(keySize);
            KeyPair keyPair = keyGen.generateKeyPair();

            System.out.println("Ingrese el nombre del archivo para almacenar las claves: ");
            String fileName = scanner.nextLine();

//            try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(fileName + "_private.key"))) {
//                out.writeObject(keyPair.getPrivate());
//            }
//
//            try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(fileName + "_public.key"))) {
//                out.writeObject(keyPair.getPublic());
//            }
            saveKeyPairToFile(keyPair,fileName+".key");
            System.out.println("Claves generadas y almacenadas correctamente.");
            return keyPair;
        } catch (Exception e) {
            System.out.println("Error al generar las claves: " + e.getMessage());
        }
        return null;
    }

    public static KeyPair logicaCargarClaves(Scanner scanner) {
        try{
            System.out.print("Escribe el nombre del fichero donde se guarda el par de claves a utilizar:");

            String KeyPairPath = scanner.nextLine();
            return loadKeyPairFromFile(KeyPairPath);
        }
        catch (Exception e) {
            System.out.println("Error al generar las claves: " + e.getMessage());
        }
        return null;
    }

    /**
     * Lógica para firmar un archivo. Se puede utilizar tanto claves RSA o DSA.
     *
     * @param scanner Objeto Scanner para la entrada del usuario.
     * @param keyPair
     */

    public static void logicaFirmarArchivo(Scanner scanner, KeyPair keyPair) {
        try {
            System.out.println("Ingrese el nombre del archivo a firmar: ");
            String fileName = scanner.nextLine();
            PrivateKey privateKey = keyPair.getPrivate();
            if (keyPair == null) {

                System.out.println("Ingrese el nombre del archivo de la clave privada: ");
                String privateKeyFile = scanner.nextLine();


                try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(privateKeyFile))) {
                    privateKey = (PrivateKey) in.readObject();
                }
            }

                String signAlgorithm = "SHA1withRSA"; //Por defecto
                if (privateKey.getAlgorithm().equals("RSA")) {
                    //MOSTRAR ALGORITMOS COMPATIBLES CON RSA y dar la elección al usuario
                    signAlgorithm = DigitalSignature.solicitarAlgoritmoCifradoClavePublica(scanner);
                } else if (privateKey.getAlgorithm().equals("DSA")) {
                    //MOSTRAR ALGORITMOS COMPATIBLES CON DSA y dar la elección al usuario
                    System.out.println("El algoritmo DSA se encuentra valido.");
                    signAlgorithm = "SHA1withDSA";

                }

//            System.out.println("El algoritmo a utilizar para la firma es: " + signAlgorithm);

            System.out.println("Ingrese el nombre del archivo donde guardar la firma: ");
            String signatureFile = scanner.nextLine();

            DigitalSignature.firmarFicheroClavePrivada(fileName, signatureFile,privateKey, signAlgorithm);

            System.out.println("Archivo firmado correctamente. Firma guardada en " + signatureFile);
        } catch (Exception e) {
            System.out.println("Error al firmar el archivo: " + e.getMessage());
        }
    }
    /**
     * Lógica para verificar la firma de un archivo. Se puede utilizar tanto claves RSA o DSA.
     * @param scanner Objeto Scanner para la entrada del usuario.
     */
    public static void logicaVerificarFirmaArchivo(Scanner scanner, KeyPair keyPair) {
        try {

            System.out.println("Ingrese el nombre del archivo de la firma: ");
            String signatureFile = scanner.nextLine();

            System.out.println("Ingrese el nombre del archivo de salida: ");
            String outputFile = scanner.nextLine();
            PublicKey publicKey = keyPair.getPublic();

            if (keyPair == null) {
                System.out.println("Ingrese el nombre del archivo de la clave pública: ");
                String publicKeyFile = scanner.nextLine();

                try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(publicKeyFile))) {
                    publicKey = (PublicKey) in.readObject();
                }
            }


            boolean verified = DigitalSignature.verificarFicheroFirmado(signatureFile,outputFile,publicKey);

            if (verified) {
                System.out.println("La firma es válida.");
            } else {
                System.out.println("La firma NO es válida.");
            }
        } catch (Exception e) {
            System.out.println("Error al verificar la firma: " + e.getMessage());
        }
    }
    /**
     * Cifra mediante algoritmos de clave pública un archivo utilizando una clave pública, pedida al usuario por consola.
     * @param scanner Objeto Scanner para la entrada del usuario.
     */
    public static void logicaEncriptarFichero(Scanner scanner, KeyPair keyPair) {
        try {
            System.out.println("Ingrese el nombre del archivo a cifrar: ");
            String fileName = scanner.nextLine();
            PublicKey publicKey = keyPair.getPublic();

            if(keyPair == null) {
                System.out.println("Ingrese el nombre del archivo de la clave pública: ");
                String publicKeyFile = scanner.nextLine();

                try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(publicKeyFile))) {
                    publicKey = (PublicKey) in.readObject();
                }
            }


            if(publicKey.getAlgorithm().equals("RSA")) {
                System.out.println("Ingrese el nombre del archivo cifrado de salida: ");
                String encryptedFile = scanner.nextLine();

                Encryption.cifrarBloques(fileName,encryptedFile,publicKey,"RSA/ECB/PKCS1Padding");
                System.out.println("Archivo cifrado correctamente. Guardado en " + encryptedFile);
            }
            else{
                System.out.println("No se puede encriptar un archivo con una clave de tipo DSA.");
            }



        } catch (Exception e) {
            System.out.println("Error al cifrar el archivo: " + e.getMessage());
        }
    }
    /**
     * Descifra mediante algoritmos de clave pública un archivo utilizando una clave privada pedida al usuario por consola
     * @param scanner Objeto Scanner para la entrada del usuario.
     */
    public static void logicaDescifrarArchivo(Scanner scanner, KeyPair keyPair) {
        try {
            System.out.println("Ingrese el nombre del archivo cifrado: ");
            String encryptedFile = scanner.nextLine();
            PrivateKey privateKey = keyPair.getPrivate();

            if(keyPair == null) {
                System.out.println("Ingrese el nombre del archivo de la clave privada: ");
                String privateKeyFile = scanner.nextLine();

                try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(privateKeyFile))) {
                    privateKey = (PrivateKey) in.readObject();
                }
            }


            if(privateKey.getAlgorithm().equals("RSA")) {
                System.out.println("Ingrese el nombre del archivo descifrado de salida: ");
                String decryptedFile = scanner.nextLine();

                Encryption.descifrarBloques(encryptedFile,decryptedFile,privateKey);
                System.out.println("Archivo descifrado correctamente. Guardado en " + decryptedFile);
            }
            else{
                System.out.println("No se puede desencriptar un archivo con una clave de tipo DSA.");
            }


        } catch (Exception e) {
            System.out.println("Error al descifrar el archivo: " + e.getMessage());
        }
    }

    public static void mostrarSubmenuAsimetrico(Scanner scanner) {
        System.out.println("\n🧩 Submenú de Integridad");
        System.out.println("Seleccione una opción:");
        System.out.println("1. Cifrar un archivo");
        System.out.println("2. Descifrar un archivo");
        System.out.println("3. Calcular HASH");
        System.out.println("4. Calcular MAC");
        System.out.println("5. Verificar HASH");
        System.out.println("6. Verificar MAC");
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

            default:
                System.out.println("Opción inválida.");
        }
    }



}
