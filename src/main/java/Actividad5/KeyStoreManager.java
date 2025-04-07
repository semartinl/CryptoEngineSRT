package Actividad5;


import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Scanner;



public class KeyStoreManager {
    private KeyStore keyStore;
    private String keyStorePath;
    private char[] keyStorePassword;

    public KeyStoreManager(String keyStorePath, char[] keyStorePassword) throws Exception {
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        this.keyStore = KeyStore.getInstance("JKS");
        File file = new File(keyStorePath);
        // Verifica si el archivo existe y no está vacío
//        if (file.exists() && file.length() > 0) {
//            try (FileInputStream fis = new FileInputStream(keyStorePath)) {
//                keyStore.load(fis, keyStorePassword);
//            }
//        } else {
//            keyStore.load(null, keyStorePassword);
//            saveKeyStore();
//        }
        // Verifica si el archivo existe y no está vacío
        if (file.exists() && file.length() > 0) {
            try (FileInputStream fis = new FileInputStream(keyStorePath)) {
                keyStore = KeyStore.getInstance(detectKeyStoreType(keyStorePath));
                keyStore.load(fis, keyStorePassword);
            } catch (IOException e) {
                throw new IOException("Error al cargar el almacén de claves. Verifique la contraseña y el formato.", e);
            }
        } else {
            keyStore = KeyStore.getInstance("PKCS12"); // Usar PKCS12 por compatibilidad
            keyStore.load(null, keyStorePassword);
            saveKeyStore();
        }

    }
    private String detectKeyStoreType(String path) {
        return path.endsWith(".p12") || path.endsWith(".pkcs12") ? "PKCS12" : "JKS";
    }

    public void listKeys() throws Exception {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            System.out.println("Clave: " + aliases.nextElement());
        }
    }

//    public void storeKeyPair(String alias, KeyPair keyPair, char[] keyPassword) throws Exception {
//        X509Certificate certificate = generateSelfSignedCertificate(keyPair);
//        Certificate[] certChain = new Certificate[]{certificate}; // Asegurar compatibilidad con Certificate[]
//        keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyPassword, certChain);
//        saveKeyStore();
//    }

    public KeyPair loadKeyPair(String alias, char[] keyPassword) throws Exception {
        Key key = keyStore.getKey(alias, keyPassword);
        if (key instanceof PrivateKey) {
            Certificate cert = keyStore.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();
            return new KeyPair(publicKey, (PrivateKey) key);
        }
        return null;
    }

    private void saveKeyStore() throws Exception {
        try (FileOutputStream fos = new FileOutputStream(keyStorePath)) {
            keyStore.store(fos, keyStorePassword);
        }
    }

//    private X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
//        long validity = 365 * 24 * 60 * 60 * 1000L; // 1 año en milisegundos
//        Date startDate = new Date();
//        Date expiryDate = new Date(startDate.getTime() + validity);
//        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
//        X500Principal dnName = new X500Principal("CN=Self-Signed Certificate");
//
//        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME)
//                .build(keyPair.getPrivate());
//
//        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
//                dnName, serialNumber, startDate, expiryDate, dnName, keyPair.getPublic());
//
//        return new JcaX509CertificateConverter()
//                .getCertificate(certBuilder.build(signer));
//    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Scanner scanner = new Scanner(System.in);
        KeyPair loadedKeyPair = null;
        try {
            System.out.print("Ingrese la ruta del almacén de claves: ");
            String path = scanner.nextLine();

            System.out.print("Ingrese la contraseña del almacén de claves: ");
            char[] password = scanner.nextLine().toCharArray();

            KeyStoreManager manager = new KeyStoreManager(path, password);

            while (true) {
                System.out.println("\nAplicación de Criptografía");
                System.out.println("1. Listar claves del KeyStore");
                System.out.println("2. Agregar nueva clave al KeyStore");
                System.out.println("3. Seleccionar clave del KeyStore");
                System.out.println("4. Firmar archivo");
                System.out.println("5. Verificar firma");
                System.out.println("6. Cifrar archivo");
                System.out.println("7. Descifrar archivo");
                System.out.println("8. Salir");
                System.out.print("Seleccione una opción: ");

                int option = scanner.nextInt();
                scanner.nextLine(); // Consumir el salto de línea

                switch (option) {
                    case 1:
                        manager.listKeys();
                        break;
                    case 2:
                        System.out.print("Ingrese alias de la clave: ");
                        String alias = scanner.nextLine();
                        KeyPair keyPair = generateKeyPair(scanner);
//                        manager.storeKeyPair(alias, keyPair, password);
                        System.out.println("Clave almacenada con éxito.");
                        break;
                    case 3:
                        manager.listKeys();
                        System.out.print("Ingrese alias de la clave: ");
                        alias = scanner.nextLine();
                        loadedKeyPair = manager.loadKeyPair(alias, password);
                        if (loadedKeyPair != null) {
                            System.out.println("Clave cargada con éxito.");
                            System.out.println(loadedKeyPair.getPublic().getAlgorithm());
                            System.out.println(loadedKeyPair.getPrivate().getAlgorithm());
                        } else {
                            System.out.println("Clave no encontrada.");
                        }
                        break;
                    case 4:
                        System.out.println("Saliendo...");
                        scanner.close();
                        return;
                    default:
                        System.out.println("Opción no válida.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair(Scanner scanner) throws Exception {
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
        return keyGen.generateKeyPair();
    }
}
