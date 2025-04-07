package Actividad5;

import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

import DigitalSignature.ParClaves;

/**
 * Clase que representa el almacén de claves.
 */
public class AlmacenClaves extends ParClaves {
    private KeyStore keyStore;


    /**
     * Constructor de la clase KeyStoreManager.
     *
     */
    public AlmacenClaves() {
//        this.app = app;
        this.keyStore = null;
    }

    /**
     * Carga un almacén de claves desde un archivo.
     *
     * @param filePath Ruta del archivo del almacén de claves.
     * @param password Contraseña del almacén de claves.
     * @return true si el almacén de claves se cargó correctamente, false en caso contrario.
     */
    private boolean loadKeyStore(String filePath, char[] password) {
        boolean bool = false;
        try {
            this.keyStore = KeyStore.getInstance("JKS");
            FileInputStream fileInputStream = new FileInputStream(filePath);
            this.keyStore.load(fileInputStream, password);
            fileInputStream.close();
            bool = true;
        } catch (Exception exception) {
            this.keyStore = null;
        }
        return bool;
    }
    /**
     * Importa claves desde un almacén de claves.
     *
     * @param filePath_keyStore Ruta del archivo del almacén de claves.
     * @param password_keyStore Contraseña del almacén de claves.
     * @return true si la clave se importó correctamente, false en caso contrario.
     */
    public final boolean importKeys(String filePath_keyStore, char[] password_keyStore) {
        boolean bool = false;
        if (!loadKeyStore(filePath_keyStore, password_keyStore)) {
            System.out.println("\nEl almacen de claves no ha sido cargado correctamente.\n");
        } else {
            try {
                System.out.println("\nImportando claves desde el almacen de claves ...\n");
                Enumeration<String> enumeration = this.keyStore.aliases();
                Object[][] arrayOfObject = new Object[this.keyStore.size()][3];
                byte b = 0;
                while (enumeration.hasMoreElements()) {
                    String str = enumeration.nextElement();
                    arrayOfObject[b][0] = str;
                    if (this.keyStore.isKeyEntry(str)) {
                        arrayOfObject[b][1] = "Private Key";
                        arrayOfObject[b++][2] = Boolean.valueOf(true);
                        continue;
                    }
                    if (this.keyStore.isCertificateEntry(str)) {
                        arrayOfObject[b][1] = "Certificate KU";
                        arrayOfObject[b++][2] = Boolean.valueOf(false);
                    }
                }

//                if (ventanaDialogoAlmacenLlaves.getSelectedAlias() != null && loadKeyPairFromKeyStore(ventanaDialogoAlmacenLlaves.getSelectedAlias(), ventanaDialogoAlmacenLlaves.getEnteredPassword())) {
//                    System.out.println("Importada clave: " + ventanaDialogoAlmacenLlaves.getSelectedAlias());
//                    bool = true;
//                }
            } catch (Exception exception) {
                System.out.println(exception.toString());
            }
        }
        return bool;
    }

    /**
     * Muestra el contenido del almacén de claves.
     *
     * @param aliasKeyPair Alias del par de clave que se va a cargar del almacén de claves
     * @param password Contraseña del par de claves
     * @return true si el contenido se mostró correctamente, false en caso contrario.
     */
    private boolean loadKeyPairFromKeyStore(String aliasKeyPair, char[] password) {
        try {
            if (this.keyStore.isKeyEntry(aliasKeyPair)) {
                PrivateKey privateKey = (PrivateKey)this.keyStore.getKey(aliasKeyPair, password);
                Certificate certificate = this.keyStore.getCertificate(aliasKeyPair);
                PublicKey publicKey = certificate.getPublicKey();

//                this.app.keypair = new ParClaves(new KeyPair(publicKey, privateKey));
//                this.app.opciones.setKeyFilePasswd(password);
                return true;
            }
        } catch (Exception exception) {
            System.out.println(exception.toString());
        }
        return false;
    }

    /**
     * Función que muestra el contenido del almacén de claves.
     * @param filePath Nombre del fichero en el que se encuentra guardado el almacén de claves.
     * @param password Contraseña para abrir el almacén de claves.
     * @return True si el almacén ha sido cargado correctamente. False en caso contrario.
     */
    public final boolean displayKeyPairsFromKeyStore(String filePath, char[] password) {
        boolean bool = true;
        if (!loadKeyStore(filePath, password)) {
            System.out.println("\nEl almacen de claves no ha sido cargado correctamente.\n");
            bool = false;
        } else {
            try {
                System.out.println("\nContenido del almacen de claves:\n");
                Enumeration<String> enumeration = this.keyStore.aliases();
                while (enumeration.hasMoreElements()) {
                    String str = enumeration.nextElement();
                    if (this.keyStore.isKeyEntry(str)) {
                        System.out.println("Clave: " + str + "\n");
                        System.out.println("-------------------\n");
                        Certificate certificate = this.keyStore.getCertificate(str);
                        System.out.println("\nCertificado de Clave Pública:\n");
                        System.out.println(certificate.getPublicKey().getAlgorithm());
                        System.out.println("\n--------------------------------------------\n");
                        continue;

                    }
                    if (this.keyStore.isCertificateEntry(str)) {
                        System.out.println("Clave: " + str + "\n");
                        System.out.println("-------------------\n");
                        Certificate certificate = this.keyStore.getCertificate(str);
                        System.out.println("Certificado de Clave Pública:\n");
                        System.out.println(certificate.getPublicKey().getAlgorithm());
                        System.out.println("--------------------------------------------\n");
                        continue;
                    }
                    System.out.println("Clave: " + str + "\n");
                    System.out.println("-------------------\n");
                }
            } catch (Exception exception) {
                System.out.println(exception.toString());
                bool = false;
            }
        }
        return bool;
    }
}
