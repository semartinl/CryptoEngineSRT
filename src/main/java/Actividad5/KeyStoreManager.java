package Actividad5;



import java.io.*;

import java.security.*;
import java.security.cert.Certificate;

/**
 * Clase que gestiona el acceso y operaciones sobre un almacén de claves (KeyStore),
 * incluyendo carga, lectura de alias, recuperación de pares de claves y almacenamiento seguro.
 *
 * Soporta los formatos JKS y PKCS12, y permite la detección automática del tipo según la extensión del archivo.
 *
 * Esta clase está diseñada para integrarse tanto en aplicaciones gráficas como en línea de comandos.
 *
 * @author Sergio Martín Ledesma
 */
public class KeyStoreManager {
    private KeyStore keyStore;
    private String keyStorePath;
    private char[] keyStorePassword;
    /**
     * Devuelve la contraseña actual del KeyStore.
     *
     * @return Contraseña del KeyStore.
     */
    public char[] getKeyStorePassword() {
        return keyStorePassword;
    }
    /**
     * Establece una nueva contraseña para el KeyStore.
     *
     * @param keyStorePassword Contraseña a establecer.
     */
    public void setKeyStorePassword(char[] keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }
    /**
     * Devuelve la ruta del archivo del KeyStore.
     *
     * @return Ruta del archivo del KeyStore.
     */
    public String getKeyStorePath() {
        return keyStorePath;
    }   /**
     * Establece una nueva ruta para el archivo KeyStore.
     *
     * @param keyStorePath Nueva ruta del archivo.
     */

    public void setKeyStorePath(String keyStorePath) {
        this.keyStorePath = keyStorePath;
    }
    /**
     * Devuelve el objeto KeyStore actualmente cargado.
     *
     * @return KeyStore cargado en memoria.
     */
    public KeyStore getKeyStore() {
        return keyStore;
    }
    /**
     * Asigna un nuevo objeto KeyStore.
     *
     * @param keyStore KeyStore a establecer.
     */
    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }
    /**
     * Crea una instancia de KeyStoreManager y carga el almacén de claves desde el archivo proporcionado.
     * Si el archivo no existe, se crea uno nuevo con el tipo PKCS12 por defecto.
     *
     * @param keyStorePath Ruta del archivo del almacén de claves.
     * @param keyStorePassword Contraseña del almacén de claves.
     * @throws Exception Si ocurre un error al cargar o crear el KeyStore.
     */

    public KeyStoreManager(String keyStorePath, char[] keyStorePassword) throws Exception {
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        this.keyStore = KeyStore.getInstance("JKS");

        File file = new File(keyStorePath);

        // Verifica si el archivo del KeyStore existe y no está vacío
        if (file.exists() && file.length() > 0) {
            try (FileInputStream fis = new FileInputStream(keyStorePath)) {
                // Detecta el tipo de almacén (JKS o PKCS12) según la extensión del archivo
                keyStore = KeyStore.getInstance(detectKeyStoreType(keyStorePath));

                // Carga el contenido del almacén usando la contraseña proporcionada
                keyStore.load(fis, keyStorePassword);
            } catch (IOException e) {
                // Error típico: formato incorrecto o contraseña inválida
                throw new IOException("Error al cargar el almacén de claves. Verifique la contraseña y el formato.", e);
            }
        } else {
            // Si no existe, se crea un nuevo almacén PKCS12 vacío
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, keyStorePassword);

            // Se guarda inmediatamente para crear el archivo en disco
            saveKeyStore();
        }
    }
    /**
     * Detecta automáticamente el tipo de almacén de claves en base a la extensión del archivo.
     *
     * @param path Ruta del archivo del almacén.
     * @return "PKCS12" si la extensión es .p12 o .pkcs12, "JKS" en caso contrario.
     */
    private String detectKeyStoreType(String path) {
        // Retorna el tipo de KeyStore basado en la extensión del archivo
        return path.endsWith(".p12") || path.endsWith(".pkcs12") ? "PKCS12" : "JKS";
    }

    /**
     * Carga un par de claves (pública y privada) desde el KeyStore usando el alias y contraseña.
     *
     * @param alias Alias de la entrada que contiene el par de claves.
     * @param keyPassword Contraseña para acceder a la clave privada.
     * @return Objeto KeyPair con la clave pública y privada, o null si no se encuentra.
     * @throws Exception Si ocurre un error al acceder al KeyStore o recuperar la clave.
     */
    public KeyPair loadKeyPair(String alias, char[] keyPassword) throws Exception {
        // Se obtiene la clave privada correspondiente al alias
        Key key = keyStore.getKey(alias, keyPassword);

        // Si la clave existe y es privada, se construye el par con su certificado
        if (key instanceof PrivateKey) {
            Certificate cert = keyStore.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();
            return new KeyPair(publicKey, (PrivateKey) key);
        }

        // Si no se encuentra clave privada válida, se retorna null
        return null;
    }
    /**
     * Guarda el estado actual del KeyStore en el archivo definido.
     *
     * @throws Exception Si ocurre un error durante la escritura del archivo.
     */
    private void saveKeyStore() throws Exception {
        // Guarda el estado del KeyStore en el archivo asociado
        try (FileOutputStream fos = new FileOutputStream(keyStorePath)) {
            keyStore.store(fos, keyStorePassword);
        }
    }


}
