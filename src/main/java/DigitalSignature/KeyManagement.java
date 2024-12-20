package DigitalSignature;

import java.security.*;
import java.io.*;
import java.security.spec.*;

public class KeyManagement {

    /**
     * Genera un par de claves RSA y las guarda en los archivos especificados.
     *
     * @param algoritmo Nombre del algoritmo de cifrado (no se usa en este método, siempre usa "RSA").
     * @param publicKeyFile Ruta del archivo donde se almacenará la clave pública.
     * @param privateKeyFile Ruta del archivo donde se almacenará la clave privada.
     * @return boolean true si las claves se generaron y almacenaron correctamente.
     * @throws Exception Si ocurre un error durante la generación o almacenamiento de las claves.
     */
    public static boolean generateAndStoreKeys(String algoritmo, String publicKeyFile, String privateKeyFile) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048); // Tamaño de clave
        KeyPair keyPair = kpg.generateKeyPair();

        // Guardar clave pública
        try (ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKeyFile))) {
            publicKeyOS.writeObject(keyPair.getPublic());
        }

        // Guardar clave privada
        try (ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(privateKeyFile))) {
            privateKeyOS.writeObject(keyPair.getPrivate());
        }
        return true;
    }

    // Carga una clave pública desde un archivo
    /**
     * Carga una clave pública desde un archivo especificado.
     *
     * @param publicKeyFile Ruta del archivo que contiene la clave pública.
     * @return PublicKey Objeto que representa la clave pública cargada.
     * @throws Exception Si ocurre un error al leer o interpretar el archivo de clave pública.
     */
    public static PublicKey loadPublicKey(String publicKeyFile) throws Exception {
        try (ObjectInputStream publicKeyIS = new ObjectInputStream(new FileInputStream(publicKeyFile))) {
            return (PublicKey) publicKeyIS.readObject();
        }
    }

    /**
     * Carga una clave privada desde un archivo especificado.
     *
     * @param privateKeyFile Ruta del archivo que contiene la clave privada.
     * @return PrivateKey Objeto que representa la clave privada cargada.
     * @throws Exception Si ocurre un error al leer o interpretar el archivo de clave privada.
     */
    public static PrivateKey loadPrivateKey(String privateKeyFile) throws Exception {
        try (ObjectInputStream privateKeyIS = new ObjectInputStream(new FileInputStream(privateKeyFile))) {
            return (PrivateKey) privateKeyIS.readObject();
        }
    }
}
