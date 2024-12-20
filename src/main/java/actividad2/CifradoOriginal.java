/**
 * Actividad 2 - JCA
 * Seguridad en Redes Telemáticas
 * Estudiantes:
 * Guillén Torrado, Sara
 * Martín Ledesma, Sergio
 */

package actividad2;

import librerias.Header;
import librerias.Options;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;


public class CifradoOriginal {
    /**
     * Devuelve true si se va a cifrar, false si se va a descifrar
     * @return boolean true si se va a cifrar, false si se va a descifrar
     */
    static boolean elegirCifradoDescifrado() {
        boolean esCifrado = false;
        char eleccionCifrado = leerTeclado("¿Desea cifrar o descifrar? (C/E): ").charAt(0);
        while (!eleccionCifradoValida(eleccionCifrado)) {
            eleccionCifrado = leerTeclado("Elige un valor válido (C/E): ").charAt(0);
        }
        if (esCifrado(eleccionCifrado)) {
            esCifrado = true;
        }
        return esCifrado;
    }

    /**
     * Devuelve true si se va a terminar, false si se va a continuar
     * @return boolean true si se va a cifrar, false si se va a descifrar
     */
    static boolean terminar() {
        boolean fin = false;
        boolean valido = false;
        while (!valido) {
            char respuesta = leerTeclado("¿Desea terminar la ejecución? (S/N): ").charAt(0);
            if (respuesta == 'S' || respuesta == 's' || respuesta == 'Y' || respuesta == 'y') {
                fin = true;
                valido = true;
            } else if (respuesta == 'N' || respuesta == 'n') {
                valido = true;
            }
        }
        return fin;
    }

    /**
     * Muestra las distintas opciones de algoritmos de cifrado y devuelve el elegido
     * @return String Algoritmo de cifrado elegido
     */
    static String solicitarAlgoritmoCifrado() {
        int alCifrado = -1;
        while (alCifrado < 0 || alCifrado >= Options.cipherAlgorithms.length) {
            for (int i = 0; i < Options.cipherAlgorithms.length; i++) {
                System.out.println("[" + i + "]" + Options.cipherAlgorithms[i]);
            }
            alCifrado = leerIntegerTeclado("Elige un algoritmo de cifrado: ");
        }
        return Options.cipherAlgorithms[alCifrado];
    }


    /**
     * Devuelve si el caracter introducido es una elección válida (C o E, mayúscula o minúscula)
     * @param eleccionCifrado Caracter introducido por el usuario
     * @return boolean true si es una elección válida, false en caso contrario
     */
    static boolean eleccionCifradoValida(char eleccionCifrado) {
        return esCifrado(eleccionCifrado) || esDescifrado(eleccionCifrado);
    }

    /**
     * Devuelve si el caracter introducido es una elección de cifrado (C o c)
     *
     * @param eleccionCifrado Caracter introducido por el usuario
     * @return boolean true si es una elección de cifrado, false en caso contrario
     */
    static boolean esCifrado(char eleccionCifrado) {
        return eleccionCifrado == 'C' || eleccionCifrado == 'c';
    }

    /**
     * Devuelve si el caracter introducido es una elección de cifrado (C o c)
     * @param eleccionDescifrado Caracter introducido por el usuario
     * @return boolean true si es una elección de cifrado, false en caso contrario
     */
    static boolean esDescifrado(char eleccionDescifrado) {
        return eleccionDescifrado == 'E' || eleccionDescifrado == 'e';
    }

    /**
     * Lee y devuelve la cadena introducida por teclado
     * @param prompt Mensaje que se muestra al usuario
     * @return String Cadena introducida por el usuario
     */
    static String leerTeclado(String prompt) {
        try {
            StringBuffer buffer = new StringBuffer();
            System.out.print(prompt);
            System.out.flush();
            int c = System.in.read();
            while (c != '\n' && c != -1) {
                buffer.append((char) c);
                c = System.in.read();
            }
            return buffer.toString().trim();
        } catch (IOException e) {
            return "";
        }
    }

    /**
     * Lee y devuelve el número por teclado
     * @param prompt Mensaje que se muestra al usuario
     * @return int Número introducido por el usuario
     */
    static int leerIntegerTeclado(String prompt) {
        try {
            StringBuffer buffer = new StringBuffer();
            System.out.print(prompt);
            System.out.flush();
            int c = System.in.read();
            while (c != '\n' && c != -1) {
                buffer.append((char) c);
                c = System.in.read();
            }
            int numero = Integer.parseInt(buffer.toString().trim());
            return numero;
        } catch (IOException e) {
            return -1;
        }
    }

    /**
     * Crea un fichero de salida, dado su nombre y un objeto de cifrado inicializado,
     * y lo almacena en un fichero.cif
     * @param c       Objeto de cifrado inicializado
     * @param archivo Nombre del archivo a cifrar
     * @param h       La cabecera
     * @throws FileNotFoundException Si no se encuentra el archivo
     * @throws IOException           Si hay un error al leer el archivo
     * @throws Exception             Si hay un error al cifrar el archivo
     */
    public static boolean escribirFicheroCifrado(Cipher c, String archivo, Header h) throws Exception {
        String salida = archivo + ".cif";

        FileOutputStream fos = new FileOutputStream(salida); // Abre el flujo de salida desde un fichero
        CipherOutputStream cos = new CipherOutputStream(fos, c); // Abre el flujo de salida cifrado

        boolean exito = false;
        if (!h.save(fos)) {
            System.out.println("Error al guardar la cabecera");
        }

        try {
            FileInputStream fis = new FileInputStream(archivo);
            byte[] contenido = new byte[1024];
            int leidos;
            while ((leidos = fis.read(contenido)) > -1) {
                cos.write(contenido, 0, leidos);
            }
            cos.close();

            fis.close();
            exito = true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        fos.close();

        return exito;
    }

    /**
     * Descifra un fichero y guarda la salida en un fichero.cla
     * @param c Objeto de cifrado inicializado
     * @param archivo El nombre del archivo a descifrar
     * @return true si se ha descifrado correctamente, y false en caso contrario
     * @throws Exception
     */
    public static boolean escribirFicheroDescifrado(Cipher c, String archivo, FileInputStream fis) throws Exception {
        String salida = archivo + ".cla";

        FileOutputStream fos = new FileOutputStream(salida); // Abre el flujo de salida desde un fichero

        boolean exito = false;
        try {
            CipherInputStream cis = new CipherInputStream(fis, c);

            byte[] contenido = new byte[1024];
            int leidos;
            while ((leidos = cis.read(contenido)) > -1) {
                fos.write(contenido, 0, leidos);
            }

            fis.close();
            exito = true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        fos.close();

        return exito;
    }

    /**
     * Genera una clave de sesión a partir de una contraseña y un algoritmo
     *
     * @param contrasena Contraseña a partir de la cual se generará la clave de sesión
     * @param algoritmo  Algoritmo con el que se generará la clave de sesión
     * @return SecretKey Clave de sesión generada
     * @throws Exception Si el algoritmo no existe o si la clave generada no es válida
     */
    public static SecretKey generacionClaveSesion(String contrasena, String algoritmo) throws Exception {
        System.out.println("GENERANDO CLAVE DE SESION");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(contrasena.toCharArray());

        SecretKeyFactory kf = SecretKeyFactory.getInstance(algoritmo);

        SecretKey sKey = kf.generateSecret(pbeKeySpec);
        return sKey;

    }

    /**
     * Configura el objeto de cifrado y cifra el fichero
     * @param fichero El fichero a cifrar
     * @param contrasena La contraseña simétrica
     * @param algoritmoCifrado El algoritmo de cifrado elegido
     * @throws Exception
     */
    public static void processingCipher(String fichero, String contrasena, String algoritmoCifrado, int numIteraciones) throws Exception {

        Options confAlgoritmo = new Options();
        confAlgoritmo.setCipherAlgorithm(algoritmoCifrado);
        Cipher c = Cipher.getInstance(algoritmoCifrado);

        SecretKey sKey = generacionClaveSesion(contrasena, algoritmoCifrado);
        byte[] salt;
        SecureRandom random = SecureRandom.getInstance("DEFAULT", "BC");
        salt = random.generateSeed(8);

        PBEParameterSpec pPS = new PBEParameterSpec(salt, numIteraciones);
        c.init(Cipher.ENCRYPT_MODE, sKey, pPS);


        Header h = new Header(Options.OP_SYMMETRIC_CIPHER, algoritmoCifrado,
                Options.authenticationAlgorithms[0], salt);

        if(!escribirFicheroCifrado(c, fichero, h)) {
            System.out.println("Error al cifrar el fichero");
        } else {
            System.out.println("El fichero se cifrado correctamente");
        }

    }

    /**
     * Configura el objeto de descifrado y genera el fichero descifrado
     * @param fichero El nombre del fichero
     * @param contrasena La contraseña
     * @throws Exception
     */
    public static void processingDecipher(String fichero, String contrasena, int numIteraciones) throws Exception {
        Header h = new Header();
        FileInputStream fis = new FileInputStream(fichero);
        if (h.load(fis)) {
            String algoritmoCifrado = h.getAlgorithm1();
            byte[] salt = h.getData();
            Options confAlgoritmo = new Options();
            confAlgoritmo.setCipherAlgorithm(algoritmoCifrado);
            Cipher c = Cipher.getInstance(algoritmoCifrado);
            SecretKey sKey = generacionClaveSesion(contrasena, algoritmoCifrado);
            PBEParameterSpec pPS = new PBEParameterSpec(salt, numIteraciones);
            c.init(Cipher.DECRYPT_MODE, sKey, pPS);

            if(!escribirFicheroDescifrado(c, fichero,fis)) {
                System.out.println("Error al descifrar el fichero");
            } else {
                System.out.println("El fichero se ha descifrado correctamente");
            }
        }


    }


    /**
     * Comprueba si una contraseña es segura
     *
     * @param contrasena Contraseña a comprobar
     * @return boolean True si la contraseña es segura, false en caso contrario
     */
    public static boolean contrasenaSegura(String contrasena) {

        return contrasena.length() >= 8;
    }

    /**
     * Solicita una contraseña segura por teclado, y solicita de nuevo la contraseña
     *
     * @return La contraseña introducida por el usuario
     */
    public static String solicitarContrasena() {
        String contrasena = "";
        while (!contrasenaSegura(contrasena)) {
            contrasena = leerTeclado("Introduce la contraseña: ");
        }
        String repetida = "";
        while (!contrasena.equals(repetida)) {
            repetida = leerTeclado("Repite la primera contraseña: ");
        }
        return contrasena;
    }
}