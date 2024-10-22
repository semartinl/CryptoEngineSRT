package algoritmos;

import java.io.*;
import java.security.SecureRandom;
import java.security.Security;
import java.util.List;
import java.util.ArrayList;
import librerias.*;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider; 

// C:\\Users\\celia\\eclipse-workspace-pbd\\cryptoEngineSRT\\src\\algoritmos\\documento.txt

public class Main{
    
    public static void main(String[] args) throws Exception {
        
        //Se añade como proveedor de los servicios de seguridad, la librería de Bouncy Castle. Si no, no reconoce aquellas funciones de esta
        Security.addProvider(new BouncyCastleProvider());
        
        //Se pide al usuario si quiere cifrar o descifrar
        boolean esCifrado = elegirCifradoDescifrado();
        
        //Se pide al usuario el algoritmo de cifrado
        String algoritmoCifrado = solicitarAlgoritmoCifrado();
        
        


        //CONFIGURACIÓN DE LOS ALGORITMOS DE CIFRADO
        Cipher c = configuracionAlgoritmo(esCifrado,algoritmoCifrado);
        
        String ubicacionFichero = "C:\\Users\\celia\\eclipse-workspace-pbd\\cryptoEngineSRT\\src\\algoritmos\\documento.txt";

        CipherOutputStream cos = escribirFicheroSalida(c,ubicacionFichero);

        System.out.println(c.doFinal());
        
    }


    /**
     * Devuelve true si se va a cifrar, false si se va a descifrar
     * @return boolean true si se va a cifrar, false si se va a descifrar
     */
    static boolean elegirCifradoDescifrado() {
        boolean esCifrado = false;
        char eleccionCifrado = leerTeclado("¿Desea cifrar o descifrar? (C/E): ").charAt(0);
        while(!eleccionCifradoValida(eleccionCifrado)){
            eleccionCifrado = leerTeclado("Elige un valor válido (C/E): ").charAt(0);
        }
        if (esCifrado(eleccionCifrado)){
            esCifrado = true;
        }
        return esCifrado;
    }
    
    /**
     * Muestra las distintas opciones de algoritmos de cifrado y devuelve el elegido
     * @return String Algoritmo de cifrado elegido
     */
    static String solicitarAlgoritmoCifrado () {
        int alCifrado = -1;
        while (alCifrado < 0 || alCifrado >= Options.cipherAlgorithms.length) {
            for (int i = 0; i<Options.cipherAlgorithms.length; i++) {
                System.out.println(Options.cipherAlgorithms[i]);
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
    static boolean eleccionCifradoValida(char eleccionCifrado){
        return esCifrado(eleccionCifrado) || esDescifrado(eleccionCifrado);
    }

    /**
     * Devuelve si el caracter introducido es una elección de cifrado (C o c)
     * @param eleccionCifrado Caracter introducido por el usuario
     * @return boolean true si es una elección de cifrado, false en caso contrario
     */
    static boolean esCifrado(char eleccionCifrado){
        return eleccionCifrado == 'C' || eleccionCifrado == 'c';
    }

    /**
     * Devuelve si el caracter introducido es una elección de cifrado (C o c)
     * @param eleccionCifrado Caracter introducido por el usuario
     * @return boolean true si es una elección de cifrado, false en caso contrario
     */
    static boolean esDescifrado(char eleccionDescifrado){
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
     * Crea un fichero de salida, dado su nombre y un objeto de cifrado inicializado
     * @param c Objeto de cifrado inicializado
     * @param archivo Nombre del archivo a cifrar
     * @throws FileNotFoundException Si no se encuentra el archivo
     * @throws IOException Si hay un error al leer el archivo
     * @throws Exception Si hay un error al cifrar el archivo
     */
    public static CipherOutputStream escribirFicheroSalida (Cipher c, String archivo) throws FileNotFoundException, IOException {
        String salida = archivo+".cif";
        
        FileOutputStream fos = new FileOutputStream(salida); // Abre el flujo de salida desde un fichero
        OutputStream os = new BufferedOutputStream(fos); // Abre el flujo de salida desde un buffer
        CipherOutputStream cos = new CipherOutputStream(os,c); // Abre el flujo de salida cifrado

        FileReader f = new FileReader(archivo); // Lee el archivo
        BufferedReader b = new BufferedReader(f); // Para poder iterar sobre el archivo
        
        String cadena = b.readLine();

        while(cadena!=null) {
            cos.write(cadena.getBytes()); // Escribe en el flujo de salida cifrado
            cadena = b.readLine();
        }

        os.close();
        fos.close();
        f.close();
        b.close();
        // cos.close();

        return cos;
    }

    public static void crearFicheroGenera (Cipher c, String archivo) throws FileNotFoundException, IOException {
        InputStream os = new BufferedInputStream(System.in);

        CipherInputStream cos = new CipherInputStream(os,c);

        // while true {

        // // TODO

        // read(buffer);

        // cos.write(buffer);

        // // TODO


        // }
        String cadena;
        FileWriter f = new FileWriter("archivoGenerado"); // Leer el archivo
        BufferedReader b = new BufferedReader(f); // Para poder iterar sobre el archivo
        while((cadena = b.readLine())!=null) {
            System.out.println(cadena);
            // TODO: Procesar la cadena
        }
        b.close();
    }


    

    /**
     * Genera una clave de sesión a partir de una contraseña y un algoritmo
     * @param contrasena Contraseña a partir de la cual se generará la clave de sesión
     * @param algoritmo Algoritmo con el que se generará la clave de sesión
     * @return SecretKey Clave de sesión generada
     * @throws Exception Si el algoritmo no existe o si la clave generada no es válida
     */
    public static SecretKey generacionClaveSesion(String contrasena, String algoritmo) throws Exception{
        System.out.println("GENERANDO CLAVE DE SESION");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(contrasena.toCharArray());

        SecretKeyFactory kf = SecretKeyFactory.getInstance(algoritmo);

        SecretKey sKey = kf.generateSecret(pbeKeySpec);
        return sKey;

    }
    
    /**
     * Configura el algoritmo de cifrado
     * @param esCifrado True si se va a cifrar, false si se va a descifrar
     * @param algoritmoCifrado Algoritmo de cifrado a utilizar
     * @return Cipher Algoritmo de cifrado configurado
     * @throws Exception Si el algoritmo no existe
     */
    public static Cipher configuracionAlgoritmo(boolean esCifrado, String algoritmoCifrado) throws Exception{
        String contrasena = leerTeclado("Introduce la contraseña: ");

        int numIteraciones = leerIntegerTeclado("Introduce el número de iteraciones que desea que haga el algoritmo: ");

        Options confAlgoritmo = new Options();
        confAlgoritmo.setCipherAlgorithm(algoritmoCifrado);
        System.out.println("Conseguir algoritmo de cifrado: instancia");
        Cipher c = Cipher.getInstance(algoritmoCifrado);

        SecureRandom random = SecureRandom.getInstance("DEFAULT", "BC");
        byte[] salt = random.generateSeed(8);

        PBEParameterSpec pPS = new PBEParameterSpec(salt,numIteraciones);
        SecretKey sKey = generacionClaveSesion(contrasena, algoritmoCifrado);
        if(esCifrado)
            c.init(Cipher.ENCRYPT_MODE,sKey,pPS);
        else
            c.init(Cipher.DECRYPT_MODE,sKey,pPS);
            
        

        return c;
    }

    /**
     * Comprueba si una contraseña es segura
     * @param contrasena Contraseña a comprobar
     * @return boolean True si la contraseña es segura, false en caso contrario
     */
    public static boolean contrasenaSegura(String contrasena){
        
        return contrasena.length() >= 8;
    }
}