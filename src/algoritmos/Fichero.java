package algoritmos;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException; 


public class Fichero {
    public static void muestraContenido(String archivo) throws FileNotFoundException, IOException {
        String cadena;
        FileReader f = new FileReader(archivo); // Leer el archivo
        BufferedReader b = new BufferedReader(f); // Para poder iterar sobre el archivo
        while((cadena = b.readLine())!=null) {
            System.out.println(cadena);
            // TODO: Procesar la cadena
        }
        b.close();
    }
}
