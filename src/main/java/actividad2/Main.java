package actividad2;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean continuar = true;

        while (continuar) {
            System.out.println("Seleccione una opción:");
            System.out.println("1. Cifrar un archivo");
            System.out.println("2. Descifrar un archivo");
            System.out.println("3. Salir");
            System.out.print("Opción: ");
            int opcion = scanner.nextInt();
            scanner.nextLine();

            switch (opcion) {
                case 1:
                    procesarCifrado(scanner);
                    break;
                case 2:
                    procesarDescifrado(scanner);
                    break;
                case 3:
                    continuar = false;
                    break;
                default:
                    System.out.println("Opción no válida, intente de nuevo.");
            }
        }
        scanner.close();
    }

    private static void procesarCifrado(Scanner scanner) {
        System.out.print("Ingrese la ruta del archivo a cifrar: ");
        String rutaArchivo = scanner.nextLine();
        String contrasena;
        do {
            System.out.print("Ingrese la contraseña de cifrado: ");
            contrasena = scanner.nextLine();
            evaluarSeguridadContrasena(contrasena);
        } while (contrasena.length() < 8);

        System.out.print("Número de iteraciones (ej. 1000): ");
        int iteraciones = scanner.nextInt();
        scanner.nextLine();

        String algoritmo = CifradoOriginal.solicitarAlgoritmoCifrado();

        try {
            PBEActivity.processingCipher(rutaArchivo, contrasena, algoritmo, iteraciones);
        } catch (Exception e) {
            System.out.println("Error al cifrar el archivo: " + e.getMessage());
        }
    }

    private static void procesarDescifrado(Scanner scanner) {
        System.out.print("Ingrese la ruta del archivo a descifrar: ");
        String rutaArchivo = scanner.nextLine();
        String contrasena;
        do {
            System.out.print("Ingrese la contraseña de descifrado: ");
            contrasena = scanner.nextLine();
            evaluarSeguridadContrasena(contrasena);
        } while (contrasena.length() < 8);

        System.out.print("Número de iteraciones (ej. 1000): ");
        int iteraciones = scanner.nextInt();
        scanner.nextLine();

        try {
            PBEActivity.processingDecipher(rutaArchivo, contrasena, iteraciones);
        } catch (Exception e) {
            System.out.println("Error al descifrar el archivo: " + e.getMessage());
        }
    }

    private static void evaluarSeguridadContrasena(String contrasena) {
        if (contrasena.length() < 8) {
            System.out.println("[Débil] La contraseña debe tener al menos 8 caracteres.");
        } else if (!contrasena.matches(".*[A-Z].*") || !contrasena.matches(".*\\d.*")) {
            System.out.println("[Media] Agrega mayúsculas y números para mayor seguridad.");
        } else {
            System.out.println("[Fuerte] La contraseña es segura.");
        }
    }

    private static byte[] calcularHash(String contrasena) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(contrasena.getBytes(StandardCharsets.UTF_8));
            return Arrays.copyOf(hash, 2); // Usamos solo los primeros 2 bytes
        } catch (Exception e) {
            throw new RuntimeException("Error al calcular hash de la contraseña", e);
        }
    }
}

