package actividad2;
/**
 * Clase de utilidad para evaluar la fortaleza de contraseñas.
 *
 * Proporciona un método estático que analiza características comunes de seguridad en contraseñas,
 * como longitud, presencia de mayúsculas, dígitos y caracteres especiales, devolviendo un nivel
 * de fuerza entre 0 (muy débil) y 3 (fuerte).
 *
 * Puede integrarse fácilmente en interfaces gráficas o lógicas de validación de contraseñas.
 *
 * @author Sergio Martín Ledesma
 */
public class PasswordStrength {

    /**
     * Calcula la fortaleza de una contraseña de 0 (muy débil) a 3 (fuerte).
     *
     * @param password Contraseña a evaluar
     * @return 0 (débil), 1 (media), 2 (fuerte), 3 (muy fuerte)
     */
    public static int calculateStrength(String password) {
        // Inicializa el contador de puntuación
        int score = 0;

        // +1 si la longitud de la contraseña es al menos 8 caracteres
        if (password.length() >= 8) {
            score++;
            // +1 si contiene al menos una letra mayúscula
            if (password.matches(".*[A-Z].*")) score++;

            // +1 si contiene al menos un número
            if (password.matches(".*[0-9].*")) score++;

            // +1 si contiene al menos un símbolo especial
            if (password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) score++;

            // +1 adicional si la longitud es mayor o igual a 12 y tiene buena variedad
            if (password.length() >= 12 && score >= 3) score++;
        }



        // Se limita el valor máximo a 3 para normalizar la salida
        return Math.min(score, 3);
    }
}