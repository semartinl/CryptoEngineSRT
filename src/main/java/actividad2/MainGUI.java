package actividad2;

import Resumen_hash.FileProtectorMac;
import librerias.Options;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;


import static actividad2.PBEActivity.calcularHash;
/**
 * Clase principal que representa la interfaz gráfica de usuario (GUI) para la aplicación
 * de protección de archivos. Integra funcionalidades como cifrado, hash, HMAC, firma digital,
 * generación de claves, y gestión de almacenes KeyStore.
 *
 * Esta aplicación permite a los usuarios proteger archivos mediante distintos algoritmos
 * criptográficos configurables a través de pestañas y componentes Swing.
 *
 * @author Sergio Martin Ledesma
 */
public class MainGUI extends JFrame{

    // Variable para seleccionar el algoritmo de cifrado en la aplicación
    private String algoritmoCifrado = Options.cipherAlgorithms[1];
    //Variable para conseguir la dirección absoluta del proyecto para abrir la ventana de seleccion de arhivos en dicho directorio.
    private File actualPath = new File(System.getProperty("user.dir"));

    /**
     * Constructor de la interfaz principal. Configura la ventana principal,
     * inicializa los paneles de pestañas para cada funcionalidad y hace visible la interfaz.
     */
    public MainGUI() {
        //Se selecciona título
        setTitle("Protección de Archivos - SRT");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 500);
        setLocationRelativeTo(null);

        JTabbedPane tabs = new JTabbedPane();

        //Se añade el apartado de Cifrado/Descifrado al menu principal
        tabs.add("Cifrado / Descifrado", crearPanelCifrado());
        //Se añade el apartado de Configuración al menu principal
        tabs.add("Configuración", crearPanelConfiguracion());

        add(tabs);
        setVisible(true);
    }
    /**
     * Crea el panel correspondiente a la pestaña de Cifrado/Descifrado simétrico.
     * Permite cifrar o descifrar archivos con contraseña, mostrando además la fortaleza
     * de la contraseña introducida.
     *
     * @return JPanel con todos los controles de cifrado simétrico.
     */
    private JPanel crearPanelCifrado() {
        JPanel panel = new JPanel(new GridLayout(7, 1));

        //Variables e input referentes a la fortaleza de la contraseña
        JLabel fuerzaLabel = new JLabel("Fortaleza de la contraseña: ");
        JProgressBar barraFuerza = new JProgressBar(0, 3);
        barraFuerza.setValue(0);
        barraFuerza.setStringPainted(true);

        //Label y botón para seleccionar el archivo.
        JLabel rutaArchivoLabel = new JLabel("Ningún archivo seleccionado");
        JButton btnSeleccionarArchivo = new JButton("Seleccionar archivo");
        //Campo para la contraseña
        JTextField password = new JTextField();
        //Campo para seleccionar las iteraciones del algoritmo.
        JTextField iteraciones = new JTextField("1000");

        //Botón para cifrar y descifrar archivo
        JButton btnCifrar = new JButton("Cifrar archivo");
        JButton btnDescifrar = new JButton("Descifrar archivo");

        //Acción que se realiza al dar al botón de Seleccionar archivo. Se actualiza la variable "rutaArchivoLabel".

        btnSeleccionarArchivo.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser(actualPath);
            fileChooser.setDialogTitle("Seleccionar archivo de entrada");
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int resultado = fileChooser.showOpenDialog(this);
            if (resultado == JFileChooser.APPROVE_OPTION) {
                File archivo = fileChooser.getSelectedFile();
                rutaArchivoLabel.setText(archivo.getAbsolutePath());
            }
        });

        //Acción que se realiza al dar al botón de cifrar.
        btnCifrar.addActionListener((ActionEvent e) -> {
            String input = rutaArchivoLabel.getText();
            String pass = password.getText();
            int it = Integer.parseInt(iteraciones.getText());

            int strength = PasswordStrength.calculateStrength(pass);
            if (strength == 0) {
                mostrar("❌ La contraseña es demasiado débil.\nNo se permite descifrar con contraseñas tan inseguras.");
                return;
            }

            try {
                byte[] hash = calcularHash(pass);
                String algoritmo = algoritmoCifrado;
                actividad2.PBEActivity.processingCipher(input, pass, algoritmo, it, hash);
                mostrar("Archivo cifrado correctamente.");
            } catch (Exception ex) {
                mostrar("Error: " + ex.getMessage());
            }
        });

        //Acción que se realiza al dar al botón de Descifrar.
        btnDescifrar.addActionListener((ActionEvent e) -> {
            String input = rutaArchivoLabel.getText();
            String pass = password.getText();
            int it = Integer.parseInt(iteraciones.getText());

            int strength = PasswordStrength.calculateStrength(pass);
            if (strength == 0) {
                mostrar("❌ La contraseña es demasiado débil.\nNo se permite descifrar con contraseñas tan inseguras.");
                return;
            }

            try {
                byte[] hash = calcularHash(pass);
                if (actividad2.PBEActivity.verifyPasswordHash(input, hash)) {
                    actividad2.PBEActivity.processingDecipher(input, pass, it);
                    mostrar("Archivo descifrado correctamente.");
                } else {
                    mostrar("Contraseña incorrecta.");
                }
            } catch (Exception ex) {
                mostrar("Error: " + ex.getMessage());
            }
        });

        //Listener para la fuerza de la contraseña. Se llamada a la función "actualizarFuerza" cada vez que se realiza un cambio en el campo de la contraseña.
        password.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void changedUpdate(javax.swing.event.DocumentEvent e) { actualizarFuerza(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { actualizarFuerza(); }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { actualizarFuerza(); }

            //Función personalizada para cambiar el label de la contraseña.
            public void actualizarFuerza() {
                String pwd = password.getText();
                if (pwd.isEmpty()) {
                    fuerzaLabel.setText("Fortaleza de la contraseña: ");
                    barraFuerza.setValue(0);
                    barraFuerza.setForeground(Color.GRAY);
                    return;
                }

                int strength = PasswordStrength.calculateStrength(pwd);

                String nivel;
                Color color;

                switch (strength) {
                    case 0: nivel = "Muy débil 🔴"; color = Color.RED; break;
                    case 1: nivel = "Media 🟠"; color = Color.ORANGE; break;
                    case 2: nivel = "Buena 🟡"; color = Color.YELLOW; break;
                    case 3: nivel = "Fuerte 🟢"; color = Color.GREEN; break;
                    default: nivel = "Desconocido"; color = Color.GRAY;
                }

                fuerzaLabel.setText("Fortaleza de la contraseña: " + nivel);
                barraFuerza.setValue(strength);
                barraFuerza.setForeground(color);
            }
        });

        //Label para seleccionar el archivo
        panel.add(new JLabel("Archivo:")); panel.add(btnSeleccionarArchivo);
        //Label para mostrar el archivo mostrado
        panel.add(new JLabel("Archivo seleccionado:")); panel.add(rutaArchivoLabel);
        //Label para la contraseña
        panel.add(new JLabel("Contraseña:")); panel.add(password);
        //Labels para la fortaleza de la contraseña
        panel.add(fuerzaLabel); panel.add(barraFuerza);
        //Label para las iteraciones
        panel.add(new JLabel("Iteraciones:")); panel.add(iteraciones);
        //Botones para cifrar y descifrar
        panel.add(btnCifrar); panel.add(btnDescifrar);
        return panel;
    }

    /**
     * Crea el panel de configuración de algoritmos.
     * Permite al usuario seleccionar los algoritmos usados en cada operación:
     * cifrado
     *
     * @return JPanel con opciones de configuración criptográfica.
     */
    private JPanel crearPanelConfiguracion() {
        JPanel panel = new JPanel(new GridLayout(6, 1));

        // Cifrado
        JLabel labelCifrado = new JLabel("Algoritmo de Cifrado:");
        JComboBox<String> comboCifrado = new JComboBox<>(librerias.Options.cipherAlgorithms);
        comboCifrado.setSelectedItem(algoritmoCifrado);
        comboCifrado.addActionListener(e -> algoritmoCifrado = (String) comboCifrado.getSelectedItem());

        panel.add(labelCifrado);
        panel.add(comboCifrado);
        return panel;
    }
    /**
     * Muestra un mensaje emergente al usuario.
     *
     * @param mensaje El mensaje que se desea mostrar.
     */
    private void mostrar(String mensaje) {
        JOptionPane.showMessageDialog(this, mensaje);
    }
    /**
     * Método principal de la aplicación.
     * Lanza la interfaz gráfica en el hilo de eventos de Swing.
     *
     * @param args Argumentos de línea de comandos (no utilizados).
     */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(MainGUI::new);
    }
}





