package Actividad3;

import Actividad2.PasswordStrength;
import librerias.Options;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;

import static Actividad2.PBEActivity.calcularHash;
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

    private FileProtectorMac protector = new FileProtectorMac();

    // Variables de configuración seleccionada
    private String algoritmoCifrado = Options.cipherAlgorithms[1];
    private String algoritmoHash = Options.hashAlgorithms[1];
    private String algoritmoHMAC = Options.macAlgorithms[0];
    private File actualPath = new File(System.getProperty("user.dir"));

    /**
     * Constructor de la interfaz principal. Configura la ventana principal,
     * inicializa los paneles de pestañas para cada funcionalidad y hace visible la interfaz.
     */
    public MainGUI() {
        setTitle("Protección de Archivos - SRT");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 500);
        setLocationRelativeTo(null);

        JTabbedPane tabs = new JTabbedPane();

        tabs.add("Cifrado / Descifrado", crearPanelCifrado());
        tabs.add("Hash", crearPanelHash());
        tabs.add("HMAC", crearPanelHMAC());
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
                Actividad2.PBEActivity.processingCipher(input, pass, algoritmo, it, hash);
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
                if (Actividad2.PBEActivity.verifyPasswordHash(input, hash)) {
                    Actividad2.PBEActivity.processingDecipher(input, pass, it);
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
     * Crea el panel correspondiente a la pestaña de HASH.
     * Permite aplicar y verificar un resumen hash sobre un archivo dado,
     * empleando una contraseña y mostrando su fortaleza.
     *
     * @return JPanel con controles de resumen hash.
     */
    private JPanel crearPanelHash() {
        // Se crea un nuevo panel con disposición en cuadrícula
        JPanel panel = new JPanel(new GridLayout(6, 1));

        // Label para mostrar la ruta del archivo seleccionado
        JLabel rutaArchivoLabel = new JLabel("Ningún archivo seleccionado");
        // Botón para abrir el explorador de archivos y seleccionar uno
        JButton btnSeleccionarArchivo = new JButton("Seleccionar archivo");

        // Campo de texto para escribir el nombre del archivo de salida
        JTextField output = new JTextField();
        // Campo para introducir la contraseña del usuario
        JTextField pass = new JTextField();

        // Label y barra para mostrar la fortaleza de la contraseña introducida
        JLabel fuerzaLabel = new JLabel("Fortaleza de la contraseña: ");
        JProgressBar barraFuerza = new JProgressBar(0, 3);
        barraFuerza.setValue(0);
        barraFuerza.setStringPainted(true);

        // Botones para aplicar el hash y para verificar el hash del archivo
        JButton aplicar = new JButton("Aplicar HASH");
        JButton verificar = new JButton("Verificar HASH");

        // Listener para detectar los cambios en el campo de contraseña y actualizar la fortaleza visualmente
        pass.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void changedUpdate(javax.swing.event.DocumentEvent e) { actualizarFuerza(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { actualizarFuerza(); }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { actualizarFuerza(); }

            // Función personalizada que evalúa la fortaleza de la contraseña y actualiza el label y la barra
            public void actualizarFuerza() {
                String pwd = pass.getText();
                if (pwd.isEmpty()) {
                    fuerzaLabel.setText("Fortaleza de la contraseña: ");
                    barraFuerza.setValue(0);
                    barraFuerza.setForeground(Color.GRAY);
                    return;
                }

                int strength = PasswordStrength.calculateStrength(pwd);
                String nivel;
                Color color;

                // Según el resultado de la evaluación, asignamos una etiqueta de nivel y color a la barra
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

        // Acción que se realiza al pulsar el botón de seleccionar archivo
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

        // Acción que se realiza al pulsar el botón "Aplicar HASH"
        aplicar.addActionListener(e -> {
            int strength = PasswordStrength.calculateStrength(pass.getText());
            // Se bloquea la acción si la contraseña es demasiado débil
            if (strength == 0) {
                mostrar("❌ La contraseña es demasiado débil.\nNo se permite descifrar con contraseñas tan inseguras.");
                return;
            }

            try {
                // Se aplica el resumen HASH al archivo seleccionado
                String alg = algoritmoHash;
                protector.applyHash(rutaArchivoLabel.getText(), output.getText(), pass.getText(), alg);
                mostrar("Archivo resumido correctamente.");
            } catch (Exception ex) {
                mostrar("Error: " + ex.getMessage());
            }
        });

        // Acción que se realiza al pulsar el botón "Verificar HASH"
        verificar.addActionListener(e -> {
            int strength = PasswordStrength.calculateStrength(pass.getText());
            // Se bloquea la verificación si la contraseña es débil
            if (strength == 0) {
                mostrar("❌ La contraseña es demasiado débil.\nNo se permite descifrar con contraseñas tan inseguras.");
                return;
            }

            try {
                // Se verifica que el resumen hash del archivo coincida
                String alg = algoritmoHash;
                boolean ok = protector.verifyHash(rutaArchivoLabel.getText(), output.getText(), pass.getText(), alg);

                if (ok) {
                    JOptionPane.showMessageDialog(this,
                            "✅ El resumen coincide.\nEl documento no ha sido modificado.",
                            "Verificación Exitosa",
                            JOptionPane.INFORMATION_MESSAGE
                    );
                } else {
                    JOptionPane.showMessageDialog(this,
                            "❌ El resumen NO coincide.\nEs posible que el documento haya sido modificado o la contraseña no coincida.",
                            "Verificación Fallida",
                            JOptionPane.ERROR_MESSAGE
                    );
                }
            } catch (Exception ex) {
                mostrar("Error: " + ex.getMessage());
            }
        });

        // Se añaden todos los componentes al panel en orden de disposición
        panel.add(new JLabel("Archivo:")); panel.add(btnSeleccionarArchivo);
        panel.add(new JLabel("Archivo seleccionado:")); panel.add(rutaArchivoLabel);
        panel.add(new JLabel("Salida:")); panel.add(output);
        panel.add(new JLabel("Contraseña:")); panel.add(pass);
        panel.add(fuerzaLabel);
        panel.add(barraFuerza);
        panel.add(aplicar); panel.add(verificar);

        return panel;
    }


    /**
     * Crea el panel correspondiente a la pestaña de HMAC.
     * Permite aplicar/verificar códigos de autenticación de mensaje (HMAC)
     * usando una contraseña segura y un algoritmo configurable.
     *
     * @return JPanel con controles de HMAC.
     */
    private JPanel crearPanelHMAC() {
        // Se crea el panel principal con una cuadrícula vertical de 6 filas
        JPanel panel = new JPanel(new GridLayout(6, 1));

        // Label para mostrar la ruta del archivo seleccionado
        JLabel rutaArchivoLabel = new JLabel("Ningún archivo seleccionado");

        // Botón que permite seleccionar un archivo del sistema de archivos
        JButton btnSeleccionarArchivo = new JButton("Seleccionar archivo");

        // Acción que se ejecuta al pulsar el botón de seleccionar archivo
        btnSeleccionarArchivo.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser(actualPath);
            fileChooser.setDialogTitle("Seleccionar archivo de entrada");
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int resultado = fileChooser.showOpenDialog(this);
            if (resultado == JFileChooser.APPROVE_OPTION) {
                File archivo = fileChooser.getSelectedFile();
                // Se actualiza la etiqueta con la ruta del archivo seleccionado
                rutaArchivoLabel.setText(archivo.getAbsolutePath());
            }
        });

        // Campo para especificar el archivo de salida donde se almacenará el resultado del HMAC
        JTextField output = new JTextField();
        // Campo para introducir la contraseña utilizada para generar/verificar el HMAC
        JTextField pass = new JTextField();

        // Elementos para mostrar la fortaleza de la contraseña
        JLabel fuerzaLabel = new JLabel("Fortaleza de la contraseña: ");
        JProgressBar barraFuerza = new JProgressBar(0, 3);
        barraFuerza.setValue(0);
        barraFuerza.setStringPainted(true);

        // Botones para aplicar y verificar el HMAC
        JButton aplicar = new JButton("Aplicar HMAC");
        JButton verificar = new JButton("Verificar HMAC");

        // Acción que se ejecuta al pulsar el botón "Aplicar HMAC"
        aplicar.addActionListener(e -> {
            int strength = PasswordStrength.calculateStrength(pass.getText());

            // Se impide aplicar HMAC si la contraseña es demasiado débil
            if (strength == 0) {
                mostrar("❌ La contraseña es demasiado débil.\nNo se permite descifrar con contraseñas tan inseguras.");
                return;
            }

            try {
                // Se obtiene el algoritmo HMAC desde la configuración actual
                String alg = algoritmoHMAC;

                // Se aplica HMAC al archivo utilizando la contraseña y el algoritmo configurado
                protector.applyHMAC(rutaArchivoLabel.getText(), output.getText(), pass.getText(), alg);
                mostrar("Archivo resumido correctamente.");
            } catch (Exception ex) {
                mostrar("Error: " + ex.getMessage());
            }
        });

        // Acción que se ejecuta al pulsar el botón "Verificar HMAC"
        verificar.addActionListener(e -> {
            int strength = PasswordStrength.calculateStrength(pass.getText());

            // Se impide verificar HMAC si la contraseña es demasiado débil
            if (strength == 0) {
                mostrar("❌ La contraseña es demasiado débil.\nNo se permite descifrar con contraseñas tan inseguras.");
                return;
            }

            try {
                // Se obtiene el algoritmo HMAC desde la configuración actual
                String alg = algoritmoHMAC;

                // Se verifica que el HMAC generado con la contraseña coincida con el existente
                boolean ok = protector.verifyHMAC(rutaArchivoLabel.getText(), output.getText(), pass.getText(), alg);

                // Mensaje visual según si el resumen HMAC coincide o no
                if (ok) {
                    JOptionPane.showMessageDialog(this,
                            "✅ El resumen coincide.\nEl documento no ha sido modificado.",
                            "Verificación Exitosa",
                            JOptionPane.INFORMATION_MESSAGE
                    );
                } else {
                    JOptionPane.showMessageDialog(this,
                            "❌ El resumen NO coincide.\nEs posible que el documento haya sido modificado o la contraseña no coincida.",
                            "Verificación Fallida",
                            JOptionPane.ERROR_MESSAGE
                    );
                }
            } catch (Exception ex) {
                mostrar("Error: " + ex.getMessage());
            }
        });

        // Listener para evaluar la fortaleza de la contraseña conforme se escribe
        pass.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void changedUpdate(javax.swing.event.DocumentEvent e) { actualizarFuerza(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { actualizarFuerza(); }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { actualizarFuerza(); }

            // Función que actualiza el label y la barra de progreso según la fuerza de la contraseña
            public void actualizarFuerza() {
                String pwd = pass.getText();
                if (pwd.isEmpty()) {
                    fuerzaLabel.setText("Fortaleza de la contraseña: ");
                    barraFuerza.setValue(0);
                    barraFuerza.setForeground(Color.GRAY);
                    return;
                }

                int strength = PasswordStrength.calculateStrength(pwd);
                String nivel;
                Color color;

                // Se asigna un nivel y color según el valor de fuerza obtenido
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

        // Se añaden todos los elementos al panel en orden
        panel.add(new JLabel("Archivo:")); panel.add(btnSeleccionarArchivo);
        panel.add(new JLabel("Archivo seleccionado:")); panel.add(rutaArchivoLabel);
        panel.add(new JLabel("Salida:")); panel.add(output);
        panel.add(new JLabel("Contraseña:")); panel.add(pass);
        panel.add(fuerzaLabel);
        panel.add(barraFuerza);
        panel.add(aplicar); panel.add(verificar);

        return panel;
    }
    /**
     * Crea el panel de configuración de algoritmos.
     * Permite al usuario seleccionar los algoritmos usados en cada operación:
     * cifrado, hash, HMAC
     *
     * @return JPanel con opciones de configuración criptográfica.
     */
    private JPanel crearPanelConfiguracion() {
        // Se crea el panel con un layout de 6 filas verticales
        JPanel panel = new JPanel(new GridLayout(6, 1));

        // ======== Configuración del algoritmo de Cifrado ========

        // Etiqueta descriptiva para el combo de cifrado
        JLabel labelCifrado = new JLabel("Algoritmo de Cifrado:");

        // Desplegable con los algoritmos disponibles en Options.cipherAlgorithms
        JComboBox<String> comboCifrado = new JComboBox<>(Options.cipherAlgorithms);

        // Se selecciona el algoritmo previamente configurado como valor por defecto
        comboCifrado.setSelectedItem(algoritmoCifrado);

        // Acción que se ejecuta al cambiar la opción seleccionada: se actualiza la variable global
        comboCifrado.addActionListener(e -> algoritmoCifrado = (String) comboCifrado.getSelectedItem());


        // ======== Configuración del algoritmo de Hash ========

        // Etiqueta descriptiva para el combo de hash
        JLabel labelHash = new JLabel("Algoritmo de Hash:");

        // Desplegable con los algoritmos disponibles en Options.hashAlgorithms
        JComboBox<String> comboHash = new JComboBox<>(Options.hashAlgorithms);

        // Se selecciona el algoritmo de hash previamente definido
        comboHash.setSelectedItem(algoritmoHash);

        // Acción que se ejecuta al cambiar la opción de hash: se actualiza la variable global
        comboHash.addActionListener(e -> algoritmoHash = (String) comboHash.getSelectedItem());


        // ======== Configuración del algoritmo de HMAC ========

        // Etiqueta descriptiva para el combo de HMAC
        JLabel labelHmac = new JLabel("Algoritmo de HMAC:");

        // Desplegable con los algoritmos disponibles en Options.macAlgorithms
        JComboBox<String> comboHmac = new JComboBox<>(Options.macAlgorithms);

        // Se selecciona el algoritmo HMAC previamente definido
        comboHmac.setSelectedItem(algoritmoHMAC);

        // Acción que se ejecuta al cambiar la opción de HMAC: se actualiza la variable global
        comboHmac.addActionListener(e -> algoritmoHMAC = (String) comboHmac.getSelectedItem());


        panel.add(labelCifrado);
        panel.add(comboCifrado);
        panel.add(labelHash);
        panel.add(comboHash);
        panel.add(labelHmac);
        panel.add(comboHmac);

        // Se retorna el panel completo
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





