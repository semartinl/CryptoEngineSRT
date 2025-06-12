package Actividad4;

import Actividad3.FileProtectorMac;
import Actividad2.PasswordStrength;
import librerias.Options;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static Actividad2.PBEActivity.calcularHash;

public class MainGUI extends JFrame{
    private FileProtectorMac protector = new FileProtectorMac();

    // Variables de configuración seleccionada
    private String algoritmoCifrado = Options.cipherAlgorithms[1];
    private String algoritmoHash = Options.hashAlgorithms[1];
    private String algoritmoHMAC = Options.macAlgorithms[0];
    private String algoritmoFirma = Options.signAlgorithms[1];
    private KeyPair currentKeyPair = null;
    private File actualPath = new File(System.getProperty("user.dir"));

    //Variables para la craeciónd e un par de claves
    private final String[] tiposClave = {"RSA", "DSA"};
    private final String[] tamanosClave = {"512", "768", "1024"};

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
        tabs.add("Asimétrico", crearPanelAsimetrico());
        tabs.add("Generar Claves", crearPanelGenerarClaves());
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
     * cifrado, hash, HMAC y firma digital.
     *
     * @return JPanel con opciones de configuración criptográfica.
     */
    private JPanel crearPanelConfiguracion() {
        // Se crea el panel con una cuadrícula vertical para mostrar las opciones
        JPanel panel = new JPanel(new GridLayout(6, 1));

        // ======== Configuración del algoritmo de Cifrado ========

        // Etiqueta descriptiva para el combo de algoritmos de cifrado
        JLabel labelCifrado = new JLabel("Algoritmo de Cifrado:");

        // Desplegable que contiene la lista de algoritmos de cifrado disponibles
        JComboBox<String> comboCifrado = new JComboBox<>(Options.cipherAlgorithms);

        // Se establece el algoritmo actualmente seleccionado en la aplicación
        comboCifrado.setSelectedItem(algoritmoCifrado);

        // Acción que actualiza la variable global cuando se selecciona un nuevo algoritmo
        comboCifrado.addActionListener(e -> algoritmoCifrado = (String) comboCifrado.getSelectedItem());


        // ======== Configuración del algoritmo de Hash ========

        // Etiqueta descriptiva para el combo de algoritmos de hash
        JLabel labelHash = new JLabel("Algoritmo de Hash:");

        // Desplegable que contiene los algoritmos hash disponibles
        JComboBox<String> comboHash = new JComboBox<>(Options.hashAlgorithms);

        // Se selecciona el algoritmo hash actual por defecto
        comboHash.setSelectedItem(algoritmoHash);

        // Se actualiza la variable global cuando se selecciona un nuevo algoritmo hash
        comboHash.addActionListener(e -> algoritmoHash = (String) comboHash.getSelectedItem());


        // ======== Configuración del algoritmo de HMAC ========

        // Etiqueta descriptiva para el combo de algoritmos HMAC
        JLabel labelHmac = new JLabel("Algoritmo de HMAC:");

        // Desplegable que contiene los algoritmos HMAC disponibles
        JComboBox<String> comboHmac = new JComboBox<>(Options.macAlgorithms);

        // Se selecciona el algoritmo HMAC actual como opción por defecto
        comboHmac.setSelectedItem(algoritmoHMAC);

        // Se actualiza la variable global cuando se elige un nuevo algoritmo HMAC
        comboHmac.addActionListener(e -> algoritmoHMAC = (String) comboHmac.getSelectedItem());


        // ======== Configuración del algoritmo de Firma Digital ========

        // Etiqueta descriptiva para el combo de algoritmos de firma
        JLabel labelFirma = new JLabel("Algoritmo de Firma:");

        // Desplegable que contiene los algoritmos de firma disponibles
        JComboBox<String> comboFirma = new JComboBox<>(Options.signAlgorithms);

        // Se selecciona el algoritmo de firma actualmente configurado
        comboFirma.setSelectedItem(algoritmoFirma);

        // Acción que actualiza la variable global al seleccionar otro algoritmo de firma
        comboFirma.addActionListener(e -> algoritmoFirma = (String) comboFirma.getSelectedItem());

        // ======== Añadir componentes al panel ========

        // Se agregan las etiquetas y combos en orden para formar el panel de configuración
        panel.add(labelCifrado);
        panel.add(comboCifrado);
        panel.add(labelHash);
        panel.add(comboHash);
        panel.add(labelHmac);
        panel.add(comboHmac);
        panel.add(labelFirma);
        panel.add(comboFirma);

        // Se devuelve el panel completo con todas las configuraciones
        return panel;
    }
    /**
     * Crea el panel de cifrado y firma asimétrica.
     * Permite al usuario seleccionar un par de claves y realizar operaciones
     * de cifrado, descifrado, firma digital y verificación.
     *
     * @return JPanel con controles de criptografía asimétrica.
     */
    private JPanel crearPanelAsimetrico() {
        // Se crea el panel con disposición de 9 filas y 2 columnas
        JPanel panel = new JPanel(new GridLayout(9, 2));

        // ======== Selección del archivo de entrada ========
        JLabel rutaArchivoLabel = new JLabel("Ningún archivo seleccionado");
        JButton btnSeleccionarArchivo = new JButton("Seleccionar archivo");

        // Acción al pulsar "Seleccionar archivo"
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

        // Campo de texto para especificar la ruta del archivo de salida o firma generada
        JTextField archivoSalida = new JTextField();

        // ======== Selección del archivo .key (par de claves) ========
        JLabel rutaClaveLabel = new JLabel("Ningún archivo seleccionado");
        JButton btnSeleccionarClave = new JButton("Seleccionar archivo .key");

        // Botones para operaciones criptográficas
        JButton btnCifrar = new JButton("Cifrar con clave pública");
        JButton btnDescifrar = new JButton("Descifrar con clave privada");
        JButton btnFirmar = new JButton("Firmar archivo");
        JButton btnVerificar = new JButton("Verificar firma");

        // Acción al pulsar "Seleccionar archivo .key"
        btnSeleccionarClave.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser(actualPath);
            fileChooser.setDialogTitle("Seleccionar archivo .key");
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int resultado = fileChooser.showOpenDialog(this);

            if (resultado == JFileChooser.APPROVE_OPTION) {
                File archivoKeyPair = fileChooser.getSelectedFile();
                rutaClaveLabel.setText(archivoKeyPair.getAbsolutePath());

                try {
                    // Se carga el par de claves desde el archivo seleccionado
                    currentKeyPair = DigitalSignature.loadKeyPairFromFile(archivoKeyPair.getAbsolutePath());
                    mostrar("Clave cargada correctamente.");
                } catch (Exception ex) {
                    mostrar("Error al cargar la clave: " + ex.getMessage());
                }
            }
        });

        // ======== Cifrado con clave pública ========
        btnCifrar.addActionListener(e -> {
            // Se verifica que el par de claves esté cargado
            if (currentKeyPair == null) {
                mostrar("⚠️ Debes cargar un par de claves primero.");
                return;
            }
            // Se impide cifrar si se ha cargado una clave DSA (no válida para cifrado)
            if ("DSA".equalsIgnoreCase(currentKeyPair.getPublic().getAlgorithm())) {
                JOptionPane.showMessageDialog(this,
                        "❌ No se puede cifrar archivos con claves de tipo DSA.\nUtiliza RSA.",
                        "Error de algoritmo",
                        JOptionPane.ERROR_MESSAGE
                );
                return;
            }
            try {
                // Se realiza el cifrado del archivo usando la clave pública y modo RSA
                Encryption.cifrarBloques(
                        rutaArchivoLabel.getText(),
                        archivoSalida.getText(),
                        currentKeyPair.getPublic(),
                        "RSA/ECB/PKCS1Padding"
                );
                mostrar("Archivo cifrado con clave pública.");
            } catch (Exception ex) {
                mostrar("Error al cifrar: " + ex.getMessage());
            }
        });

        // ======== Descifrado con clave privada ========
        btnDescifrar.addActionListener(e -> {
            // Se verifica que el par de claves esté cargado
            if (currentKeyPair == null) {
                mostrar("⚠️ Debes cargar un par de claves primero.");
                return;
            }
            // Se impide descifrar si se ha cargado una clave DSA (no válida para descifrado)
            if ("DSA".equalsIgnoreCase(currentKeyPair.getPrivate().getAlgorithm())) {
                JOptionPane.showMessageDialog(this,
                        "❌ No se puede descifrar archivos con claves de tipo DSA.\nUtiliza RSA.",
                        "Error de algoritmo",
                        JOptionPane.ERROR_MESSAGE
                );
                return;
            }
            try {
                // Se descifra el archivo usando la clave privada
                Encryption.descifrarBloques(
                        rutaArchivoLabel.getText(),
                        archivoSalida.getText(),
                        currentKeyPair.getPrivate()
                );
                mostrar("Archivo descifrado con clave privada.");
            } catch (Exception ex) {
                mostrar("Error al descifrar: " + ex.getMessage());
            }
        });

        // ======== Firma digital con clave privada ========
        btnFirmar.addActionListener(e -> {
            if (currentKeyPair == null) {
                mostrar("⚠️ Debes cargar un par de claves primero.");
                return;
            }

            // Se fuerza el algoritmo de firma si la clave es de tipo DSA
            if ("DSA".equalsIgnoreCase(currentKeyPair.getPrivate().getAlgorithm())) {
                algoritmoFirma = "SHA1withDSA";
            }

            try {
                // Se firma el archivo usando la clave privada y el algoritmo seleccionado
                DigitalSignature.firmarFicheroClavePrivada(
                        rutaArchivoLabel.getText(),
                        archivoSalida.getText(),
                        currentKeyPair.getPrivate(),
                        algoritmoFirma
                );
                mostrar("Archivo firmado correctamente.");
            } catch (Exception ex) {
                mostrar("Error al firmar: " + ex.getMessage());
            }
        });

        // ======== Verificación de firma digital con clave pública ========
        btnVerificar.addActionListener(e -> {
            if (currentKeyPair == null) {
                mostrar("⚠️ Debes cargar un par de claves primero.");
                return;
            }
            try {
                // Se verifica si la firma del archivo es válida
                boolean ok = DigitalSignature.verificarFicheroFirmado(
                        rutaArchivoLabel.getText(),
                        archivoSalida.getText(),
                        currentKeyPair.getPublic()
                );

                if (ok) {
                    JOptionPane.showMessageDialog(this,
                            "✅ La firma es válida.\nEl documento no ha sido modificado.",
                            "Verificación Exitosa",
                            JOptionPane.INFORMATION_MESSAGE
                    );
                } else {
                    JOptionPane.showMessageDialog(this,
                            "❌ La firma NO es válida.\nEs posible que el documento haya sido modificado o la clave pública no coincida.",
                            "Verificación Fallida",
                            JOptionPane.ERROR_MESSAGE
                    );
                }
            } catch (Exception ex) {
                mostrar("Error al verificar firma: " + ex.getMessage());
            }
        });

        // ======== Añadir componentes al panel ========
        panel.add(new JLabel("Archivo:")); panel.add(btnSeleccionarArchivo);
        panel.add(new JLabel("Archivo de entrada seleccionado:")); panel.add(rutaArchivoLabel);
        panel.add(new JLabel("Archivo de salida / firma:")); panel.add(archivoSalida);
        panel.add(new JLabel("Archivo .key (par de claves):")); panel.add(rutaClaveLabel);
        panel.add(btnSeleccionarClave);
        panel.add(btnCifrar); panel.add(btnDescifrar);
        panel.add(btnFirmar); panel.add(btnVerificar);

        return panel;
    }
    /**
     * Crea el panel para la generación de pares de claves (RSA/DSA) de diferentes tamaños.
     * Guarda el par generado en un archivo .key.
     *
     * @return JPanel con opciones para generar claves.
     */
    private JPanel crearPanelGenerarClaves() {
        // Se crea el panel principal con una cuadrícula vertical
        JPanel panel = new JPanel(new GridLayout(8, 2));

        // Desplegable con los tipos de clave disponibles: RSA o DSA
        JComboBox<String> comboTipo = new JComboBox<>(tiposClave);

        // Desplegable con los tamaños de clave disponibles en bits
        JComboBox<String> comboTamano = new JComboBox<>(tamanosClave);

        // Campo de texto donde se especificará el nombre del archivo .key a guardar
        JTextField nombreArchivo = new JTextField("par_claves");

        // Botón para iniciar la generación del par de claves
        JButton btnGenerar = new JButton("Generar Par de Claves");

        // Acción que se ejecuta al pulsar el botón "Generar Par de Claves"
        btnGenerar.addActionListener(e -> {
            // Se obtiene el tipo de clave seleccionado (RSA o DSA)
            String tipo = (String) comboTipo.getSelectedItem();

            // Se obtiene el tamaño de clave seleccionado (512, 768, 1024 bits)
            int tam = Integer.parseInt((String) comboTamano.getSelectedItem());

            // Se obtiene el nombre de archivo introducido por el usuario
            String nombre = nombreArchivo.getText().trim();

            // Validación: el campo de nombre no puede estar vacío
            if (nombre.isEmpty()) {
                mostrar("⚠️ Debes introducir un nombre de archivo válido.");
                return;
            }

            try {
                // Se inicializa el generador de claves con el tipo y tamaño seleccionados
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance(tipo);
                keyGen.initialize(tam);

                // Se genera el par de claves (pública y privada)
                KeyPair kp = keyGen.generateKeyPair();

                // Se define la ruta absoluta del archivo .key de salida
                String ruta = System.getProperty("user.dir") + File.separator + nombre + ".key";

                // Se guarda el par de claves en un archivo utilizando la utilidad de firma digital
                DigitalSignature.saveKeyPairToFile(kp, ruta);

                // Se muestra mensaje de éxito al usuario
                mostrar("✅ Claves generadas y guardadas correctamente en:\n" + ruta);

            } catch (Exception ex) {
                // En caso de error durante la generación o guardado, se notifica al usuario
                mostrar("❌ Error al generar claves: " + ex.getMessage());
            }
        });

        // Se agregan todos los componentes al panel en orden lógico
        panel.add(new JLabel("Selecciona el tipo de clave:"));
        panel.add(comboTipo);
        panel.add(new JLabel("Selecciona el tamaño de la clave (bits):"));
        panel.add(comboTamano);
        panel.add(new JLabel("Nombre del archivo (.key) a guardar:"));
        panel.add(nombreArchivo);
        panel.add(btnGenerar);

        // Se devuelve el panel completamente configurado
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





