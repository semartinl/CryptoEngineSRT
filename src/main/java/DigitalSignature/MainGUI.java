package DigitalSignature;

import Resumen_hash.FileProtectorMac;
import actividad2.PBEActivity;
import librerias.Options;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Scanner;

import static actividad2.Main.calcularHash;

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

    private JPanel crearPanelCifrado() {
        JPanel panel = new JPanel(new GridLayout(7, 1));
        JTextField inputFile = new JTextField();
        JTextField password = new JTextField();
        JTextField iteraciones = new JTextField("1000");

        JButton btnCifrar = new JButton("Cifrar archivo");
        JButton btnDescifrar = new JButton("Descifrar archivo");

        btnCifrar.addActionListener((ActionEvent e) -> {
            String input = inputFile.getText();
            String pass = password.getText();
            int it = Integer.parseInt(iteraciones.getText());

            try {
                byte[] hash = calcularHash(pass);
                String algoritmo = algoritmoCifrado;
                PBEActivity.processingCipher(input, pass, algoritmo, it, hash);
                mostrar("Archivo cifrado correctamente.");
            } catch (Exception ex) {
                mostrar("Error: " + ex.getMessage());
            }
        });

        btnDescifrar.addActionListener((ActionEvent e) -> {
            String input = inputFile.getText();
            String pass = password.getText();
            int it = Integer.parseInt(iteraciones.getText());

            try {
                byte[] hash = calcularHash(pass);
                if (PBEActivity.verifyPasswordHash(input, hash)) {
                    PBEActivity.processingDecipher(input, pass, it);
                    mostrar("Archivo descifrado correctamente.");
                } else {
                    mostrar("Contraseña incorrecta.");
                }
            } catch (Exception ex) {
                mostrar("Error: " + ex.getMessage());
            }
        });

        panel.add(new JLabel("Archivo:")); panel.add(inputFile);
        panel.add(new JLabel("Contraseña:")); panel.add(password);
        panel.add(new JLabel("Iteraciones:")); panel.add(iteraciones);
        panel.add(btnCifrar); panel.add(btnDescifrar);
        return panel;
    }

    private JPanel crearPanelHash() {
        JPanel panel = new JPanel(new GridLayout(6, 1));
        JTextField input = new JTextField();
        JTextField output = new JTextField();
        JTextField pass = new JTextField();

        JButton aplicar = new JButton("Aplicar HASH");
        JButton verificar = new JButton("Verificar HASH");

        aplicar.addActionListener(e -> {
            String alg = algoritmoHash;
            protector.applyHash(input.getText(), output.getText(), pass.getText(), alg);
        });

        verificar.addActionListener(e -> {
            String alg = algoritmoCifrado;
            protector.verifyHash(input.getText(), output.getText(), pass.getText(), alg);
        });

        panel.add(new JLabel("Archivo:")); panel.add(input);
        panel.add(new JLabel("Salida:")); panel.add(output);
        panel.add(new JLabel("Contraseña:")); panel.add(pass);
        panel.add(aplicar); panel.add(verificar);

        return panel;
    }

    private JPanel crearPanelHMAC() {
        JPanel panel = new JPanel(new GridLayout(6, 1));
        JTextField input = new JTextField();
        JTextField output = new JTextField();
        JTextField pass = new JTextField();

        JButton aplicar = new JButton("Aplicar HMAC");
        JButton verificar = new JButton("Verificar HMAC");

        aplicar.addActionListener(e -> {
            String alg = algoritmoHMAC;
            protector.applyHMAC(input.getText(), output.getText(), pass.getText(), alg);
        });

        verificar.addActionListener(e -> {
            String alg = algoritmoHMAC;
            protector.verifyHMAC(input.getText(), output.getText(), pass.getText(), alg);
        });

        panel.add(new JLabel("Archivo:")); panel.add(input);
        panel.add(new JLabel("Salida:")); panel.add(output);
        panel.add(new JLabel("Contraseña:")); panel.add(pass);
        panel.add(aplicar); panel.add(verificar);

        return panel;
    }

    private JPanel crearPanelConfiguracion() {
        JPanel panel = new JPanel(new GridLayout(6, 1));

        // Cifrado
        JLabel labelCifrado = new JLabel("Algoritmo de Cifrado:");
        JComboBox<String> comboCifrado = new JComboBox<>(Options.cipherAlgorithms);
        comboCifrado.setSelectedItem(algoritmoCifrado);
        comboCifrado.addActionListener(e -> algoritmoCifrado = (String) comboCifrado.getSelectedItem());

        // Hash
        JLabel labelHash = new JLabel("Algoritmo de Hash:");
        JComboBox<String> comboHash = new JComboBox<>(Options.hashAlgorithms);
        comboHash.setSelectedItem(algoritmoHash);
        comboHash.addActionListener(e -> algoritmoHash = (String) comboHash.getSelectedItem());

        // HMAC
        JLabel labelHmac = new JLabel("Algoritmo de HMAC:");
        JComboBox<String> comboHmac = new JComboBox<>(Options.macAlgorithms);
        comboHmac.setSelectedItem(algoritmoHMAC);
        comboHmac.addActionListener(e -> algoritmoHMAC = (String) comboHmac.getSelectedItem());

        //Algoritmo de firma
        JLabel labelFirma = new JLabel("Algoritmo de Firma:");
        JComboBox<String> comboFirma = new JComboBox<>(Options.signAlgorithms);
        comboFirma.setSelectedItem(algoritmoFirma);
        comboFirma.addActionListener(e -> algoritmoFirma = (String) comboFirma.getSelectedItem());

        panel.add(labelCifrado);
        panel.add(comboCifrado);
        panel.add(labelHash);
        panel.add(comboHash);
        panel.add(labelHmac);
        panel.add(comboHmac);
        panel.add(labelFirma);
        panel.add(comboFirma);

        return panel;
    }

    private JPanel crearPanelAsimetrico() {
        JPanel panel = new JPanel(new GridLayout(9, 1));
//        JTextField archivo = new JTextField();

        JLabel rutaArchivoLabel = new JLabel("Ningún archivo seleccionado");
        JButton btnSeleccionarArchivo = new JButton("Seleccionar archivo");

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

        JTextField archivoSalida = new JTextField();
        JTextField archivoFirma = new JTextField();
//        JTextField clavePath = new JTextField();
        JLabel rutaClaveLabel = new JLabel("Ningún archivo seleccionado");
        JButton btnSeleccionarClave = new JButton("Seleccionar archivo .key");

//        JButton btnCargarClave = new JButton("Cargar Par de Claves");
        JButton btnCifrar = new JButton("Cifrar con clave pública");
        JButton btnDescifrar = new JButton("Descifrar con clave privada");
        JButton btnFirmar = new JButton("Firmar archivo");
        JButton btnVerificar = new JButton("Verificar firma");

//        btnCargarClave.addActionListener(e -> {
//            try {
//                currentKeyPair = InterfazGraficaP4.loadKeyPairFromFile(clavePath.getText());
//                mostrar("Clave cargada correctamente.");
//            } catch (Exception ex) {
//                mostrar("Error al cargar clave: " + ex.getMessage());
//            }
//        });

        btnSeleccionarClave.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser(actualPath);
            fileChooser.setDialogTitle("Seleccionar archivo .key");
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int resultado = fileChooser.showOpenDialog(this);

            if (resultado == JFileChooser.APPROVE_OPTION) {
                File archivoKeyPair = fileChooser.getSelectedFile();
                rutaClaveLabel.setText(archivoKeyPair.getAbsolutePath());

                try {
                    currentKeyPair = InterfazGraficaP4.loadKeyPairFromFile(archivoKeyPair.getAbsolutePath());
                    mostrar("Clave cargada correctamente.");
                } catch (Exception ex) {
                    mostrar("Error al cargar la clave: " + ex.getMessage());
                }
            }
        });


        btnCifrar.addActionListener(e -> {
            if (currentKeyPair == null) {
                mostrar("⚠️ Debes cargar un par de claves primero.");
                return;
            }
            if ("DSA".equalsIgnoreCase(currentKeyPair.getPublic().getAlgorithm())) {
                JOptionPane.showMessageDialog(this,
                        "❌ No se puede cifrar archivos con claves de tipo DSA.\nUtiliza RSA.",
                        "Error de algoritmo",
                        JOptionPane.ERROR_MESSAGE
                );
                return;
            }
            try {
                Encryption.cifrarBloques(rutaArchivoLabel.getText(), archivoSalida.getText(), currentKeyPair.getPublic(), "RSA/ECB/PKCS1Padding");
                mostrar("Archivo cifrado con clave pública.");
            } catch (Exception ex) {
                mostrar("Error al cifrar: " + ex.getMessage());
            }
        });

        btnDescifrar.addActionListener(e -> {
            if (currentKeyPair == null) {
                mostrar("⚠️ Debes cargar un par de claves primero.");
                return;
            }
            if ("DSA".equalsIgnoreCase(currentKeyPair.getPrivate().getAlgorithm())) {
                JOptionPane.showMessageDialog(this,
                        "❌ No se puede descifrar archivos con claves de tipo DSA.\nUtiliza RSA.",
                        "Error de algoritmo",
                        JOptionPane.ERROR_MESSAGE
                );
                return;
            }
            try {
                Encryption.descifrarBloques(rutaArchivoLabel.getText(), archivoSalida.getText(), currentKeyPair.getPrivate());
                mostrar("Archivo descifrado con clave privada.");
            } catch (Exception ex) {
                mostrar("Error al descifrar: " + ex.getMessage());
            }
        });

        btnFirmar.addActionListener(e -> {
            if (currentKeyPair == null) {
                mostrar("⚠️ Debes cargar un par de claves primero.");
                return;
            }
            if ("DSA".equalsIgnoreCase(currentKeyPair.getPrivate().getAlgorithm())) {
                algoritmoFirma = "SHA1withDSA";
            }

            try {
//                String algoritmo = DigitalSignature.solicitarAlgoritmoCifradoClavePublica(new Scanner(System.in));
                DigitalSignature.firmarFicheroClavePrivada(rutaArchivoLabel.getText(), archivoSalida.getText(), currentKeyPair.getPrivate(), algoritmoFirma);
                mostrar("Archivo firmado correctamente.");
            } catch (Exception ex) {
                mostrar("Error al firmar: " + ex.getMessage());
            }
        });

        btnVerificar.addActionListener(e -> {
            if (currentKeyPair == null) {
                mostrar("⚠️ Debes cargar un par de claves primero.");
                return;
            }
            try {
                boolean ok = DigitalSignature.verificarFicheroFirmado(rutaArchivoLabel.getText(), archivoSalida.getText(), currentKeyPair.getPublic());
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

        panel.add(new JLabel("Archivo:")); panel.add(btnSeleccionarArchivo);
        panel.add(new JLabel("Archivo de entrada seleccionado:")); panel.add(rutaArchivoLabel);
        panel.add(new JLabel("Archivo de salida / firma:")); panel.add(archivoSalida);
//        panel.add(new JLabel("Archivo .key (par de claves):")); panel.add(clavePath);
//        panel.add(btnCargarClave);
        panel.add(new JLabel("Archivo .key (par de claves):"));  panel.add(rutaClaveLabel);
        panel.add(btnSeleccionarClave);
        panel.add(btnCifrar); panel.add(btnDescifrar);
//        panel.add(new JLabel("Firma para verificar:")); panel.add(archivoFirma);
        panel.add(btnFirmar); panel.add(btnVerificar);

        return panel;
    }

    private JPanel crearPanelGenerarClaves() {
        JPanel panel = new JPanel(new GridLayout(7, 1));

        JComboBox<String> comboTipo = new JComboBox<>(tiposClave);
        JComboBox<String> comboTamano = new JComboBox<>(tamanosClave);
        JTextField nombreArchivo = new JTextField("par_claves");

        JButton btnGenerar = new JButton("Generar Par de Claves");

        btnGenerar.addActionListener(e -> {
            String tipo = (String) comboTipo.getSelectedItem();
            int tam = Integer.parseInt((String) comboTamano.getSelectedItem());
            String nombre = nombreArchivo.getText().trim();

            if (nombre.isEmpty()) {
                mostrar("⚠️ Debes introducir un nombre de archivo válido.");
                return;
            }

            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance(tipo);
                keyGen.initialize(tam);
                KeyPair kp = keyGen.generateKeyPair();

                String ruta = System.getProperty("user.dir") + File.separator + nombre + ".key";
                InterfazGraficaP4.saveKeyPairToFile(kp, ruta);

                mostrar("✅ Claves generadas y guardadas correctamente en:\n" + ruta);

            } catch (Exception ex) {
                mostrar("❌ Error al generar claves: " + ex.getMessage());
            }
        });

        panel.add(new JLabel("Selecciona el tipo de clave:"));
        panel.add(comboTipo);
        panel.add(new JLabel("Selecciona el tamaño de la clave (bits):"));
        panel.add(comboTamano);
        panel.add(new JLabel("Nombre del archivo (.key) a guardar:"));
        panel.add(nombreArchivo);
        panel.add(btnGenerar);

        return panel;
    }




    private void mostrar(String mensaje) {
        JOptionPane.showMessageDialog(this, mensaje);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(MainGUI::new);
    }
}





