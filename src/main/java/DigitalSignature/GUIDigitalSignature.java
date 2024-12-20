package DigitalSignature;


import javax.swing.*;
        import java.awt.*;
        import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
/**
 * Constructor principal para la interfaz gráfica de usuario (GUI) de la aplicación de firma digital.
 * Configura los componentes principales de la ventana, incluyendo los botones de navegación y los paneles dinámicos.
 * Inicializa un `CardLayout` para alternar entre diferentes paneles de funcionalidad.
 */
public class GUIDigitalSignature extends JFrame {

    private JPanel contentPanel;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public GUIDigitalSignature() {
        // Configuración de la ventana principal
        setTitle("CryptoApp - Gestión de Claves y Criptografía");
        setSize(800, 600);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        // Crear el topbar
        JToggleButton btnKeys = new JToggleButton("Gestión de Claves");
        JToggleButton btnSign = new JToggleButton("Firmar Archivo");
        JToggleButton btnVerify = new JToggleButton("Verificar Firma");
        JToggleButton btnEncrypt = new JToggleButton("Encriptar Archivo");
        JToggleButton btnDecrypt = new JToggleButton("Desencriptar Archivo");

        ButtonGroup toggleGroup = new ButtonGroup();
        toggleGroup.add(btnKeys);
        toggleGroup.add(btnSign);
        toggleGroup.add(btnVerify);
        toggleGroup.add(btnEncrypt);
        toggleGroup.add(btnDecrypt);


        JMenuBar topBar = new JMenuBar();

//        JPanel topBar = new JPanel();
        topBar.setLayout(new FlowLayout(FlowLayout.LEFT));
        topBar.add(btnKeys);
        topBar.add(btnSign);
        topBar.add(btnVerify);
        topBar.add(btnEncrypt);
        topBar.add(btnDecrypt);

        add(topBar, BorderLayout.NORTH);

        // Panel central dinámico
        contentPanel = new JPanel();
        contentPanel.setLayout(new CardLayout());
        add(contentPanel, BorderLayout.CENTER);

        // Añadir paneles a las funciones
        contentPanel.add(createKeyManagementPanel(), "KEYS");
        contentPanel.add(createSignFilePanel(), "SIGN");
        contentPanel.add(createVerifyFilePanel(), "VERIFY");
        contentPanel.add(createEncryptFilePanel(), "ENCRYPT");
        contentPanel.add(createDecryptFilePanel(), "DECRYPT");

        // Listeners para los botones
        btnKeys.addActionListener(e -> showPanel("KEYS"));
        btnSign.addActionListener(e -> showPanel("SIGN"));
        btnVerify.addActionListener(e -> showPanel("VERIFY"));
        btnEncrypt.addActionListener(e -> showPanel("ENCRYPT"));
        btnDecrypt.addActionListener(e -> showPanel("DECRYPT"));

        // Mostrar panel inicial
        btnKeys.setSelected(true);
        showPanel("KEYS");
    }
    /**
     * Muestra el panel correspondiente al nombre especificado utilizando un `CardLayout`.
     *
     * @param name Nombre del panel que se desea mostrar. Debe coincidir con las claves utilizadas al agregar los paneles.
     */
    private void showPanel(String name) {
        CardLayout cl = (CardLayout) contentPanel.getLayout();
        cl.show(contentPanel, name);
    }


    /**
     * Crea el panel para la gestión de claves. Este panel incluye opciones para:
     * - Generar un par de claves RSA.
     * - Cargar una clave pública desde un archivo.
     * - Cargar una clave privada desde un archivo.
     *
     * @return JPanel configurado con botones para la gestión de claves.
     */
    private JPanel createKeyManagementPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(3, 1));

        JButton btnGenerateKeys = new JButton("Generar Claves");
        btnGenerateKeys.addActionListener(e -> {
            // Lógica para generar claves
            try {
                if(KeyManagement.generateAndStoreKeys("RSA","publickey.key","privateKey.key")){
                    JOptionPane.showMessageDialog(this, "Claves generadas y almacenadas.");
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error al generar las claves.");
            }

        });

        JButton btnLoadPublicKey = new JButton("Cargar Clave Pública");
        btnLoadPublicKey.addActionListener(e -> {
            // Lógica para cargar clave pública
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();

                try {
                    publicKey = KeyManagement.loadPublicKey(file.getAbsolutePath());
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
                JOptionPane.showMessageDialog(this, "Clave Pública cargada desde: " + file.getAbsolutePath());

            }
        });

        JButton btnLoadPrivateKey = new JButton("Cargar Clave Privada");
        btnLoadPrivateKey.addActionListener(e -> {
            // Lógica para cargar clave privada
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();

                try {
                    privateKey = KeyManagement.loadPrivateKey(file.getAbsolutePath());
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
                JOptionPane.showMessageDialog(this, "Clave Privada cargada desde: " + file.getAbsolutePath());
            }
        });

        panel.add(btnGenerateKeys);
        panel.add(btnLoadPublicKey);
        panel.add(btnLoadPrivateKey);

        return panel;
    }

    /**
     * Crea el panel para firmar archivos. Este panel permite:
     * - Seleccionar un archivo para firmarlo utilizando la clave privada cargada.
     * - Generar un archivo de firma con la extensión `.sig`.
     *
     * @return JPanel configurado con la funcionalidad para firmar archivos.
     */
    private JPanel createSignFilePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(2, 1));

        JButton btnSignFile = new JButton("Firmar Archivo");
        btnSignFile.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                JOptionPane.showMessageDialog(this, "Archivo firmado: " + file.getAbsolutePath());
                try {
                    DigitalSignature.signFile(file.getAbsolutePath(),file.getAbsolutePath()+".sig",privateKey);
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }

            }
        });

        panel.add(btnSignFile);
        return panel;
    }

    /**
     * Crea el panel para verificar la firma de archivos. Este panel permite:
     * - Seleccionar un archivo de firma.
     * - Verificar si la firma coincide con el archivo original utilizando la clave pública cargada.
     *
     * @return JPanel configurado con la funcionalidad para verificar firmas.
     */
    private JPanel createVerifyFilePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(2, 1));

        JButton btnVerifyFile = new JButton("Verificar Firma");
        btnVerifyFile.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();

                try {
                    if(DigitalSignature.verifyFile(DigitalSignature.eliminarUltimaExtension(file.getAbsolutePath()),file.getAbsolutePath(),publicKey)){
                        JOptionPane.showMessageDialog(this, "Firma verificada para: " + file.getAbsolutePath());
                    }else{
                        JOptionPane.showMessageDialog(this, "¡¡CUIDADO!! La firma no coincide con el archivo: " + file.getAbsolutePath());
                    }

                } catch (Exception ex) {
                    System.err.println(ex);
                    JOptionPane.showMessageDialog(this, "Ha habido algún error al intentar verificar la firma del archivo: " + file.getAbsolutePath());

                }
            }
        });

        panel.add(btnVerifyFile);
        return panel;
    }

    /**
     * Crea el panel para encriptar archivos. Este panel permite:
     * - Seleccionar un archivo para encriptarlo utilizando la clave pública cargada.
     * - Generar un archivo encriptado con la extensión `.enc`.
     *
     * @return JPanel configurado con la funcionalidad para encriptar archivos.
     */
    private JPanel createEncryptFilePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(2, 1));

        JButton btnEncryptFile = new JButton("Encriptar Archivo");
        btnEncryptFile.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                try {
                    Encryption.encryptFile(file.getAbsolutePath(),file.getAbsolutePath()+".enc",publicKey);
                    JOptionPane.showMessageDialog(this, "Archivo encriptado: " + file.getAbsolutePath());
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }

            }
        });

        panel.add(btnEncryptFile);
        return panel;
    }

    /**
     * Crea el panel para desencriptar archivos. Este panel permite:
     * - Seleccionar un archivo encriptado.
     * - Desencriptarlo utilizando la clave privada cargada.
     * - Guardar el archivo desencriptado sin la extensión `.enc`.
     *
     * @return JPanel configurado con la funcionalidad para desencriptar archivos.
     */
    private JPanel createDecryptFilePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(2, 1));

        JButton btnDecryptFile = new JButton("Desencriptar Archivo");
        btnDecryptFile.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                try {
                    Encryption.decryptFile(file.getAbsolutePath(),DigitalSignature.eliminarUltimaExtension(file.getAbsolutePath()),privateKey);
                    JOptionPane.showMessageDialog(this, "Archivo desencriptado: " + file.getAbsolutePath());
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }

            }
        });

        panel.add(btnDecryptFile);
        return panel;
    }
    /**
     * Método principal que inicia la aplicación GUI de firma digital.
     * Utiliza `SwingUtilities.invokeLater` para asegurar que la creación de la interfaz gráfica
     * ocurra en el hilo de despacho de eventos de Swing.
     *
     * @param args Argumentos de línea de comandos (no utilizados en esta aplicación).
     */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            GUIDigitalSignature app = new GUIDigitalSignature();
            app.setVisible(true);
        });
    }
}

