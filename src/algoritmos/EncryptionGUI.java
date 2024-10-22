package algoritmos;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.File;

public class EncryptionGUI extends JFrame {
    private JTextField saltField;
    private JPasswordField passwordField;
    private JPasswordField confirmPasswordField;
    private JSpinner iterationsSpinner;
    private JComboBox<String> algorithmCombo;
    private JTextField sourceFileField;
    private JTextField destFileField;
    private JButton sourceButton;
    private JButton destButton;
    private JButton encryptButton;
    private JButton decryptButton;
    private boolean isEncrypting = true; // Para controlar el modo actual

    public EncryptionGUI() {
        // Configuración básica de la ventana
        setTitle("Cifrado de Archivos - PBE");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 400);
        setLocationRelativeTo(null);

        // Panel principal con GridBagLayout para mejor organización
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Configuración del algoritmo
        String[] algorithms = {"PBEWithMD5AndDES", "PBEWithMD5AndTripleDES", "PBEWithSHA1AndDESede", "PBEWithSHA1AndRC2_40"};
        algorithmCombo = new JComboBox<>(algorithms);
        addComponent(mainPanel, new JLabel("Algoritmo:"), gbc, 0, 0);
        addComponent(mainPanel, algorithmCombo, gbc, 1, 0, 2, 1);

        // Campo para el SALT
        saltField = new JTextField(20);
        saltField.setEditable(false);
        addComponent(mainPanel, new JLabel("Salt:"), gbc, 0, 1);
        addComponent(mainPanel, saltField, gbc, 1, 1, 2, 1);

        // Spinner para las iteraciones
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(1000, 1, 100000, 100);
        iterationsSpinner = new JSpinner(spinnerModel);
        addComponent(mainPanel, new JLabel("Iteraciones:"), gbc, 0, 2);
        addComponent(mainPanel, iterationsSpinner, gbc, 1, 2, 2, 1);

        // Campos de contraseña
        passwordField = new JPasswordField(20);
        confirmPasswordField = new JPasswordField(20);
        addComponent(mainPanel, new JLabel("Contraseña:"), gbc, 0, 3);
        addComponent(mainPanel, passwordField, gbc, 1, 3, 2, 1);
        addComponent(mainPanel, new JLabel("Confirmar Contraseña:"), gbc, 0, 4);
        addComponent(mainPanel, confirmPasswordField, gbc, 1, 4, 2, 1);

        // Selección de archivos
        sourceFileField = new JTextField(20);
        destFileField = new JTextField(20);
        destFileField.setEditable(false); // El campo de destino no será editable
        sourceButton = new JButton("Examinar");
        destButton = new JButton("Examinar");
        destButton.setEnabled(false); // Deshabilitamos el botón de destino

        // Panel para archivo origen
        JPanel sourcePanel = new JPanel(new BorderLayout(5, 0));
        sourcePanel.add(sourceFileField, BorderLayout.CENTER);
        sourcePanel.add(sourceButton, BorderLayout.EAST);
        addComponent(mainPanel, new JLabel("Archivo Origen:"), gbc, 0, 5);
        addComponent(mainPanel, sourcePanel, gbc, 1, 5, 2, 1);

        // Panel para archivo destino
        JPanel destPanel = new JPanel(new BorderLayout(5, 0));
        destPanel.add(destFileField, BorderLayout.CENTER);
        destPanel.add(destButton, BorderLayout.EAST);
        addComponent(mainPanel, new JLabel("Archivo Destino:"), gbc, 0, 6);
        addComponent(mainPanel, destPanel, gbc, 1, 6, 2, 1);

        // Botones de acción
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        encryptButton = new JButton("Cifrar");
        decryptButton = new JButton("Descifrar");
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

        gbc.gridwidth = 3;
        gbc.gridy = 7;
        mainPanel.add(buttonPanel, gbc);

        // Añadir el panel principal a la ventana
        add(mainPanel);

        // Configurar los listeners de los botones
        configureListeners();
    }

    private void addComponent(JPanel panel, JComponent component,
                              GridBagConstraints gbc, int x, int y) {
        addComponent(panel, component, gbc, x, y, 1, 1);
    }

    private void addComponent(JPanel panel, JComponent component,
                              GridBagConstraints gbc, int x, int y, int width, int height) {
        gbc.gridx = x;
        gbc.gridy = y;
        gbc.gridwidth = width;
        gbc.gridheight = height;
        panel.add(component, gbc);
    }

    private void configureListeners() {
        sourceButton.addActionListener(e -> selectSourceFile());

        // Listener para el campo de archivo fuente
        sourceFileField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateDestinationFile(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateDestinationFile(); }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateDestinationFile(); }
        });

        encryptButton.addActionListener(e -> {
            isEncrypting = true;
            updateDestinationFile();
            if (validateInputs()) {
                // Aquí iría la lógica de cifrado
                JOptionPane.showMessageDialog(this, "Iniciando proceso de cifrado...");
            }
        });

        decryptButton.addActionListener(e -> {
            isEncrypting = false;
            updateDestinationFile();
            if (validateInputs()) {
                // Aquí iría la lógica de descifrado
                JOptionPane.showMessageDialog(this, "Iniciando proceso de descifrado...");
            }
        });
    }

    private void selectSourceFile() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            sourceFileField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            updateDestinationFile();
        }
    }

    private void updateDestinationFile() {
        String sourcePath = sourceFileField.getText();
        if (!sourcePath.isEmpty()) {
            File sourceFile = new File(sourcePath);
            String parentPath = sourceFile.getParent();
            String fileName = sourceFile.getName();

            // Eliminar cualquier extensión existente
            String baseFileName = fileName.replaceFirst("[.][^.]+$", "");

            // Añadir la extensión apropiada según la operación
            String newFileName;
            if (isEncrypting) {
                newFileName = baseFileName + ".cif";
            } else {
                // Si el archivo fuente termina en .cif, cambiamos a .dec
                if (fileName.toLowerCase().endsWith(".cif")) {
                    newFileName = baseFileName + ".dec";
                } else {
                    // Si no es un archivo .cif, mostramos un mensaje de error
                    destFileField.setText("");
                    JOptionPane.showMessageDialog(this,
                            "Para descifrar, el archivo de entrada debe tener extensión .cif",
                            "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }

            // Construir la ruta completa del archivo de destino
            String destPath = new File(parentPath, newFileName).getAbsolutePath();
            destFileField.setText(destPath);
        } else {
            destFileField.setText("");
        }
    }

    private boolean validateInputs() {
        // Validar que los campos no estén vacíos
        if (sourceFileField.getText().isEmpty() || destFileField.getText().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Por favor, seleccione un archivo de origen válido.",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        // Validar que las contraseñas coincidan
        String pass1 = new String(passwordField.getPassword());
        String pass2 = new String(confirmPasswordField.getPassword());
        if (pass1.isEmpty() || !pass1.equals(pass2)) {
            JOptionPane.showMessageDialog(this,
                    "Las contraseñas no coinciden o están vacías.",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        // Para descifrado, validar que el archivo de entrada sea .cif
        if (!isEncrypting && !sourceFileField.getText().toLowerCase().endsWith(".cif")) {
            JOptionPane.showMessageDialog(this,
                    "Para descifrar, el archivo de entrada debe tener extensión .cif",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        return true;
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }
            new EncryptionGUI().setVisible(true);
        });
    }
}