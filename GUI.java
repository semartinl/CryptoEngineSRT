/**
 * Actividad 2 - JPA
 * Seguridad en Redes Telemáticas
 * Estudiantes:
 * Guillén Torrado, Sara
 * Martín Ledesma, Sergio
 */

package algoritmos;

import librerias.Options;

import javax.swing.*;
import java.awt.*;
import java.io.File;

public class GUI extends JFrame {
    private JPasswordField passwordField;
    private JPasswordField confirmPassword;
    private JSpinner iterations;
    private JComboBox<String> algorithmCombo;
    private JTextField sourceFile;
    private JTextField destFile;
    private JButton sourceButton;
    private JButton destButton;
    private JButton encryptButton;
    private JButton decryptButton;
    private boolean isEncrypting = true; // Para controlar el modo actual

    public String getFileName() {
        return sourceFile.getText();
    }

    public String getPassword() {
        return new String(passwordField.getPassword());
    }

    public String getAlgorithm() {
        return algorithmCombo.getSelectedItem().toString();
    }

    public int getIterations() {
        return Integer.parseInt(iterations.getValue().toString());
    }


    public GUI() {
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
        String[] algorithms = Options.PBEAlgorithms;
        algorithmCombo = new JComboBox<>(algorithms);
        addComponent(mainPanel, new JLabel("Algoritmo:"), gbc, 0, 0);
        addComponent(mainPanel, algorithmCombo, gbc, 1, 0, 2, 1);

        // Spinner para las iteraciones
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(1000, 1, 100000, 100);
        iterations = new JSpinner(spinnerModel);
        addComponent(mainPanel, new JLabel("Iteraciones:"), gbc, 0, 2);
        addComponent(mainPanel, iterations, gbc, 1, 2, 2, 1);

        // Campos de contraseña
        passwordField = new JPasswordField(20);
        confirmPassword = new JPasswordField(20);
        addComponent(mainPanel, new JLabel("Contraseña:"), gbc, 0, 3);
        addComponent(mainPanel, passwordField, gbc, 1, 3, 2, 1);
        addComponent(mainPanel, new JLabel("Confirmar Contraseña:"), gbc, 0, 4);
        addComponent(mainPanel, confirmPassword, gbc, 1, 4, 2, 1);

        // Selección de archivos
        sourceFile = new JTextField(20);
        destFile = new JTextField(20);
        destFile.setEditable(false); // El campo de destino no será editable
        sourceButton = new JButton("Examinar");
        destButton = new JButton("Examinar");
        destButton.setEnabled(false); // Deshabilitamos el botón de destino

        // Panel para archivo origen
        JPanel sourcePanel = new JPanel(new BorderLayout(5, 0));
        sourcePanel.add(sourceFile, BorderLayout.CENTER);
        sourcePanel.add(sourceButton, BorderLayout.EAST);
        addComponent(mainPanel, new JLabel("Archivo Origen:"), gbc, 0, 5);
        addComponent(mainPanel, sourcePanel, gbc, 1, 5, 2, 1);

        // Panel para archivo destino
        JPanel destPanel = new JPanel(new BorderLayout(5, 0));
        destPanel.add(destFile, BorderLayout.CENTER);
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
        sourceFile.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                updateDestinationFile();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                updateDestinationFile();
            }

            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                updateDestinationFile();
            }
        });

        encryptButton.addActionListener(e -> {
            isEncrypting = true;
            updateDestinationFile();
            if (validateInputs()) {
                try {
                    LogicaCifrado.processingCipher(getFileName(), getPassword(), getAlgorithm(), getIterations());
                    JOptionPane.showMessageDialog(this, "Cifrado completado");

                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Ha ocurrido un error al cifrar.");
                }
            }
        });

        decryptButton.addActionListener(e -> {
            isEncrypting = false;
            updateDestinationFile();
            if (validateInputs()) {

                try {
                    LogicaCifrado.processingDecipher(getFileName(), getPassword(), getIterations());
                    JOptionPane.showMessageDialog(this, "Descifrado completado");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Ha ocurrido un error al descifrar.");
                }
            }
        });
    }

    private void selectSourceFile() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            sourceFile.setText(fileChooser.getSelectedFile().getAbsolutePath());
            updateDestinationFile();
        }
    }

    private void updateDestinationFile() {
        String sourcePath = sourceFile.getText();
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
                    destFile.setText("");
                    JOptionPane.showMessageDialog(this,
                            "Para descifrar, el archivo de entrada debe tener extensión .cif",
                            "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }

            // Construir la ruta completa del archivo de destino
            String destPath = new File(parentPath, newFileName).getAbsolutePath();
            destFile.setText(destPath);
        } else {
            destFile.setText("");
        }
    }

    private boolean validateInputs() {
        // Validar que los campos no estén vacíos
        if (sourceFile.getText().isEmpty() || destFile.getText().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Por favor, seleccione un archivo de origen válido.",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        // Validar que las contraseñas coincidan
        String pass1 = new String(passwordField.getPassword());
        String pass2 = new String(confirmPassword.getPassword());
        if (!LogicaCifrado.contrasenaSegura(pass1)) {
            JOptionPane.showMessageDialog(this,
                    "La contraseña debe contener, al menos, 8 caracteres.",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        if (pass1.isEmpty() || !pass1.equals(pass2)) {
            JOptionPane.showMessageDialog(this,
                    "Las contraseñas no coinciden o están vacías.",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return false;

        }

        // Para descifrado, validar que el archivo de entrada sea .cif
        if (!isEncrypting && !sourceFile.getText().toLowerCase().endsWith(".cif")) {
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
            new GUI().setVisible(true);


        });
    }
}