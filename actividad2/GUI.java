/**
 * Actividad 2 - JCA
 * Seguridad en Redes Telemáticas
 * Estudiantes:
 * Guillén Torrado, Sara
 * Martín Ledesma, Sergio
 */

package actividad2;

import librerias.Options;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * Clase para la interfaz de usuario
 */
public class GUI extends JFrame {
    //En esta sección, se guardarán las elecciones realizadas por el usuario dentro de la Interfaz Gráfica.
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

    /**
     * Función que nos devuelve el path del fichero elegido. Es decir, el source file
     *
     * @return Devuelve la ruta del fichero elegido
     */
    public String getFileName() {
        return sourceFile.getText();
    }

    /**
     * Función que nos devuelve la contraseña establecida en el campo de "Contraseña".
     *
     * @return La contraseña
     */
    public String getPassword() {
        return new String(passwordField.getPassword());
    }

    /**
     * Devuelve el algoritmo elegido en el campo de "Algoritmo".
     *
     * @return El algoritmo elegido
     */
    public String getAlgorithm() {
        return algorithmCombo.getSelectedItem().toString();
    }

    /**
     * Devuelve el número de iteraciones guardado en el camop de "Iteraciones".
     *
     * @return El número de iteraciones
     */
    public int getIterations() {
        return Integer.parseInt(iterations.getValue().toString());
    }

    /**
     * Inicializa los parámetros y campos necesarios para construir la Interfaz Gráfica de Usuario.
     */
    public GUI() {
        // Configuración básica de la ventana
        setTitle("Cifrado de Archivos - PBE");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); //Establece el comportamiento que se debe ejecutar cuando se quiera cerrar la ventana. Es decir, al darle a la cruz de arriba a la derecha.
        setSize(600, 400); //Establece un ancho de 600px y un alto de 400px a la ventana.
        setLocationRelativeTo(null);

        // Panel principal con GridBagLayout para mejor organización
        JPanel mainPanel = new JPanel(new GridBagLayout());  //Se inicializa el Layout de la ventana.
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Configuración del algoritmo.
        // String[] algorithms = Options.PBEAlgorithms;
        algorithmCombo = new JComboBox<>(Options.PBEAlgorithms); // Se establece las elecciones del tipo de algoritmos de cifrado que se pueden realizar. Esto se guarda en un campo de selección desplegable.
        addComponent(mainPanel, new JLabel("Algoritmo:"), gbc, 0, 0);     //Se añade una nueva fila a la ventana principal.
        addComponent(mainPanel, algorithmCombo, gbc, 1, 0, 2, 1);   //Se añade una nueva fila a la ventana principal, relacionada con el campo de elecciones de Algoritmo.

        // Spinner para las iteraciones. Se establece un campo numérico, relacionado con el número de iteraciones del algoritmo.
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(1000, 1, 100000, 100);
        iterations = new JSpinner(spinnerModel);
        addComponent(mainPanel, new JLabel("Iteraciones:"), gbc, 0, 2);
        addComponent(mainPanel, iterations, gbc, 1, 2, 2, 1);

        // Campos de contraseña.
        // Se establece e inicializa los campos de contraseña, que se utilizará en el algoritmo de cifrado.
        passwordField = new JPasswordField(20);
        confirmPassword = new JPasswordField(20);
        addComponent(mainPanel, new JLabel("Contraseña:"), gbc, 0, 3);
        addComponent(mainPanel, passwordField, gbc, 1, 3, 2, 1);
        addComponent(mainPanel, new JLabel("Confirmar Contraseña:"), gbc, 0, 4);
        addComponent(mainPanel, confirmPassword, gbc, 1, 4, 2, 1);

        // Selección de archivos. Se inicializan los campos relacionados con el campo de selección de archivos.
        sourceFile = new JTextField(20);
        destFile = new JTextField(20);
        destFile.setEditable(false); // El campo de destino no será editable
        sourceButton = new JButton("Examinar");
        destButton = new JButton("Examinar");
        destButton.setEnabled(false); // Deshabilitamos el botón de destino

        // Panel para archivo origen. Se establece la fila que se complementará para la elección del archivo de origen.
        JPanel sourcePanel = new JPanel(new BorderLayout(5, 0));
        sourcePanel.add(sourceFile, BorderLayout.CENTER);
        sourcePanel.add(sourceButton, BorderLayout.EAST);
        addComponent(mainPanel, new JLabel("Archivo Origen:"), gbc, 0, 5);
        addComponent(mainPanel, sourcePanel, gbc, 1, 5, 2, 1);

        // Panel para archivo destino. Se establece la fila relacionada con el campo de selección del archivo destino.
        JPanel destPanel = new JPanel(new BorderLayout(5, 0));
        destPanel.add(destFile, BorderLayout.CENTER);
        destPanel.add(destButton, BorderLayout.EAST);
        addComponent(mainPanel, new JLabel("Archivo Destino:"), gbc, 0, 6);
        addComponent(mainPanel, destPanel, gbc, 1, 6, 2, 1);

        // Botones de acción. En esta sección, se inicializan el comportamiento y la posición de los botones de acción.
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

    /**
     * Añade un componente a un panel, estableciendo la posición y el estilo del componente.
     *
     * @param panel     El panel existente
     * @param component El nuevo componente
     * @param gbc       El estilo del componente
     * @param x         Posición en el eje de las x
     * @param y         Posición en el eje de las y
     */
    private void addComponent(JPanel panel, JComponent component,
                              GridBagConstraints gbc, int x, int y) {
        addComponent(panel, component, gbc, x, y, 1, 1);
    }

    /**
     * Añade un componente a un panel
     *
     * @param panel     El panel existente
     * @param component El nuevo componente
     * @param gbc       El estilo del componente
     * @param x         Posición en el eje de las x
     * @param y         Posición en el eje de las y
     * @param width     Ancho del componente
     * @param height    Altura del componente
     */
    private void addComponent(JPanel panel, JComponent component,
                              GridBagConstraints gbc, int x, int y, int width, int height) {
        gbc.gridx = x;
        gbc.gridy = y;
        gbc.gridwidth = width;
        gbc.gridheight = height;
        panel.add(component, gbc);
    }

    /**
     * Establece los eventos y comportamientos que se desea por cada componente y funcionalidad de nuestra aplicación.
     */
    private void configureListeners() {
        // Se configura el listener para el botón de selección de archivo origen.
        // Cada vez que se hace clic en el botón de "sourceButton", se ejecuta la función de "SelectSourceFile"
        sourceButton.addActionListener(e -> selectSourceFile());

        // Listener para el campo de archivo fuente.
        // Se configura el comportamiento a la hora de elegir el documento fuente en la aplicación.
        sourceFile.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            //Comportamiento cuando se cambia el archivo.
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                updateDestinationFile();
            }

            //Comportamiento cuando se borra el archivo.
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                updateDestinationFile();
            }

            //Comportamiento cuando se selecciona por primera vez el archivo.
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                updateDestinationFile();
            }
        });

        //Se establece el evento y el comportamiento que se desea cuando se hace clic sobre el botón de "Encriptar"
        encryptButton.addActionListener(e -> {
            //Se establece la variable a true, haciendo ver que se quiere cifrar.
            isEncrypting = true;
            updateDestinationFile();
            //Esta condicional nos ayuda a comprobar si se trata de un archivo correcto.
            // Si es así, se procede a ejecutar la función deseada.
            // Si no, se mostrará un mensaje de error.
            if (validateInputs()) {
                try {
                    //Se llama al método de cifrado, realizado por los estudiantes.
                    PBEActivity.processingCipher(getFileName(), getPassword(), getAlgorithm(), getIterations());
                    JOptionPane.showMessageDialog(this, "Cifrado completado");

                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Ha ocurrido un error al cifrar.");
                }
            }
        });

        //Se establece el evento y el comportamiento que se desea cuando se hace clic sobre el botón de "Encriptar"
        decryptButton.addActionListener(e -> {
            //Se establece la variable a false, haciendo ver que se quiere descifrar.
            isEncrypting = false;
            //Se actualiza el fichero de destino.
            updateDestinationFile();
            //Esta condicional nos ayuda a comprobar si se trata de un archivo correcto.
            // Si es así, se procede a ejecutar la función deseada. Si no, se mostrará un mensaje de error.
            if (validateInputs()) {

                try {
                    //Se llama al método de descifrado, realizado por los estudiantes.
                    PBEActivity.processingDecipher(getFileName(), getPassword(), getIterations());
                    JOptionPane.showMessageDialog(this, "Descifrado completado");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Ha ocurrido un error al descifrar.");
                }
            }
        });
    }

    /**
     * Abre una ventana para elegir el fichero fuente del dispositivo
     * El fichero elegido se guarda en la variable "sourceFile" de nuestra clase.
     */
    private void selectSourceFile() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            sourceFile.setText(fileChooser.getSelectedFile().getAbsolutePath());
            updateDestinationFile();
        }
    }

    /**
     * Se actualiza el fichero destino, dependiendo de la extensión del fichero fuente
     */
    private void updateDestinationFile() {
        String sourcePath = sourceFile.getText();
        if (!sourcePath.isEmpty()) {
            File sourceFile = new File(sourcePath);
            String parentPath = sourceFile.getParent();
            String fileName = sourceFile.getName();

            // Añadir la extensión apropiada según la operación
            String newFileName;
            if (isEncrypting) {
                newFileName = fileName + ".cif";
            } else {
                if (fileName.toLowerCase().endsWith(".cif")) {
                    newFileName = fileName + ".cla";
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

    /**
     * Valida todos los campos de la ventana
     *
     * @return true si todos los campos son válidos, false en caso contrario
     */
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
        //Valida si se establece una contraseña segura.
        if (!PBEActivity.securePassword(pass1)) {
            JOptionPane.showMessageDialog(this,
                    "La contraseña debe contener, al menos, 8 caracteres.",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        //Valida que las dos contraseñas sean iguales.
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

    /**
     * Método principal
     *
     * @param args Argumentos al ejecutar, no son necesarios
     */
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