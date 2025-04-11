package Resumen_hash;

import actividad2.PBEActivity;
import librerias.Options;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

import static actividad2.Main.calcularHash;

public class MainGUI extends JFrame{
    private FileProtectorMac protector = new FileProtectorMac();

    // Variables de configuración seleccionada
    private String algoritmoCifrado = Options.cipherAlgorithms[1];
    private String algoritmoHash = Options.hashAlgorithms[1];
    private String algoritmoHMAC = Options.macAlgorithms[0];


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

        panel.add(labelCifrado);
        panel.add(comboCifrado);
        panel.add(labelHash);
        panel.add(comboHash);
        panel.add(labelHmac);
        panel.add(comboHmac);

        return panel;
    }

    private void mostrar(String mensaje) {
        JOptionPane.showMessageDialog(this, mensaje);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(MainGUI::new);
    }
}





