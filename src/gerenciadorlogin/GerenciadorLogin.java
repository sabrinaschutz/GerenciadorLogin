package gerenciadorlogin;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 *
 * @author sabrina
 */
public class GerenciadorLogin {

    private static final String FILE_NAME = "locker.txt";
    private static final String FILE_PATH = "/home/sabrina/";
    private static final int PBKDF_ITERATIONS = 100000;

    private final Scanner input = new Scanner(System.in);

    public static void main(String[] args) {
        GerenciadorLogin gl = new GerenciadorLogin();
        System.out.println("######## SISTEMA SUPER SECRETO ########"
                + "\n"
                + "\n"
                + "\nBem vinda(o)!");
        gl.menu();
    }

    public void menu() {
        System.out.println(""
                + "\nO que deja fazer?"
                + "\n"
                + "\n1-Iserir novo usuário"
                + "\n2-Autenticar"
                + "\n");

        String opcao = input.nextLine();

        if (opcao.equals("1")) {
            this.inserirLogin();
        } else if (opcao.equals("2")) {
            this.autenticar();
        }
    }

    private void inserirLogin() {
        try {

            System.out.println("Insira um novo nome de usuário:");
            String login = input.nextLine();

            System.out.println("Insira uma senha:");
            String senha = new String(input.nextLine());

            byte[] saltHmacLogin = getSalt().getBytes();
            byte[] chaveDerivHmacLogin = derivarChave(senha, saltHmacLogin);

            byte[] saltHmacSenha = getSalt().getBytes();
            byte[] chaveDerivHmacSenha = derivarChave(Utils.toString(chaveDerivHmacLogin), saltHmacLogin);

            String loginCifrado = encrypt(chaveDerivHmacLogin, login, saltHmacLogin);

            String senhaCifrada = encrypt(chaveDerivHmacSenha, senha, saltHmacSenha);

            FileWriter arquivo = new FileWriter(FILE_PATH + FILE_NAME, true);
            BufferedWriter gravar = new BufferedWriter(arquivo);
            gravar.append(loginCifrado + ";" + senhaCifrada + "\n");
            gravar.close();
            arquivo.close();
            System.out.println("Login gravado com sucesso!\n");
            this.menu();
        } catch (Exception ex) {
            System.out.println("Erro ao criar usuário." + ex.getMessage());
        }

    }

    private void autenticar() {
        try {
            System.out.println("Usuário:");
            String login = input.nextLine();

            System.out.println("Senha:");
            String senha = new String(input.nextLine());

            FileReader arquivo = new FileReader(FILE_PATH + FILE_NAME);
            BufferedReader lerArq = new BufferedReader(arquivo);

            String linha = lerArq.readLine();
            while (linha != null) {
                String[] parametros = linha.split(";");
                String loginLinha = parametros[0] + ";" + parametros[1] + ";" + parametros[2] + ";" + parametros[3];

                byte[] chaveDerivHmacLogin = derivarChave(senha, Utils.toByteArray(parametros[3]));

                if (decrypt(loginLinha, Utils.toString(chaveDerivHmacLogin), login)) {

                    String senhaLinha = parametros[4] + ";" + parametros[5] + ";" + parametros[6] + ";" + parametros[7];
                    byte[] chaveDerivHmacSenha = derivarChave(Utils.toString(chaveDerivHmacLogin), Utils.toByteArray(parametros[7]));

                    if (decrypt(senhaLinha, Utils.toString(chaveDerivHmacSenha), senha)) {
                        System.out.println("Usuário autenticado com sucesso!");
                    }

                }

                linha = lerArq.readLine();
            }

            System.out.println("Usuário não cadastrado ou dados de login incorretos.");
            this.menu();
        } catch (Exception ex) {
            System.out.println("Erro ao autenticar usuário." + ex.getMessage());
        }
    }

    public byte[] derivarChave(
            String password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF_ITERATIONS, 128);
        byte[] derivedPass = null;
        try {
            SecretKeyFactory pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            SecretKey sk = pbkdf2.generateSecret(spec);
            derivedPass = sk.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return derivedPass;
    }

    public String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return Hex.encodeHexString(salt);
    }

    public String encrypt(byte[] senha, String texto, byte[] saltHmac) {

        try {
            SecureRandom r = SecureRandom.getInstance("SHA1PRNG");

            byte[] saltCifra = getSalt().getBytes();

            byte[] chaveDerivHmac = senha;
            byte[] chaveDerivCifra = derivarChave(Utils.toString(chaveDerivHmac), saltHmac);

            SecretKeySpec chaveCifra = new SecretKeySpec(chaveDerivCifra, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, chaveCifra, new GCMParameterSpec(128, saltCifra));
            byte[] textoCifrado = cipher.doFinal(Utils.toByteArray(texto));

            SecretKeySpec chaveHmac = new SecretKeySpec(chaveDerivHmac, "HmacSHA256");
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(chaveHmac);
            return Utils.toString(textoCifrado) + ";" + Utils.toString(hmac.doFinal(textoCifrado)) + ";" + Utils.toString(saltCifra) + ";"
                    + Utils.toString(saltHmac);

        } catch (Exception ex) {
            Logger.getLogger(GerenciadorLogin.class.getName()).log(Level.SEVERE, "Erro ao cifrar o texto", ex);
        }
        return null;
    }

    public boolean decrypt(String linha, String senha, String texto) {

        try {
            String[] tokens = linha.split(";");

            byte[] textoCifrado = tokens[0].getBytes();
            byte[] tag = tokens[1].getBytes();
            byte[] saltCifra = tokens[2].getBytes();
            byte[] saltHmac = tokens[3].getBytes();

            byte[] chaveDerivHmac = derivarChave(senha, saltHmac);

            SecretKeySpec chaveHmac = new SecretKeySpec(chaveDerivHmac, "HmacSHA256");
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(chaveHmac);
            byte[] tagGerada = hmac.doFinal(textoCifrado);

            if (MessageDigest.isEqual(tag, tagGerada)) {

                byte[] chaveDerivCifra = derivarChave(chaveDerivHmac.toString(), saltCifra);

                SecretKeySpec chaveCifra = new SecretKeySpec(chaveDerivCifra, "AES");
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, chaveCifra, new GCMParameterSpec(128, saltCifra));
                byte[] s = c.doFinal(textoCifrado);

                if (s.equals(texto)) {
                    return true;
                }

            }
        } catch (Exception e) {
            Logger.getLogger(GerenciadorLogin.class.getName()).log(Level.SEVERE, "Erro ao decifrar o texto", e);
        }
        return false;
    }
}
