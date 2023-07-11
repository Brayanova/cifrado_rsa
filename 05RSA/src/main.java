import java.security.*;
import javax.crypto.*;
import java.io.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        
        System.out.println("1.- Vamos a crear las llaves pública y privada de RSA");
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        keygen.initialize(2048);
        
        KeyPair clavesRSA = keygen.genKeyPair();
        
        PublicKey clavePublica = clavesRSA.getPublic();
        PrivateKey clavePrivada = clavesRSA.getPrivate();
        
        System.out.println("Llave Pública: ");
        mostrarBytes(clavePublica.getEncoded());
        System.out.println("\n");
        
        System.out.println("Llave Privada: ");
        mostrarBytes(clavePrivada.getEncoded());
        System.out.println("\n");
        
        System.out.println("2.- Introduzca el texto que desea cifrar máximo 64 caracteres");
        
        byte[] bufferPlano = leerLinea(System.in);
        
        System.out.println("3.- Seleccione el modo de cifrado: ");
        System.out.println("    a. Cifrar con clave pública");
        System.out.println("    b. Cifrar con clave privada");
        System.out.print("Ingrese su opción: ");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String opcion = br.readLine();
        
        Cipher cifrador = Cipher.getInstance("RSA", "BC");
        Cipher descifrador = Cipher.getInstance("RSA", "BC");
        
        if (opcion.equals("a")) {
            cifrador.init(Cipher.ENCRYPT_MODE, clavePublica);
            descifrador.init(Cipher.DECRYPT_MODE, clavePrivada);
            System.out.println("Cifrando con clave pública y descifrando con clave privada...");
        } else if (opcion.equals("b")) {
            cifrador.init(Cipher.ENCRYPT_MODE, clavePrivada);
            descifrador.init(Cipher.DECRYPT_MODE, clavePublica);
            System.out.println("Cifrando con clave privada y descifrando con clave pública...");
        } else {
            System.out.println("Opción inválida. Saliendo del programa.");
            return;
        }
        
        System.out.println("Texto a cifrar: ");
        mostrarBytes(bufferPlano);
        System.out.println("\n");
        
        byte[] bufferCifrado = cifrador.doFinal(bufferPlano);
        
        System.out.println("Texto Cifrado: ");
        mostrarBytes(bufferCifrado);
        System.out.println("\n");
        
        byte[] bufferPlano2 = descifrador.doFinal(bufferCifrado);
        
        System.out.println("Texto Descifrado: ");
        mostrarBytes(bufferPlano2);
        System.out.println("\n");
    }

    public static byte[] leerLinea(InputStream in) throws IOException {
        byte[] buffer1 = new byte[1000];
        int i = 0;
        byte c;
        c = (byte)in.read();
        while((c != '\n') && (i < 1000)){
            buffer1[i] = c;
            c = (byte)in.read();
            i++;
        }
        
        byte[] buffer2 = new byte[i];
        for(int j = 0; j < i; j++){
            buffer2[j] = buffer1[j];
        }
        return buffer2;
    }

    public static void mostrarBytes(byte[] buffer) {
        System.out.write(buffer, 0, buffer.length);
    }
}
