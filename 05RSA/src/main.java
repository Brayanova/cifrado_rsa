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
        
        Cipher cifrador = Cipher.getInstance("RSA", "BC");
        
        cifrador.init(Cipher.ENCRYPT_MODE, clavePrivada);
        
        System.out.println("3.- Ciframos con la clave privada: ");
        byte[] bufferCifrado = cifrador.doFinal(bufferPlano);
        System.out.println("Texto Cifrado: ");
        mostrarBytes(bufferCifrado);
        System.out.println("\n");
        
        cifrador.init(Cipher.DECRYPT_MODE, clavePublica);
        
        System.out.println("4.- Desciframos con la clave pública: ");
        byte[] bufferPlano2 = cifrador.doFinal(bufferCifrado);
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

