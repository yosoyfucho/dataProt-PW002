import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;

import javax.crypto.Cipher;


public class Main{
	
	public static void main(String args[]){

		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		String plaintextString = "Hola Rafa, esto es un mensaje super secreto";
		byte[] plaintext = null;
		byte[] ciphertext = null;
		byte[] decryptedPlaintext = null;
		byte[] generatedSignature = null;
		boolean isVerified = false;
		
		RSALibrary rsa = new RSALibrary();
		
		plaintext = plaintextString.getBytes();
		
		try{
			
			rsa.generateKeys();
			
			//comprobar que existen los ficheros tras generar las claves
			
			File filePublicKey = new File("./public.key");
			File filePrivateKey = new File("./private.key");
			File prueba = new File("./prueba.txt");
			
		
			//Si existe el fichero de clave publica, la obtenemos y encriptamos
			if(filePublicKey.exists() && !filePublicKey.isDirectory()) 
			{ 
				System.out.println("Existe public.key");
				FileInputStream fileInput = new FileInputStream(filePublicKey);
				ObjectInputStream objectInputStream = new ObjectInputStream(fileInput);
				publicKey = (PublicKey) objectInputStream.readObject();
				objectInputStream.close();
			
				ciphertext = rsa.encrypt(plaintext, publicKey);
			}
			else
			{
				System.out.println("Archivo de clave publica no creado");
			}
		
			//Si existe el fichero de clave privada, la obtenemos y desencriptamos
			if(filePrivateKey.exists() && !filePrivateKey.isDirectory()) 
			{ 
				System.out.println("Existe private.key");
				FileInputStream fileInput = new FileInputStream(filePrivateKey);
				ObjectInputStream objectInputStream = new ObjectInputStream(fileInput);
				privateKey = (PrivateKey) objectInputStream.readObject();
				objectInputStream.close();
		
				decryptedPlaintext = rsa.decrypt(ciphertext, privateKey);
			}
			else
			{
				System.out.println("Archivo de clave privada no creado");
			}
		
			System.out.println("Plaintext original:      " + plaintextString);
			String ciphertextString = new String(ciphertext);
			System.out.println("Texto cifrado:      " + ciphertextString);	
			String decryptedPlaintextString = new String(decryptedPlaintext);
			System.out.println("Plaintext desencriptado: " + decryptedPlaintextString);
			
			
			System.out.println("Ahora a firmar ! ");
			
			byte[] signatureToBeVerified = rsa.sign(plaintext, privateKey);
			System.out.println("Firma: " + signatureToBeVerified.toString());
			
			isVerified = rsa.verify(plaintext, signatureToBeVerified, publicKey);
		
			System.out.println("¿La firma es correcta? : " + isVerified);
		
		}
		catch(IOException | ClassNotFoundException e)
		{
			e.printStackTrace();
		}
		
		
	}

}