import java.net.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.io.*; 
import Encryption.*;

public class Client { 
    private Socket socket = null; 
    private BufferedReader input = null; 
    private DataOutputStream out = null; 
    private DataInputStream in = null; 
    private PublicKey serverPublicKey;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    
    private RSA keyPair = new RSA();

    public void connectToServer(String address, int port){
        try{ 
            socket = new Socket(address, port); 
            System.out.println("Connected"); 
            // sends output to the socket 
            
            System.out.println("Generating private connection");
            keyPair.GenerateKeyPair();
            privateKey=keyPair.getPrivateKey();
            publicKey = keyPair.getPublicKey();
            System.out.println("Connection generated");


            in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            serverPublicKey = RSA.getPublicKey(in.readUTF());


            out = new DataOutputStream(socket.getOutputStream());
            String pub = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            out.writeUTF(pub);

            System.out.println("Ready to chat");
        } 
        catch(Exception e) { 
            System.out.println(e);
        }
    }

    public void sendMSG() {         
        // takes input from terminal 
        input = new BufferedReader(new InputStreamReader(System.in));

        String line = ""; 
        while (true){ 
            try{ 
                line = input.readLine();
                String str= RSA.encrypt(line, serverPublicKey);
                out.writeUTF(str);
            } 
            catch(Exception i) { 
                System.out.println("Server is disconected");
                close();
                break;
            } 
        } 
        
    } 

    public void reciveMSG(){
        // takes inputs from the Server 
		String line = ""; 
		while (true) { 
			try{ 
                line = in.readUTF();
                String str = RSA.decrypt(line, privateKey);
				System.out.println("Server : " + str); 
			} 
			catch(Exception e){ 
                System.out.println("Server is disconected");
                close();
                break;
			} 
        }
    }

    public void close(){
        // close the connection 
        try{ 
            input.close(); 
            out.close(); 
            socket.close(); 
        } 
        catch(IOException i) { 
        } 
    }
  
    public static void main(String args[]){ 
        Client client = new Client();
        client.connectToServer("192.168.1.9", 4789);

        new Thread(new Runnable(){
            @Override
            public void run() {
                client.sendMSG();
            }
        }).start();

        new Thread(new Runnable(){
        
            @Override
            public void run() {
                client.reciveMSG();
            }
        }).start();
    } 
} 
