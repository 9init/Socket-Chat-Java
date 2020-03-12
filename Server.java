import java.net.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.io.*; 
import Encryption.*;

public class Server{ 
	private Socket socket = null; 
	private ServerSocket server = null; 
    private DataInputStream in = null; 
    private BufferedReader input = null; 
    private DataOutputStream out = null; 

    private PublicKey clientPubKey;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private RSA keyPair = new RSA();

    public void startServer(int port){
        try{ 
			server = new ServerSocket(port); 
			System.out.println("Server started"); 

			System.out.println("Waiting for a client ...be patient"); 

            //waiting for client
			socket = server.accept(); 
            System.out.println("Client Connected"); 
            
            System.out.println("Generating private connection");
            keyPair.GenerateKeyPair();
            privateKey=keyPair.getPrivateKey();
            publicKey = keyPair.getPublicKey();
            System.out.println("Connection generated");


            out = new DataOutputStream(socket.getOutputStream());
            String pub = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            out.writeUTF(pub);

            in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            clientPubKey = RSA.getPublicKey(in.readUTF());

            System.out.println("Ready to chat");
		} 
		catch(Exception e){ 
			System.out.println(e); 
		} 
    }

    public void closeConnectio(){
        try {
            System.out.println("Closing connection"); 
		    // close connection 
		    socket.close(); 
            in.close(); 
        } catch (Exception e) {
        }
        
    }

    public void reciveMSG(){
        // takes inputs from the client 
		String line = ""; 
		while (true) { 
			try{ 
                line = in.readUTF();
                String str = RSA.decrypt(line, privateKey);
				System.out.println("Client : " + str); 
			} 
			catch(Exception e){ 
				System.out.println("Client is disconected");
                closeConnectio();
                return;
			} 
        }
    }

    public void sendMSG() {
        // takes input from terminal 
        input = new BufferedReader(new InputStreamReader(System.in));

        String line = ""; 
        while (true){ 
            try{
                line = input.readLine();
                String str = RSA.encrypt(line, clientPubKey);
                out.writeUTF(str);
            } 
            catch(Exception e) { 
                System.out.println("Client is disconected");
                closeConnectio();
                return;
            } 
        } 
        
    } 


	public static void main(String args[]){ 
        Server sock = new Server(); 
        sock.startServer(4789);

        new Thread(new Runnable(){
            @Override
            public void run() {
                sock.reciveMSG();                
            }
        }).start();

        new Thread(new Runnable(){
        
            @Override
            public void run() {
                sock.sendMSG();
            }
        }).start();
	} 
} 
