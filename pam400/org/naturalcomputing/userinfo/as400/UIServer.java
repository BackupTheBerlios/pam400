
package org.naturalcomputing.userinfo.as400;


import java.net.*;
import java.io.*;

public class UIServer  implements Cloneable, Runnable {
   Thread runner = null;
   ServerSocket server = null;
   Socket data = null;
   boolean shouldStop = false;
   ThreadGroup group = null;
   int groupNo = 0;
   
   public synchronized void startServer(int port) throws IOException {
      if (runner == null) {
	 server = new ServerSocket(port, 200, InetAddress.getByName("localhost"));
	 runner = new Thread(this);
	 runner.start();
      }
   }
   
   public synchronized void stopServer() {
      if (server != null) {
	 shouldStop = true;
	 runner.interrupt();
	 runner = null;
	 try {
	    server.close();
	 } catch (IOException ioe) {}
	 server = null;
      }
   }
   
   public void run() {
      if (server != null) {
	 while (!shouldStop) {
	    try {
	       Socket datasocket = server.accept();
	       UIServer newSocket = (UIServer) clone();
	       newSocket.server = null;
	       newSocket.data = datasocket;
	       newSocket.group = new ThreadGroup("PAM-NSS-400-" + groupNo++);
	       newSocket.runner = new Thread(newSocket.group, newSocket);
	       newSocket.runner.start();
	    } catch (Exception e) {
	       e.printStackTrace();
	       System.exit(1);
	    }
	 }
      }else{ 
	run(data);
      }
      
   }
   
   public void run(Socket data) { }
   
}
