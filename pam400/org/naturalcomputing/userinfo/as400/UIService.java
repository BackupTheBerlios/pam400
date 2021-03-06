
package org.naturalcomputing.userinfo.as400;


import java.net.*;
import java.io.*;
import java.util.*;


public class UIService extends UIServer {

   public final static int INTERRUPT = 0;

   public void run(Socket data) {
      threadGroup = new ThreadGroup("PAM-NSS-400-");
      
      try {
	 is  = data.getInputStream();
	 os  = data.getOutputStream();
	 osw = new PrintWriter(os);
	 String cmd = getCommand(is);
	 
	 doCommand(cmd);				

      } catch (Exception e) {
	 e.printStackTrace();
	 threadGroup.interrupt();
      }
   }

   public static void main(String args[]) {

      try {
//	 int port      = UIService.DEFAULT_PORT;
	 int port      = UIService.getServiceByName("ncclient", "tcp");
	 UIServer serv = new UIService();
	 UI400.SYSTEM  = args[0];
	 
	 UI400.debug   = debug;
	 
	 serv.startServer(port);			

      } catch (Exception e) {	
	 e.printStackTrace();
	 System.exit(1);		
      }
   }



//   public final static int DEFAULT_PORT  = 55443;
   public final static String EMPTY_LINE = ":::";
   public static boolean debug = false;
   InputStream is = null;
   public int max_output_len = 512;
   OutputStream os = null;
   PrintWriter osw = null;
   ThreadGroup threadGroup;
   final String tz = ":";
   
   void answer(String output) {
      
      try {
	 if (debug)
	   System.out.println("answer: >" + output + "< (" + output.length() + ")");
	 
	 if (output.length() > max_output_len)
	   output = output.substring(0, max_output_len);
	 
	 osw.println(output);
	 
	 osw.flush();
      } catch (Exception e) { 
	 e.printStackTrace();
      }
   }

   String checkPassword(String username, String password) {
      String ok="ko";
      
      try {
	if (UI400.login(username, password) == true)
	   ok = "ok";
      } catch (Exception e) {
	 ok = "ko"; 
      }
      
      return ok;
   }

   void doCommand(String line) {
      
      if (line == null)
	return;
      
      String output = EMPTY_LINE;
      
      if (debug) {
	 System.out.println("usernane: "  + UI400.username);
	 System.out.println("userline: "  + UI400.userline);
	 System.out.println("groupline: " + UI400.grouplines[0]);
      }
      
      try {
	 
	 if (debug)
	   System.out.println("doCommand: " + line);
	 
	 java.util.StringTokenizer st = new java.util.StringTokenizer(line, ":");
	 if (st.countTokens() != 3)
	   throw new Exception("wrong command line for UIService->'"+line+"'");
	 
	 String command = st.nextToken();
	 String param1  = st.nextToken();
	 String param2  = st.nextToken();

	 if (debug)
	   System.out.println("command: " + command + " PARAM1:" + param1 + "  PARAM2:" + param2);
	 
	 if (!command.equals("password"))
	   max_output_len = new Integer(param2).intValue();
	 
	 if (command.equalsIgnoreCase("username")) {
	    if (!param1.equals(UI400.sessionusername)) {
	       output = UI400.initDummyUserline(param1);
	    }else{
	       output = UI400.userline;
	    }
	 }else{
	    if (command.equalsIgnoreCase("initgroups")) {
	       if (param1.equals(UI400.sessionusername))
		 output = UI400.usergroupIDs;
	    }else{
	       if (command.equalsIgnoreCase("groupname")) {
		  output = getGroupInfoLineByName(param1);
	       }else {
		  if (command.equalsIgnoreCase("gid")) {
		     output = getGroupInfoLineById(param1);
		  }else{
		     if (command.equalsIgnoreCase("uid")) {
			if (param1.equals(UI400.userid))
			  output = UI400.userline;
		     }else{
			if (command.equalsIgnoreCase("shadowname")) {
			   output = param1+":x:10000:0:99999:7:-1:-1:-1"; 
			}else{
			   if (command.equalsIgnoreCase("password"))
			     output = checkPassword(param1,param2);
			}
		     }
		  }
	       }
	    }
	 }
	 
      } catch (Exception e) { 
	 e.printStackTrace();	
      }finally{
	 answer(output);
      }	
   }
   
   private String getCommand(InputStream is) {
      String command = null;
      
      try {
	 InputStreamReader in  = new InputStreamReader(is);
	 BufferedReader reader = new BufferedReader(in);
	 
	 command = reader.readLine();

      } catch (Exception e) { 
	 e.printStackTrace();
      }
      
      return command;
   }

   public String getGroupInfoLineById(String id) {	
      String ret = EMPTY_LINE;
      
      try {
	 for (int i=0; i < UI400.grouplines.length; i++)
	   {	
	      java.util.StringTokenizer st = new java.util.StringTokenizer(UI400.grouplines[i], ":");
	      st.nextToken();
	      st.nextToken();
	      String gid = st.nextToken();
	      if (id.equals(gid)) {
		 ret = UI400.grouplines[i];
		 break;
	      }
	   }
      } catch( Exception e) {
	 e.printStackTrace(); 
      }
      
      return ret;
   }

   public String getGroupInfoLineByName(String name) {	
      String ret = EMPTY_LINE;
      
      try {
	 for (int i=0; i < UI400.grouplines.length; i++)
	   if (UI400.grouplines[i].startsWith(name)) {
	      ret = UI400.grouplines[i];
	      break;
	   }
      } catch( Exception e) { 
	 e.printStackTrace();
      }
      
      return ret;
   }
   
   final static private String SERVICES_FILENAME = "/etc/services";

   static private int parseServicesLine(String line,
					String tcpipService,
					String tcpipClass) {
      // Parse line
      StringTokenizer st = new StringTokenizer(line, " \t/#");

      // First get the name on the line (parameter 1):
      if (! st.hasMoreTokens()) {
	 return -1; // error
      }
      String name = st.nextToken().trim();
   
      // Next get the service name on the line (parameter 2):
      if (! st.hasMoreTokens()) {
	 return -1; // error
      }
      String portValue = st.nextToken().trim();

      // Finally get the class on the line (parameter 3):
      if (! st.hasMoreTokens()) {
	 return -1; // error
      }
      String classValue = st.nextToken().trim();

      //System.out.println("DEBUG: name: "
      // + name + ", portValue: " + portValue
      // + ", serviceValue: " + serviceValue);

      // Class doesn't match--reject:
      if (! classValue.equals(tcpipClass)) {
	 return -1; // error
      }
      
      // Return port number, if name on this line matches:
      if (name.equals(tcpipService)) {
	 try { // Convert the port number string to integer
	    return (Integer.parseInt(portValue));
	 } catch (NumberFormatException nfe) {
	    // Ignore corrupt /etc/services lines:
	 return -1; // error
	 }
      } else {
	 return -1; // no match
      }
   }	// parseServicesLine()


   static public int getServiceByName(String tcpipService,
				      String tcpipClass) {
      int	port = -1;
      
      // Look for our service, line-by-line:
      try {
	 String line;
	 BufferedReader br = new BufferedReader(
			        new InputStreamReader(
				   new FileInputStream(
				      SERVICES_FILENAME)));

	 // Read /etc/services file.
	 // Skip comments and empty lines.
	 while (((line = br.readLine()) != null)
		  && (port == -1)) {
	    if ((line.length() != 0)
		 && (line.charAt(0) != '#')) {
	       port = parseServicesLine(line, tcpipService, tcpipClass);
	    }
	 }	// while
	 br.close();
	 
	 return (port); // port number or -1 (on error)
	 
      } catch (IOException ioe) {
	 // File doesn't exist or is otherwise not available.
	 // Keep defaults
	 return -1; // error
      }
   }	// getServiceByName

}
