/**
 * 
 * PAM-NSS-400: UI400
 * 
 * 
 */

package org.naturalcomputing.userinfo.as400;

import com.ibm.as400.access.*;
import java.io.*;

public abstract class UI400 {

   private static AS400 as400 = null;
   
   public static boolean debug = false;
   
   public static String sessionusername = "";	
   public static String username        = "";	
   public static String userid          = "";
   
   public static int UID_UNKNOWN = 65533;
   public static int UID_START   =   120;
   public static int UID_END     = 65535;
	
   public static int GID_UNKNOWN = 65534;
   public static int GID_START   =   100;
   public static int GID_END     = 65535;
   
   public static String USERNAME_UNKNOWN   = "nobody";	
//   public static String GROUPNAME_UNKNOWN = "*NONE";	
   public static String GROUPNAME_UNKNOWN  = "nogroup";	

   public static String SHELL  = "/bin/bash";	
   public static String SYSTEM = "";
	
   public static String userline      = "";
   public static String usergroups    = "";
   public static String usergroupIDs  = ":::";
   public static String [] grouplines = new String[1];
   

   private static AS400 getAS4001() {
      
      if (as400 == null) {
	 try {			
	    as400 = new com.ibm.as400.access.AS400();

	    as400.setGuiAvailable(false);
	    as400.setSystemName(SYSTEM);

	 } catch (java.lang.Throwable ivjExc) {

	    handleException(ivjExc);
	 }
      };
      
      return as400;
   }
   

   private static void handleException(Throwable exception) {

      /* Entfernen die den Kommentar für die folgenden Zeilen, um nicht abgefangene Ausnahmebedingungen auf der Standardausgabeeinheit (stdout) auszugeben */
      // System.out.println("--------- NICHT ABGEFANGENE AUSNAHMEBEDINGUNG ---------");
      exception.printStackTrace(System.out);
      //exit(1);
   }
   
   static String initDummyUserline(String name) {
      
      if (username.length()==0) {
	 username = name;
	 
	 userline = name + ":x:" + UID_UNKNOWN + ": " + GID_UNKNOWN + "::/home/" + name.toUpperCase() + ":" + SHELL;

	 grouplines[0] = GROUPNAME_UNKNOWN + ":x:" + GID_UNKNOWN + ":" + name;
      }
      
      return userline;
   }
   
   static void initUserInfo() {

      try {	
	 User u = new User(getAS4001(), getAS4001().getUserId());
	 
	 int groupcounter=0;
	 int uid=UID_UNKNOWN;
	 int pgid=GID_UNKNOWN;
	 userid      ="";
	 usergroups  ="";
	 usergroupIDs=":";
	 userline    ="";
	   
	   {
	      uid=u.getUserIDNumber();
	      if (uid<UID_START || uid >UID_END)
		throw new Exception("UID: " + uid + " out of Range-> " + UID_START + "<=UID>=" + UID_END);
	      
	      userline += username + ":x:" + uid + ":";
	      userid   += uid;
	      
	      String primaryGroupName = u.getGroupProfileName();
	      String primaryGroupLine = primaryGroupName+":x:";

	      if (primaryGroupName.equalsIgnoreCase("*NONE")) {
	
		 pgid = GID_UNKNOWN;		 	
	      
	      }else{	
		 User primGroup = new User(getAS4001(), primaryGroupName);
		 
		 pgid = primGroup.getGroupIDNumber();
		 
		 if (pgid<GID_START || pgid >GID_END)
		   throw new Exception("GID: " + pgid + " out of Range-> " + GID_START + "<=GID>=" + GID_END);
	      }
		
	      usergroups       += primaryGroupName;
	      primaryGroupLine += pgid + ":" + username;
	      groupcounter      = 1;			 	

	      userline         += pgid + ":" + u.getDescription() + ":" + u.getHomeDirectory() + ":" + SHELL;

	      //more groups...
	      int countOtherGroups = u.getSupplementalGroupsNumber();

	      groupcounter += countOtherGroups;			
	      grouplines    = new String[groupcounter];
	      grouplines[0] = primaryGroupLine;
	      
	      if (countOtherGroups > 0) {	
		 String [] grps = u.getSupplementalGroups();
		 
		 if (grps != null && grps.length > 0)			
		   for (int i = 0; grps!=null && i<grps.length  ; i++) {
		      User grp = new User(getAS4001(), grps[i]);
			
		      int sgid = grp.getGroupIDNumber();
		      
		      if (sgid < GID_START || sgid > GID_END)
			throw new Exception("GID: " + sgid + " out of Range-> " + GID_START + "<=GID>=" + GID_END);
		      
		      usergroupIDs += "," + sgid;
		      usergroups   += "," + grps[i];
		      
		      grouplines[i+1] = grps[i] + ":x:" + sgid + ":" + username;
		      groupcounter++;
		   }					
	      }						
	   }
      } catch (Exception e) {
	 e.printStackTrace();
	 userline = UIService.EMPTY_LINE;
      }
      
      if (debug) {

	 System.out.println("Userline:"+userline);
	 
	 for(int i=0; i < grouplines.length; i++)
	   System.out.println("Groupline:" + grouplines[i]);
      }
      
//      as400 = null;
   }
   
   public static boolean login(String uname, String pwd) {
      boolean ret = false;
      
      try {
	 if (! uname.equals(sessionusername)) {
	    if (debug)
	      System.out.println("Set UserId >" + uname + "<");
	         
	    getAS4001().setUserId(uname);
	    getAS4001().setPassword(pwd);
	 }

	 if (false == getAS4001().validateSignon())
	   throw new Exception("Signon failed!");

	 if (sessionusername.equals(username))
	   ret = true;
	 
	 if (!sessionusername.equals(uname)) {
	    sessionusername = uname;
	    username        = uname;

	    initUserInfo();
	 }

      } catch (Exception e) {
	 e.printStackTrace();
      }
      
      return ret;
   }

   private boolean systemCall(String command) {
      if (command == null)
	return true;
      
      try {
	 Runtime RT = null;
	 Process PR = null;
	 DataInputStream IS = null;
	 String s = null;
	 RT = Runtime.getRuntime();
	 
	 try {
	    PR = RT.exec(command);						      
	    if (PR.waitFor() != 0)
	      return false;
	 } catch( java.io.IOException e ) {
	    e.printStackTrace();  
	 }
	 
      }catch (Exception e) {
	 e.printStackTrace();
      }

      return true;
   }
}
