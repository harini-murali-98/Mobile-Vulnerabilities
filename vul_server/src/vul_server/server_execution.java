package vul_server;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import javax.print.DocFlavor.STRING;

public class server_execution {

	static int port = 5011;
	static ServerSocket serverSocket;
	static Socket socket;

	static int spflag = 0;
	static int empty = 0;

	public static void main(String[] args) {
		String packName = new String();
		String code = new String();
		List<String> tmp = new ArrayList<String>();

		try {
			serverSocket = new ServerSocket(port);

			while (true) {
				// Reading the message from the client
				socket = serverSocket.accept();
				ObjectInputStream is = new ObjectInputStream(socket.getInputStream());
				;

				tmp = (List<String>) is.readObject();
				packName = tmp.get(0);
				code = tmp.get(1);
				System.out.println(packName);
				System.out.println(code);

//				switch (code) {
//				case "M1":
//
//					executeADB(packName);
//					break;
//				case "M2":
//					executeADB_encryption(packName);
//					break;
//				case "M3":
//					executeADB_dataleak(packName);
//					break;
//
//				case "M5":
//					executeADB_clipboardleak(packName);
//					break;
//
//				}
				
				String sharedPrefVul = executeADB(packName);
				String localDBVul = executeADB_encryption(packName);
				String logVul = executeADB_dataleak(packName);
				String clipboardVul = executeADB_clipboardleak(packName);
				
				String serverResponse = sharedPrefVul+"\n"+localDBVul+"\n"+logVul+"\n"+clipboardVul;
				
				ObjectOutputStream os = new ObjectOutputStream(socket.getOutputStream());
				os.writeObject(serverResponse);
				
				

			}

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	// vul-1 (shared prefs check)
	public static String executeADB(String pack) throws IOException {

		ExecuteCommand ec = new ExecuteCommand();

		String nameOfSharedPrefFile = ec
				.command("adb shell run-as " + pack + " ls /data/data/" + pack + "/shared_prefs ");
		System.out.println(nameOfSharedPrefFile);
		System.out.println("Name of SP File is " + nameOfSharedPrefFile);
		if (!nameOfSharedPrefFile.contentEquals("")) {
			String fileContent = ec.command(
					"adb shell run-as " + pack + " cat /data/data/" + pack + "/shared_prefs/" + nameOfSharedPrefFile);
			System.out.println("The file contents are " + fileContent);
			if (!fileContent.equals("") && !nameOfSharedPrefFile.equals("")) {
				spflag = 1;
			}
		}
		if (nameOfSharedPrefFile.trim().equals("ls: /data/data/" + pack + "/shared_prefs: No such file or directory")) {
			spflag = 0;
		}

		if (spflag == 1) {
			String messageS = "Yes";
		

			spflag = 0;
			
			return messageS;

		} else {
			String messageF = "No";
			
     
			return messageF;
		}
	}

	// vul-2 (encrypted db check)
	public static String executeADB_encryption(String pack) throws IOException {
		String message = "";
		String localDb;
		ExecuteCommand ec = new ExecuteCommand();
		
		String nameOfDBFiles = ec.command("adb shell run-as " + pack + " ls /data/data/" + pack + "/databases");
		System.out.println("Name of database " + nameOfDBFiles);
		String dbnames[] = nameOfDBFiles.split("\n");
		List<String> localDB = new ArrayList<String>();

		for (String file : dbnames) {
			if (file.endsWith(".db"))
				localDB.add(file.toString());
		}

		System.out.println("The local database is " + localDB.toString());

		if (localDB.size() > 0) {
			for (String db : localDB) {
				ec.command("adb pull /data/data/" + pack + "/databases/" + db + "C:\\Users\\mhari\\DBFiles");

				if (isValidSQLite("C:\\Users\\mhari\\DBfiles\\" + db)) {
					System.out.println("db present but not excrypted");
					message = "Yes";
					
					
					
				} else {
					System.out.println("db present and  excrypted");
					message="No";

					
									}

			}

		} else {
			System.out.println("db not present");
			message="No";
		
			
			
			
		}
		return message ;

	}

	public static boolean isValidSQLite(String dbPath) {
		File file = new File(dbPath);

		if (!file.exists() || !file.canRead()) {
			return false;
		}

		try {
			FileReader fr = new FileReader(file);
			char[] buffer = new char[16];

			fr.read(buffer, 0, 16);
			String str = String.valueOf(buffer);
			fr.close();
			System.out.println(str);

			return str.equals("SQLite format 3\u0000");

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	// vu;-3(data leakage check)
	public static String executeADB_dataleak(String pack) throws IOException {
String message="";
		ExecuteCommand ec = new ExecuteCommand();
	
		String pid = ec.command("adb shell pidof " + pack);
		pid = pid.replaceAll("\\n", "");
		ec.command("cmd /c adb logcat -d > C:\\Users\\mhari\\Desktop\\log_capture.txt");
		File newFile = new File("C:\\\\Users\\\\mhari\\\\Desktop\\\\log_capture.txt");

		if (newFile.length() == 0) {
			
			System.out.println("File is empty after creating it...");

			message = "No";
			
		} else {
			System.out.println("File is not empty after creation...");

			message = "Yes";
			
		}
return message;
	}

	private static String executeADB_clipboardleak(String packName) throws IOException {
String message="";
		ExecuteCommand ec = new ExecuteCommand();
		
		String packages_with_clipboard = ec.command("adb shell cmd appops query-op --user 0 READ_CLIPBOARD allow");
		if (packages_with_clipboard.contains(packName)) {
			System.out.println("vul");
			message = "Yes";
			

		} else {
			System.out.println("not");
			message = "No";
			
		}
return message;
	}

}
