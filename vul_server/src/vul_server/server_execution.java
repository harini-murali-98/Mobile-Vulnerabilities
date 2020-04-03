package vul_server;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class server_execution {

	static int port = 5011;
	static ServerSocket serverSocket;
	static Socket socket;
	static String vul1_details = "";
	static String vul2_details = "";
	static String vul3_details;
	static String vul4_details;
	static int spflag = 0;
	static int empty = 0;

	public static void main(String[] args) {
		String packName = new String();

		List<String> tmp = new ArrayList<String>();

		try {
			serverSocket = new ServerSocket(port);

			while (true) {
				// Reading the message from the client
				socket = serverSocket.accept();
				ObjectInputStream is = new ObjectInputStream(socket.getInputStream());

				tmp = (List<String>) is.readObject();
				packName = tmp.get(0);

				System.out.println(packName);

				String sharedPrefVul = executeADB(packName);
				String localDBVul = executeADB_encryption(packName);
				String logVul = executeADB_dataleak(packName);
				String clipboardVul = executeADB_clipboardleak(packName);

				String resultDetails;
				resultDetails = vul1_details + "\n" + vul2_details + "\n\n" + vul3_details + "\n\n" + vul4_details;
				// System.out.print("Result"+resultDetails+"over");

				List<String> server_response = new ArrayList<String>();
				server_response.add(sharedPrefVul + "\n" + localDBVul + "\n" + logVul + "\n" + clipboardVul);
				server_response.add(resultDetails);

				System.out.println("Server " + server_response.toString());
				ObjectOutputStream os = new ObjectOutputStream(socket.getOutputStream());
				os.writeObject(server_response);
				System.out.println("sent");

			}

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	// vul-1 (shared prefs check)
	public static String executeADB(String pack) throws IOException {
		vul1_details = "";
		ExecuteCommand ec = new ExecuteCommand();
		String fileContent = "";
		String nameOfSharedPrefFile = ec
				.command("adb shell run-as " + pack + " ls /data/data/" + pack + "/shared_prefs ");

		if (!nameOfSharedPrefFile.contentEquals("")) {
			fileContent = ec.command(
					"adb shell run-as " + pack + " cat /data/data/" + pack + "/shared_prefs/" + nameOfSharedPrefFile);

			if (!fileContent.equals("") && !nameOfSharedPrefFile.equals("")) {
				spflag = 1;
			}
		}
		if (nameOfSharedPrefFile.trim().equals("ls: /data/data/" + pack + "/shared_prefs: No such file or directory")) {
			spflag = 0;
		}

		if (spflag == 1) {
			String messageS = "Yes";
			vul1_details = vul1_details + "Name of SP File is " + nameOfSharedPrefFile + "The file contents are "
					+ fileContent + "\n";

			spflag = 0;

			return messageS;

		} else {
			String messageF = "No";

			vul1_details = "Data is secured" + "\n";
			return messageF;
		}
	}

	// vul-2 (encrypted db check)
	public static String executeADB_encryption(String pack) throws IOException {
		String message = "";
		vul2_details = "";
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
				System.out.print(db);
				ec.command("adb pull /data/data/" + pack + "/databases/" + db + " C:\\Users\\mhari\\DBFiles");

				if (isValidSQLite("C:\\Users\\mhari\\DBfiles\\" + db)) {
					System.out.println("db present but not excrypted");
					message = "Yes";
					vul2_details = vul2_details + "Name of database " + nameOfDBFiles;
					vul2_details = vul2_details + "The local database is " + db.toString();

				} else {
					System.out.println("db present and  excrypted");
					message = "No";
					vul2_details = "Data is secured";

				}

			}

		} else {
			System.out.println("db not present");
			message = "No";
			vul2_details = "Data is secured";

		}
		return message;

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
		String message = "";
		vul3_details = "";
		ExecuteCommand ec = new ExecuteCommand();

		String pid = ec.command("adb shell pidof " + pack);
		pid = pid.replaceAll("\\n", "");
		ec.command("cmd /c adb logcat -d > C:\\Users\\mhari\\log_file\\log_capture.txt");
		File newFile = new File("C:\\Users\\mhari\\log_file\\log_capture.txt");

		if (newFile.length() == 0) {

			System.out.println("File is empty after creating it...");
			vul3_details = "Data is secured";
			message = "No";

		} else {
			System.out.println("File is not empty after creation...");

			FileReader fr = new FileReader(newFile);
			BufferedReader br = new BufferedReader(fr);
			String line;
			while ((line = br.readLine()) != null) {
				// process the line
				vul3_details += line;
			}

			message = "Yes";

		}
		return message;
	}

	private static String executeADB_clipboardleak(String packName) throws IOException, UnsupportedFlavorException {
		String message = "";
		vul4_details = "";
		ExecuteCommand ec = new ExecuteCommand();

		String packages_with_clipboard = ec.command("adb shell cmd appops query-op --user 0 READ_CLIPBOARD allow");
		if (packages_with_clipboard.contains(packName)) {
			Clipboard c = Toolkit.getDefaultToolkit().getSystemClipboard();

			System.out.println("vul");
			message = "Yes";

			vul4_details += c.getData(DataFlavor.stringFlavor);
		} else {
			System.out.println("not");
			message = "No";
			vul4_details = "Data is secured";

		}
		return message;
	}

}