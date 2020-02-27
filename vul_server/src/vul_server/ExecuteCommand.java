package vul_server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class ExecuteCommand {





public String command(String cmd)
{
StringBuilder output = new StringBuilder();
try {
	
	//Process process1 = Runtime.getRuntime().exec("adb -s emulator-5554 shell");
    Process process = Runtime.getRuntime().exec(cmd);
BufferedReader reader = new BufferedReader(
new InputStreamReader(process.getInputStream()));

String line;
while ((line = reader.readLine()) != null) {
output.append(line + "\n");
}


}

catch (IOException e) {
e.printStackTrace();
}
return output.toString();
}

}