package Turtle;

/**
 * @author xp4xbox
 * Date: June 10, 2018
 * Turtle.java
 * Dictionary based anti-virus to determine if a file is infected with a virus.
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.MessageDigest;
import javax.xml.bind.DatatypeConverter;
import javafx.application.Application;
import javafx.concurrent.Task;
import javafx.geometry.HPos;
import javafx.geometry.Insets;
import javafx.geometry.VPos;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.layout.GridPane;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontPosture;
import javafx.scene.text.FontWeight;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javax.swing.filechooser.FileSystemView;

public class Turtle extends Application {
	
	// create global constants to store the title and the location of the cloud dictionary
	final static String TITLE = "Turtle Anti-Virus";
	final static String CLOUD_DICTIONARY = "https://raw.githubusercontent.com/xp4xbox/Turtle-Anti-Virus/master/resources/dictionary";
	
	public static void main(String[] args) {
		// launch gui
		launch(args);
	}

	// main gui method
	
	@Override
	public void start(Stage primaryStage) throws Exception {
		
		// create a stage and set the title and prevent from being resized
		Stage stgMainWindow = primaryStage;
		stgMainWindow.setTitle(TITLE);
		stgMainWindow.setResizable(false);
		
		// add icon
		stgMainWindow.getIcons().add(new Image(getClass().getResourceAsStream("icon.png")));

		// create new grid pane with spacing to look nice
		GridPane grdGridPane = new GridPane();
		grdGridPane.setPadding(new Insets(10, 10, 10, 10));
		grdGridPane.setVgap(8);
		grdGridPane.setHgap(10);
		
		// create a label for the title of the program to be in bold and in italics
		Label lbTitle = new Label(TITLE);
		lbTitle.setFont(Font.font(null, FontWeight.BOLD, FontPosture.ITALIC, 16));
		
		// place the title in the upper center field of the window
		GridPane.setConstraints(lbTitle, 0, 0, 5, 1, HPos.CENTER, VPos.CENTER);
		
		// create a new text field to store the file path of the file browsed by the user
		TextField txtFilePath = new TextField();
		
		// prevent the text field from being editable
		txtFilePath.setEditable(false);
		
		// set size and place it in the window
		txtFilePath.setPrefColumnCount(100);
		GridPane.setConstraints(txtFilePath, 0, 2, 4, 1);
		
		// create a new button for the file that will be browsed
		Button btnBrowseFile = new Button("Browse File");
		
		// set size and place it in the window
		btnBrowseFile.setPrefWidth(80);
		GridPane.setConstraints(btnBrowseFile, 4, 2);
		
		// create label to simply say MD5 to be placed in front of the next text field
		Label lbMD5 = new Label("MD5:");
		GridPane.setConstraints(lbMD5, 0, 4);

		// create text field to store the MD5 checksum that will be generated
		TextField txtMD5Field = new TextField();
		
		// prevent the text field from being editable and place it right next to the previous label
		txtMD5Field.setEditable(false);
		GridPane.setConstraints(txtMD5Field, 1, 4, 4, 1);

		// create label to say Status
		Label lbStatusTitle = new Label("Status:");
		
		// make the font bold and place it right below the previous label
		lbStatusTitle.setFont(Font.font(null, FontWeight.BOLD, 12));
		GridPane.setConstraints(lbStatusTitle, 0, 5);

		// create label to be in front of "Status:" which will display if the file is Clean or Infected.
		Label lbStatus = new Label();
		GridPane.setConstraints(lbStatus, 1, 5);

		// add everything to grid
		grdGridPane.getChildren().addAll(lbTitle, txtFilePath, btnBrowseFile, lbMD5, txtMD5Field, lbStatusTitle, lbStatus);

		// create new scene with window dimensions
		Scene scnMainScene = new Scene(grdGridPane, 380, 136);
		stgMainWindow.setScene(scnMainScene);
		
		// show the main window
		stgMainWindow.show();
		
		// lambda function if the browse file button is pressed
		btnBrowseFile.setOnAction(evtStart -> {
			// call the method to get file path from user
			String strFilePath = browseForFile(stgMainWindow);
			
			// if the user did not cancel the open file dialogue
			if (strFilePath != "none") {
				// set the file path in the txtFilePath text field
				txtFilePath.setText(strFilePath);
				
				// reset the fields from any previous scan
				txtMD5Field.setText(null);
				lbStatus.setText(null);
				
				// disable the button while the file is being scanned
				btnBrowseFile.setDisable(true);
				
				// create a new instance of the ValuesForUI class
				ValuesForUI objValuesForUI = new ValuesForUI();

				
				// create a new task to run as a thread to handle the heavy background processing
				Task<Void> tskOnButtonClickTask = new Task<Void>() {
					@Override
					public Void call() {
						// generate md5 hash as byte array
						byte[] arrbytMD5Hash = hashGenerator(strFilePath);
						
						// convert the byte array to hex string
						String strMD5Checksum = byteArrayToString(arrbytMD5Hash);
						
						// set the variable to store the checksum for gui
						objValuesForUI.setStrCheksum(strMD5Checksum);

						// if the checksum did not return an error
						if (!strMD5Checksum.equals("00")) {
							// call method to determine if the file is infected
							objValuesForUI.setSgnInfected(compareChecksum(strMD5Checksum, CLOUD_DICTIONARY));
						
						// if the checksum was generated with an error
						} else {
							// set the status for the gui to be none
							objValuesForUI.setSgnInfected(Signal.None);
						}
						
						// javafx Void different from java void, so in order to avoid syntax errors, I must return null
						return null;
					}
				};

				// when the task thread is completed
				tskOnButtonClickTask.setOnSucceeded(evtTaksDone -> {
					
					// if there was an error getting the checksum, display an error messagebox
					if (objValuesForUI.getStrChecksum().equals("00")) {
						errorMessageBox("Error getting MD5 Hash!", TITLE);
						
					} else {
						// set the gui md5 field to be the checksum generated
						txtMD5Field.setText(objValuesForUI.getStrChecksum());
						
						// if the file is not infected, set the status on the gui to Clean in a green color
						if (objValuesForUI.getSgnInfected() == Signal.False) {
							lbStatus.setText("Clean!");
							lbStatus.setTextFill(Color.GREEN);

						// if the file is infected, set the status on the gui to be Infected in a red color
						} else if (objValuesForUI.getSgnInfected()  == Signal.True) {
							lbStatus.setText("Infected!");
							lbStatus.setTextFill(Color.RED);
						
						// if there was an error while scanning, show error message box
						} else if (objValuesForUI.getSgnInfected() == Signal.Error) {
							errorMessageBox("Error scanning file!", TITLE);
							
						// if there was a network error reaching the cloud dictionary, show error message box
						} else if (objValuesForUI.getSgnInfected() == Signal.NetworkError) {
							errorMessageBox("Could not reach cloud dictionary! Please check your internet connection.", TITLE);
						}
					}
					
					// enable the button once the scan has finished
					btnBrowseFile.setDisable(false);
				});
				
				// run the task as a thread
				new Thread(tskOnButtonClickTask).start();
			}
		});
	}
	
	// method to display error message box
	public static void errorMessageBox(String message, String title) {
		// create new message box with an error icon
		Alert altAlert = new Alert(AlertType.ERROR);
		
		// set the title and message to display
		altAlert.setTitle(title);
		altAlert.setHeaderText(null);
		altAlert.setContentText(message);
		
		// show the message box
		altAlert.showAndWait();
	}
	
	// method to browse for file
	public static String browseForFile(Stage window) {
		// create a new file chooser
		FileChooser flcFileChooser = new FileChooser();
		
		// set text for dialogue
		flcFileChooser.setTitle("Open file to scan");
		
		/*
		 * set the initial directory to be the desktop since when most people want to scan a file,
		 * they usually have it on the desktop.
		*/
		flcFileChooser.setInitialDirectory(FileSystemView.getFileSystemView().getHomeDirectory());
		
		// get the file from the open file dialogue
		File fleFile = flcFileChooser.showOpenDialog(window);
		
		// define String var to store the file path as string
		String strFilePath;
		
		// if the user canceled the open file dialogue
		if (fleFile == null) {
			// set the path to be none
			strFilePath = "none";
			
		// otherwise set the strFilePath to be the absolute path of the file chosen
		} else {
			strFilePath = fleFile.getAbsolutePath();
		}
		
		// return the file path
		return strFilePath;
		
	}
	
	// method to generate MD5 hash as byte array
	public static byte[] hashGenerator(String filepath) {
		// define byte array in case error occurs
		byte[] arrbytMD5Hash = {0x00};

		try {
			// get MD5 instance
			MessageDigest mdMessageDigest = MessageDigest.getInstance("MD5");
			
			// get fileInputStream from file path browsed by user
			FileInputStream fisFileInputStream = new FileInputStream(filepath);

			// create a byte array with a buffer size of 1024 bytes
			byte[] arrbytData = new byte[1024];

			// define var to be used to read int data
			int intIntegerRead;

			// while all the data of the file has not been read, append it to the MessageDigest
			while ((intIntegerRead = fisFileInputStream.read(arrbytData)) != -1) {
				mdMessageDigest.update(arrbytData, 0, intIntegerRead);
			}

			// dump the MD5 hash
			arrbytMD5Hash = mdMessageDigest.digest();
			
			// close the FileInputStream
			fisFileInputStream.close();

		} catch (Exception evtError) {
			// if error occurs, method will return value initiated at the top
			
			// print error in console
			System.out.println(evtError);
		}
		
		// return byte hash
		return arrbytMD5Hash;
	}
	
	// method to convert the MD5 hash to hexadecimal checksum
	public static String byteArrayToString(byte[] array) {
		// convert the array to hex since MD5 checksums use the base 16 numbering system
		String strArray = DatatypeConverter.printHexBinary(array);
		
		// return the string as lower case
		return strArray.toLowerCase();
	}
	
	// custom data type called Signal to be a boolean but with two extra error ones and one for none
	static enum Signal {
		True, False, Error, NetworkError, None
	}
	
	
	// method to compare checksum with infected dictionary to determine if file is infected
	public static Signal compareChecksum(String checksum, String checksumdicpath) {
		
		/*
		* since the dictionary stores file names based on the first three digits, the correct section to use can easily be found by taking
		* a substring of the first three characters of the checksum
		*/ 
		String strChecksumDicPath = checksumdicpath + "/" + checksum.substring(0, 3) + ".txt";
		
		// define vars
		Signal sgnMatch = Signal.False;
		String strCurrentLine;
		
		try {
			// get URL of checksum file to use
			URL urlChecksumDic = new URL(strChecksumDicPath);
			
			// open the URL with InputStream reader and then open that with the buffered reader
			InputStreamReader isrInputStreamReader = new InputStreamReader(urlChecksumDic.openStream());
			BufferedReader bfrBufferReader = new BufferedReader(isrInputStreamReader);

			// loop to run until entire text file has been read or there is a match
			do {
				// read current line in the dictionary
				strCurrentLine = bfrBufferReader.readLine();
				
				// if the the reader has not read the entire file
				if (strCurrentLine != null) {
					
					// check if there is a match with the current item in the dictionary to the user's MD5 checksum
					if (strCurrentLine.equals(checksum)) {
						// if there is a match, set the sgnMatch to be true
						sgnMatch = Signal.True;
					}
				}
				
			} while (strCurrentLine != null && sgnMatch == Signal.False);
			
			// close the InputStreamReader and BufferedReader
			isrInputStreamReader.close();
			bfrBufferReader.close();
		
		// if there is a error getting the dictionary
		} catch (IOException evtNetworkError) {
			// set the sgnMatch to be a network error
			sgnMatch = Signal.NetworkError;
		
		// if there is an error scanning the file
		} catch (Exception evtError) {
			// set the sgnMatch to be a error
			sgnMatch = Signal.Error;
			
			// print the error to the console
			System.out.println(evtError);
		}
		
		// return the variable
		return sgnMatch;
	}

}
