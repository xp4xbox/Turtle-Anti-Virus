package Turtle;

/**
 * @author xp4xbox
 * Date: Jun 14, 2018
 * ValuesForUI.java
 * Class to store values for UI
 */

public class ValuesForUI {
	// define volatile variables so they can be accessed outside the thread
	private volatile Turtle.Signal sgnInfected;
	private volatile String strMD5Checksum;
	
	// method to set the status of the file
	public void setSgnInfected(Turtle.Signal infected) {
		this.sgnInfected = infected;
	}
	
	// method to set the MD5 checksum
	public void setStrCheksum(String checksum) {
		this.strMD5Checksum = checksum;
	}
	
	// method to return the MD5 checksum
	public String getStrChecksum() {
		return this.strMD5Checksum;
	}
	
	// method to return the status of the file
	public Turtle.Signal getSgnInfected() {
		return this.sgnInfected;
	}
}