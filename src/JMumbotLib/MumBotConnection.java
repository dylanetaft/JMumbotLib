package JMumbotLib;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import MumbleProto.Mumble;
import MumbleProto.Mumble.ChannelState;
import MumbleProto.Mumble.UserRemove;
import MumbleProto.Mumble.UserState;

// 2b type, 4b length, rest data

public class MumBotConnection 
{
	public static final short PKT_TYPE_VERSION = 0;
	public static final short PKT_TYPE_UDPTUNNEL = 1;
	public static final short PKT_TYPE_AUTH = 2;
	public static final short PKT_TYPE_PING = 3;
	public static final short PKT_TYPE_REJECT = 4;
	public static final short PKT_TYPE_SERVERSYNC = 5;
	public static final short PKT_TYPE_CHANNELREMOVE = 6;
	public static final short PKT_TYPE_CHANNELSTATE = 7;
	public static final short PKT_TYPE_USERREMOVE = 8;
	public static final short PKT_TYPE_USERSTATE = 9;
	public static final short PKT_TYPE_TEXTMESSAGE = 11;
	public static final short PKT_TYPE_PERMISSIONDENIED = 12;
	public static final short PKT_TYPE_CRYPTSETUP = 15;
	
	private Socket s;
	DataInputStream is;
	DataOutputStream os;
	private boolean syncComplete = false; //server sync received
	private static MumBotConnection instance = null;
	public HashMap<Integer,UserState> userStateList = new HashMap<Integer, UserState>(); //used to keep track of users by session
	public HashMap<Integer, ChannelState> channelStateList = new HashMap<Integer,ChannelState>(); //used to keep track of channels by id
	
	private int mySession = 0;
	
	private MumBotListener myListener;
	
	
	private Thread socketThread = new Thread(new SocketHandler());
	
	private class MumSSLTrustManager implements X509TrustManager
	{        
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        public void checkClientTrusted(
                java.security.cert.X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(
                java.security.cert.X509Certificate[] certs, String authType) {
        }
	    

	}
	
	private void gotUserRemove(UserRemove remove) {
		int session = remove.getSession();
		userStateList.remove(session);	
		if (myListener != null) myListener.gotUserRemove(remove);
	}
	
	private void gotChannelState(ChannelState state) {
		int channelID = state.getChannelId();
		ChannelState chan = channelStateList.get(channelID);
		if (!channelStateList.containsKey(channelID)) { //new channel
			channelStateList.put(channelID, state);
		}
		else {
			ChannelState oldState = channelStateList.get(channelID);
			
			ChannelState mergedState = oldState.newBuilder()
				//.setName(state.hasName() ? state.getName() : oldState.getName())
				//.setChannelId(state.getChannelId()) //always sent
				//.setDescription(state.hasDescription() ? state.getDescription() : oldState.getDescription())
				.mergeFrom(oldState)
				.mergeFrom(state)
			.build();
			channelStateList.put(channelID,mergedState);
			
		}
		if (myListener != null) myListener.gotChannelState(state);	
		
	}
	private void gotUserState(UserState state) {
		int session = state.getSession();
		if (!userStateList.containsKey(session)) { //new user
			userStateList.put(session, state);
			if (myListener != null) myListener.gotUserState(state, (true && syncComplete));
		}
		else {
			UserState oldState = userStateList.get(session);	
			
			UserState mergedState = UserState.newBuilder()
				//.setName((state.hasName() ? state.getName() : oldState.getName()))
				//.setChannelId((state.hasChannelId() ? state.getChannelId() : oldState.getChannelId()))
				//.setSession(state.getSession()) //always sent
				.mergeFrom(oldState)
				.mergeFrom(state)
			.build();
			userStateList.put(session,mergedState);
			if (myListener != null) myListener.gotUserState(state, false);	
		}
	}
	
	public static MumBotConnection getInstance() {
		if (instance == null) {
			instance = new MumBotConnection();
		}
		return instance;
	}
	
	protected MumBotConnection() {
		
	}
	
	public void setListener(MumBotListener listener)
	{
		myListener = listener;
	}
	
	
	public static final short APKT_TYPE_CELT_ALPHA = 0;
	public static final short APKT_TYPE_PING = 1;
	
	private int readVarInt(int inputpos, byte[] inputData, byte[] outputdata) { //returns number of bytes read, fills outputdata
		Arrays.fill(outputdata, (byte)0); //zero fill output array

		if ((inputData[inputpos] & 0xFF) < 0b10000000) { //0xff upcasts to an int, unsigned byte, 1 byte decoded, 7 * 8 + 1 leading zeros
			outputdata[7] = inputData[inputpos];
			return 1;
		}
		
		else if ((inputData[inputpos] & 0xFF) < 0b11000000) { //2 bytes decoded, 6 * 8 + 2 leading zeros
			outputdata[6] = (byte)(inputData[inputpos] & 0b00111111); //mask out first two bits
			outputdata[7] = inputData[inputpos + 1];
			return 2;
		}
		
		else if ((inputData[inputpos] & 0xFF) < 0b11100000) { //3 bytes decoded, 5 * 8 + 3 leading zeros
			outputdata[5] = (byte)(inputData[inputpos] & 0b00011111); //mask out first three bits
			outputdata[6] = inputData[inputpos + 1];
			outputdata[7] = inputData[inputpos + 2];
			return 3;
		}		
		
		
		return 0; //no bytes read, some issue
	}
	private void handleAudioPacket(ByteBuffer data) {
		
		byte varintdata[] = new byte[8];
		
		int bufferPos = 0;
		if (data.limit() == 0) return; //it's empty
		byte[] buffer = data.array();
		
		int vpktType = 0xff & ((buffer[0] & 0b11100000) >> 5); 
		int vpktTarget = 0xff & (buffer[0] & 0b00011111);
		bufferPos ++; //move to pos 1, which is varint session of user  TODO CHECK LENGTH
		
		int varintsize = readVarInt(bufferPos,buffer,varintdata);
		System.out.println(varintdata[7] & 0xff);
		System.out.println("varint size: " + varintsize + " data:" + new BigInteger(varintdata));	
	}
	
	private class SocketHandler implements Runnable {
		
		public void run() {
			try {
				ByteBuffer curHeader = ByteBuffer.allocate(6);
				ByteBuffer curData = ByteBuffer.allocate(0);
				while (true)
				{
					
					//if (is.available() == 0) continue;
					byte data = is.readByte();
					if (curHeader.hasRemaining()) { //reading header
						curHeader.put(data);
						if (!curHeader.hasRemaining()) //header read
						{
							int packetLength = curHeader.getInt(2); //length
							curData = ByteBuffer.allocate(packetLength);
						}
					}
					else //reading data
					{
						if (curData.hasRemaining())
						{
							curData.put(data);
							if (!curData.hasRemaining()) //finished reading data
							{
								short packetType = curHeader.getShort(0); //type
								switch (packetType)
								{
									case PKT_TYPE_UDPTUNNEL:
										handleAudioPacket(curData);
										break;
									case PKT_TYPE_REJECT:
										System.out.println(Mumble.Reject.parseFrom(curData.array()).getReason());
										break;
									case PKT_TYPE_CHANNELSTATE:
										ChannelState channelstate = ChannelState.parseFrom(curData.array());
										gotChannelState(channelstate);
										break;
										
									case PKT_TYPE_TEXTMESSAGE:
										if (myListener != null) myListener.gotTextMessage(Mumble.TextMessage.parseFrom(curData.array()));
										break;
									case PKT_TYPE_SERVERSYNC:
										System.out.println("Register");
										Mumble.ServerSync myServerSync = Mumble.ServerSync.parseFrom(curData.array());
										mySession = myServerSync.getSession();
										if (myListener != null) myListener.gotServerSync(myServerSync);
										sendData(PKT_TYPE_USERSTATE,createRegisterUserPktData());
										syncComplete = true;
										break;
									case PKT_TYPE_USERSTATE:
										UserState userstate = UserState.parseFrom(curData.array());
										gotUserState(userstate);
										break;
									case PKT_TYPE_USERREMOVE:
										UserRemove userRemove = Mumble.UserRemove.parseFrom(curData.array());
										gotUserRemove(userRemove);
									case PKT_TYPE_PERMISSIONDENIED:
										System.out.println("Permission denied:" + Mumble.PermissionDenied.parseFrom(curData.array()).getType().toString());
										break;
								}
								curHeader.clear();
								curData.clear();
							}
						}
					}
				}	
		}
			catch (Exception e)
			{
				e.printStackTrace();
				System.err.println(e.getCause().getMessage());
				System.err.println(e.getMessage());
			}
		}
	}
	public void connect(String hostname, int port, String username) { //used for login without auth
		System.out.println("Whee");
		try
		{
			
			SSLContext sslc = SSLContext.getInstance("TLS");
			TrustManager[] trustAllCerts = new TrustManager[]{new MumSSLTrustManager()};
			sslc.init(null, trustAllCerts, new java.security.SecureRandom());		
			SSLSocketFactory sfac = sslc.getSocketFactory();
			s = (SSLSocket) sfac.createSocket(hostname,port);
			is = new DataInputStream(s.getInputStream());
			os = new DataOutputStream(s.getOutputStream());
			sendData(PKT_TYPE_VERSION,createVersionPktData());
			sendData(PKT_TYPE_AUTH,createAuthPktData(username));
			
			startKeepAlive();
			socketThread.start();
		}
		catch (Exception e) {
			e.printStackTrace();
			System.err.println(e.getCause().getMessage());
			System.err.println(e.getMessage());			
		}
	}
	
	public void connect(String hostname, int port, String username, String password) //used for login with auth
	{
		try
		{
			System.out.println("Connect with pw");
			KeyStore ks = KeyStore.getInstance("JKS");
			InputStream ksfile = new FileInputStream("keystore.jks");
			ks.load(ksfile, "password".toCharArray());
			ksfile.close();
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks,"password".toCharArray());
			TrustManager[] trustAllCerts = new TrustManager[]{new MumSSLTrustManager()};
			
			 
			SSLContext sslc = SSLContext.getInstance("TLS");
			sslc.init(kmf.getKeyManagers(), trustAllCerts, new java.security.SecureRandom());
		
			SSLSocketFactory sfac = sslc.getSocketFactory();
			s = (SSLSocket) sfac.createSocket(hostname,port);
					
			is = new DataInputStream(s.getInputStream());
			os = new DataOutputStream(s.getOutputStream());
			sendData(PKT_TYPE_VERSION,createVersionPktData());
			sendData(PKT_TYPE_AUTH,createAuthPktData(username, password));
			startKeepAlive();
			socketThread.start();
			
		}
		catch (Exception e)
		{
			e.printStackTrace();
			System.err.println(e.getCause().getMessage());
			System.err.println(e.getMessage());
		}
		
	}
	private void startKeepAlive()
	{
		TimerTask task = new TimerTask() {

			@Override
			public void run() {
				// TODO Auto-generated method stub
				try
				{
					sendData(PKT_TYPE_PING,createPingPktData());
				}
				catch (Exception e)
				{
					
				}
			}
			
		};
		Timer timer = new Timer();
		timer.scheduleAtFixedRate(task, 0, 15000);
	}
	
	public void setSelfDeaf(boolean deaf) {
		sendData(PKT_TYPE_USERSTATE,createSelfDeafPktData(deaf));
	}
	
	public void setSelfMute(boolean mute) {
		sendData(PKT_TYPE_USERSTATE,createSelfMutePktData(mute));		
	}	
	
	public void sendTextMessage(int channelID, String message)  {
		sendData(PKT_TYPE_TEXTMESSAGE,createTextMessagePktData(channelID, message));
	}
	
	public void sendPrivateTextMessage(int userID, String message) {
		sendData(PKT_TYPE_TEXTMESSAGE, createPrivateTextMessagePktData(userID, message));
	}
	public void joinChannel(int id)
	{
			sendData(PKT_TYPE_USERSTATE,createJoinChannelPktData(id));
	}
	
	public synchronized void sendData(short ptype, byte[] data) 
	{
		ByteBuffer packet = ByteBuffer.allocate(2 + 4 + data.length); //2 bytes for type, 4 bytes for length, data.length
		packet.putShort(ptype);
		packet.putInt(data.length);
		packet.put(data);
		try
		{
			os.write(packet.array());
		}
		catch (Exception e)
		{
			e.printStackTrace();
			System.err.println(e.getCause().getMessage());
			System.err.println(e.getMessage());
		}
	}
	
	private byte[] createTextMessagePktData(int channelID, String message) {
		return Mumble.TextMessage.newBuilder()
				.addChannelId(channelID)
				.setMessage(message)
				.build().toByteArray();
	}

	private byte[] createPrivateTextMessagePktData(int userID, String message) {
		return Mumble.TextMessage.newBuilder()
				.addSession(userID)
				.setMessage(message)
				.build().toByteArray();
	}
	
	private byte[] createVersionPktData() {
		int major = 1 << 16;
		int minor = 2 << 8;
		int patch = 8;
				
		return Mumble.Version.newBuilder()
		.setVersion(major + minor + patch)
		.setRelease("1.2.8")
		.build().toByteArray();
	}
	
	private byte[] createAuthPktData(String username) {
		return Mumble.Authenticate.newBuilder()
				.setUsername(username)
				.build().toByteArray();
	}
	
	private byte[] createAuthPktData(String username, String password) {
		return Mumble.Authenticate.newBuilder()
				.setUsername(username)
				.setPassword(password)
				.build().toByteArray();
	}
	
	private byte[] createSelfDeafPktData(boolean deaf) {
		return Mumble.UserState.newBuilder()
				.setSelfDeaf(deaf)
				.build().toByteArray();
	}
	
	private byte[] createSelfMutePktData(boolean mute) {
		return Mumble.UserState.newBuilder()
				.setSelfMute(mute)
				.build().toByteArray();
	}	
	
	private byte[] createPingPktData() {
		return Mumble.UserState.newBuilder()
		.build().toByteArray();
	}
	private byte[] createJoinChannelPktData(int id) {
		return Mumble.UserState.newBuilder()
				.setChannelId(id)
				.build().toByteArray();
			
	}
	private byte[] createRegisterUserPktData() {
		return Mumble.UserState.newBuilder()
				.setUserId(0)
				.setSession(mySession)
				.build().toByteArray();
				
		
	}
	
}
