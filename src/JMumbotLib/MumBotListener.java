package JMumbotLib;
import MumbleProto.Mumble;


public interface MumBotListener {

	public void gotChannelState(Mumble.ChannelState state); //used to obtain channel info from server
	public void gotTextMessage(Mumble.TextMessage message); //used for channel messages
	public void gotUserState(Mumble.UserState state, boolean newlogin); //used for user state
	public void gotUserRemove(Mumble.UserRemove remove); //used when clients disconnect
	public void gotServerSync(Mumble.ServerSync sync); //used to obtain session id and welcome text etc

}
